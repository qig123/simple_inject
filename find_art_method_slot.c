#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

static void die(const char *msg) {
  fprintf(stderr, "error: %s\n", msg);
  exit(1);
}

// 根据进程名查找PID
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

static bool str_contains(const char *haystack, const char *needle) {
  return haystack && needle && strstr(haystack, needle) != NULL;
}

// 解析maps文件的一行
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
  }

  return true;
}

// 查找目标库的信息（基址和路径）
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
    if (e.offset != 0) // 只取第一个LOAD段作为基址
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

// 将vaddr转换为文件偏移
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

// 解析GNU hash表获取符号数量
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

// 在ELF文件中查找符号的偏移
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

  // 查找DYNAMIC段
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

  // 解析DYNAMIC段
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

  // 转换为文件偏移
  uint64_t symtab_off = 0;
  uint64_t strtab_off = 0;
  if (!vaddr_to_offset(phdrs, eh.e_phnum, symtab_vaddr, &symtab_off) ||
      !vaddr_to_offset(phdrs, eh.e_phnum, strtab_vaddr, &strtab_off)) {
    free(phdrs);
    fclose(f);
    return false;
  }

  // 获取符号数量
  uint64_t symcount = 0;
  if (gnu_hash_vaddr != 0) {
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

  // 读取字符串表
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

  // 遍历符号表查找目标符号
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

// 判断是否是堆内存区域
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

// 扫描内存查找指针
static int scan_for_pointer(int mem_fd, uint64_t target_ptr, map_entry_t *maps,
                            size_t map_count, uint64_t *out_slot) {
  uint8_t needle[8];
  memcpy(needle, &target_ptr, sizeof(needle));

  uint8_t *buf = malloc(READ_CHUNK);
  if (!buf)
    return -1;

  for (size_t i = 0; i < map_count; i++) {
    map_entry_t *m = &maps[i];
    uint64_t addr = m->start;

    while (addr < m->end) {
      size_t to_read = READ_CHUNK;
      uint64_t remaining = m->end - addr;
      if (remaining < to_read)
        to_read = (size_t)remaining;

      ssize_t n = pread(mem_fd, buf, to_read, (off_t)addr);
      if (n <= 0) {
        break;
      }

      for (size_t off = 0; off + sizeof(needle) <= (size_t)n; off++) {
        if (memcmp(buf + off, needle, sizeof(needle)) == 0) {
          *out_slot = addr + off;
          free(buf);
          return 0;
        }
      }

      addr += (uint64_t)n;
    }
  }

  free(buf);
  return -1;
}

// 收集可读的内存区域
static int collect_readable_maps(int pid, map_entry_t **out_maps,
                                 size_t *out_count) {
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
    if (!is_heap_candidate(e.path))
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

  fclose(f);

  if (count == 0) {
    free(arr);
    return -1;
  }

  *out_maps = arr;
  *out_count = count;
  return 0;
}
// 自动寻找 Payload 地址的函数
uint64_t find_payload_cave(int pid) {
  char map_path[64];
  snprintf(map_path, sizeof(map_path), "/proc/%d/maps", pid);

  FILE *fp = fopen(map_path, "r");
  if (!fp) {
    perror("[-] Failed to open maps");
    return 0;
  }

  char line[1024];
  uint64_t start, end;
  char perms[16];
  char path[256];
  uint64_t target_addr = 0;

  printf("[*] Scanning maps for libstagefright.so...\n");

  while (fgets(line, sizeof(line), fp)) {
    // 筛选包含 libstagefright.so 的行
    if (strstr(line, "libstagefright.so")) {
      // 解析行: start-end perms ... path
      // 例子: 76b0eb131000-76b0eb2ff000 r-xp ...
      sscanf(line, "%lx-%lx %s", &start, &end, perms);

      // 必须是可执行段 (r-xp)
      if (strstr(perms, "x")) { // 只要包含 'x' 即可，通常是 r-xp
        // 找到了！
        // 这里的 end 是这一段内存的结束位置。
        // 内存分页通常是 4096 (0x1000) 对齐的，而代码通常填不满最后一页。
        // 我们往回退 0x200 (512字节)，这块地方通常全是 0 (Padding)
        target_addr = end - 0x200;
        printf("[+] Found executable segment: %lx-%lx [%s]\n", start, end,
               perms);
        break;
      }
    }
  }
  fclose(fp);
  return target_addr;
}

void write_mem(int fd, uint64_t addr, void *data, size_t len) {
  if (lseek64(fd, (off64_t)addr, SEEK_SET) == -1) {
    perror("[-] lseek failed");
    exit(1);
  }
  if (write(fd, data, len) != len) {
    perror("[-] write failed");
    exit(1);
  }
}
int main(int argc, char **argv) {
  int pid = -1;

  // 解析命令行参数
  if (argc == 3 && strcmp(argv[1], "--pid") == 0) {
    pid = atoi(argv[2]);
  } else {
    // 如果没有指定PID，自动查找zygote64
    pid = find_pid_by_name(TARGET_PROC_NAME);
    if (pid <= 0) {
      die("zygote64 process not found. Please specify PID with --pid <pid>");
    }
  }

  printf("[+] Target PID: %d\n", pid);

  // 查找目标库信息
  lib_info_t lib;
  if (!find_lib_info(pid, &lib)) {
    die("libandroid_runtime.so not found in target process");
  }

  // 查找符号在文件中的偏移
  uint64_t sym_offset = 0;
  if (!find_symbol_offset(lib.path, TARGET_SYMBOL, &sym_offset)) {
    die("failed to find symbol offset in libandroid_runtime.so");
  }

  // 计算符号在内存中的绝对地址
  uint64_t sym_runtime = lib.base + sym_offset;

  printf("[+] Library: %s\n", lib.path);
  printf("[+] Library base: 0x%016" PRIx64 "\n", lib.base);
  printf("[+] Symbol offset: 0x%016" PRIx64 "\n", sym_offset);
  printf("[+] Symbol absolute address: 0x%016" PRIx64 "\n", sym_runtime);

  // 收集可读的内存区域
  map_entry_t *maps = NULL;
  size_t map_count = 0;
  if (collect_readable_maps(pid, &maps, &map_count) != 0) {
    die("no readable heap maps found");
  }

  // 打开进程内存
  char mem_path[64];
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

  int mem_fd = open(mem_path, O_RDONLY);
  if (mem_fd < 0) {
    free(maps);
    die("failed to open /proc/<pid>/mem (need root)");
  }

  // 扫描内存中指向目标符号的指针
  uint64_t slot = 0;
  if (scan_for_pointer(mem_fd, sym_runtime, maps, map_count, &slot) != 0) {
    close(mem_fd);
    free(maps);
    die("pointer not found in heap maps");
  }

  // 读取slot处的值
  uint64_t slot_value = 0;
  if (pread(mem_fd, &slot_value, sizeof(slot_value), (off_t)slot) !=
      sizeof(slot_value)) {
    close(mem_fd);
    free(maps);
    die("failed to read slot value");
  }

  close(mem_fd);
  free(maps);
  // arg_method_value
  printf("\n[+] Found pointer at: 0x%016" PRIx64 "\n", slot);
  // set_arg_v0的绝对地址
  printf("[+] Slot value: 0x%016" PRIx64 "\n", slot_value);
  // set_arg_v0的绝对地址
  printf("[+] setArgV0 absolute address: 0x%016" PRIx64 "\n", sym_runtime);
  // 1. 自动寻找 Payload 存放位置
  uint64_t payload_addr = find_payload_cave(pid);
  if (payload_addr == 0) {
    printf("[-] Could not find a suitable place in libstagefright.so\n");
    return 1;
  }
  printf("[+] Calculated Payload Address: %lx\n", payload_addr);

  // 2. 准备 payload (x86_64 汇编: 恢复Slot并跳转)
  uint8_t payload[64];
  int idx = 0;

  // mov rax, SLOT_ADDR
  payload[idx++] = 0x48;
  payload[idx++] = 0xb8;
  memcpy(&payload[idx], &slot, 8);
  idx += 8;

  // mov rcx, ORIG_ADDR
  payload[idx++] = 0x48;
  payload[idx++] = 0xb9;
  memcpy(&payload[idx], &sym_runtime, 8);
  idx += 8;

  // mov [rax], rcx  (恢复指针)
  payload[idx++] = 0x48;
  payload[idx++] = 0x89;
  payload[idx++] = 0x08;

  // jmp rcx (跳转回原函数)
  payload[idx++] = 0xff;
  payload[idx++] = 0xe1;

  printf("[*] Generated %d bytes of machine code.\n", idx);

  // 3. 打开内存写入
  char mem_path2[64];
  snprintf(mem_path2, sizeof(mem_path2), "/proc/%d/mem", pid);
  int fd = open(mem_path2, O_RDWR);
  if (fd < 0) {
    perror("[-] Failed to open /proc/pid/mem (Root required?)");
    return 1;
  }

  // 4. 写入 Payload
  printf("[*] Injecting payload to: %lx\n", payload_addr);
  write_mem(fd, payload_addr, payload, idx);

  // 5. 修改 Slot 指向 Payload
  printf("[*] Overwriting ArtMethod Slot: %lx\n", slot);
  write_mem(fd, slot, &payload_addr, 8);

  close(fd);
  printf("[SUCCESS] Injection complete! Launch an app to test.\n");
  return 0;
}