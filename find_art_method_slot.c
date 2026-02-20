#include "elf_utils.h"
#include "mem_scan.h"
#include "proc_maps.h"

#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define TARGET_PROC_NAME "zygote64"
#define TARGET_LIB_NAME "libandroid_runtime.so"
#define TARGET_LIB_LOG_NAME "liblog.so"
#define TARGET_LOG_SYMBOL "__android_log_print"
#define TARGET_LIB_SLEEP_NAME "libc.so"
#define TARGET_SLEEP_SYMBOL "sleep"
#define TARGET_SYMBOL                                                          \
  "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring"

static void die(const char *msg) {
  fprintf(stderr, "error: %s\n", msg);
  exit(1);
}

static uint64_t find_payload_cave(int pid) {
  char map_path[64];
  snprintf(map_path, sizeof(map_path), "/proc/%d/maps", pid);

  FILE *fp = fopen(map_path, "r");
  if (!fp)
    return 0;

  char line[1024];
  uint64_t start = 0;
  uint64_t end = 0;
  char perms[16] = {0};
  uint64_t target_addr = 0;

  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "libstagefright.so") && strstr(line, "r-xp")) {
      sscanf(line, "%lx-%lx %15s", &start, &end, perms);
      target_addr = end - 0x400;
      break;
    }
  }

  fclose(fp);
  return target_addr;
}

static void write_mem(int fd, uint64_t addr, const void *data, size_t len) {
  if (lseek64(fd, (off64_t)addr, SEEK_SET) == -1) {
    perror("[-] lseek failed");
    exit(1);
  }
  if (write(fd, data, len) != (ssize_t)len) {
    perror("[-] write failed");
    exit(1);
  }
}

static void format_proc_path(char *buf, size_t size, int pid,
                             const char *file) {
  snprintf(buf, size, "/proc/%d/%s", pid, file);
}

#define PAYLOAD_PATH "/data/local/tmp/payload.bin"
#define PLACEHOLDER_LOG 0x1111111111111111ULL
#define PLACEHOLDER_ORIG 0x2222222222222222ULL
#define PLACEHOLDER_SLOT 0x3333333333333333ULL

static uint8_t *load_file(const char *path, size_t *out_size) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;

  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long size = ftell(f);
  if (size <= 0) {
    fclose(f);
    return NULL;
  }
  if (fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }

  uint8_t *buf = malloc((size_t)size);
  if (!buf) {
    fclose(f);
    return NULL;
  }

  if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
    free(buf);
    fclose(f);
    return NULL;
  }

  fclose(f);
  *out_size = (size_t)size;
  return buf;
}

static size_t patch_u64_pattern(uint8_t *buf, size_t size, uint64_t pattern,
                                uint64_t value) {
  uint8_t pat[8];
  uint8_t val[8];
  memcpy(pat, &pattern, sizeof(pat));
  memcpy(val, &value, sizeof(val));

  size_t count = 0;
  for (size_t i = 0; i + sizeof(pat) <= size; i++) {
    if (memcmp(buf + i, pat, sizeof(pat)) == 0) {
      memcpy(buf + i, val, sizeof(val));
      count++;
      i += sizeof(pat) - 1;
    }
  }
  return count;
}

static void print_payload_hex(const uint8_t *buf, size_t size) {
  const size_t bytes_per_line = 16;
  for (size_t i = 0; i < size; i += bytes_per_line) {
    printf("%08zx  ", i);
    for (size_t j = 0; j < bytes_per_line; j++) {
      if (i + j < size)
        printf("%02x ", buf[i + j]);
      else
        printf("   ");
    }
    printf(" |");
    for (size_t j = 0; j < bytes_per_line; j++) {
      if (i + j < size) {
        unsigned char c = buf[i + j];
        if (c >= 32 && c <= 126)
          putchar(c);
        else
          putchar('.');
      } else {
        putchar(' ');
      }
    }
    printf("|");
  }
}

int main(int argc, char **argv) {
  int target_pid = -1;
  const char *payload_path = PAYLOAD_PATH;
  bool dump_payload = false;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
      target_pid = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--payload") == 0 && i + 1 < argc) {
      payload_path = argv[++i];
    } else if (strcmp(argv[i], "--dump") == 0) {
      dump_payload = true;
    } else {
      die("usage: --pid <pid> [--payload <path>] [--dump]");
    }
  }

  if (target_pid <= 0) {
    target_pid = find_pid_by_name(TARGET_PROC_NAME);
    if (target_pid <= 0)
      die("zygote64 process not found. Please specify PID with --pid <pid>");
  }

  printf("[+] Target PID: %d\n", target_pid);

  lib_info_t runtime_lib;
  if (!find_lib_info(target_pid, TARGET_LIB_NAME, &runtime_lib))
    die("libandroid_runtime.so not found in target process");

  uint64_t setargv0_offset = 0;
  if (!find_symbol_offset(runtime_lib.path, TARGET_SYMBOL, &setargv0_offset))
    die("failed to find symbol offset in libandroid_runtime.so");

  uint64_t setargv0_addr = runtime_lib.base + setargv0_offset;

  printf("[+] Library: %s\n", runtime_lib.path);
  printf("[+] Library base: 0x%016" PRIx64 "\n", runtime_lib.base);
  printf("[+] Symbol offset: 0x%016" PRIx64 "\n", setargv0_offset);
  printf("[+] Symbol absolute address: 0x%016" PRIx64 "\n", setargv0_addr);

  map_entry_t *heap_maps = NULL;
  size_t heap_map_count = 0;
  if (collect_readable_maps(target_pid, &heap_maps, &heap_map_count) != 0)
    die("no readable heap maps found");

  char mem_path[64];
  format_proc_path(mem_path, sizeof(mem_path), target_pid, "mem");
  int mem_fd = open(mem_path, O_RDONLY);
  if (mem_fd < 0) {
    free(heap_maps);
    die("failed to open /proc/<pid>/mem (need root)");
  }

  uint64_t slot_addr = 0;
  if (scan_for_pointer(mem_fd, setargv0_addr, heap_maps, heap_map_count,
                       &slot_addr) != 0) {
    close(mem_fd);
    free(heap_maps);
    die("pointer not found in heap maps");
  }

  uint64_t slot_value = 0;
  if (pread(mem_fd, &slot_value, sizeof(slot_value), (off_t)slot_addr) !=
      (ssize_t)sizeof(slot_value)) {
    close(mem_fd);
    free(heap_maps);
    die("failed to read slot value");
  }

  close(mem_fd);
  free(heap_maps);

  printf("\n[+] Found pointer at: 0x%016" PRIx64 "\n", slot_addr);
  printf("[+] Slot value: 0x%016" PRIx64 "\n", slot_value);
  printf("[+] setArgV0 absolute address: 0x%016" PRIx64 "\n", setargv0_addr);

  uint64_t payload_addr = find_payload_cave(target_pid);
  if (!payload_addr) {
    printf("[-] Can't find code cave\n");
    return 1;
  }

  // lib_info_t sleep_lib;
  // if (!find_lib_info(target_pid, TARGET_LIB_SLEEP_NAME, &sleep_lib))
  //   die("liblog.so not found in target process");

  // uint64_t sleep_offset = 0;
  // if (!find_symbol_offset(sleep_lib.path, TARGET_SLEEP_SYMBOL,
  // &sleep_offset))
  //   die("failed to find symbol offset in libc.so");

  // uint64_t sleep_addr = sleep_lib.base + sleep_offset;
  // printf("[*] uSleep Function: %lx (Offset: %lx)\n", sleep_addr,
  // sleep_offset);

  lib_info_t log_lib;
  if (!find_lib_info(target_pid, TARGET_LIB_LOG_NAME, &log_lib))
    die("liblog.so not found in target process");

  uint64_t log_offset = 0;
  if (!find_symbol_offset(log_lib.path, TARGET_LOG_SYMBOL, &log_offset))
    die("failed to find symbol offset in libc.so");

  uint64_t log_addr = log_lib.base + log_offset;
  printf("[*] __android_log_print Function: %lx (Offset: %lx)\n", log_addr,
         log_offset);

  printf("[*] Payload Cave: %lx\n", payload_addr);

  // 构造机器码

  size_t payload_size = 0;
  uint8_t *payload = load_file(payload_path, &payload_size);
  if (!payload)
    die("failed to load payload file");

  size_t patched_log =
      patch_u64_pattern(payload, payload_size, PLACEHOLDER_LOG, log_addr);
  size_t patched_orig =
      patch_u64_pattern(payload, payload_size, PLACEHOLDER_ORIG, setargv0_addr);
  size_t patched_slot =
      patch_u64_pattern(payload, payload_size, PLACEHOLDER_SLOT, slot_addr);

  if (patched_log == 0 || patched_orig == 0 || patched_slot == 0) {
    free(payload);
    die("failed to patch payload placeholders");
  }

  format_proc_path(mem_path, sizeof(mem_path), target_pid, "mem");
  int fd = open(mem_path, O_RDWR);
  if (fd < 0) {
    perror("open mem");
    free(payload);
    return 1;
  }

  printf("Payload size: %zu bytes\n", payload_size);
  if (dump_payload)
    print_payload_hex(payload, payload_size);
  // write_mem(fd, payload_addr, payload, payload_size);
  // write_mem(fd, slot_addr, &payload_addr, 8);
  free(payload);
  close(fd);
  printf("[SUCCESS] Simple Log Injection Done.\n");
  return 0;
}
