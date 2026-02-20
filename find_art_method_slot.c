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

#define LOG_TAG "HOOK_TEST"
#define LOG_MSG "Hello from Zymbiote Payload!"
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
// 构建 Shellcode 的辅助函数
void build_log_payload(uint8_t *buffer, int *out_len, uint64_t log_func_addr,
                       uint64_t slot_addr, uint64_t orig_func_addr,
                       const char *tag_str, const char *msg_str) {
  int idx = 0;

  // ==========================================
  // Part 1: 保存现场 (Save Context)
  // 关键修正：Push 15 个寄存器 (15 * 8 = 120 bytes)
  // 假设进入时 RSP 结尾是 8，减去 120 后结尾是 0 (16字节对齐)
  // ==========================================
  uint8_t pushes[] = {
      0x50,       // push rax
      0x53,       // push rbx
      0x51,       // push rcx
      0x52,       // push rdx
      0x57,       // push rdi
      0x56,       // push rsi
      0x55,       // push rbp
      0x41, 0x50, // push r8
      0x41, 0x51, // push r9
      0x41, 0x52, // push r10
      0x41, 0x53, // push r11
      0x41, 0x54, // push r12
      0x41, 0x55, // push r13
      0x41, 0x56, // push r14
      0x41, 0x57  // push r15  <-- 新增这个，凑成奇数
  };
  memcpy(&buffer[idx], pushes, sizeof(pushes));
  idx += sizeof(pushes);

  // ==========================================
  // Part 2: 准备参数
  // ==========================================

  // 1. RDI = Priority (3 = DEBUG)
  buffer[idx++] = 0x48;
  buffer[idx++] = 0xc7;
  buffer[idx++] = 0xc7;
  buffer[idx++] = 0x03;
  buffer[idx++] = 0x00;
  buffer[idx++] = 0x00;
  buffer[idx++] = 0x00;

  // 2. 清空 RAX (变参函数必须)
  buffer[idx++] = 0x31;
  buffer[idx++] = 0xc0;

  // 3. 相对寻址 RSI (Tag)
  buffer[idx++] = 0x48;
  buffer[idx++] = 0x8d;
  buffer[idx++] = 0x35;
  int offset_tag_pos = idx;
  buffer[idx++] = 0x00;
  buffer[idx++] = 0x00;
  buffer[idx++] = 0x00;
  buffer[idx++] = 0x00;

  // 4. 相对寻址 RDX (Msg)
  buffer[idx++] = 0x48;
  buffer[idx++] = 0x8d;
  buffer[idx++] = 0x15;
  int offset_msg_pos = idx;
  buffer[idx++] = 0x00;
  buffer[idx++] = 0x00;
  buffer[idx++] = 0x00;
  buffer[idx++] = 0x00;

  // ==========================================
  // Part 3: 调用 Log
  // ==========================================
  buffer[idx++] = 0x49;
  buffer[idx++] = 0xbb;
  memcpy(&buffer[idx], &log_func_addr, 8);
  idx += 8;

  // call r11
  // 此时 RSP 应该是 16字节对齐的，否则 liblog 会崩
  buffer[idx++] = 0x41;
  buffer[idx++] = 0xff;
  buffer[idx++] = 0xd3;

  // ==========================================
  // Part 4: 恢复现场 (反向 Pop)
  // ==========================================
  uint8_t pops[] = {
      0x41, 0x5f, // pop r15   <-- 对应 pop
      0x41, 0x5e, // pop r14
      0x41, 0x5d, // pop r13
      0x41, 0x5c, // pop r12
      0x41, 0x5b, // pop r11
      0x41, 0x5a, // pop r10
      0x41, 0x59, // pop r9
      0x41, 0x58, // pop r8
      0x5d,       // pop rbp
      0x5e,       // pop rsi
      0x5f,       // pop rdi
      0x5a,       // pop rdx
      0x59,       // pop rcx
      0x5b,       // pop rbx
      0x58        // pop rax
  };
  memcpy(&buffer[idx], pops, sizeof(pops));
  idx += sizeof(pops);

  // ==========================================
  // Part 5: 恢复 Hook 并跳转
  // ==========================================

  // mov rax, slot_addr
  buffer[idx++] = 0x48;
  buffer[idx++] = 0xb8;
  memcpy(&buffer[idx], &slot_addr, 8);
  idx += 8;

  // mov rcx, orig_func_addr
  buffer[idx++] = 0x48;
  buffer[idx++] = 0xb9;
  memcpy(&buffer[idx], &orig_func_addr, 8);
  idx += 8;

  // mov [rax], rcx
  buffer[idx++] = 0x48;
  buffer[idx++] = 0x89;
  buffer[idx++] = 0x08;

  // jmp rcx
  buffer[idx++] = 0xff;
  buffer[idx++] = 0xe1;

  // ==========================================
  // Part 6: 填充数据区
  // ==========================================

  // Tag String
  int tag_start_idx = idx;
  strcpy((char *)&buffer[idx], tag_str);
  idx += strlen(tag_str) + 1;

  // Msg String
  int msg_start_idx = idx;
  strcpy((char *)&buffer[idx], msg_str);
  idx += strlen(msg_str) + 1;

  // 回填偏移量
  int32_t tag_rel_offset = tag_start_idx - (offset_tag_pos + 4);
  memcpy(&buffer[offset_tag_pos], &tag_rel_offset, 4);

  int32_t msg_rel_offset = msg_start_idx - (offset_msg_pos + 4);
  memcpy(&buffer[offset_msg_pos], &msg_rel_offset, 4);

  *out_len = idx;
}
int main(int argc, char **argv) {
  int target_pid = -1;

  if (argc == 3 && strcmp(argv[1], "--pid") == 0) {
    target_pid = atoi(argv[2]);
  } else {
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
  int len = 0;
  uint8_t payload[1024];

  build_log_payload(payload, &len, log_addr, slot_addr, setargv0_addr,
                    "INJECTOR", "Success from C!");
  format_proc_path(mem_path, sizeof(mem_path), target_pid, "mem");
  int fd = open(mem_path, O_RDWR);
  if (fd < 0) {
    perror("open mem");
    return 1;
  }

  printf("Payload generated, size: %d bytes\n", len);
  write_mem(fd, payload_addr, payload, len);
  write_mem(fd, slot_addr, &payload_addr, 8);

  close(fd);
  printf("[SUCCESS] Simple Log Injection Done.\n");
  return 0;
}
