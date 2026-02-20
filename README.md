find_art_method_slot
====================

Purpose
-------
Single program with two stages:
1) Resolve the runtime address of android_os_Process_setArgV0.
2) Scan zygote64 heap for a pointer to that address.

# -----
adb logcat -b crash

adb shell pidof zygote64
adb shell "su -c 'kill -9 21771'"



Build (NDK, x86_64)
------------------
Example:

 C:\Users\qiuguo\AppData\Local\Android\Sdk\ndk\28.2.13676358\toolchains\llvm\prebuilt\windows-x86_64\bin\clang -v -O2
  -static --target=x86_64-linux-android35 -o find_art_method_slot find_art_method_slot.c proc_maps.c elf_utils.c
  mem_scan.c


  adb push find_art_method_slot /data/local/tmp/
  adb push payload.bin /data/local/tmp/

  adb shell su -c "ls -l /data/local/tmp/find_art_method_slot; chmod 755 /data/local/tmp/find_art_method_slot; ls -l /
  data/local/tmp/find_art_method_slot"

  adb shell su -c "ls -l /data/local/tmp/payload.bin; chmod 755 /data/local/tmp/payload.bin; ls -l /
  data/local/tmp/payload.bin"

  adb shell su -c "/data/local/tmp/find_art_method_slot --pid 10123 --dump"

.\run_all.ps1 -TargetPid 10123 -Dump
Options
-------
  --pid <pid>   use a specific process instead of zygote64
--------

 


# 1. 编译成目标文件 (.o)
# -fPIC: 位置无关代码 (关键!)
# -Os: 优化大小
# -fno-stack-protector: 禁用栈保护 (防止引用 canary)
# -fno-builtin: 禁用内置函数优化
# -nostdlib: 不链接标准库
C:\Users\qiuguo\AppData\Local\Android\Sdk\ndk\28.2.13676358\toolchains\llvm\prebuilt\windows-x86_64\bin\clang -target x86_64-linux-android -Os -fPIC -fno-stack-protector -fno-builtin -nostdlib -c payload.c -o payload.o

# 2. 提取纯机器码 (.bin)
# -O binary: 输出原始二进制
# -j .text: 只提取代码段
C:\Users\qiuguo\AppData\Local\Android\Sdk\ndk\28.2.13676358\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-objcopy -O binary -j .text.entry payload.o payload.bin

######
 新流程

  1. 编译 payload.c → payload.o
  2. llvm-objcopy 提取 .text.entry → payload.bin
  3. 编译注入器
  4. push 到设备
  5. chmod
  6. 运行

  用法

  .\run_all.ps1 -TargetPid 10123 -Dump

  如需自定义路径：

  - -PayloadSrc payload.c
  - -PayloadBin payload.bin
  - -NdkObjcopy <path>
