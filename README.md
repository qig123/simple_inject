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

Run (on emulator)
-----------------
  adb push find_art_method_slot /data/local/tmp/

  adb shell su -c "ls -l /data/local/tmp/find_art_method_slot; chmod 755 /data/local/tmp/find_art_method_slot; ls -l /
  data/local/tmp/find_art_method_slot"

  adb shell su -c "/data/local/tmp/find_art_method_slot --pid 21771"

Options
-------
  --pid <pid>   use a specific process instead of zygote64
--------
核心思路如下：
数据与代码混合：把字符串（Tag 和 Log内容）直接贴在机器码屁股后面。
手动重定位：在 C 代码里算好 __android_log_print 的地址，直接用 memcpy 填入机器码的占位符中。
1. 核心逻辑图解
我们将构造一块内存（Payload），长这样：
code
Text
+-----------------------+ <--- Payload Start
| 1. 保存寄存器 (Push)   |
+-----------------------+
| 2. 准备参数            |
|    RDI = 优先级 (3)    |
|    RSI = Tag 地址      | (难点：用 RIP 相对寻址指向下方)
|    RDX = Msg 地址      | (难点：用 RIP 相对寻址指向下方)
|    RAX = 0 (变参清零)  |
+-----------------------+
| 3. 调用 Log 函数       |
|    MOV R11, [占位符]   | <--- 在 C 代码里把函数地址填这
|    CALL R11           |
+-----------------------+
| 4. 恢复寄存器 (Pop)    |
+-----------------------+
| 5. 恢复 Hook 并跳转    |
+-----------------------+
|    String: "MyTag\0"  | <--- 放在代码末尾
+-----------------------+
|    String: "Hello\0"  |
+-----------------------+  


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
C:\Users\qiuguo\AppData\Local\Android\Sdk\ndk\28.2.13676358\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-objcopy -O binary -j .text payload.o payload.bin
