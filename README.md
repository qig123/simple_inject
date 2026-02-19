find_art_method_slot
====================

Purpose
-------
Single program with two stages:
1) Resolve the runtime address of android_os_Process_setArgV0.
2) Scan zygote64 heap for a pointer to that address.

adb shell pidof zygote64
adb logcat -b crash

Build (NDK, x86_64)
------------------
Example:
C:\Users\qiuguo\AppData\Local\Android\Sdk\ndk\28.2.13676358\toolchains\llvm\prebuilt\windows-x86_64\bin\clang -v -O2 -static --target=x86_64-linux-android35 -o find_art_method_slot find_art_method_slot.c

Run (on emulator)
-----------------
  adb push find_art_method_slot /data/local/tmp/

  adb shell su -c "ls -l /data/local/tmp/find_art_method_slot; chmod 755 /data/local/tmp/find_art_method_slot; ls -l /
  data/local/tmp/find_art_method_slot"

  adb shell su -c "/data/local/tmp/find_art_method_slot --pid 22758"

Options
-------
  --pid <pid>   use a specific process instead of zygote64
  --pause       pause after printing the symbol address
  --scan-all-readable  scan all readable mappings (slower)
  --no-rw       include non-writable readable mappings
  --debug-maps  print candidate mappings selected for scan
