param(
  [Parameter(Mandatory=$true)][int]$TargetPid,
  [string]$NdkClang = "C:\Users\qiuguo\AppData\Local\Android\Sdk\ndk\28.2.13676358\toolchains\llvm\prebuilt\windows-x86_64\bin\clang",
  [string]$NdkObjcopy = "C:\Users\qiuguo\AppData\Local\Android\Sdk\ndk\28.2.13676358\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-objcopy",
  [string]$Target = "x86_64-linux-android35",
  [string]$Out = "find_art_method_slot",
  [string]$DevicePath = "/data/local/tmp",
  [string]$PayloadSrc = "payload.c",
  [string]$PayloadObj = "payload.o",
  [string]$PayloadBin = "payload.bin",
  [switch]$Dump
)

$ErrorActionPreference = "Stop"

Write-Host "[1/5] Building payload.bin..."
& $NdkClang -target x86_64-linux-android -Os -fPIC -fno-stack-protector -fno-builtin -nostdlib `
  -c $PayloadSrc -o $PayloadObj
& $NdkObjcopy -O binary -j .text.entry $PayloadObj $PayloadBin

Write-Host "[2/5] Building injector..."
& $NdkClang -v -O2 -static --target=$Target -o $Out `
  find_art_method_slot.c proc_maps.c elf_utils.c mem_scan.c

Write-Host "[3/5] Pushing binaries..."
& adb push $Out "$DevicePath/"
& adb push $PayloadBin "$DevicePath/"

Write-Host "[4/5] Setting permissions..."
& adb shell su -c "chmod 755 $DevicePath/$Out"
& adb shell su -c "chmod 644 $DevicePath/$PayloadBin"

Write-Host "[5/5] Running..."
$dumpFlag = ""
if ($Dump) { $dumpFlag = " --dump" }
& adb shell su -c "$DevicePath/$Out --pid $TargetPid$dumpFlag"
