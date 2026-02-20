#include <stddef.h>
#include <stdint.h>

// 定义 JNI 类型和函数原型
typedef void *JNIEnv;
typedef void *jobject;
typedef void *jstring;

// 原始函数指针定义
typedef void (*set_argv0_func_t)(JNIEnv *env, jobject clazz, jstring name);
// Log 函数指针定义
typedef int (*log_func_t)(int prio, const char *tag, const char *fmt, ...);

// 强制放在 .text 段，作为入口
__attribute__((section(".text.entry"))) void
my_replacement_set_argv0(JNIEnv *env, jobject clazz, jstring name) {

  // ==========================================
  // 1. 定义占位符 (注入时替换为真实地址)
  // ==========================================
  volatile uint64_t log_addr_placeholder = 0x1111111111111111;
  volatile uint64_t orig_addr_placeholder = 0x2222222222222222;
  volatile uint64_t slot_addr_placeholder = 0x3333333333333333;

  volatile uint64_t *slot_ptr = (volatile uint64_t *)slot_addr_placeholder;
  set_argv0_func_t orig_func = (set_argv0_func_t)orig_addr_placeholder;
  log_func_t log_func = (log_func_t)log_addr_placeholder;

  // ==========================================
  // 2. 立即恢复 Hook
  // ==========================================
  *slot_ptr = orig_addr_placeholder;

  // ==========================================
  // 3. 先调用原函数 (让 App 正常初始化)
  // 编译器会自动生成代码：把 env(RDI), clazz(RSI), name(RDX) 传给 orig_func
  // 我们不需要手写 push/pop，编译器全包了！
  // ==========================================
  orig_func(env, clazz, name);

  // ==========================================
  // 4. 原函数执行完了，现在是我们的时间！
  // 此时寄存器乱了也没关系，反正原函数已经结束了。
  // ==========================================

  // 栈上字符串 (防止 .rodata 问题)
  char tag[] = {'H', 'O', 'O', 'K', 0};
  char msg[] = {'I', 'n', 'j', 'e', 'c', 't', ' ', 'D', 'o', 'n', 'e', 0};

  log_func(3, tag, msg);

  // ==========================================
  // 5. 任务结束，正常返回
  // ==========================================
  return;
}