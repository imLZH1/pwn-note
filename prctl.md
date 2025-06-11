# prctl

‍

```bash
https://man7.org/linux/man-pages/man2/prctl.2.html#SEE%20ALSO
```

‍

## SYNOPSIS

```c
#include <linux/prctl.h>  /* Definition of PR_* constants */
#include <sys/prctl.h>

int prctl(int op, ...);
```

‍

## DESCRIPTION

prctl（）操纵调用行为的各个方面线程或进程。

调用prctl（）时，第一个参数描述了要做什么，以及进一步的论点，其重要性取决于第一个论点。

第一个论点可以是：

‍

```c
PR_CAP_AMBIENT = 0x2f
PR_CAPBSET_READ = 0x17
PR_CAPBSET_DROP = 0x18
PR_SET_CHILD_SUBREAPER = 0x24
PR_GET_CHILD_SUBREAPER = 0x25
PR_SET_DUMPABLE = 0x4
PR_GET_DUMPABLE = 0x3
PR_SET_ENDIAN = 0x14
PR_GET_ENDIAN = 0x13
PR_SET_FP_MODE = 0x2d
PR_GET_FP_MODE = 0x2e
PR_SET_FPEMU = 0xa
PR_GET_FPEMU = 0x9
PR_SET_FPEXC = 0xc
PR_GET_FPEXC = 0xb
PR_SET_IO_FLUSHER = 0x39
PR_GET_IO_FLUSHER = 0x3a
PR_SET_KEEPCAPS = 0x8
PR_GET_KEEPCAPS = 0x7
PR_MCE_KILL = 0x21
PR_MCE_KILL_GET = 0x22
PR_SET_MM = 0x23
PR_SET_VMA = 0x53564d41
PR_MPX_ENABLE_MANAGEMENT = 0x2b
PR_MPX_DISABLE_MANAGEMENT = 0x2c
PR_SET_NAME = 0xf
PR_GET_NAME = 0x10
PR_SET_NO_NEW_PRIVS = 0x26
PR_GET_NO_NEW_PRIVS = 0x27
PR_PAC_RESET_KEYS = 0x36
PR_SET_PDEATHSIG = 0x1
PR_GET_PDEATHSIG = 0x2
PR_SET_PTRACER = 0x59616d61
PR_SET_SECCOMP = 0x16
PR_GET_SECCOMP = 0x15
PR_SET_SECUREBITS = 0x1c
PR_GET_SECUREBITS = 0x1b
PR_GET_SPECULATION_CTRL = 0x34
PR_SET_SPECULATION_CTRL = 0x35
PR_SVE_SET_VL = 0x32
PR_SVE_GET_VL = 0x33
PR_SET_SYSCALL_USER_DISPATCH = 0x3b
PR_SET_TAGGED_ADDR_CTRL = 0x37
PR_GET_TAGGED_ADDR_CTRL = 0x38
PR_TASK_PERF_EVENTS_DISABLE = 0x1f
PR_TASK_PERF_EVENTS_ENABLE = 0x20
PR_SET_THP_DISABLE = 0x29
PR_GET_THP_DISABLE = 0x2a
PR_GET_TID_ADDRESS = 0x28
PR_SET_TIMERSLACK = 0x1d
PR_GET_TIMERSLACK = 0x1e
PR_SET_TIMING = 0xe
PR_GET_TIMING = 0xd
PR_SET_TSC = 0x1a
PR_GET_TSC = 0x19
PR_SET_UNALIGN = 0x6
PR_GET_UNALIGN = 0x5
PR_GET_AUXV = 0x41555856
PR_SET_MDWE = 0x41
PR_GET_MDWE = 0x42
PR_RISCV_SET_ICACHE_FLUSH_CTX = 0x47
```

‍

## PR_SET_MDWE

‍

- 你可以查看 /usr/include/linux/prctl.h，找到类似这样的定义：

```c

#define PR_SET_MDWE 65
```

‍

‍

PR_SET_MDWE 是 Linux 内核中引入的一个较新的 prctl 选项，全称是 Memory Deny Write Execute（拒绝写后执行）。它旨在增强安全性，防止进程在运行时意外或恶意地将可写内存变为可执行内存。这个功能最初由 Google 等公司推动，主要用于防御某些类型的内存攻击（如 ROP 或 JIT 喷射攻击）。

‍

参数解析

- PR_SET_MDWE: 设置进程的 MDWE 策略。
- PR_MDWE_REFUSE_EXEC_GAIN: 这是一个标志，表示拒绝任何试图将内存区域变为可执行的操作（包括通过 mmap 或 mprotect）。
- 后面的 0, 0, 0: 占位参数，通常用于未来的扩展，目前无特殊含义。

- 当调用 prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) 后，进程会被标记为启用 MDWE 策略。
- 在这种模式下：

  - 禁止 mmap 创建同时具有 PROT_WRITE 和 PROT_EXEC 的内存段。
  - 对于只申请 PROT_EXEC（不带 PROT_WRITE）的情况，行为取决于具体实现。

‍

```c
prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0)
 65 1 0
```

‍

mmap 不能生成 可执行的段
