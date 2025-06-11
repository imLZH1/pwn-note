# TIPS

‍

## 程序初始化

```c
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
int init(){
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 1, 0);
    setvbuf(stderr, 0, 1, 0);
    alarm(0); // 无
    // alarm(10); 10秒后结束
    return 0;
}


int myinit()
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  return setvbuf(stderr, 0LL, 2, 0LL);
}


```

- 如果没有初始化，在端口上运行的进程，stdio里的基本不能正常输出

如 printf

## 沙箱规则编写

[pwn_repo/asm.c at master · bash-c/pwn_repo (github.com)](https://github.com/bash-c/pwn_repo/blob/master/pwnable_asm/asm.c)

- 编译参数

sudo apt install libseccomp-dev

```python
gcc test1.c -o simple_syscall_seccomp -lseccomp
```

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>
#define LENGTH 128

void sandbox(){
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		printf("seccomp error\n");
		exit(0);
	}
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	if (seccomp_load(ctx) < 0){
		seccomp_release(ctx);
		printf("seccomp error\n");
		exit(0);
	}
	seccomp_release(ctx);
}
```

## Linux 下 Signal 信号 详解

信号是Linux编程中非常重要的部分，本文将详细介绍信号机制的基本概念、Linux对信号机制的大致实现方法、如何使用信号，以及有关信号的几个系统调用。

信号机制是进程之间相互传递消息的一种方法，信号全称为软中断信号，也有人称作软中断。从它的命名可以看出，它的实质和使用很象中断。所以，信号可以说是进程控制的一部分。

一、信号的基本概念

本节先介绍信号的一些基本概念，然后给出一些基本的信号类型和信号对应的事件。基本概念对于理解和使用信号，对于理解信号机制都特别重要。下面就来看看什么是信号。

1、基本概念

软中断信号（signal，又简称为信号）用来通知进程发生了异步事件。进程之间可以互相通过系统调用kill发送软中断信号。内核也可以因为内部事件而给进程发送信号，通知进程发生了某个事件。注意，信号只是用来通知某进程发生了什么事件，并不给该进程传递任何数据。

收 到信号的进程对各种信号有不同的处理方法。处理方法可以分为三类：第一种是类似中断的处理程序，对于需要处理的信号，进程可以指定处理函数，由该函数来处 理。第二种方法是，忽略某个信号，对该信号不做任何处理，就象未发生过一样。第三种方法是，对该信号的处理保留系统的默认值，这种缺省操作，对大部分的信 号的缺省操作是使得进程终止。进程通过系统调用signal来指定进程对某个信号的处理行为。

在进程表的表项中有一个软中断信号域，该域中每一位对应一个信号，当有信号发送给进程时，对应位置位。由此可以看出，进程对不同的信号可以同时保留，但对于同一个信号，进程并不知道在处理之前来过多少个。

2、信号的类型

发出信号的原因很多，这里按发出信号的原因简单分类，以了解各种信号：

（1） 与进程终止相关的信号。当进程退出，或者子进程终止时，发出这类信号。
（2） 与进程例外事件相关的信号。如进程越界，或企图写一个只读的内存区域（如程序正文区），或执行一个特权指令及其他各种硬件错误。
（3） 与在系统调用期间遇到不可恢复条件相关的信号。如执行系统调用exec时，原有资源已经释放，而目前系统资源又已经耗尽。
（4） 与执行系统调用时遇到非预测错误条件相关的信号。如执行一个并不存在的系统调用。
（5） 在用户态下的进程发出的信号。如进程调用系统调用kill向其他进程发送信号。
（6） 与终端交互相关的信号。如用户关闭一个终端，或按下break键等情况。
（7） 跟踪进程执行的信号。

Linux支持的信号列表如下。很多信号是与机器的体系结构相关的，首先列出的是POSIX.1中列出的信号：

信号 值 处理动作 发出信号的原因

---

SIGHUP 1 A 终端挂起或者控制进程终止
SIGINT 2 A 键盘中断（如break键被按下）
SIGQUIT 3 C 键盘的退出键被按下
SIGILL 4 C 非法指令
SIGABRT 6 C 由abort(3)发出的退出指令
SIGFPE 8 C 浮点异常
SIGKILL 9 AEF Kill信号
SIGSEGV 11 C 无效的内存引用
SIGPIPE 13 A 管道破裂: 写一个没有读端口的管道
SIGALRM 14 A 由alarm(2)发出的信号
SIGTERM 15 A 终止信号
SIGUSR1 30,10,16 A 用户自定义信号1
SIGUSR2 31,12,17 A 用户自定义信号2
SIGCHLD 20,17,18 B 子进程结束信号
SIGCONT 19,18,25 进程继续（曾被停止的进程）
SIGSTOP 17,19,23 DEF 终止进程
SIGTSTP 18,20,24 D 控制终端（tty）上按下停止键
SIGTTIN 21,21,26 D 后台进程企图从控制终端读
SIGTTOU 22,22,27 D 后台进程企图从控制终端写

## C 类型取值范围

```python
-32768 - 32767

-2147483648 2147483647

-2147483648    0X7fffffff

无符号情况下表示为 0 ~ 4294967295



类型	占用字节及取值范围
int	4               -2147483648~2147483648
short int        	-32768~32768
long int	        -2147483648~2147483648
unsigned int	    0~4294967295
unsigned short int	0~65537
unsigned long int   0~4294967295





Maybe these help you:
 ====================================================================================================
           Type         |      Byte      |                          Range
 ====================================================================================================
      short int         |     2 byte     |                  0~0x7fff 0x8000~0xffff
   unsigned short int   |     2 byte     |                        0~0xffff
          int           |     4 byte     |             0~0x7fffffff 0x80000000~0xffffffff
    unsigned int        |     4 byte     |                        0~0xffffffff
      long int          |     8 byte     | 0~0x7fffffffffffffff 0x8000000000000000~0xffffffffffffffff
   unsigned long int    |     8 byte     |                    0~0xffffffffffffffff
 ====================================================================================================



```

## gcc 编译选项

```python
gcc xx.c -no-pie # 关闭地址随机化

gcc xx.c -fno-stack-protector # 关闭堆栈溢出

gcc xx.c -fstack-protector-all # 打开堆栈溢出
```

```pyhon
NX：-z execstack / -z noexecstack (关闭 / 开启)    不让执行栈上的数据，于是JMP ESP就不能用了

Canary：-fno-stack-protector /-fstack-protector / -fstack-protector-all (关闭 / 开启 / 全开启)  栈里插入cookie信息

PIE：-no-pie / -pie (关闭 / 开启)   地址随机化，另外打开后会有get_pc_thunk

RELRO：-z norelro / -z lazy / -z now (关闭 / 部分开启 / 完全开启)  对GOT表具有写权限


```

## 被 close() 了

- 1

```python
# close(1)关闭了标准输出  
# close(2)关闭了标准错误
exec 1>&0
cat /flag
```

- 2

```python
# close(1)关闭了标准输出
exec 1>&2
cat /flag
```

- 3

```python
shellcraft.open('/dev/pts/1',2)
```

‍

## 这啥呀

```text
按 ctrl-d 发送数据而不发送`\x0A`
```

```python
pop rdi; ret # socket
pop rsi; ret # buffer
pop rdx; ret # length
pop rax; ret # write syscall number
syscall
```
