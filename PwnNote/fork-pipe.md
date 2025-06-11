# fork-pipe

‍

## pipe

‍

- 总结

‍

```c
#include<stdio.h>


int main(){
    int pid  = getpid();
    printf("pid = %d\n",pid);

    int fds[2];
    pipe(fds);
    // fds[0] 只进数据  read(fd[0]
    // fds[1] 只出数据  write(fd[1]

    char *buf[] = {"h1\n","h2\n"};

    int fork_pid = fork();
    // 子进程返回子进程的pid
    // 父进程会返回 0

    char tmp[0x10] = {0};

    if(fork_pid){
        // 子进程执行                                                                                                                                                 printf("fork_pid = %d\n",fork_pid);
        write(fds[1],buf[0],3);
    }else{
        // 父进程执行                                                                                                                                                 read(fds[0],tmp,3);
        write(1,tmp,6);
    }


    return 0;
}
```

‍

```c
pid = 16289
fork_pid = 16290
h1
```

‍

## fork

‍

```c
SYSCALL_DEFINE0(fork)
{
#ifdef CONFIG_MMU
        struct kernel_clone_args args = {
                .exit_signal = SIGCHLD,
        };

        return kernel_clone(&args);
#else
        /* can not support in nommu mode */
        return -EINVAL;
#endif
}
```

1. 使用fork()函数创建子进程时，子进程和父进程有各自独立的进程地址空间，fork后会重新申请一份资源，包括进程描述符、进程上下文、进程堆栈、内存信息、打开的文件描述符、进程优先级、根目录、资源限制、控制终端等，拷贝给子进程。
2. [fork函数](https://zhida.zhihu.com/search?q=fork%E5%87%BD%E6%95%B0&zhida_source=entity&is_preview=1)会返回两次，一次在父进程，另一次在子进程，如果返回值为0，说明是子进程；如果返回值为正数，说明是父进程
3. fork系统调用只使用SIGCHLD标志位，子进程终止后发送SIGCHLD信号通知父进程；
4. fork是重量级调用，为子[进程创建](https://zhida.zhihu.com/search?q=%E8%BF%9B%E7%A8%8B%E5%88%9B%E5%BB%BA&zhida_source=entity&is_preview=1)了一个基于父进程的完整副本，然后子进程基于此运行，为了减少工作量采用写时拷贝技术。子进程只复制父进程的页表，不会复制页面内容，页表的权限为RD-ONLY。当子进程需要写入新内容时会触发写时复制机制，为子进程创建一个副本，并将页表权限修改为RW。
5. 由于需要修改页表，触发page fault等，因此[fork](https://zhida.zhihu.com/search?q=fork&zhida_source=entity&is_preview=1)需要mmu的支持

‍

```c
#include<stdio.h>


int main(){
    int pid  = getpid();
    printf("pid = %d\n",pid);

    int fork_pid = fork();
    // 子进程返回子进程的pid
    // 父进程会返回 0

    if(fork_pid){
        // 子进程执行                                                                                                                                                 printf("fork_pid = %d\n",fork_pid);
        printf("my pid = %d\n",fork_pid);
    }else{
        // 父进程执行                                                                                                                                                 read(fds[0],tmp,3);
        printf("我是主进程\n");
    }


    return 0;
}
```

‍

‍

‍

## vfork

```text
SYSCALL_DEFINE0(vfork)
{
        struct kernel_clone_args args = {
                .flags          = CLONE_VFORK | CLONE_VM,
                .exit_signal    = SIGCHLD,
        };

        return kernel_clone(&args);
}
```

1. 使用vfork()函数创建子进程时， 子进程和父进程有相同的进程地址空间，vfork会将父进程除mm_struct的资源拷贝给子进程，也就是创建子进程时，它的task_struct->mm指向父进程的，父子进程共享一份同样的mm_struct；
2. vfork会阻塞父进程，直到子进程退出或调用exec释放虚拟内存资源，父进程才会继续执行；
3. vfork的实现比fork多了两个标志位，分别是CLONE_VFORK和CLONE_VM。CLONE_VFORK表示父进程会被挂起，直至子进程释放虚拟内存资源。CLONE_VM表示父子进程运行在相同的内存空间中；
4. 由于没有写时拷贝，不需要页表管理，因此vfork不需要MMU

## clone

```c
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,
                 int __user *, parent_tidptr,
                 unsigned long, tls, 
                 int __user *, child_tidptr)
{
        struct kernel_clone_args args = {
                .flags          = (lower_32_bits(clone_flags) & ~CSIGNAL),
                .pidfd          = parent_tidptr,
                .child_tid      = child_tidptr,
                .parent_tid     = parent_tidptr,
                .exit_signal    = (lower_32_bits(clone_flags) & CSIGNAL),
                .stack          = newsp,
                .tls            = tls, 
        };   

        return kernel_clone(&args);
}
```

1. 使用clone()创建用户线程时， clone不会申请新的资源，所有线程指向相同的资源，举例：P1创建P2，P2的全部资源指针指向P1，P1和P2指向同样的资源，那么P1和P2就是线程；
2. 当调用pthread_create时，linux就会执行clone，并通过不同的clone_flags标记，保证p2指向p1相同的资源。
3. 创建进程和创建线程采用同样的api即kernel_clone，带有标记clone_filag可以指明哪些是要克隆的，哪些不需要克隆的；
4. 进程是完全不共享父进程资源，线程是完全共享父进程的资源，通过clone_flags标志克隆父进程一部分资源，部分资源与父进程共享，部分资源与父进程不共享，是位于进程和线程间的临界态

> 1.Linux将进程和线程都采用task_struct进行管理；  
> 2.理解线程要从调度的角度，理解进程要从资源的角度，而相同资源可调度就是线程，线程也称为轻量级进程 lwp

## kernel_thread

```c
/*
 * Create a kernel thread.
 */
pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)
{
        struct kernel_clone_args args = {
                .flags          = ((lower_32_bits(flags) | CLONE_VM |
                                    CLONE_UNTRACED) & ~CSIGNAL),
                .exit_signal    = (lower_32_bits(flags) & CSIGNAL),
                .stack          = (unsigned long)fn,
                .stack_size     = (unsigned long)arg,
        };

        return kernel_clone(&args);
}
```

1. kernel_thread用于创建一个[内核线程](https://zhida.zhihu.com/search?q=%E5%86%85%E6%A0%B8%E7%BA%BF%E7%A8%8B&zhida_source=entity&is_preview=1)，它只运行在内核地址空间，且所有内核线程共享相同的内核地址空间，没有独立的进程地址空间，即task_struct->mm为NULL；
2. 通过kernel_thread创建的内核线程处于不可运行态，需要wake_up_process()来唤醒并调加到就绪队列；kthread_run()是kthread_create和wake_up_process的封装，可创建并唤醒进程；

‍

‍

‍

```bash
https://zhuanlan.zhihu.com/p/617413539
```
