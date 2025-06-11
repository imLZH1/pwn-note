# shellcode

‍

‍

```python
➜  PWN附件 py bp_sc.py |grep -v .byte
0x0         ...
0x6    0:   06                      push   es
0x7    0:   07                      pop    es
0xe    0:   0e                      push   cs
0x16    0:   16                      push   ss
0x17    0:   17                      pop    ss
0x1e    0:   1e                      push   ds
0x1f    0:   1f                      pop    ds
0x26    0:   26                      es
0x27    0:   27                      daa
0x2e    0:   2e                      cs
0x2f    0:   2f                      das
0x36    0:   36                      ss
0x37    0:   37                      aaa
0x3e    0:   3e                      ds
0x3f    0:   3f                      aas
0x40    0:   40                      inc    eax
0x41    0:   41                      inc    ecx
0x42    0:   42                      inc    edx
0x43    0:   43                      inc    ebx
0x44    0:   44                      inc    esp
0x45    0:   45                      inc    ebp
0x46    0:   46                      inc    esi
0x47    0:   47                      inc    edi
0x48    0:   48                      dec    eax
0x49    0:   49                      dec    ecx
0x4a    0:   4a                      dec    edx
0x4b    0:   4b                      dec    ebx
0x4c    0:   4c                      dec    esp
0x4d    0:   4d                      dec    ebp
0x4e    0:   4e                      dec    esi
0x4f    0:   4f                      dec    edi
0x50    0:   50                      push   eax
0x51    0:   51                      push   ecx
0x52    0:   52                      push   edx
0x53    0:   53                      push   ebx
0x54    0:   54                      push   esp
0x55    0:   55                      push   ebp
0x56    0:   56                      push   esi
0x57    0:   57                      push   edi
0x58    0:   58                      pop    eax
0x59    0:   59                      pop    ecx
0x5a    0:   5a                      pop    edx
0x5b    0:   5b                      pop    ebx
0x5c    0:   5c                      pop    esp
0x5d    0:   5d                      pop    ebp
0x5e    0:   5e                      pop    esi
0x5f    0:   5f                      pop    edi
0x60    0:   60                      pusha
0x61    0:   61                      popa
0x64    0:   64                      fs
0x65    0:   65                      gs
0x66    0:   66                      data16
0x67    0:   67                      addr16
0x6c    0:   6c                      ins    BYTE PTR es:[edi], dx
0x6d    0:   6d                      ins    DWORD PTR es:[edi], dx
0x6e    0:   6e                      outs   dx, BYTE PTR ds:[esi]
0x6f    0:   6f                      outs   dx, DWORD PTR ds:[esi]
0x90    0:   90                      nop
0x91    0:   91                      xchg   ecx, eax
0x92    0:   92                      xchg   edx, eax
0x93    0:   93                      xchg   ebx, eax
0x94    0:   94                      xchg   esp, eax
0x95    0:   95                      xchg   ebp, eax
0x96    0:   96                      xchg   esi, eax
0x97    0:   97                      xchg   edi, eax
0x98    0:   98                      cwde
0x99    0:   99                      cdq
0x9b    0:   9b                      fwait
0x9c    0:   9c                      pushf
0x9d    0:   9d                      popf
0x9e    0:   9e                      sahf
0x9f    0:   9f                      lahf
0xa4    0:   a4                      movs   BYTE PTR es:[edi], BYTE PTR ds:[esi]
0xa5    0:   a5                      movs   DWORD PTR es:[edi], DWORD PTR ds:[esi]
0xa6    0:   a6                      cmps   BYTE PTR ds:[esi], BYTE PTR es:[edi]
0xa7    0:   a7                      cmps   DWORD PTR ds:[esi], DWORD PTR es:[edi]
0xaa    0:   aa                      stos   BYTE PTR es:[edi], al
0xab    0:   ab                      stos   DWORD PTR es:[edi], eax
0xac    0:   ac                      lods   al, BYTE PTR ds:[esi]
0xad    0:   ad                      lods   eax, DWORD PTR ds:[esi]
0xae    0:   ae                      scas   al, BYTE PTR es:[edi]
0xaf    0:   af                      scas   eax, DWORD PTR es:[edi]
0xc3    0:   c3                      ret
0xc9    0:   c9                      leave
0xcb    0:   cb                      retf
0xcc    0:   cc                      int3
0xce    0:   ce                      into
0xcf    0:   cf                      iret
0xd6    0:   d6                      (bad)
0xd7    0:   d7                      xlat   BYTE PTR ds:[ebx]
0xec    0:   ec                      in     al, dx
0xed    0:   ed                      in     eax, dx
0xee    0:   ee                      out    dx, al
0xef    0:   ef                      out    dx, eax
0xf0    0:   f0                      lock
0xf1    0:   f1                      int1
0xf2    0:   f2                      repnz
0xf3    0:   f3                      repz
0xf4    0:   f4                      hlt
0xf5    0:   f5                      cmc
0xf8    0:   f8                      clc
0xf9    0:   f9                      stc
0xfa    0:   fa                      cli
0xfb    0:   fb                      sti
0xfc    0:   fc                      cld
0xfd    0:   fd                      std
```

‍

‍

## 扩展

```python
CDQ 是汇编语言中的一个指令，全称是 "Convert Doubleword to Quadword"，意为将双字（32位）扩展为四字（64位）。它的主要作用是将 EAX 寄存器的符号位（即最高位，第31位）复制到 EDX 寄存器的所有位上。这样，如果 EAX 是一个正数，EDX 将被清零；如果 EAX 是一个负数（最高位为1），EDX 将被设置为全1（即 0xFFFFFFFF）
。

这个指令通常用在需要进行64位带符号数运算的场合，尤其是在进行除法运算之前。例如，在进行32位带符号整数除法时，如果除数是32位的，而被除数需要是64位的，那么就需要使用 CDQ 指令来扩展 EAX 寄存器的值到 EDX:EAX，形成一个64位的带符号整数
。

具体来说，如果 EAX 的值为 0xFFFFFFFFFFFFFFFB（即 -5），执行 CDQ 指令后，EDX 将被设置为 0xFFFFFFFF，这样 EDX:EAX 就形成了一个64位的整数，其值为 -5
。

在64位模式下，CDQ 指令可以通过使用 REX.W 前缀来扩展到64位操作，此时的指令称为 CQO（Convert Quadword to Octaword），它会将 RAX 寄存器的符号位扩展到 RDX 寄存器中
。

总结一下，CDQ 指令的主要作用是：

将 EAX 寄存器的符号位扩展到 EDX 寄存器，形成64位的带符号整数。
通常用于准备64位的除法运算，确保被除数是一个64位的整数。
在64位模式下，可以通过 REX.W 前缀扩展为 CQO 指令，将 RAX 的符号位扩展到 RDX 中。
```
