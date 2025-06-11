# apache-cgi

‍

- 调试 ，通过 环境变量传值

‍

## 参考1

```python
from pwn import *
#from ctypes import CDLL
#cdl = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
s    = lambda   x : io.send(x)
sa   = lambda x,y : io.sendafter(x,y)
sl   = lambda   x : io.sendline(x)
sla  = lambda x,y : io.sendlineafter(x,y)
r    = lambda x   : io.recv(x)
ru   = lambda x   : io.recvuntil(x)
rl   = lambda     : io.recvline()
itr  = lambda     : io.interactive()
uu32 = lambda x   : u32(x.ljust(4,b'\x00'))
uu64 = lambda x   : u64(x.ljust(8,b'\x00'))
ls   = lambda x   : log.success(x)
lss  = lambda x   : ls('\033[1;31;40m%s -> 0x%x \033[0m' % (x, eval(x)))

attack = ''.replace(' ',':')
binary = './main'

def start(argv=[], *a, **kw):
    if args.GDB:return gdb.debug(binary,gdbscript)
    if args.TAG:return remote(*args.TAG.split(':'))
    if args.REM:return remote(*attack.split(':'))
    return process([binary] + argv, *a, **kw)


#context(log_level = 'debug')
context(binary = binary, log_level = 'debug',
terminal='tmux splitw -h -l 170'.split(' '))

gdbscript = '''
brva 0x002844
brva 0x271F
'''

#pwd = 'a' * 65
#env_vars = {
#    "QUERY_STRING": "passwd_re="+pwd,
#    }
#io = gdb.debug('./main', gdbscript=gdbscript, env=env_vars)
#


text = b'hack'
env_vars = {
        "QUERY_STRING": b"passwd_lo="+text,
    }
io = gdb.debug('./main', gdbscript=gdbscript, env=env_vars)


itr()

```

‍

## 参考2

‍

‍

```python
env_vars = {
        'REQUEST_METHOD': 'POST',
        "QUERY_STRING": "login",
        'HTTP_AUTHORIZATION': f'\'{http_auth}\'', # 传值有空格，想要 单引号包裹
        'CONTENT_LENGTH': str(len(post_data)),
    }
io = gdb.debug('./login.cgi', gdbscript=g1, env=env_vars)
```
