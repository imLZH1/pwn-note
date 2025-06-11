# glibc 随机数预测

- ## python 调用 libc 函数

‍

```python
from ctypes import *
import time
dll = CDLL('/usr/lib/x86_64-linux-gnu/libc.so.6')
dll.srand(int(time.time()))

x = dll.rand()
```

‍

‍

```python
from pwn import *
from ctypes import *
import time
context.log_level = 'debug'

from ctypes import *
import time
clibc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
clibc.srand(int(time.time()))
choice = clibc.random() % 3 
x = clibc.random() % 0x666
y = clibc.random() % 0x666

```

## 固定seed值测试

- 固定`seed`​ ，每次重新运行程序，`rand()`​ 生成的随机数 第 N 此都是一样的

```bash
root@ubuntu:~/share/test/3# cat test.c 
#include <stdio.h>
#include <stdlib.h>
int main(void) { 
srand(0);
for(int i=0;i<10;i++)
{
    printf("%d,",rand()%6+1);
}
printf("\n");
}
root@ubuntu:~/share/test/3# gcc test.c 
root@ubuntu:~/share/test/3# ./a.out 
2,5,4,2,6,2,5,1,4,2,
root@ubuntu:~/share/test/3# ./a.out 
2,5,4,2,6,2,5,1,4,2,
root@ubuntu:~/share/test/3# ./a.out 
2,5,4,2,6,2,5,1,4,2,
root@ubuntu:~/share/test/3# ./a.out
```

‍

## C-rand()随机数预测

- 在不知道 seed 的情况的，但是生成的随机数是已知的（生成的前100随机数是已知的），那么我们就可以一次后面生成的随机数

```python
pay = '1 1 1 1 ' * 31
sl(pay)

a = [] # 已知前 31 个随机数

for i in range(31):
    ru('Number is ')
    num = int(rl())
    a.append(num)

################################################
j, k = 0, 0
for i in range(31):
    idx_1, idx_2, idx_3 = i + 31, i, i + 28
    result = (int(a[idx_2]) + int(a[idx_3])) & 0x7FFFFFFF

    try:
        if result == a[idx_1]:
            print('success', idx_1)
    except:
        pay = result # 第 32 随机很有可能就是 这个 result 
        print(idx_1, result)
        break
    #print(f'true:false = {j}:{k}')
################################################
game()
sl(str(pay))
```

```bash
https://blog.csdn.net/j284886202/article/details/134676894
```

‍

‍

‍

‍

## **setstate**

‍

```c
char *initstate(unsigned int seed, char *statebuf, size_t statelen);
```

‍

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char *state1, *state2;
    char state_buf[256];

    // 初始化随机数生成器
    state1 = initstate(42, state_buf, 256);
    printf("Random number 1: %ld\n", random());

    // 保存当前状态
    state2 = setstate(state1);
    printf("Random number 2: %ld\n", random());

    // 恢复之前的状态
    setstate(state2);
    printf("Random number 3 (same as 2): %ld\n", random());

    return 0;
}
```

输出示例

```bash
Random number 1: 1608637542
Random number 2: 3421126067
Random number 3 (same as 2): 3421126067
```
