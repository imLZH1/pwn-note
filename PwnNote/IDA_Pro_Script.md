# IDA_Pro_Script

## patch 花指令

```python
print('-'*40)
p = 0x01740275
for a in range(0x004012A2,0x00446F5C):
    t = ida_bytes.get_dword(a)
    if t == p:
        print("yes")
        patch_dword(a, 0x90909090)
        patch_byte(a+4, 0x90)
```

[idapython使用笔记 | wonderkun&apos;s | blog](https://wonderkun.cc/2020/12/11/idapython%E4%BD%BF%E7%94%A8%E7%AC%94%E8%AE%B0/)

‍

```bash
https://wonderkun.cc/2020/12/11/idapython%E4%BD%BF%E7%94%A8%E7%AC%94%E8%AE%B0/
```

‍

‍

‍

## 获取寄存器的值

‍

‍

```python
eax = idc.get_reg_value('eax')
print(eax,',',end='')
```

‍

‍

‍

## 其他

‍

### 修改类型

- y 键

```python
char a1[]
char a1*

int16_t *a1

site_t a1[]
```

‍

‍

‍

### Other

‍

有位大佬，应该是俄罗斯的，收集了IDA历次版本(Demo/Free/Leak)，从0.1到8.3，在

http: **//fckilfkscwusoopguhi7i6yg3l6tknaz7lrumvlhg5mvtxzxbbxlimid.onion/**

‍

‍

‍

已下载放在

```
https://od.cloudsploit.top/zh-CN/tools/IDA/
```

‍

## 异常处理

选择本地Windows调试器后点击debugger选项卡中的debugger options，选择左下角的edit exceptions，如触发了除零异常，可以找到整数除零异常（`EXCEPTION_INT_DIVIDE_BY_ZERO`​)，选择pass to application和silent，下断调试即可。

![f_c](https://lazzzaro.github.io/2020/05/12/reverse-IDA/f_c.png)

‍
