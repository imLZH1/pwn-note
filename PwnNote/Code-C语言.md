# Code-C语言

## ELF保护机制

- NX(DEP)：数据执行防护

  > 栈上的数据没有执行权限防止攻击手段：栈溢出+ 跳到栈上执行shellcode
  >
- Canary(FS)：栈溢出保护

  > 在函数开始时就随机产生一个值，将这个值CANARY
  > 放到栈上紧挨ebp的上一个位置，当攻击者想通过缓冲
  > 区溢出覆盖ebp或者ebp下方的返回地址时，一定会覆
  > 盖掉CANARY的值；当程序结束时，程序会检查
  > CANARY这个值和之前的是否一致，如果不一致，则
  > 不会往下运行，从而避免了缓冲区溢出攻击。
  >
- RELRO(ASLR)：（地址随机化）

  > 堆栈地址随机化
  > 防止攻击手段：所有需要用到堆栈精确地址的攻击，要想成功,必须用提前泄露地址
  >
- PIE（代码地址随机化）

  > 代码部分地址无关
  > 防止攻击手段：构造ROP链攻击
  >

‍

‍

‍

## C 语言里写汇编代码（内联汇编）

‍

```c
asm volatile(
        ".intel_syntax noprefix\n"
        "mov rbx, 0x13371337\n"
        "mov rcx, rbx\n"
        "mov rdx, rbx\n"
        "mov rdi, rbx\n"
        "mov rsi, rbx\n"
        "mov rsp, 0x13371337000\n"
        "mov rbp, rbx\n"
        "mov r8,  rbx\n"
        "mov r9,  rbx\n"
        "mov r10, rbx\n"
        "mov r11, rbx\n"
        "mov r12, rbx\n"
        "mov r13, rbx\n"
        "mov r14, rbx\n"
        "mov r15, rbx\n"
        "jmp rax\n"
        ".att_syntax prefix\n"
        :
        : [code] "rax" (code)
        :
    );



```

‍

‍

```c
size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}
// gcc -masm=intel
```

‍

‍

```c
void *ptr = mmap((void*)0x321000, 0x1000, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0LL);
    read(0, ptr, 0x10);
    __asm__(
        "mov rax, %0;"
        "call rax;"
        : : "r"(ptr) : "rax"
    );
```

‍

‍

## C 语言 数据类型范围

‍

```python
char		--->	-128 to 127 (signed) /	 0 to 255 (unsigned)

int			--->	-2147483648 to 2147483647 (signed) /	 0 to 4294967295 (unsigned)
short		--->	-32768 to 32767 (signed) /	 0 to 65535 (unsigned)
long		--->	-2147483648 to 2147483647 (signed) /	 0 to 4294967295 (unsigned)
long long	--->	-9223372036854775808 to 9223372036854775807 (signed) /	 0 to 18446744073709551615 (unsigned)

float ---> Approximately -3.4e38 to 3.4e38
double ---> Approximately -1.7e308 to 1.7e308
long double ---> Range and precision depend on the system
```

|类型|字节|范围|
| :------------------: | :------------: | :------------------------------------------------------------------: |
|short int|2byte(word)|0~32767(0~0x7fff)<br />-32768~-1(0x8000~0xffff)|
|unsigned short int|2byte(word)|0~65535(0~0xffff)|
|int|4byte(dword)|0~2147483647(0~0x7fffffff)<br />-2147483648~-1(0x80000000~0xffffffff)|
|unsigned int|4byte(dword)|0~4294967295(0~0xffffffff)|
|long int|8byte(qword)|正: 0~0x7fffffffffffffff<br />负:0x8000000000000000~0xffffffffffffffff|
|unsigned long int|8byte(qword)|0~0xffffffffffffffff|

‍

‍

‍

## scanf()

```c
scanf(" %[^\n]", dest);
具体来说:
- __isoc99_scanf 表示调用的是 ISO C99 标准的 scanf 实现。
- " %[^\n]" 是格式字符串:
  - % 表示接下来是格式规范
  - [^\n] 表示读取除换行符之外的所有字符
  - 空格在 % 前面表示跳过前导的空白字符
- dest 是读取输入保存的字符数组。
这个调用的效果是:
- 跳过输入行前面的任何空白
- 读取输入行中的所有字符(除换行符),直到遇到换行符
- 将读取的字符串存储到 dest 数组中
```

‍

‍

## posix_openpt()

‍

posix_openpt用来打开下一个可用的伪终端主设备，该函数是可移植的。

‍

# C 语言函数指南

‍

## strstr()

```python
1、strstr() 函数搜索一个字符串在另一个字符串中的第一次出现。
2、找到所搜索的字符串，则该函数返回第一次匹配的字符串的地址；
3、如果未找到所搜索的字符串，则返回NULL。


  char *strstr(char *str1, const char *str2);   //返回值为字符型指针
  str1: 被查找目标
  str2: 要查找对象
```

## atio()

- 个人理解 判断是不是数字*(2023-打破，str转int)  
  返回值  
  此函数将转换后的整数作为 int 值返回。如果无法执行有效转换，则返回零。

```python
strcpy(str, "98993489");
val = atoi(str);
```

## strncmp()

```python
面是 strncmp() 函数的声明。

int strncmp(const char *str1, const char *str2, size_t n)

* 参数

-   **str1** -- 要进行比较的第一个字符串。
-   **str2** -- 要进行比较的第二个字符串。
-   **n** -- 要比较的最大字符数。

* 返回值

该函数返回值如下：

-   如果返回值 < 0，则表示 str1 小于 str2。
-   如果返回值 > 0，则表示 str1 大于 str2。
-   如果返回值 = 0，则表示 str1 等于 str2。
```

## mprotect()

```python
int mprotect(const void *start, size_t len, int prot);

第一个参数填的是一个地址，是指需要进行操作的地址。
第二个参数是地址往后多大的长度。
第三个参数的是要赋予的权限。

mprotect()函数把自start开始的、长度为len的内存区的保护属性修改为prot指定的值。

嗯。。。还是上面这一句话讲的明白…

prot可以取以下几个值，并且可以用“|”将几个属性合起来使用：

1）PROT_READ：表示内存段内的内容可写；
2）PROT_WRITE：表示内存段内的内容可读；
3）PROT_EXEC：表示内存段中的内容可执行；
4）PROT_NONE：表示内存段中的内容根本没法访问。
```

- 实例

```python
 ► 0x806ec92 <mprotect+18>    call   dword ptr [0x80eb9f0]         <__kernel_vsyscall>
        arg[0]: 0x804818c (_init) ◂— push   ebx
        arg[1]: 0x41414141 ('AAAA')         # gdb的原因所以 arg 0 1都不是，显示错误
        arg[2]: 0x80ea000 ◂— 0x41100ec3     # 第 1 个参数 你要修改权限的地址
        arg[3]: 0x1000                      # 第 2 个参数 修改的长度
 
   0x806ec98 <mprotect+24>    pop    ebx
   0x806ec99 <mprotect+25>    cmp    eax, 0xfffff001
   0x806ec9e <mprotect+30>    jae    __syscall_error                     <__syscall_error>
 
   0x806eca4 <mprotect+36>    ret  
 
   0x806eca5                  nop  
──────────────────────[ STACK ]────────────────────────────
00:0000│ esp 0xffbdb5ec —▸ 0x804818c (_init) ◂— push   ebx
01:0004│     0xffbdb5f0 ◂— 'AAAA'                   # mprotect执行结束后的返回地址
02:0008│     0xffbdb5f4 —▸ 0x80ea000 ◂— 0x41100ec3
03:000c│     0xffbdb5f8 ◂— 0x1000
04:0010│     0xffbdb5fc ◂— 0x7                      # 第 3 个参数 权限 rwx 7 
```

在Linux中，mprotect()函数可以用来修改一段指定内存区域的保护属性。

函数原型如下：

```C
#include <unistd.h>   
#include <sys/mmap.h>   
int mprotect(const void *start, size_t len, int prot);

```

## memchr()

```python
* 描述

C 库函数 **void *memchr(const void *str, int c, size_t n)** 在参数 **str** 所指向的字符串的前 **n** 个字节中搜索第一次出现字符 **c**（一个无符号字符）的位置。

* 声明

下面是 memchr() 函数的声明。

void *memchr(const void *str, int c, size_t n)

* 参数

-   **str** -- 指向要执行搜索的内存块。
-   **c** -- 以 int 形式传递的值，但是函数在每次字节搜索时是使用该值的无符号字符形式。
-   **n** -- 要被分析的字节数。
```

## memcpy()

```python
* 描述

C 库函数 **void *memcpy(void *str1, const void *str2, size_t n)** 
从存储区 **str2** 复制 **n** 个字节到存储区 **str1**。

* 声明

下面是 memcpy() 函数的声明。

void *memcpy(void *str1, const void *str2, size_t n)

*参数

-   **str1** -- 指向用于存储复制内容的目标数组，类型强制转换为 void* 指针。
-   **str2** -- 指向要复制的数据源，类型强制转换为 void* 指针。
-   **n** -- 要被复制的字节数。

*返回值

该函数返回一个指向目标存储区 str1 的指针。
```

‍

‍

# C 代码

## base64

```c
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <stdint.h>

int init(){
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 1, 0);
    setvbuf(stderr, 0, 1, 0);
}
static char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int mod_table[] = {0, 2, 1};
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
  *output_length = 4 * ((input_length + 2) / 3);
  char *encoded_data = malloc(*output_length);
  if (encoded_data == NULL) return NULL;
  for (int i = 0, j = 0; i < input_length;) {
    uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
    uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
    uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
    encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
  }
  for (int i = 0; i < mod_table[input_length % 3]; i++)
    encoded_data[*output_length - 1 - i] = '=';
  return encoded_data;
}

// Base64字符集
static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// 查找字符在Base64字符集中的位置
static int base64_decode_char(char c) {
    const char *p = strchr(base64_chars, c);
    if (p) {
        return p - base64_chars;
    } else {
        return -1;
    }
}

// Base64解码函数
void base64_decode(const char *input, uint8_t *output, size_t *output_length) {
    size_t input_length = strlen(input);
    size_t decoded_length = 0;
  
    for (size_t i = 0; i < input_length; i += 4) {
        uint8_t block[4];
        for (int j = 0; j < 4; j++) {
            int char_value = base64_decode_char(input[i + j]);
            if (char_value >= 0) {
                block[j] = (uint8_t)char_value;
            } else {
                block[j] = 0; // Padding character
            }
        }

        output[decoded_length++] = (block[0] << 2) | (block[1] >> 4);
        if (block[2] != 0) {
            output[decoded_length++] = (block[1] << 4) | (block[2] >> 2);
        }
        if (block[3] != 0) {
            output[decoded_length++] = (block[2] << 6) | block[3];
        }
    }

    *output_length = decoded_length;
}


unsigned char de_text[100] = {0};

int backdoor(){
	execve(de_text,NULL,NULL);
	return 0;
}


int set_base64encode(){
	unsigned char text[200] = {0};
	size_t encoded_len;
	printf("base64_Encode: ");
	scanf("%180s",&text);
	getchar();
	size_t text_len = strlen((char *)text);
	char *en_text = base64_encode(text, text_len, &encoded_len);
	memcpy(text, en_text, encoded_len);
	printf("%s\n",text);
	return 0;
}
int set_base64decode(){
	unsigned char text[100] = {0};
	printf("base64_Decode: ");
	scanf("%90s",&text);
	getchar();
	int i = strlen(text);
	if(! (i%4)){
		return 1;
	}
	size_t decoded_length = 0;
	base64_decode(text, de_text, &decoded_length);
	printf("%s\n",de_text);
	return 0;
}


//gcc main.c -fno-stack-protector
int main(){
	init();
	size_t text;
	while(1){
		printf("---------------------\n");
		printf("1.b64encode\n");
		printf("2.b64decode\n");
		printf("3.exit\n");
		printf("---------------------\n");
		printf("choice: ");
		if(scanf("%d", &text) != 1){
			text = -1;
			printf("error choice!\n");
			break;
		}
		switch(text){
			case 1:
				set_base64encode();
				break;
			case 2:
				set_base64decode();
				break;
			case 3:
				exit(0);
			break;

		}
	}
	return 0;

}
```

‍

‍

## strdup

‍

```python
#include <string.h>
char *strdup(const char *s);

char * __strdup(const char *s)
{
   size_t  len = strlen(s) +1;
   void *new = malloc(len);
   if (new == NULL)
      return NULL;
   return (char *)memecpy(new,s,len);
}

```

‍
