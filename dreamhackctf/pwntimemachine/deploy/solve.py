from pwn import *

if args.LOCAL:
    io=process('./prob_patched')
    if args.GDB:
        cmd="""
        """
        gdb.attach(io, cmd)
else:
    io=remote()

elf=ELF('./prob_patched')
libc=ELF('./libc.so.6')



io.interactive()