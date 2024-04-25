from pwn import *

if args.LOCAL:
    io=process('./prob')
    if args.GDB:
        cmd="""
        init-pwndbg
        b* main+720
        """
        gdb.attach(io, cmd)
else:
    io=remote('host3.dreamhack.games', 10399)

sc=asm("""
    nop
""")
pause()
io.sendline(sc)

io.interactive()

    
    