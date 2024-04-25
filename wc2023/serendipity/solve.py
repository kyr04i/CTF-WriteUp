from pwn import *
if args.LOCAL:
    io=process('./serendipity_patched')
    if args.GDB:
        cmd="""
        init-pwndbg
        brva 0x0000000000002FD7
        """
        gdb.attach(io, cmd)
else:
    io=remote('157.245.147.89', 25201, typ="udp")
elf=context.binary=ELF('./serendipity_patched')
libc=ELF('./libc.so.6') 

io.interactive()   
                                                 