from pwn import *
import os
if args.LOCAL:
    io = process('./challenge/oracle_patched')
    if args.GDB:
        cmd = """
        b* handle_request+386
        """
        gdb.attach(io, cmd)

elf=ELF('./challenge/oracle')

try:
    io.interactive()
except:
    os.system("fuser -n tcp -k 9001")
os.system("fuser -n tcp -k 9001")