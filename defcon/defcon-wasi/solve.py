#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ template template
from pwn import *

# Set up pwntools for the correct architecture
# context.update(arch='i386')
exe = './chatgpt-wasi'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    if args.REMOTE:
        return remote("chatgpt-wasi.shellweplayaga.me", 31337)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()
if args.REMOTE:
    ticket = b'ticket{OleNice6960n24:4JnQ5_yUI8QF6DkykawfPeQZO88METJv7p9FYoW1EN2CqSpO}' 
    io.sendlineafter(b'Ticket please: ', ticket)

io.sendline(b'ok')

io.interactive()