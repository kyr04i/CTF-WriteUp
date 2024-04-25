from pwn import *

io = remote("challenges.france-cybersecurity-challenge.fr" ,2107)
with open("./poc.js", "rb") as f:
    data = f.read().replace(b'\n', b'').replace(b' ', b'').replace(b'var', b'var ').replace(b'let', b'let ')
    print(data)
io.interactive()

