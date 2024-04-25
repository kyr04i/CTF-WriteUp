from pwn import *

io = remote('chall.ctf.0ops.sjtu.cn',37000)
io.recvuntil(b'Show me your computation:')
io.recvline()

expr = [int(x) for x in io.recvuntil('mod ')[:-4].strip().replace(b'(',b'').replace(b')', b'').split(b'^')][-1] 
mod = int(io.recvuntil(' ').strip())
oth = process(['./a.out', str(expr), str(mod)]) 
io.sendlineafter('answer: ', oth.recvline())
io.interactive()