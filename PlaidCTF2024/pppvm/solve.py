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
    io = process(["./exec"])
    if args.GDB:
        cmd = """
        b* main.main+211
        """    
        gdb.attach(io, cmd)
        
else: 
    io = remote("")

def push(offset):
    return p8(OP_PUSH) + p64(offset)

def dup(offset):
    return p8(OP_DUP) + p8(offset)

def swap(offset):
    return p8(OP_SWAP) + p8(offset)

def add_(lhs, rhs):
    return push(lhs) + push(rhs) + p8(OP_ADD)
    
def sub_(lhs, rhs):
    return push(lhs) + push(rhs) + p8(OP_SUB)
    
def mul_(lhs, rhs):
    return push(lhs) + push(rhs) + p8(OP_MUL)

def div_(lhs, rhs):
    return push(lhs) + push(rhs) + p8(OP_DIV)

def mod_(lhs, rhs):
    return push(lhs) + push(rhs) + p8(OP_MOD)

def eq(lhs, rhs):
    return push(lhs) + push(rhs) + p8(OP_EQ)

def lt(lhs, rhs):
    return push(lhs) + push(rhs) + p8(OP_LT)

def gt(lhs, rhs):
    return push(lhs) + push(rhs) + p8(OP_GT) 

def is_zero(v):
    return push(v) + p8(OP_ISZERO)

def jmp(dst):
    return push(dst) + p8(OP_JMP)

def jmp_if(dst, cond):
    return push(dst) + push(cond) + p8(OP_JUMPIF)

def jmp_rel(offset):
    return p8(OP_JMPREL) + p16(offset)

def jmp_rel_if(offset, cond):
    return push(cond) + p8(OP_JMPRELIF) + p16(offset)

def ret(length):
    return push(length) + p8(OP_RET)

def recv_():
    return p8(OP_RECV) 

def sleep_(ms):
    return push(ms) + p8(OP_SLEEP)

def send_(dest, length):
    return push(dest) + push(length) + p8(OP_SEND) 

def delete_():
    return p8(OP_ID) + p8(OP_DELETE)

def launch(start, end):
    return  push(end) + push(start) + p8(OP_LAUNCH)        
    
def reset():
    return p8(OP_ID) + p8(OP_RESET)

def join_():
    return p8(OP_ID)  + p8(OP_JOIN)

pl = add_(1, 2)
pl += p8(OP_DUMP)
pause()
io.sendline(pl.ljust(0x4000, p8(OP_NOP)))


io.interactive()