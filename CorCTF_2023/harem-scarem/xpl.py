from pwn import *

#io=remote('')
io=process('./harem')
exe=context.binary=ELF('./harem')

def 