#!/usr/bin/env python

import os, sys
from subprocess import Popen, PIPE


def main():
    archs = ["aarch64", "mips64", "riscv32"]
    toks = [gen_tok() for _ in archs]
    print(toks)
    ps = [
        spawn([f"qemu-{a}", f"./chall-{a}"], 13370 + i, t)
        for i, (a, t) in enumerate(zip(archs, toks))
    ]
    print(ps)
    while True:
        read(ps, archs)
        line = sys.stdin.buffer.readline()
        if line == b"magic word\n":
            xprint("toks:")
            if toks == [sys.stdin.buffer.readline().strip() for _ in toks]:
                xprint("flag:")
                with open("flag.txt") as f:
                    xprint(f.read())
                    exit()
            else:
                xprint("wrong")
                exit()
        write(ps, line)


def gen_tok():
    return os.urandom(8).hex().encode()


def spawn(args, uid, tok):
    fd = os.memfd_create("token")
    os.write(fd, tok)
    os.lseek(fd, 0, os.SEEK_SET)
    os.dup2(fd, 42)
    return Popen(args, stdin=PIPE, stdout=PIPE, pass_fds=[42], user=uid)


def read(ps, archs):
    for p, a in zip(ps, archs):
        try:
            x = p.stdout.readline()
        except IOError:
            x = b""
        xprint(f"{a}: {x!r}")

def write(ps, line):
    for p in ps:
        try:
            p.stdin.write(line)
            p.stdin.flush()
        except IOError:
            pass


def xprint(x):
    print(x, flush=True)


if __name__ == "__main__":
    main()
