#!/bin/bash

qemu-system-arm \
    -smp cores=4 \
    -M virt \
    -m 4096 \
    -monitor /dev/null \
    -kernel ./zImage \
    -initrd ./debug.cpio \
    -append "console=ttyAMA0 root=/dev/ram" \
    -netdev user,id=vmnic,hostfwd=tcp::1337-:1337 \
    -device virtio-net-device,netdev=vmnic \
    -s \
    -nographic 