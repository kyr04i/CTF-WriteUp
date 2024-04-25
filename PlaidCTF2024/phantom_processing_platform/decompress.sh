#!/bin/sh
mkdir fs
cd fs
cp ../rootfs.cpio ./rootfs.cpio
cpio -idm < ./rootfs.cpio
rm rootfs.cpio
cd ..
