#!/bin/sh

mkdir initramfs
cd initramfs
cp ../$1 .
cpio -idm < ./$1
rm $1
