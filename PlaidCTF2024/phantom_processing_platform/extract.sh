#!/bin/sh

# Given a linux zimage, extract the vmlinux file. Useful for getting symbols into gdb when debugging linux kernels
# Requires binwalk for extracting the slightly malformed xz data

set -e

file=$1

# Get 2nd offset of 7zXZ
offset_s=$(grep -aob "7zXZ" $file | tail -n1)
offset=$(echo $offset_s | cut -d: -f1)
offset="$(($offset-1))"
outfile=$(mktemp)
echo "Writing to tempfile at $outfile"

dd if=$file of=$outfile bs=1 skip=$offset
echo "Done writing tempfile"
echo $outfile

localfile=$(basename $file)
mv $outfile ${localfile}_sliced.xz
echo "Moved to ${localfile}_sliced.xz"

binwalk -e ${localfile}_sliced.xz

echo "Binwalk extracted"
mv _${localfile}_sliced.xz.extracted/0 ${file}_vmlinux
rm -rf _${localfile}_sliced.xz.extracted

echo "Created ${file}_vmlinux" 