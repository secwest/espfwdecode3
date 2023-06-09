#!/usr/bin/env python
# patterned after: https://microcontrollerelectronics.com/decoding-an-esp8266-firmware-image/

import os
import struct
import sys

filename = sys.argv[1]
f = open(filename, "rb")
afsize = os.stat(filename).st_size

print(f"Parsing: {filename} Size: {hex(afsize)}/{afsize}")

fsize = chk = bsize = usize = 0
htype = baddr = uaddr = ''
useg = b''

def hexdump(data, length=16):
    for i in range(0, len(data), length):
        chunk = data[i:i + length]
        hex_chunk = ' '.join(f'{b:02x}' for b in chunk)
        ascii_chunk = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'{hex_chunk:<48} {ascii_chunk}')

while True:
    t = f.read(8)
    if not t:
        break
    l = len(t)
    sh = t[0]
    if sh != 0xff and baddr:
        print(f"{'Blank(s)':<8} {'0xff':<12} {'Len: 0x'+format(bsize, '08x'):<17} {bsize:<12} {'Off: 0x'+format(baddr, '08x'):<17} {baddr}")
        baddr, bsize = '', 0
    if sh in [0xea, 0xe9, 0xff] and uaddr:
        print(f"{'Unknown':<8} {'':<12} {'Len: 0x'+format(usize, '08x'):<17} {usize:<12} {'Off: 0x'+format(uaddr, '08x'):<17} {uaddr}")
        hexdump(useg)
        uaddr, useg, usize = '', b'', 0
    if l < 8:
        print(f"Extra Data [no-header] of Length: {len(t)} -> {' '.join(hex(b) for b in bytearray(t))}")
        fsize += l
        break

    h = struct.unpack("<BBBBI", t)
    if h[0] == 0xea:
        segments, htype = 1, 0xea
    elif h[0] == 0xe9:
        segments, htype, chk = int(h[1]), 0xe9, 0
    elif h[0] == 0xff:
        if not baddr:
            baddr = fsize
        bsize += l
        fsize += l
        continue
    else:
        if not uaddr:
            uaddr = fsize
        useg += t
        usize += l
        fsize += l
        continue

    fsize += l
    print(f"Header: {hex(h[0])} {int(h[1])} {hex(h[2])} {hex(h[3])} {hex(h[4])}")

    for s in range(segments):
        t = f.read(8)
        if not t:
            break
        l = len(t)
        if l < 8:
            print(f"Extra Data [no-header] of Length: {len(t)} -> {' '.join(hex(b) for b in bytearray(t))}")
            fsize += l
            break
        seg = struct.unpack("<II", t)
        fsize += l
        chk += seg[1] + seg[0]
        print(f"Segment: {s} Start: 0x{seg[0]:08x} Length: {hex(seg[1])}/{seg[1]}")
        f.read(seg[1])
        fsize += seg[1]

    if htype == 0xe9:
        t = f.read(1)
        if not t:
            break
        l = len(t)
        if l < 1:
            print(f"Extra Data [no-header] of Length: {len(t)} -> {' '.join(hex(b) for b in bytearray(t))}")
            fsize += l
            break
        chk += t[0]
        print(f"Calculated Checksum: 0x{chk % 256:02x} [matches]")
        fsize += 1
print("Finished parsing")
print(f"Parsed file size: {hex(fsize)}/{fsize}")
f.close()

if fsize != afsize:
    print(f"Error: Filesize mismatch! Parsed: {hex(fsize)}/{fsize} Actual: {hex(afsize)}/{afsize}")
else:
    print("Filesize matches")
