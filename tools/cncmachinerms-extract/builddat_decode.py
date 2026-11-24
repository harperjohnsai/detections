#!/usr/bin/env python3
"""Decode the shellcode hidden in the NuGet-looking `Build.dat` of the ROMULUS Stardock chain.

The side-loaded `I++u.dll` reads 0x53613 bytes at offset 0x5847b of Build.dat and XORs them with a
rolling one-byte key (recovered from the DLL's loop; constants below reproduce it exactly), then hands the
buffer to senddmp.resources.dll!request (EnumSystemCodePagesW trampoline).  Offsets/length are per build:
pass --offset/--length for other builds.  Static only: nothing is executed.
"""
import argparse
import hashlib
import sys


def decode(buf: bytes) -> bytes:
    out = bytearray(buf)
    r10, r8, r15 = 6, 0x13, 8
    for i in range(len(out)):
        ecx = (r15 + 0x77 + i * 4 + i) & 0xFFFFFFFF
        edx = ecx & 0xFF
        keep = edx <= 0xE3                      # cmp edx,0xe3 ; cmovbe
        eax = (r10 + 0x16) & 0xFF
        r10 = eax
        edi = ((r8 * 2 + 8) & 0xFFFFFFFF) & 0xFF
        r8 = 0x17C
        r15 = edx if keep else (edx - 0x28) & 0xFFFFFFFF
        out[i] ^= (r15 + 0x77 + r10) & 0xFF
        if edi != 0x8E:
            r8 = edi
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('build_dat')
    ap.add_argument('--offset', type=lambda x: int(x, 0), default=0x5847B)
    ap.add_argument('--length', type=lambda x: int(x, 0), default=0x53613)
    ap.add_argument('-o', '--out')
    a = ap.parse_args()
    d = open(a.build_dat, 'rb').read()[a.offset:a.offset + a.length]
    sc = decode(d)
    print('sha256', hashlib.sha256(sc).hexdigest(), 'head', sc[:8].hex(), file=sys.stderr)
    if a.out:
        open(a.out, 'wb').write(sc)


if __name__ == '__main__':
    main()
