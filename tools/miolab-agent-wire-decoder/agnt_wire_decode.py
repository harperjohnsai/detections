#!/usr/bin/env python3
"""Decoder for the MioLab macOS agent (.agnt) C2 wire format, reconstructed statically from the arm64 slice
(sub_100001d44 / sub_100004f0c / static initialiser at 0x100012d00):
  body = custom-alphabet hex ("ptXQVlhBezPSEioO", LOW nibble first) of a byte buffer;
  buffer[0:4]  = u32 LE magic 0xb4f749ff (= ror32(0xdd27fed3, 10)), stored in clear;
  buffer[i>=4] = rotl8(v ^ k, k & 7) with k = low byte of (i * 0x4c957f2d + 0x43fd007c)  (PCG multiplier).
Usage: agnt_wire_decode.py <body> [...]   (also used on bodies seen in public sandbox reports)"""
import sys
ALPH = 'ptXQVlhBezPSEioO'
def unhex(s):
    s = s.strip()
    return bytes(ALPH.index(s[i]) | (ALPH.index(s[i + 1]) << 4) for i in range(0, len(s) - 1, 2))
def tohex(b):
    return ''.join(ALPH[x & 15] + ALPH[x >> 4] for x in b)
def key(i): return (i * 0x4c957f2d + 0x43fd007c) & 0xffffffff
def rotr8(x, n): n &= 7; return ((x >> n) | (x << (8 - n))) & 0xff if n else x
def rotl8(x, n): n &= 7; return ((x << n) | (x >> (8 - n))) & 0xff if n else x
def deobf(buf):
    out = bytearray(buf[:4])
    for i in range(4, len(buf)):
        k = key(i); out.append(rotr8(buf[i], k & 7) ^ (k & 0xff))
    return bytes(out)
def obf(plain):
    out = bytearray(plain[:4])
    for i in range(4, len(plain)):
        k = key(i); out.append(rotl8(plain[i] ^ (k & 0xff), k & 7))
    return bytes(out)
if __name__ == '__main__':
    for body in sys.argv[1:]:
        raw = unhex(body); pl = deobf(raw)
        print('magic', raw[:4][::-1].hex(), 'len', len(raw))
        print(' hex  ', pl[4:].hex())
        print(' ascii', ''.join(chr(c) if 32 <= c < 127 else '.' for c in pl[4:]))
