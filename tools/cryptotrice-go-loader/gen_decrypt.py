#!/usr/bin/env python3
"""The blob transform of the cryptotrice Go loader core b8c1d239, re-implemented in numpy from the six pass loops
(constants and addresses are those of this one build; extract_pipeline.py finds them in other builds).

Passes, in code order (VA of each loop in the 4 MB core):
  0x5d5187  buf = imm64(0xbb56f3a4d77717b6) || imm64(0x54f3f19447bc7914)[:4] || .rdata[0x63a5a8 : +0x1eb8c*8]
  0x5d7ebb  b[i] = rol8(b[i], 5)
  0x5d8662  reverse whole buffer (len 0xf5c6c)
  0x5d8e3b  b[i] = b[i] + 29*i + 10            (mod 256)
  0x5d9d7b  swap b[i] <-> b[i+0x7ae36] for i < 0x7ae36  (half swap)
  0x5da53b  b[i] = b[i] - 17*i - 0x7a          (mod 256)
  0x5dacf1  b[i] = rol8(b[i], 3)
  0x5db48f  return (buf, 0xf5c6c)
Static only: reads the sample bytes, executes nothing.
"""
import struct, sys, hashlib
import numpy as np

N, HALF = 0xf5c6c, 0x7ae36


def extract_blob(core: bytes, pe) -> bytes:
    off = pe.get_offset_from_rva(0x63a5a8 - 0x400000)
    head = struct.pack('<QQ', 0xbb56f3a4d77717b6, 0x54f3f19447bc7914)[:12]
    return head + core[off: off + 0x1eb8c * 8]


def rol(a, r):
    return ((a << r) | (a >> (8 - r))) & 0xff


def transform(blob: bytes) -> bytes:
    """Forward = what the loader computes (decryption direction)."""
    b = np.frombuffer(blob, dtype=np.uint8).astype(np.int64)
    assert len(b) == N
    i = np.arange(N, dtype=np.int64)
    b = rol(b, 5)
    b = b[::-1].copy()
    b = (b + 29 * i + 10) & 0xff
    b = np.concatenate([b[HALF:2 * HALF], b[:HALF], b[2 * HALF:]])
    b = (b - 17 * i - 0x7a) & 0xff
    b = rol(b, 3)
    return b.astype(np.uint8).tobytes()


def inverse(plain: bytes) -> bytes:
    """Encryption direction (builder side), for a round-trip self-test."""
    b = np.frombuffer(plain, dtype=np.uint8).astype(np.int64)
    i = np.arange(N, dtype=np.int64)
    b = rol(b, 5)  # inverse of rol 3
    b = (b + 17 * i + 0x7a) & 0xff
    b = np.concatenate([b[HALF:2 * HALF], b[:HALF], b[2 * HALF:]])
    b = (b - 29 * i - 10) & 0xff
    b = b[::-1].copy()
    b = rol(b, 3)  # inverse of rol 5
    return b.astype(np.uint8).tobytes()


if __name__ == '__main__':
    import pefile
    core = open(sys.argv[1], 'rb').read()
    pe = pefile.PE(data=core, fast_load=True)
    blob = extract_blob(core, pe)
    out = transform(blob)
    print('blob', len(blob), hashlib.sha256(blob).hexdigest())
    print('out ', len(out), hashlib.sha256(out).hexdigest(), 'head', out[:16].hex())
    print('MZ at 0:', out[:2] == b'MZ', ' first MZ at', out.find(b'MZ'))
    assert inverse(out) == blob, 'round trip failed'
    print('round trip OK')
    if len(sys.argv) > 2:
        open(sys.argv[2], 'wb').write(out)
