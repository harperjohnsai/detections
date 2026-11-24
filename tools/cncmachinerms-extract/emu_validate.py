#!/usr/bin/env python3
"""Bare-unicorn validation of the Storage decoder against the loader shellcode's OWN routines.

No OS layer, no syscalls, no native execution: the decoded Build.dat shellcode (see builddat_decode.py) is mapped
into a unicorn x86-64 instance and four of its internal routines are called directly:
    0x4b6f9  ctx constructor            0x4d8cd  validate header + decode header/table meta (needs build key K)
    0x4b4d9  decode one 0x58-byte record (layer 1)
    0x4bafd  blob decrypt, layer 2: (ctx, buf, len, key_byte)
Allocator / RNG / init helpers are replaced by hooks.  Sockets are blocked in-process as a belt-and-braces measure
(self-tested at import).  Offsets below are for the ROMULUS Stardock shellcode (sha256 e8e16a82...).

usage: emu_validate.py <shellcode.bin> <container> <K hex> [--props 16001,16100]
Compares every record and the requested blobs with storage.py and exits 1 on any mismatch.
"""
import argparse
import hashlib
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _blocked(*a, **k):
    raise RuntimeError('network blocked in analysis harness')


socket.socket = _blocked
socket.create_connection = _blocked
try:
    socket.socket()
    raise SystemExit('netguard self-test FAILED')
except RuntimeError:
    pass

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UcError  # noqa: E402
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,  # noqa: E402
                               UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP)
from storage import Storage  # noqa: E402

OFF = dict(ctor=0x4B6F9, validate=0x4D8CD, record=0x4B4D9, dec=0x4BAFD,
           alloc=0x42349, free=0x423C5, nops=(0x4E3A1, 0x42335, 0x41F2D, 0x44EE1))
CODE, STK, HEAP = 0x140000000, 0x7FF00000, 0x200000000


class Emu:
    def __init__(self, sc, data):
        self.sc, self.data = sc, data
        self.uc = uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(CODE, (len(sc) + 0x2FFF) & ~0xFFF)
        uc.mem_write(CODE, sc)
        uc.mem_map(STK, 0x100000)
        size = len(data) * 4 + 0x1000000
        uc.mem_map(HEAP, (size + 0xFFF) & ~0xFFF)
        uc.mem_write(HEAP, data)
        self.bump = HEAP + len(data) + 0x1000
        self.hooks = {CODE + OFF['alloc']: lambda: self._ret(self.alloc(uc.reg_read(UC_X86_REG_RCX))),
                      CODE + OFF['free']: lambda: self._ret(0)}
        for a in OFF['nops']:
            self.hooks[CODE + a] = lambda: self._ret(0)
        uc.hook_add(UC_HOOK_CODE, self._hook, begin=CODE, end=CODE + len(sc))

    def alloc(self, n):
        p = (self.bump + 15) & ~15
        self.bump = p + n + 16
        return p

    def _ret(self, v):
        uc = self.uc
        uc.reg_write(UC_X86_REG_RAX, v)
        sp = uc.reg_read(UC_X86_REG_RSP)
        ra = struct.unpack('<Q', uc.mem_read(sp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, sp + 8)
        uc.reg_write(UC_X86_REG_RIP, ra)

    def _hook(self, uc, addr, size, ud):
        h = self.hooks.get(addr)
        if h:
            h()

    def call(self, addr, *args):
        uc = self.uc
        for r, a in zip((UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9), args):
            uc.reg_write(r, a)
        sp = STK + 0xF0000 - 8
        uc.mem_write(sp, struct.pack('<Q', 0xDEAD0000))
        uc.reg_write(UC_X86_REG_RSP, sp)
        try:
            uc.emu_start(CODE + addr, 0xDEAD0000, count=2_000_000_000)
        except UcError as e:
            raise SystemExit(f'emulation error {e} at {uc.reg_read(UC_X86_REG_RIP) - CODE:#x}')
        if uc.reg_read(UC_X86_REG_RIP) != 0xDEAD0000:
            raise SystemExit('instruction budget exhausted before return')
        return uc.reg_read(UC_X86_REG_RAX)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('shellcode')
    ap.add_argument('container')
    ap.add_argument('key', type=lambda x: int(x, 16))
    ap.add_argument('--props', default='16001,16100')
    a = ap.parse_args()
    sc, data = open(a.shellcode, 'rb').read(), open(a.container, 'rb').read()
    e = Emu(sc, data)
    ctx = e.alloc(0x60)
    e.uc.mem_write(ctx, b'\0' * 0x60)
    e.call(OFF['ctor'], ctx)
    ok = e.call(OFF['validate'], ctx, HEAP, len(data), a.key) & 0xFF
    print('emulated header validation:', ok)
    if not ok:
        raise SystemExit(1)
    tm = struct.unpack('<Q', e.uc.mem_read(ctx + 0x50, 8))[0]
    n = struct.unpack('<Q', e.uc.mem_read(tm + 8, 8))[0]
    py = Storage(data, 0, a.key, variant='loader3')
    bad = 0
    out = e.alloc(0x80)
    for i in range(n):
        e.call(OFF['record'], ctx, HEAP + 0x78 + i * 0x58, out)
        o = bytes(e.uc.mem_read(out, 0x26))
        q = struct.unpack('<4Q', o[:32])
        r = py.records[i]
        if q != (r.node, r.parent, r.prop, r.length) or o[0x20:0x26] != bytes([r.f20, r.f21, r.enc, r.key, r.f24, r.f25]):
            bad += 1
    print(f'records: {n} emulated, {bad} differ from storage.py')
    for p in (int(x) for x in a.props.split(',')):
        for r in py.by_prop(p):
            if not r.length or not r.enc:
                continue
            buf = e.alloc(r.length + 16)
            e.uc.mem_write(buf, data[r.off:r.off + r.length])
            e.call(OFF['dec'], 0, buf, r.length, r.key)
            emu = bytes(e.uc.mem_read(buf, r.length))
            same = emu == r.blob
            bad += not same
            print(f'blob prop {p}: {r.length} bytes sha256 {hashlib.sha256(emu).hexdigest()} identical to storage.py: {same}')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
