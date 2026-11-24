#!/usr/bin/env python3
"""Cross-check: run the LegionLoader's OWN RC4 routine (call 0x372b0 style: buf, len, key, keylen) in bare unicorn
on one ciphertext and compare with the Python RC4.  No OS layer; sockets blocked in-process (self-tested).
usage: emu_check.py <PE> <RVA of RC4 routine> <cipher RVA> <length> <key RVA>
e.g.  emu_check.py daydream_stage5.exe 0x372b0 0x74xxx 15 0x744e8   (values printed by legionloader_config.py --all)
"""
import socket, struct, sys

def _blocked(*a, **k):
    raise RuntimeError('network blocked')
socket.socket = _blocked
try:
    socket.socket(); raise SystemExit('self-test failed')
except RuntimeError:
    pass
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RAX
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from legionloader_config import rc4

pe = pefile.PE(sys.argv[1]); img = pe.get_memory_mapped_image()
fn, cr, ln, kr = (int(x, 0) for x in sys.argv[2:6])
base = pe.OPTIONAL_HEADER.ImageBase
uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(base, (len(img) + 0xFFFF) & ~0xFFF)
uc.mem_write(base, bytes(img))
STK, BUF = 0x7F000000, 0x7E000000
uc.mem_map(STK, 0x100000); uc.mem_map(BUF, 0x10000)
uc.mem_write(BUF, bytes(img[cr:cr + ln]))
sp = STK + 0xF0000 - 8
uc.mem_write(sp, struct.pack('<Q', 0xDEAD0000))
uc.reg_write(UC_X86_REG_RSP, sp)
for r, v in ((UC_X86_REG_RCX, BUF), (UC_X86_REG_RDX, ln), (UC_X86_REG_R8, base + kr), (UC_X86_REG_R9, 16)):
    uc.reg_write(r, v)
uc.emu_start(base + fn, 0xDEAD0000, count=5_000_000)
emu = bytes(uc.mem_read(BUF, ln))
ref = rc4(bytes(img[kr:kr + 16]), bytes(img[cr:cr + ln]))
print('emulated :', emu)
print('python   :', ref)
print('IDENTICAL' if emu == ref else 'DIFFERENT')
sys.exit(0 if emu == ref else 1)
