#!/usr/bin/env python3
"""Tests for blob_fn_emu.py (whole-function emulation, v2).
  test_fn_emu.py --core LOADER.exe [--builds DIR] [--negative BENIGN.exe ...]
--core      reference build b8c1d239...: must decrypt to inner PE c8f5b1c2...; three non-builder main.* functions
            of the same file are emulated as controls and must not yield an MZ buffer.
--builds    directory of further loader builds (*.exe/*.bin): each must decrypt to an AMD64 PE in file layout, and
            where extract_pipeline.py (v1) also decrypts a build, both inner PEs must be identical.
--negative  benign Go executables: none may yield a PE.
PASS/FAIL lines, exit 1 on any FAIL. Inputs are only parsed and emulated (calls stubbed), never executed."""
import argparse, glob, hashlib, json, os, subprocess, sys
import capstone, pefile
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from blob_fn_emu import Emu, analyse
from gosyms import SymIndex, coff_symbols
ap = argparse.ArgumentParser(); ap.add_argument('--core', required=True); ap.add_argument('--builds')
ap.add_argument('--negative', nargs='*', default=[]); a = ap.parse_args()
bad = 0
def chk(ok, msg):
    global bad; bad += 0 if ok else 1; print('PASS' if ok else 'FAIL', msg, flush=True)

r = analyse(a.core)
chk(r.get('pe_sha256', '').startswith('c8f5b1c2b898a7c1'), f'reference build -> inner PE {r.get("pe_sha256", "-")[:16]} (expected c8f5b1c2b898a7c1)')
d = open(a.core, 'rb').read(); pe = pefile.PE(data=d, fast_load=True); base = pe.OPTIONAL_HEADER.ImageBase
t = [s for s in pe.sections if s.Name.startswith(b'.text')][0]
syms = SymIndex(coff_symbols(d, pe), base + t.VirtualAddress, base + t.VirtualAddress + t.Misc_VirtualSize)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
for n in [n for n in syms.name if n.startswith('main.') and n != r.get('fn')][:3]:
    fn = syms.by_name[n]; e = Emu(d, pe, base, syms); ptr, ln = e.run(fn, syms.end_of(fn), md, timeout_s=30)
    mz = (not e.error) and 1 < ln < 0x4000000 and bytes(e.mu.mem_read(ptr, 2)) == b'MZ'
    chk(not mz, f'control: non-builder {n} yields no MZ')
if a.builds:
    for f in sorted(glob.glob(os.path.join(a.builds, '*.exe')) + glob.glob(os.path.join(a.builds, '*.bin'))):
        h = hashlib.sha256(open(f, 'rb').read()).hexdigest()[:12]
        r2 = analyse(f, f + '.inner.tmp')
        ok = r2['result'] == 'PE'
        if ok:
            b = open(f + '.inner.tmp', 'rb').read(); os.remove(f + '.inner.tmp'); p2 = pefile.PE(data=b)
            ok = p2.FILE_HEADER.Machine == 0x8664 and len(b) != p2.OPTIONAL_HEADER.SizeOfImage
        chk(ok, f'{h}: {r2["result"]} {r2.get("pe_len", "")} {r2.get("pe_sha256", "")[:16]}')
        p = subprocess.run([sys.executable, os.path.join(HERE, 'extract_pipeline.py'), f], capture_output=True, text=True)
        if p.returncode == 0 and json.loads(p.stdout).get('pe_sha256'):
            chk(json.loads(p.stdout)['pe_sha256'] == r2.get('pe_sha256'), f'{h}: v1 and v2 inner PE identical')
for neg in a.negative:
    r3 = analyse(neg)
    chk(r3['result'] != 'PE', f'benign {os.path.basename(neg)}: {r3["result"]}')
print('ALL CHECKS PASS' if not bad else f'{bad} FAILED'); sys.exit(1 if bad else 0)
