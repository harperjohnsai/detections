#!/usr/bin/env python3
"""Tests for extract_pipeline.py and gen_decrypt.py (static; the emulator only runs the six decryption loops).

usage: test_pipeline.py [--core CORE.exe] [--mapped-image IMAGE.bin] [--negative PE [PE ...]]

Always run (no samples needed): inverse/forward round trip on random data, pass-by-pass identities.
With --core (the 4,191,744-byte Go PE, SHA-256 b8c1d239...): builder found, six passes emulated, emulator output equals
the numpy re-implementation, inner PE SHA-256, trailer, and a negative control (one pass skipped).
With --mapped-image (the loaded-image dump of the inner PE from an emulator run, SHA-256 e7da3731...): the decrypted
bytes must equal it after folding it back to file layout (0 differences expected).
With --negative: every given benign PE must give "no blob builder found" (non-zero exit).
Needs: numpy unicorn capstone pefile.  Prints PASS/FAIL lines, exit 1 on any FAIL.
"""
import argparse, hashlib, json, os, subprocess, sys

import numpy as np
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_decrypt as G

CORE_SHA = 'b8c1d2399105a57046b24aeee74d2dea3250c8c8aa5502c448b8d954f1dcb17a'
MAPPED_SHA = 'e7da373121aed34c79efb4ba8e589bb6b142c43a62f9f83c34a068451b056991'
BLOB_SHA12 = '966021313b98'
PE_SHA = 'c8f5b1c2b898a7c13fc2843dd9771566e0a1b7e79bd18f479300e3518fda7d20'
bad = 0


def chk(ok, msg):
    global bad
    bad += 0 if ok else 1
    print('PASS' if ok else 'FAIL', msg)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def synthetic():
    rng = np.random.default_rng(1)
    plain = rng.integers(0, 256, G.N, dtype=np.uint8).tobytes()
    chk(G.transform(G.inverse(plain)) == plain, 'synthetic: transform(inverse(x)) == x on 0xf5c6c random bytes')
    chk(G.inverse(G.transform(plain)) == plain, 'synthetic: inverse(transform(x)) == x')
    x = np.arange(8, dtype=np.int64) * 37 % 256
    chk(list(G.rol(x, 3)) == [((v << 3) | (v >> 5)) & 0xff for v in x], 'synthetic: rol8 helper')


def with_core(core_path, mapped_path):
    core = open(core_path, 'rb').read()
    chk(sha(core) == CORE_SHA, f'core is {CORE_SHA[:8]} (4,191,744-byte Go PE)')
    out_path = os.path.join(os.environ.get('TMPDIR', '/tmp'), 'cryptotrice_pipeline_out.bin')
    r = subprocess.run([sys.executable, os.path.join(HERE, 'extract_pipeline.py'), core_path, out_path],
                       capture_output=True, text=True)
    rep = json.loads(r.stdout)
    chk(rep['header_len'] == 12 and rep['rdata_src'] == '0x63a5a8' and rep['qwords'] == 0x1eb8c,
        'builder found: 12-byte immediate header + .rdata 0x63a5a8, 0x1eb8c qwords')
    chk(rep['blob_sha256'].startswith(BLOB_SHA12), f'rebuilt blob SHA-256 starts {BLOB_SHA12}')
    passes = [p for p in rep['passes'] if p['kind'] == 'pass']
    chk(len(passes) == 6 and rep['passes'][-1]['kind'] == 'return' and rep['passes'][-1]['len'] == 0xf5c6c,
        f'6 in-place passes then return(len 0xf5c6c); loops {[p["loop"] for p in passes]}')
    emu = open(out_path, 'rb').read()
    pe = pefile.PE(data=core, fast_load=True)
    static = G.transform(G.extract_blob(core, pe))
    chk(emu == static, 'emulator-run loops == numpy re-implementation (gen_decrypt.py)')
    chk(G.inverse(static) == G.extract_blob(core, pe), 'inverse() round-trips to the embedded blob (encryption direction)')
    chk(rep.get('pe_sha256') == PE_SHA, f'inner PE SHA-256 {rep.get("pe_sha256", "")[:16]}')
    end = rep['pe_len']
    inner = pefile.PE(data=emu[:end], fast_load=True)
    chk(all(s.PointerToRawData != s.VirtualAddress for s in inner.sections if s.SizeOfRawData) and
        end != inner.OPTIONAL_HEADER.SizeOfImage, 'inner PE is in file layout (raw offsets differ from RVAs, size != SizeOfImage), not a memory image')
    tr = emu[end:]
    chk(len(tr) == 68716 and rep['trailer_alpha_frac'] > 0.99,
        f'trailer {len(tr)} B, ASCII-letter fraction {rep["trailer_alpha_frac"]} (letter padding, not a payload)')
    # negative control: skip the "- 17*i - 0x7a" pass, the result must not be a PE
    b = G.extract_blob(core, pe)
    x = np.frombuffer(b, dtype=np.uint8).astype(np.int64)
    i = np.arange(len(x))
    x = G.rol(x, 5)[::-1].copy()
    x = (x + 29 * i + 10) & 0xff
    x = np.concatenate([x[G.HALF:2 * G.HALF], x[:G.HALF], x[2 * G.HALF:]])
    y = G.rol(x, 3).astype(np.uint8).tobytes()
    chk(y[:2] != b'MZ' and y[:end] != emu[:end], f'negative control: one pass skipped -> MZ {y[:2] == b"MZ"}')
    if mapped_path:
        img = open(mapped_path, 'rb').read()
        chk(sha(img) == MAPPED_SHA, f'mapped image is {MAPPED_SHA[:8]}')
        ip = pefile.PE(data=img, fast_load=True)
        f = bytearray(end)
        f[:ip.OPTIONAL_HEADER.SizeOfHeaders] = img[:ip.OPTIONAL_HEADER.SizeOfHeaders]
        for s in ip.sections:
            n = min(s.SizeOfRawData, len(img) - s.VirtualAddress)
            f[s.PointerToRawData:s.PointerToRawData + n] = img[s.VirtualAddress:s.VirtualAddress + n]
        diff = sum(1 for a, c in zip(emu[:end], f) if a != c)
        chk(diff == 0, f'decrypted[:{end}] == loaded-image dump folded to file layout, {diff} byte differences')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--core')
    ap.add_argument('--mapped-image')
    ap.add_argument('--negative', nargs='*', default=[])
    a = ap.parse_args()
    synthetic()
    if a.core:
        with_core(a.core, a.mapped_image)
    else:
        print('SKIP sample tests (no --core)')
    for neg in a.negative:
        r = subprocess.run([sys.executable, os.path.join(HERE, 'extract_pipeline.py'), neg], capture_output=True, text=True)
        chk(r.returncode != 0 and 'no blob builder found' in (r.stdout + r.stderr), f'benign {os.path.basename(neg)}: no blob builder')
    print('ALL CHECKS PASS' if not bad else f'{bad} FAILED')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
