#!/usr/bin/env python3
"""LegionLoader (2026 build) config reader: decrypts the RC4 string tables in `.data` (static, nothing is executed).

Layout seen in both builds (stage-3 PE 2e3d378d... and stage-5 PE 00ef251f...): the `.data` section holds string
tables  [u32 count][count x (u32 type=4, u32 length)][ciphertext...]  and 16-byte RC4 keys stored elsewhere in
`.data`.  The reader does not hard-code table or key offsets (they move between builds): it tries every
4-byte-aligned 16-byte window of `.data` as the key of every table entry and accepts a result that is >= 95 %
printable text.  The C2 host, the `nfront.php` / `nback.php` gate paths, the User-Agent and the URL format strings
fall out.  `emu_check.py` runs the loader's own RC4 routine on one ciphertext in bare unicorn and compares it with
this implementation (identical on both builds).

usage: legionloader_config.py <PE> [--all]
"""
import argparse, json, re, struct, sys

import pefile


def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 255])
    return bytes(out)


def tables(img, lo, hi):
    for a in range(lo, hi - 12, 4):
        try:
            n = struct.unpack_from('<I', img, a)[0]
        except struct.error:
            continue
        if not 0 < n <= 64:
            continue
        ents = [struct.unpack_from('<II', img, a + 4 + 8 * i) for i in range(n)]
        if any(t != 4 or not 0 < ln <= 4096 for t, ln in ents):
            continue
        pos, out = a + 4 + 8 * n, []
        for _, ln in ents:
            out.append((pos, img[pos:pos + ln]))
            pos += ln
        yield a, out


def scan_data(img, lo, hi):
    """Decrypt every RC4 string table found in img[lo:hi] (the mapped .data section)."""
    keys = [(k, bytes(img[k:k + 16])) for k in range(lo, hi - 16, 4)]
    strings = []
    for ta, ents in tables(img, lo, hi):
        for pos, ct in ents:
            for k, kb in keys:
                if all(32 <= c < 127 or c == 0 for c in rc4(kb, ct[:12])):
                    pt = rc4(kb, ct)
                    if sum(32 <= c < 127 or c in (0, 9, 10, 13) for c in pt) >= 0.95 * len(pt):
                        strings.append(dict(table=hex(ta), cipher_rva=hex(pos), key_rva=hex(k), text=pt.rstrip(b'\0').decode('latin1')))
                        break
    return strings


def read_config(path):
    pe = pefile.PE(path)
    img = pe.get_memory_mapped_image()
    ds = [s for s in pe.sections if s.Name.startswith(b'.data')][0]
    return scan_data(img, ds.VirtualAddress, ds.VirtualAddress + ds.Misc_VirtualSize)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pe')
    ap.add_argument('--all', action='store_true', help='print every decrypted string, not only the C2 summary')
    a = ap.parse_args()
    strs = read_config(a.pe)
    uniq = {s['text']: s for s in strs}.values()
    host = [s['text'] for s in uniq if re.fullmatch(r'[a-z0-9-]+(\.[a-z0-9-]+)+', s['text']) and not s['text'].endswith(('.php', '.png', '.exe'))]
    paths = [s['text'] for s in uniq if s['text'].endswith('.php')]
    ua = [s['text'] for s in uniq if s['text'].startswith('Mozilla/')]
    fmt = [s['text'] for s in uniq if s['text'].startswith('https://%s')]
    res = dict(c2_hosts=host, gate_paths=paths, user_agent=ua, url_formats=fmt)
    if a.all:
        res['strings'] = list(uniq)
    json.dump(res, sys.stdout, indent=2)
    print()
    return 0 if host else 2


if __name__ == '__main__':
    sys.exit(main())
