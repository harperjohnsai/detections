#!/usr/bin/env python3
"""Read the cleartext per-build fields of Remus stealer payloads (static, nothing is executed).

Remus builds keep two per-build values as plain literals in .rdata: a build date (dd.mm.yyyy) and a
NUL-terminated 32-hex campaign ID (sent as tag=<id> at registration, see Malware Cake Factory's Remus C2
protocol write-up). In every build we hold the campaign ID starts exactly 0x5e4 bytes after the build date;
the tool reports a campaign ID only when it sits at that offset, so 32-digit filler runs in other families
are not reported.

usage: remus_cleartext.py OUT.csv FILE [FILE ...]
"""
import csv
import hashlib
import re
import sys

import pefile

DATE = re.compile(rb'(?<![0-9])([0-3][0-9]\.[01][0-9]\.20[2-3][0-9])(?![0-9])')
HEX32 = re.compile(rb'([0-9a-f]{32})\x00')  # the byte before the ID may be any value
TAG_DELTA = 0x5e4  # campaign ID RVA - build date RVA, constant across 14/14 known builds


def read(path):
    d = open(path, 'rb').read()
    pe = pefile.PE(data=d, fast_load=True)
    row = {'sha256': hashlib.sha256(d).hexdigest(), 'size': len(d), 'pe_timestamp': pe.FILE_HEADER.TimeDateStamp,
           'build_date': '', 'build_date_rva': '', 'campaign_id': '', 'campaign_id_rva': ''}
    rd = [s for s in pe.sections if s.Name.rstrip(b'\0') == b'.rdata']
    if not rd:
        return row
    s = rd[0]
    r = d[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
    tags = {s.VirtualAddress + m.start(1): m.group(1).decode() for m in HEX32.finditer(r)}
    for m in DATE.finditer(r):
        rva = s.VirtualAddress + m.start(1)
        tag = tags.get(rva + TAG_DELTA)
        if tag:
            row.update(build_date=m.group(1).decode(), build_date_rva=hex(rva),
                       campaign_id=tag, campaign_id_rva=hex(rva + TAG_DELTA))
            break
    return row


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    rows = [read(f) for f in argv[2:]]
    with open(argv[1], 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    for x in rows:
        print(x['sha256'][:12], x['size'], x['build_date'] or '-', x['campaign_id'] or '-')


if __name__ == '__main__':
    main(sys.argv)
