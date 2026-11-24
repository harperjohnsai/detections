#!/usr/bin/env python3
"""CNCMachineRMS config extractor (static; no execution, no network).

Input : a Storage container (ROMULUS `execute_engine_disconnect.raw`, BabaDeda `load.db`, any `.bak/.db/.bin/.dat/.raw/.pak`
        carrying the loader config), or an already decrypted CNCMachineRMS payload (blob 16100).
Output: JSON with the per-build keys, the persistence names, the payload hash and the RAT's embedded config
        (gate list = C2 host:port, campaign, timers, flags).
Usage : cncmachinerms_extract.py <file> [--dump-payload DIR] [--dump-script DIR]
"""
import argparse, hashlib, json, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from storage import Storage, scan_headers

P_SCRIPT, P_PAYLOAD = 16001, 16100
# resource entry layout (one node per setting): 16050 -> {16051 id, 16052 name, 16053 type hash, 16054 value}
# gate list entry: 16070 -> 16071 -> {16072 host, 16073 port string, 16062 flags}
# loader config: 16050 resources hold @input (the payload), registry/scheduler autorun names etc.


def _wstr(b):
    try:
        return b.decode('utf-16le')
    except UnicodeDecodeError:
        return None


# type hashes seen in the 16053 property of a resource node
T_STR, T_INT, T_BOOL, T_DICT = 0x4268, 0x4269, 0x426A, 0x426E


def _typed(b, t=None):
    if t not in (T_STR, T_INT, T_BOOL):     # unknown type hash in this build: guess from the bytes
        s = _wstr(b) if len(b) % 2 == 0 and b else None
        if len(b) == 1:
            t = T_BOOL
        elif s and all(32 <= ord(c) < 127 for c in s):
            t = T_STR
        elif len(b) <= 8:
            t = T_INT
    if t == T_BOOL:
        return any(b) if b else None
    if t == T_INT:
        return int.from_bytes(b, 'little', signed=True) if 0 < len(b) <= 8 else b.hex()
    s = _wstr(b)
    return s if s is not None else b.hex()


def resources(st):
    """Return ({name: value}, gates) for every 16050 resource node and the 16070 gate list."""
    kids = {}
    for r in st.records:
        kids.setdefault(r.parent, []).append(r)
    out, gates = {}, []
    for r in st.records:
        if r.prop == 16050:
            ch = {c.prop: c for c in kids.get(r.node, [])}
            if 16052 not in ch:
                continue
            name = _wstr(ch[16052].blob)
            t = struct.unpack('<Q', ch[16053].blob)[0] if 16053 in ch and ch[16053].length == 8 else None
            if not name or t == T_DICT:
                continue
            v = ch.get(16054)
            if v is None:
                out[name] = None            # value lives in another node (e.g. @input -> payload blob)
            elif v.length > 512:
                out[name] = {'blob_len': v.length, 'sha256': hashlib.sha256(v.blob).hexdigest()}
            else:
                out[name] = _typed(v.blob, t)
        if r.prop == 16070:
            for e in kids.get(r.node, []):
                if e.prop == 16071:
                    ec = {c.prop: c for c in kids.get(e.node, [])}
                    if 16072 in ec:
                        host = _wstr(ec[16072].blob)
                        port = _wstr(ec[16073].blob) if 16073 in ec else None
                        gates.append({'host': host, 'port': int(port) if port and port.isdigit() else port})
    return out, gates


def script_text(st, prop=P_SCRIPT):
    t = [r for r in st.records if r.prop == prop and r.length]
    return [_wstr(r.blob) for r in t]


def analyse(data, name='input'):
    res = {'file': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'containers': []}
    seen = set()
    for off, K in scan_headers(data):
        try:
            st = Storage(data, off, K)
        except ValueError:
            continue
        c = {'offset': off, 'build_key': hex(K), 'records': st.n, 'layer2_variant': st.variant, 'layer2_params': list(st.params) if st.params else None, 'container_size': st.end - off}
        if not st.layer2_ok:
            c['note'] = 'layer-2 keystream of this build not reproduced; header/record tree only'
            c['_storage'] = st
            res['containers'].append(c)
            continue
        cfg, gates = resources(st)
        if cfg:
            c['resources'] = cfg
        if gates:
            c['gates'] = gates
        pl = [r for r in st.records if r.prop == P_PAYLOAD and r.length]
        sc = [r for r in st.records if r.prop == P_SCRIPT and r.length]
        if sc:
            c['scripts'] = [{'length': r.length, 'sha256': hashlib.sha256(r.blob).hexdigest()} for r in sc]
        if pl:
            payload = pl[0].blob
            c['payload'] = {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
                            'head': payload[:8].hex()}
            if hashlib.sha256(payload).hexdigest() not in seen:
                seen.add(hashlib.sha256(payload).hexdigest())
                c['payload_analysis'] = analyse(payload, 'payload(blob %d)' % P_PAYLOAD)
            c['_payload_bytes'] = payload
        c['_storage'] = st
        res['containers'].append(c)
    return res


def _strip(o):
    if isinstance(o, dict):
        return {k: _strip(v) for k, v in o.items() if not k.startswith('_')}
    if isinstance(o, list):
        return [_strip(v) for v in o]
    return o


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('file')
    ap.add_argument('--dump-payload', metavar='DIR', help='write the decrypted payload (blob 16100) here')
    ap.add_argument('--dump-script', metavar='DIR', help='write decrypted DSL scripts here')
    a = ap.parse_args()
    data = open(a.file, 'rb').read()
    res = analyse(data, os.path.basename(a.file))
    for c in res['containers']:
        if a.dump_payload and '_payload_bytes' in c:
            os.makedirs(a.dump_payload, exist_ok=True)
            h = hashlib.sha256(c['_payload_bytes']).hexdigest()
            open(os.path.join(a.dump_payload, h + '.bin'), 'wb').write(c['_payload_bytes'])
        if a.dump_script:
            os.makedirs(a.dump_script, exist_ok=True)
            for i, t in enumerate(script_text(c['_storage'])):
                open(os.path.join(a.dump_script, f"script_{c['build_key']}_{i}.txt"), 'w').write(t or '')
    json.dump(_strip(res), sys.stdout, indent=2)
    print()
    if not res['containers']:
        sys.exit(2)


if __name__ == '__main__':
    main()
