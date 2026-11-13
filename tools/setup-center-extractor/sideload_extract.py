#!/usr/bin/env python3
"""Static config extractor for the 'Setup Center' version.dll sideload loader (YouTube TV-lure cluster C1).

Static only: parses the proxy DLL with pefile + capstone, never executes it.
Recovers from code patterns (not hardcoded RVAs):
  * payload file name  : 12 bytes XOR 4-byte key (loop `and eax,3` / `cmp edx,0xc`)
  * payload offset/size: `mov edx,<off>` before SetFilePointer, `mov ebx,<size>` before VirtualAlloc
  * RC4 key            : 32 bytes = .data[a] XOR .data[b] (loop with `cmp rdx,0x20`)
  * API table          : {mod_idx, ptr, len} entries, names XOR 4-byte key, resolved via GetProcAddress
Then RC4-decrypts the payload container and writes the inner PE (mode 0400).

usage: sideload_extract.py <version.dll> <payload_container> [out.bin]
"""
import hashlib, json, os, re, struct, sys

import capstone
import pefile


def rc4(key, data):
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255; s[i], s[j] = s[j], s[i]
    i = j = 0; out = bytearray(len(data))
    for n, c in enumerate(data):
        i = (i + 1) & 255; j = (j + s[i]) & 255; s[i], s[j] = s[j], s[i]
        out[n] = c ^ s[(s[i] + s[j]) & 255]
    return bytes(out)


def rip_target(ins):
    m = re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
    if not m:
        return None
    d = int(m.group(2), 16)
    return ins.address + ins.size + (d if m.group(1) == '+' else -d)


def extract(dll_path):
    pe = pefile.PE(dll_path)
    base = pe.OPTIONAL_HEADER.ImageBase
    img = pe.get_memory_mapped_image()
    imp = {i.address: i.name.decode() for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports if i.name}
    text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    ins = list(md.disasm(text.get_data(), base + text.VirtualAddress))
    cfg = {'exports': [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]}

    def call_name(x):
        return imp.get(rip_target(x)) if x.mnemonic == 'call' else None

    for k, x in enumerate(ins):
        n = call_name(x)
        win = ins[max(0, k - 8):k]
        if n == 'SetFilePointer':
            for w in reversed(win):
                if w.mnemonic == 'mov' and w.op_str.startswith('edx, 0x'):
                    cfg['payload_offset'] = int(w.op_str.split(', ')[1], 16); break
        if n == 'VirtualAlloc' and 'payload_size' not in cfg:
            for w in reversed(win):
                if w.mnemonic == 'mov' and re.match(r'e(bx|dx), 0x[0-9a-f]{4,}', w.op_str):
                    cfg['payload_size'] = int(w.op_str.split(', ')[1], 16); break
        if n == 'GetFileSizeEx':
            for w in ins[k:k + 4]:
                if w.mnemonic == 'cmp' and 'qword ptr' in w.op_str:
                    cfg['min_file_size'] = int(w.op_str.split(', ')[1], 16)
        # 12-byte name decode: mov al,[rax+r9+K]; xor al,[r8+r9+D]
        if x.mnemonic == 'mov' and re.match(r'al, byte ptr \[rax \+ r9 \+ 0x', x.op_str) and k + 1 < len(ins):
            y = ins[k + 1]
            if y.mnemonic == 'xor' and 'r8 + r9 + 0x' in y.op_str:
                kr = int(x.op_str.split('0x')[-1].rstrip(']'), 16)
                dr = int(y.op_str.split('0x')[-1].rstrip(']'), 16)
                for z in ins[k:k + 8]:
                    if z.mnemonic == 'cmp' and z.op_str.startswith('edx, 0x'):
                        ln = int(z.op_str.split(', ')[1], 16)
                        key = img[kr:kr + 4]
                        cfg['payload_name'] = bytes(img[dr + i] ^ key[i % 4] for i in range(ln)).decode()
        # 32-byte key: mov al,[rdx+r8+A]; xor al,[rdx+r8+B]; ...; cmp rdx,0x20
        if x.mnemonic == 'mov' and re.match(r'al, byte ptr \[rdx \+ r8 \+ 0x', x.op_str) and k + 1 < len(ins):
            y = ins[k + 1]
            if y.mnemonic == 'xor' and 'rdx + r8 + 0x' in y.op_str and any(
                    z.op_str == 'rdx, 0x20' for z in ins[k:k + 6]):
                a = int(x.op_str.split('0x')[-1].rstrip(']'), 16)
                b = int(y.op_str.split('0x')[-1].rstrip(']'), 16)
                cfg['rc4_key'] = bytes(img[a + i] ^ img[b + i] for i in range(32)).hex()
        # API name table: lea rbx,[rip+T] ... lea r10,[rip+KEY] ... GetProcAddress
        if x.mnemonic == 'lea' and x.op_str.startswith('rbx, [rip') and 'api_table' not in cfg:
            look = ins[k:k + 24]
            if any(call_name(z) == 'GetProcAddress' for z in look):
                kv = next((rip_target(z) for z in look if z.mnemonic == 'lea' and z.op_str.startswith('r10, [rip')), None)
                if kv:
                    t = rip_target(x) - base; key = img[kv - base:kv - base + 4]; names = []
                    while True:
                        ptr, ln = struct.unpack_from('<QI', img, t)
                        if not (base < ptr < base + len(img)) or not 0 < ln < 64:
                            break
                        mod = ('kernel32', 'ntdll')[img[t - 8]] if img[t - 8] < 2 else img[t - 8]
                        names.append(f"{mod}!" + bytes(img[ptr - base + i] ^ key[i % 4] for i in range(ln)).decode())
                        t += 0x18
                    cfg['api_table'] = names
    # CreateProcess flags: mov dword [rsp+X], 0x8000000 plus shl eax,2 (1<<2 = CREATE_SUSPENDED)
    for k, x in enumerate(ins):
        if x.mnemonic == 'mov' and x.op_str.endswith(', 0x8000000') and any(
                z.mnemonic == 'shl' and z.op_str == 'eax, 2' for z in ins[k - 3:k + 1]):
            cfg['create_flags'] = 'CREATE_SUSPENDED|CREATE_NO_WINDOW (0x08000004)'
    cfg['strings_cleartext'] = sorted({m.group().decode() for m in re.finditer(
        rb'(SOFTWARE|HARDWARE|SYSTEM)\\[\x20-\x7e]{6,}', open(dll_path, 'rb').read())})
    return cfg


def main():
    dll, cont = sys.argv[1], sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else None
    cfg = extract(dll)
    blob = open(cont, 'rb').read()
    cfg['container_header'] = dict(zip(('magic', 'reserved1', 'hdr_size', 'plain_size', 'body_size'),
                                       struct.unpack_from('<4sIIII', blob)))
    cfg['container_header']['magic'] = cfg['container_header']['magic'].decode('latin1')
    off, size = cfg['payload_offset'], cfg['payload_size']
    pt = rc4(bytes.fromhex(cfg['rc4_key']), blob[off:off + size])
    cfg['payload_sha256'] = hashlib.sha256(pt).hexdigest()
    cfg['payload_is_pe'] = pt[:2] == b'MZ' and pt[struct.unpack_from('<I', pt, 0x3c)[0]:][:4] == b'PE\0\0'
    if out and cfg['payload_is_pe']:
        if os.path.exists(out):
            os.chmod(out, 0o600)
        open(out, 'wb').write(pt); os.chmod(out, 0o400)
    print(json.dumps(cfg, indent=1))
    return 0 if cfg['payload_is_pe'] else 1


if __name__ == '__main__':
    sys.exit(main())
