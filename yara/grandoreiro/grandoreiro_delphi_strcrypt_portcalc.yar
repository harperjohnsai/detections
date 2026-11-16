/*
  Grandoreiro loader (Delphi), build seen 2026-11 in a Portuguese/Spanish "contraordenacao" phishing chain.
  Key derivation per string: 4-char seed + 16-byte salt (XOR 0x42) -> four FNV-1a lanes -> 256 rol5/xor rounds
  -> 32-hex key -> XOR/subtract-previous-byte decode, Base64 on both sides. The C2 port is
  (SHA-256(tag + ip)[:8] mod 9001) + 1001 (constants 0x2326 / 0x3E9). Payload: RC4 + ZipForge as in public
  Grandoreiro loader reporting. The rule keys on code idioms, which survive re-encrypting the strings, but it is
  tied to this build's key derivation and may need an update for later builds.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

import "pe"

rule Grandoreiro_Loader_Delphi_StrCrypt_PortCalc
{
    meta:
        description = "Grandoreiro Delphi loader: FNV-lane string-key derivation, XOR/subtract decoder and SHA-256-derived C2 port"
        author = "Harper Johns"
        date = "2026-11-16"
        family = "Grandoreiro"
        confidence = "high when kdf/port idioms co-occur"
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-grandoreiro-es-pt"
        sample = "93845bd3c4d6cb0a15c75d82903a88776e07bf90634f8d794aca8fd476539a52"
        yarahub_uuid = "a300594a-283a-4e6f-8e35-27d71d1e8b5f"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "a11531c8aaa981bcb1ff3feec1d43b21"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-grandoreiro-es-pt"
    strings:
        // mov [ebp-x], 0x811C9DC5 / 0xB8A3A7B9 / 0x6B88C2F1 / 0x27B98D3A  (4 lane seeds)
        $kdf_seeds = { C7 45 ?? C5 9D 1C 81 C7 45 ?? B9 A7 A3 B8 C7 45 ?? F1 C2 88 6B C7 45 ?? 3A 8D B9 27 }
        // movzx esi,word[esi+ebx*2-2]; xor [eax],esi; imul esi,[eax],0x01000193; mov [eax],esi; add eax,4
        $kdf_fnv = { 0F B7 74 5E FE 31 30 69 30 93 01 00 01 89 30 83 C0 04 }
        // mov ecx,[eax]; mov esi,ecx; shl esi,5; shr ecx,27; or esi,ecx; lea ecx,[edx+1]; and ecx,3; xor esi,[ebp+ecx*4-x]
        $kdf_mix = { 8B 08 8B F1 C1 E6 05 C1 E9 1B 0B F1 8D 4A 01 83 E1 03 33 74 8D ?? }
        // movzx esi,word[eax+edi*2-2]; xor esi,[ebp-x]; sub esi,[ebp-y]; add esi,0x100; and esi,0x800000FF
        $dec_core = { 0F B7 74 78 FE 33 75 ?? 2B 75 ?? 81 C6 00 01 00 00 81 E6 FF 00 00 80 }
        // salt bytes built on stack then XOR 0x42
        $salt_xor = { 0F B6 13 80 F2 42 0F B6 D2 E8 }
        // push 0; push 0x2326 (9001); ... ; add ebx,0x3E9 (1001)
        $port_calc = { 6A 00 68 26 23 00 00 [6-12] 81 C3 E9 03 00 00 }
        $cls1 = "TZipForge" ascii
        $cls2 = "TCryptoUtils" ascii
    condition:
        uint16(0) == 0x5A4D and
        (
            ($kdf_seeds and ($kdf_fnv or $kdf_mix)) or
            ($port_calc and $dec_core and 1 of ($kdf_*, $salt_xor)) or
            ($kdf_fnv and $kdf_mix and $dec_core and 1 of ($cls*))
        )
}
