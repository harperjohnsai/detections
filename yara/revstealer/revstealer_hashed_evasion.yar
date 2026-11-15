/*
   REVSTEALER x64 (Setup Center chain): build-invariant code shapes of the hashed evasion checks.
   Static analysis only (2026-11-15). Reference sample: c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad
   Every build re-salts its hashes (FNV basis per build; prime 0x01000193 in builds 25/26, 0x0100024b in 27 and the case
   build; export-hash init/final xor also change), so hash VALUES are build-specific. This rule keys on code shape:
   - constant-blinding helper: two stack args combined with xor (call to a nop;nop;ret stub first)
   - FNV-1a over UTF-16 code units with the prime fetched from a getter call before each multiply
   - export-name hash h=(h+c)*0x401; h^=h>>6 ($oaat, informational: present in build 27 and the case build only)

   Author: Harper Johns (autonomous AI researcher, human-reviewed).
   Repository: https://github.com/harperjohnsai/detections
   Tested with yara-python and YARA-X, see tests/ in the repository.
*/
rule REVSTEALER_x64_Hashed_Evasion_Shapes
{
    meta:
        description = "REVSTEALER x64: per-build salted FNV-1a (prime via getter call), xor/add constant-blinding helpers, one-at-a-time export hash"
        author = "Harper Johns"
        date = "2026-11-15"
        reference = "https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer"
        reference_sample = "c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad"
        scan_context = "file, memory"
        modified = "2026-11-15"
        mitre_attack = "T1497.001, T1027"
        yarahub_uuid = "13f791f4-e5cf-4281-818d-b43014fc37f5"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "eef82bab267ed96d30653ffad896c002"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        // mov [rsp+10h],edx; mov [rsp+8],ecx; sub rsp,18h; call stub; ... mov eax,[rsp]; mov ecx,[rsp+4]; xor eax,ecx
        $blind_xor = { 89 54 24 10 89 4C 24 08 48 83 EC 18 E8 ?? ?? ?? ?? 8B 44 24 20 89 04 24 8B 44 24 28 89 44 24 04 8B 04 24 8B 4C 24 04 33 C1 }
        $blind_add = { 89 54 24 10 89 4C 24 08 48 83 EC 18 E8 ?? ?? ?? ?? 8B 44 24 20 89 04 24 8B 44 24 28 89 44 24 04 8B 04 24 8B 4C 24 04 03 C1 }
        // wide FNV with length: movzx lo; movzx hi; call getPrime; xor; imul; xor; call getPrime; imul
        $fnv_w_len = { 41 0F B6 ?? ?? 41 0F B6 ?? ?? 01 E8 ?? ?? ?? ?? 33 ?? 0F AF ?? 33 ?? E8 ?? ?? ?? ?? 0F AF }
        // wide FNV null-terminated: movzx lo; call getPrime; ... imul; call getPrime; movzx; lea +2; shr 8
        $fnv_w_nul = { 41 0F B6 ?? E8 ?? ?? ?? ?? 8B ?? 8B ?? 33 ?? 0F AF ?? E8 ?? ?? ?? ?? 0F B7 ?? 4D 8D ?? 02 C1 E9 08 }
        // export hash: movzx eax,al; inc r10; add eax,r8d; imul ecx,eax,401h; mov r8d,ecx; shr r8d,6; xor r8d,ecx
        $oaat = { 0F B6 C0 49 FF C2 41 03 C0 69 C8 01 04 00 00 44 8B C1 41 C1 E8 06 44 33 C1 }
    condition:
        uint16(0) == 0x5A4D and all of ($blind_*) and (1 of ($fnv_w_*) or $oaat)   // $oaat: builds 27+ only
}
