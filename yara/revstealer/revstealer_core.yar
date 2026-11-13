/*
   REVSTEALER x64 inner payload of the "Setup Center" DLL-sideload chain.
   Static analysis only.
   Reference sample: c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad
   (RC4-decrypted localdata.db, hollowed into a signed OneDrive client renamed Installer.exe)
   Family attribution: Elastic Security Labs REF2859 / REVSTEALER (2026-09-02)
   https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer

   Author: Harper Johns (autonomous AI researcher, human-reviewed).
   Repository: https://github.com/harperjohnsai/detections
*/

rule REVSTEALER_x64_Core_SetupCenter
{
    meta:
        description = "REVSTEALER x64 core: tag%3 string-descriptor dispatcher, EOF-watermark token prompt, masked ChaCha20 constants, host:port parser"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer"
        reference_sample = "c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad"
        scan_context = "file, memory"
        yarahub_uuid = "a8323100-b2e9-4225-a57a-dc630a06756e"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "eef82bab267ed96d30653ffad896c002"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        // mov rdi,[rcx]; lea rbx,[rcx+0Ch]; mov eax,[rbx]; mov esi,2   (lazy string descriptor, state 0/1/2)
        $str_dispatch = { 48 8B 39 48 8D 59 0C 8B 03 BE 02 00 00 00 }
        // movzx r8d,word [rcx+0Ah]; mov eax,0AAAAAAABh; movzx r9d,word [rcx+8]   (algorithm = tag % 3)
        $str_mod3 = { 44 0F B7 41 0A B8 AB AA AA AA 44 0F B7 49 08 }
        // 6-char verification token: imul ecx,ebx,5C633D55h; lea eax,[rcx+48FFh]
        $wm_token = { 69 CB 55 3D 63 5C 8D 81 FF 48 00 00 }
        // EOF watermark compare: mov al,[rcx+r15+K]; xor al,[rsp+rcx+40h]; cmp al,[rcx+r15+V]
        $wm_cmp = { 42 8A 84 39 ?? ?? ?? ?? 32 44 0C 40 42 3A 84 39 }
        // ChaCha20 constants masked: mov dword [rsp+8],0A572F4DBh ... xor edi,0C4028CBEh
        $chacha_mask = { C7 44 24 08 DB F4 72 A5 }
        $chacha_x1 = { 81 F7 BE 8C 02 C4 }
        // embedded-PE key/nonce copy: lea rcx,[rip+key]; mov r9d,20h
        $chacha_kn = { 48 8D 0D ?? ?? ?? ?? 41 B9 20 00 00 00 48 2B CA 8A 04 11 88 02 }
    condition:
        uint16(0) == 0x5A4D and 4 of them
}
