/*
  CNCMachineRMS RAT core as decrypted from the Storage container (memory or payload dump).

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule MAL_CNCMachineRMS_Core_Decrypted_x64
{
    meta:
        description = "CNCMachineRMS RAT core as decrypted from the Storage container (class 16100): ~1.58 MB position-independent x64 shellcode, entry stub 'sub rsp,28; xor ecx,ecx; call; nop; add rsp,28; ret', compiled-in key 0x16DF3822A8 (the embedded-container key LevelBlue also reported) immediate-loaded 56 times in all four builds (24 or more required), plus the 0xBABADEDA container tag. Memory dump or decrypted payload, not the encrypted container."
        author = "Harper Johns"
        date = "2026-11-24"
        hash = "ab65bbfc505dbe1cebe6021fb36e2011f6aa1d64f5d87cee1cbee3fc2a0c7907"
        family = "CNCMachineRMS"
        score = 90
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
        yarahub_uuid = "b2d5d314-1f0d-4818-862b-1d1ec53638c0"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "e22c0b881f7bacf6d1610a7622eb71a0"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
    strings:
        $entry = { 48 83 EC 28 33 C9 E8 ?? ?? ?? ?? 90 48 83 C4 28 C3 }
        $key = { A8 22 38 DF 16 00 00 00 }
        $tag = { DA DE BA BA }
    condition:
        filesize > 0x100000 and filesize < 0x400000 and
        $entry at 0 and #key >= 20 and #tag >= 4
}
