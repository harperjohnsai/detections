/*
  MioLab (Nova) macOS chain, reached from the "Setup Center" YouTube-lure campaign.
  Stage-2 Mach-O of the macOS ClickFix branch (universal x86_64+arm64, ad-hoc signed). Hashes: universal file, x86_64 slice, arm64 slice.
  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule MAL_macOS_MioLab_Cpp_Stealer_ConfigDecrypt
{
    meta:
        description = "MioLab/Nova macOS stealer, C++ build (Unit 42: 'modern C++ Odyssey variant'): rotating-XOR config decrypt loop (key byte i&7, ror64 key by 1 per byte) plus CommonCrypto/popen/filesystem imports"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/47b53a06affd56b4fefbbcb1fb9fdaf88e3cca5e/2026-06-20-ClickFix-campaign-delivers-macOS-infostealer-via-DMG.txt"
        hash1 = "2b4f61c274bf8e4a79cf77e7b36d18d1dd265e8e894f5f2b6d8babc6323d556a"
        hash2 = "49de3b526ee449d9a28f73d85af2fb0b40d721b45693d80119f8db47d4bba51a"
        hash3 = "f9a80a964748880116c22e1353072b31a966a5744e930d7a1bd376cf75ba5532"
        score = 80
        yarahub_uuid = "b89831c0-a372-4f2b-bf62-5e38fa2c0869"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "90f962d66963f7189a00ad58e88cfd7c"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        // x86_64: and edi,7 ; mov dil,[rbp+rdi-X] ; xor [rdx+rsi+0x10],dil ; ror rcx,1
        $cfg_x64 = { 83 E7 07 40 8A 7C 3D ?? 40 30 7C 32 10 48 D1 C9 48 89 4D ?? 48 FF C2 }
        // arm64: bfxil x12,x11,#0,#3 ; ldrb w12,[x12] ; add x13,x21,x11 ; ldrb w14,[x13,#0x10] ; eor ; strb ; ror x10,x10,#1
        $cfg_a64 = { 6C 09 40 B3 8C 01 40 39 AD 02 0B 8B AE 41 40 39 CC 01 0C 4A AC 41 00 39 4A 05 CA 93 }
        // looser arm64 form (register allocation may change per build): bfxil ...#0,#3 ... eor w,w,w ; strb ; ror x,x,#1
        $cfg_a64_loose = { ?? 09 40 B3 ?? ?? 40 39 [4] ?? 41 40 39 ?? ?? ?? 4A ?? 41 00 39 ?? 05 ?? 93 }
        $i1 = "_CCKeyDerivationPBKDF"
        $i2 = "_CCCrypt"
        $i3 = "_popen"
        $i4 = "_setsid"
        $i5 = "21__temp_directory_pathE"
        $i6 = "recursive_directory_iterator"
        $i7 = "_fork"
    condition:
        (uint32(0) == 0xbebafeca or uint32(0) == 0xfeedfacf) and filesize < 3MB
        and 6 of ($i*)
        and ($cfg_x64 or $cfg_a64 or $cfg_a64_loose)
}
