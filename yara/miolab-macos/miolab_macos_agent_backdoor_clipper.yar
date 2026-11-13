/*
  MioLab (Nova) macOS chain, reached from the "Setup Center" YouTube-lure campaign.
  Universal x86_64+arm64 Mach-O, C++, ad-hoc signed (identifier macos-agent-<hex>). No hit on YARA Forge full 20261108 at the time of writing.
  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule MAL_macOS_MioLab_Agent_Backdoor_Clipper
{
    meta:
        description = "MioLab macOS agent (~/.hlpr/.agnt): C2 task loop with reverse shell, self-update and regex clipboard hijacker"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-revstealer-setup-center"
        hash = "5a2bef675eae4b80db636a17f5a2ef1e67ee56c4b841ef995ce3ce52a739be5e"
        score = 80
        yarahub_uuid = "2fea2b48-2e90-4267-8929-ca15927e1ba2"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "e4b4324e0c44ccff3de04b60edf4a3e5"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        $s1 = "Agent tick" ascii
        $s2 = "Got tasks: " ascii
        $s3 = "invalid task type" ascii
        $o1 = "generalPasteboard" ascii
        $o2 = "setString:forType:" ascii
        $o3 = "stringForType:" ascii
        $id = "macos-agent-" ascii
        // wire obfuscation constants: k = i * 0x4c957f2d + 0x43fd007c (x86_64 imm32)
        $x_mul = { 2D 7F 95 4C }
        $x_add = { 7C 00 FD 43 }
        // arm64: movz wN,#0x7f2d / movk wN,#0x4c95,lsl#16 / movk wN,#0x43fd,lsl#16
        $a_mul_lo = { ( A0 | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 | A9 | AA | AB | AC | AD | AE | AF | B0 | B1 | B2 | B3 | B4 | B5 | B6 | B7 | B8 | B9 | BA | BB | BC | BD | BE | BF ) E5 8F 52 }
        $a_mul_hi = { ( A0 | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 | A9 | AA | AB | AC | AD | AE | AF | B0 | B1 | B2 | B3 | B4 | B5 | B6 | B7 | B8 | B9 | BA | BB | BC | BD | BE | BF ) 92 A9 72 }
    condition:
        (uint32(0) == 0xbebafeca or uint32(0) == 0xfeedfacf) and filesize < 3MB and
        2 of ($s*) and 2 of ($o*) and
        ($id or (#x_mul > 4 and #x_add > 4) or (#a_mul_lo > 4 and #a_mul_hi > 4))
}
