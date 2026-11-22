/*
  FluxEngine Delphi loader DLL (dhlib.dll / Project1.dll, export InitModule). Matches the four Sep-Oct 2026 builds and the Nov 2026 build that the AutoIt stage maps in memory.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

import "pe"

rule MAL_FluxEngine_Loader_dhlib_DLL
{
    meta:
        description = "FluxEngine Delphi loader DLL (dhlib.dll / Project1.dll, export InitModule). Matches the four Sep-Oct 2026 builds and the Nov 2026 build that the AutoIt stage maps in memory."
        author = "Harper Johns"
        date = "2026-11-19"
        modified = "2026-11-22"
        hash1 = "dc60f22fc59a7c3cb51b97661ad69f42d3028538c0044b248fc9681487c0b433"
        hash2 = "6a9ded132c050747ae5f233a91fc84c6bbee4e91950636f5fe077bf48acdca30"
        hash3 = "7040370d8d09dc735d3ae9a77fe4b4c8e3f97c64efb60d4a962337fd6b16b114"
        hash4 = "01af2f7049e1562023835ddcbffea76e265ed2906e140ba8a200eb41d37ebf8d"
        hash5 = "c3dc04853487b4a8f0e25a9527c250c45de5f8ba8153ec5e0c83ad834a0c81de"
        family = "FluxEngine"
        score = 75
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
        yarahub_uuid = "e1c2db52-0421-41a0-bf24-a5704aa4dd10"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "f79a01841786359b82de24525302cfd2"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
    strings:
        $w1 = "Software\\FluxEngine\\Desktop" wide
        $w2 = "Software\\HWiNFO32\\Sens" wide
        $w3 = "bsource" wide fullword
        $w4 = "lurlsource" wide fullword
        $w5 = "d3dx9_43.bin" wide
        $w6 = "/registrar.php?acao=log&status=" wide
        $w7 = "dll_sandbox" wide
        $w8 = "dll_erro_injecao" wide
        $w9 = "zones/%s/dns_records?type=TXT&name=%s.%s" wide
        $w10 = "HOLLOW_DIR" wide
        $w11 = "ExecutarHollowing INICIO" wide
        $w12 = "%SystemRoot%\\System32\\attrib.exe" wide
        // Nov 2026 anti-analysis reason list
        $v1 = "SemAppsHumanos;" wide
        $v2 = "SistemaLimpo;" wide
        $v3 = "RecursosBaixos;" wide
        $v4 = "SleepSkip;" wide
        // push 0x20; lea eax,[ebp-0x40]; push eax; lea eax,[ebp-0x10]; push eax; mov ecx,<master key>; mov edx,0x30; mov eax,esi; call
        $c_keyref = { 6A 20 8D 45 C0 50 8D 45 F0 50 B9 ?? ?? ?? ?? BA 30 00 00 00 8B C6 E8 }
    condition:
        uint16(0) == 0x5A4D and pe.is_dll() and pe.exports("InitModule") and
        ( 5 of ($w*) or ($c_keyref and 2 of ($w*)) or (3 of ($v*) and 2 of ($w*)) )
}
