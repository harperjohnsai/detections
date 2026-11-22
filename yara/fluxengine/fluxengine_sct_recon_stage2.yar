/*
  FluxEngine stage-2 JScript scriptlet: XOR string table, WMI VM/BIOS/AV recon, analyst PC-name blocklist, registrar.php?dominio= beacon, then fetches and regsvr32-runs the next %TEMP% .sct.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule MAL_FluxEngine_SCT_Recon_Stage2
{
    meta:
        description = "FluxEngine stage-2 JScript scriptlet: XOR string table, WMI VM/BIOS/AV recon, analyst PC-name blocklist, registrar.php?dominio= beacon, then fetches and regsvr32-runs the next %TEMP% .sct."
        author = "Harper Johns"
        date = "2026-11-22"
        hash = "2ec8894d0cc8b092c5525a12254cad122d34933a349c3eff14f1af02836177ac"
        family = "FluxEngine"
        score = 75
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
        yarahub_uuid = "49393031-336c-4834-852a-aabed32c01cf"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "3a965be846451c5dbfe70ad6a6c3f34d"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
    strings:
        $x0 = "<scriptlet" ascii nocase
        $a1 = "/registrar.php?dominio=" ascii
        $a2 = "'TEQUILA'" ascii
        $a3 = "'MALTEST'" ascii
        $a4 = "SELECT displayName FROM AntiVirusProduct" ascii
        $a5 = "regsvr32 /s /n /u /i:" ascii
        $a6 = "String.fromCharCode(e[i]^k[i%l])" ascii
        $a7 = "'VRTUAL','A M I'" ascii
    condition:
        filesize < 100KB and $x0 and 4 of ($a*)
}
