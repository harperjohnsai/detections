/*
  Stage-1 LNK of the FluxEngine cluster (scrobj.dll copied to an alternate data stream, regsvr32 /i: scriptlet). Generic technique: a hunting rule, expect other families to share it.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule SUSP_FluxEngine_LNK_Squiblydoo_ADS
{
    meta:
        description = "Stage-1 LNK of the FluxEngine cluster (scrobj.dll copied to an alternate data stream, regsvr32 /i: scriptlet). Generic technique: a hunting rule, expect other families to share it."
        author = "Harper Johns"
        date = "2026-11-19"
        hash = "6e6d4084c6c2f3035c2fbda4daf4b705a06938d73bf91f402552b6d4ab522d9b"
        family = "FluxEngine"
        score = 50
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
        yarahub_uuid = "c32f12da-3207-4536-8331-93f6b91826b8"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "26b3f7856483622397d512ae6bc1eb2e"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
    strings:
        $a = "*crOBJ.*" wide nocase
        $b = "/V:ON" wide
        $c = /\.log:[A-Za-z0-9]{3,12}/ wide
        $d = " /u /s " wide
        $e = "/i:" wide
    condition:
        uint32(0) == 0x0000004C and filesize < 20KB and all of them
}
