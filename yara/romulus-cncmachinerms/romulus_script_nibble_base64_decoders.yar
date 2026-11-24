/*
  Script stages (VBS / PowerShell) extracted from ROMULUS-builder MSI Binary streams.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule MAL_ROMULUS_Script_Nibble_Base64_Decoders
{
    meta:
        description = "Plain-text script stages extracted from ROMULUS-builder MSI Binary streams: VBS that rebuilds a command from 'lo.hi' nibble pairs (Chr(CLng(x(1))*16+CLng(x(0))) then Execute), PowerShell that rebuilds a script from an Item,A,B nibble CSV (powershell::Create().AddScript), or from a base64 blob with a stride/offset/reverse header (scriptblock::Create)."
        author = "Harper Johns"
        date = "2026-11-24"
        hash = "98a1d42af78a82a61b1511479f7f8b3fb5f91bca8ff452cbf6576a32515c6b0d"
        family = "ROMULUS"
        score = 75
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
        yarahub_uuid = "24b80673-3fea-4e3d-a181-98269c41b50f"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "a22ca56fe10d62888b0727586ac9fc72"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
    strings:
        $vbs1 = "Chr(CLng(" ascii
        $vbs2 = ")*16+CLng(" ascii
        $vbs3 = "Split(" ascii
        $vbs4 = "Execute " ascii
        $csv1 = "StartsWith('Item')" ascii
        $csv2 = "[powershell]::Create()" ascii
        $csv3 = ".AddScript($" ascii
        $csv4 = "* 16 + [int]" ascii
        $b64a = "=[Convert]::FromBase64String('" ascii
        $b64b = ".Length - 4) / $" ascii
        $b64c = "=[scriptblock]::Create($" ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0xE011CFD0 and
        (
            ($vbs1 and $vbs2 and $vbs3 and $vbs4) or
            ($csv1 and $csv2 and $csv3 and $csv4) or
            ($b64a and $b64b and $b64c)
        )
}
