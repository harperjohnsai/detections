/*
  MSI installers produced by the ROMULUS delivery builder (script custom action stages).

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule MAL_ROMULUS_MSI_Builder_Script_CustomAction
{
    meta:
        description = "MSI produced by the ROMULUS delivery builder: random-named Binary.* streams carrying a plain-text script custom action that rebuilds and runs an obfuscated PowerShell/VBScript stage (nibble-pair Chr(CLng(..)*16+CLng(..)) VBS Execute, base64 stride/reverse decoder + scriptblock::Create, or Item,A,B nibble CSV + powershell::Create().AddScript, or Session.Property OriginalDatabase + ADODB.Stream PowerShell dropper, or a CustomAction that runs an installed .bat with [OriginalDatabase])."
        author = "Harper Johns"
        date = "2026-11-24"
        hash = "37e56899fcfeeab953dd1c0804b59848f5cc66a0e47e2197e0e276dd032f30f7"
        family = "ROMULUS"
        score = 80
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
        yarahub_uuid = "32c7f400-4c77-4050-be1a-b155f1f42a43"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "2c0f9df2db104af1b75c471a4e7465ca"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $vbs_nib = "Chr(CLng(" ascii
        $vbs_nib2 = ")*16+CLng(" ascii
        $vbs_exec = "Execute " ascii
        $ps_b64 = "=[Convert]::FromBase64String('" ascii
        $ps_stride = ".Length - 4) / $" ascii
        $ps_sb = "=[scriptblock]::Create($" ascii
        $ps_csv1 = "StartsWith('Item')" ascii
        $ps_csv2 = "[powershell]::Create()" ascii
        $ps_csv3 = ".AddScript($" ascii
        $drop1 = "Session.Property(\"OriginalDatabase\")" ascii
        $drop2 = "ADODB.Stream" ascii
        $drop3 = "-NoProfile -ExecutionPolicy Bypass -File" ascii
        $bat1 = "cmd.exe /c start \"\" /min /wait cmd.exe /c call \"[#" ascii
        $bat2 = "\"[OriginalDatabase]\"" ascii
    condition:
        $ole at 0 and filesize < 8MB and
               (
            ($vbs_nib and $vbs_nib2 and $vbs_exec) or
            ($ps_b64 and $ps_stride and $ps_sb) or
            ($ps_csv1 and $ps_csv2 and $ps_csv3) or
            ($drop1 and $drop2 and $drop3) or
            ($bat1 and $bat2)
        )
}
