/*
  Keyboard-hook helper DLL (resource PDLL of the payload, loaded in memory): Delphi DLL exporting InstallHook,
  UninstallHook and setafase. Matches the extracted DLL, not the outer payload.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

import "pe"

rule MAL_Mispadu_URSA_Hook_DLL_pDLL
{
    meta:
        description = "Mispadu/URSA keyboard hook helper DLL (RCDATA PDLL, loaded in memory): Delphi DLL exporting InstallHook/UninstallHook/setafase"
        author = "Harper Johns"
        date = "2026-11-19"
        hash = "352c8d5d8cc824c41d143af2504d2cdf5d8a16e5f4df019032a5241859b1900b"
        family = "Mispadu"
        score = 70
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-mispadu-ursa"
        yarahub_uuid = "abb6d381-1b16-4452-aa3d-a846e9ce1194"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "3af08f56f23af7902a307f776e98b83e"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-mispadu-ursa"
    strings:
        $k1 = "{CAPSLOCK}" wide
        $k2 = "{SCROLLLOCK}" wide
        $k3 = "{PRTSC}" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 200KB and
        pe.exports("setafase") and pe.exports("InstallHook") and pe.exports("UninstallHook") and 2 of ($k*)
}
