/*
  Grandoreiro loader (Delphi): hunting rule for the size padding. The loader stores one single-colour BMP
  (about 76 MB) as an RCDATA resource so that the 85 MB file is skipped by size-limited scanners. Lower
  confidence than Grandoreiro_Loader_Delphi_StrCrypt_PortCalc: a repacked build with a different padding
  resource will not match.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

import "pe"

rule Grandoreiro_Loader_Delphi_BMP_Padding_Hunt
{
    meta:
        description = "Hunting: Delphi PE with a single >40 MB uniform BMP stored as RCDATA (size padding) plus ZipForge/HTTP client classes"
        author = "Harper Johns"
        date = "2026-11-16"
        family = "Grandoreiro (hunting, lower confidence)"
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-grandoreiro-es-pt"
        sample = "93845bd3c4d6cb0a15c75d82903a88776e07bf90634f8d794aca8fd476539a52"
        yarahub_uuid = "a3bbce7c-4a1d-4f93-b074-7885c75ba6e4"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "a11531c8aaa981bcb1ff3feec1d43b21"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-grandoreiro-es-pt"
    strings:
        $delphi1 = "PACKAGEINFO" wide
        $delphi2 = "DVCLAL" wide
        $zf = "TZipForge" ascii
        $http1 = "TWinHTTPClient" ascii
        $http2 = "THTTPClient" ascii
    condition:
        uint16(0) == 0x5A4D and filesize > 40MB and
        all of ($delphi*) and $zf and 1 of ($http*) and
        for any r in pe.resources : (
            r.type == 10 and r.length > 40000000 and
            uint16(r.offset) == 0x4D42 and
            uint32(r.offset + 0x36) == uint32(r.offset + 0x36 + 0xC0000) and uint32(r.offset + 0x36 + 0xC0000) == uint32(r.offset + 0x36 + 0x1800000)
        )
}
