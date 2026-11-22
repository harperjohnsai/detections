/*
  FluxEngine first-stage VBS (DOC-*.vbs): Msxml2 GET with an MSIE 8 user agent, saves a .sct to %TEMP% and runs regsvr32 /s /n /u /i:<sct> scrobj.dll; reversed strings and Array()-minus-key tables.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule MAL_FluxEngine_VBS_Downloader
{
    meta:
        description = "FluxEngine first-stage VBS (DOC-*.vbs): Msxml2 GET with an MSIE 8 user agent, saves a .sct to %TEMP% and runs regsvr32 /s /n /u /i:<sct> scrobj.dll; reversed strings and Array()-minus-key tables."
        author = "Harper Johns"
        date = "2026-11-22"
        hash = "e683253477ca1b9b22c285cbc854a50284256b4d246b151e63dc171830bf7192"
        family = "FluxEngine"
        score = 75
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
        yarahub_uuid = "1b691cf9-ffc7-43be-8529-e8b56fd211a4"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "edcbd5d4880ef969c822fb96b70afe6b"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
    strings:
        $r1 = ":i/ u/ n/ s/ 23rvsger" ascii nocase
        $r2 = "lld.jborcs" ascii nocase
        $r3 = ")1.6 TN swodniW ;0.8 EISM ;elbitapmoc( 0.4/allizoM" ascii nocase
        $h1 = "' Windows Update Service Helper" ascii
        $h2 = "' Configuration module" ascii
        $s1 = "ExpandEnvironmentStrings" ascii nocase
        $s2 = "SaveToFile" ascii nocase
        $s3 = "Array(" ascii nocase
        $s4 = "Mid(" ascii nocase
        $s5 = ".setRequestHeader" ascii nocase
    condition:
        filesize < 50KB and
        ( ($r1 and ($r2 or $r3)) or ($r3 and 1 of ($h*)) ) and
        3 of ($s*)
}
