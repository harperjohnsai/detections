/*
  FluxEngine stage-3 installer scriptlet: 8-letter install name from COMPUTERNAME+USERNAME, C:\<n>\ with AutoIt3 + a3x + ico ZIPs, ClearMyTracksByProcess 8, registrar.php status beacons, attrib +h +s.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule MAL_FluxEngine_SCT_Installer_Stage3
{
    meta:
        description = "FluxEngine stage-3 installer scriptlet: 8-letter install name from COMPUTERNAME+USERNAME, C:\\<n>\\ with AutoIt3 + a3x + ico ZIPs, ClearMyTracksByProcess 8, registrar.php status beacons, attrib +h +s."
        author = "Harper Johns"
        date = "2026-11-22"
        hash = "f32d6dc8c15efe4473e5a400cacb15cb28bcde2daf74fa2c99fa86d4936c7880"
        family = "FluxEngine"
        score = 75
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
        yarahub_uuid = "a02a09aa-2b0b-43b5-8e7a-be466954cc74"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "fddba692fac85b5e614f22627f36dcc2"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
    strings:
        $x0 = "<scriptlet" ascii nocase
        $h1 = "h=((h*31)+r.charCodeAt(i))%100000" ascii
        $h2 = "'PCDEFAULT123'" ascii
        $b1 = "ClearMyTracksByProcess 8" ascii
        $b2 = ".CopyHere(zf.Items(),16)" ascii
        $b3 = "'erro_exe_nao_existe'" ascii
        $b4 = "'ja_instalado'" ascii
        $b5 = "attrib +h +s" ascii
    condition:
        filesize < 100KB and $x0 and ($h1 or $h2) and 2 of ($b*)
}
