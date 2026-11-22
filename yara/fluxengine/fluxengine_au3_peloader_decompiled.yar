/*
  Decompiled FluxEngine AutoIt stage (analyst text or AutoIt script memory): hex-embedded dhlib.dll mapped by an AutoIt PE loader, InitModule, HOLLOW_DIR, au3_* status beacons. The raw .a3x is encrypted and is not matched; not deployed to YARAhub.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule MAL_FluxEngine_AU3_PELoader_Decompiled
{
    meta:
        description = "Decompiled FluxEngine AutoIt stage (analyst text or AutoIt script memory): hex-embedded dhlib.dll mapped by an AutoIt PE loader, InitModule, HOLLOW_DIR, au3_* status beacons. The raw .a3x is encrypted and is not matched; not deployed to YARAhub."
        author = "Harper Johns"
        date = "2026-11-22"
        hash = "4fc99727bbb91087a474126049ced32b69d252c5ed93e2b1fa40d8c13d10257e"
        family = "FluxEngine"
        score = 60
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
    strings:
        $a1 = "_PELOADER_GETPROCADDRESS" ascii nocase
        $a2 = "\"InitModule\"" ascii
        $a3 = "HOLLOW_DIR" ascii
        $a4 = "Software\\FluxEngine\\Desktop" ascii
        $a5 = "au3_inicio" ascii
        $a6 = "au3_dll_ok" ascii
        $a7 = "_AGUARDAINTERNET" ascii nocase
    condition:
        4 of them
}
