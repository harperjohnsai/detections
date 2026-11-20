/*
  Go PE loader that maps an embedded, encrypted PE into its own process (reflective loading, T1620).
  Reference build: the loader core of the fake "cracked trading software" campaign (X account cryptotrice, 2026-11):
  Go 1.21.1, Go module path NovaMetricIndustries, self-signed Authenticode certificate "Nova Metric Industries".
  See iocs/2026-11-cryptotrice/.

  Key: Go build info plus all five API names a manual PE mapper needs (RtlAddFunctionTable for the mapped .pdata,
  NtQueryInformationThread for the TEB, CreateActCtxW / ActivateActCtx, VirtualProtect), kept as plain Go string
  data, in a 64-bit PE that imports only kernel32.dll (everything else is resolved at run time).

  Second-build check, 2026-11-20 (MalwareBazaar get_subjectinfo / get_imphash): 40 other samples with the same
  imphash 4f2f006e2ecf7172ad368f8289dc96c1 (Go, first seen 2026-10-26 to 2026-11-18) were downloaded and all 40 match.
  Two of them carry a self-signed "Nova Metric Industries" certificate (different serials from the reference build),
  the other 38 do not. MalwareBazaar labels on the 40: Vidar 20, WARDENStealer 13, RemusStealer 3, Stealc 1,
  AokigaharaStealer 1, none 2 (labels are leads, not attribution). So the rule covers a loader class that more
  than one label uses, not only the one build.
  The blob decryption passes of the reference build are NOT shared: they differ per build.
  Details and the hash list: yara/cryptotrice-go-loader/README.md.

  Author: Harper Johns (autonomous AI researcher with human oversight). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see yara/cryptotrice-go-loader/README.md and tests/.
*/

import "pe"

rule MAL_Go_Reflective_PE_Loader_Win64
{
    meta:
        description = "Go PE loader that reflectively maps an embedded encrypted PE: Go build info plus the five Win32/NT API names a manual PE mapper needs (unwind table registration, TEB query, activation context, VirtualProtect) as plain Go string data, kernel32 as the only import"
        author = "Harper Johns"
        date = "2026-11-20"
        hash = "b8c1d2399105a57046b24aeee74d2dea3250c8c8aa5502c448b8d954f1dcb17a"
        family = "Go reflective PE loader (reference build: cryptotrice, Nova Metric Industries)"
        second_build_check = "2026-11-20: 40 of 40 other MalwareBazaar samples with the same imphash match (2 with the same self-signed publisher name); several family labels; blob passes differ per build"
        score = 70
        reference = "https://github.com/harperjohnsai/detections/tree/main/yara/cryptotrice-go-loader"
        yarahub_uuid = "a4319675-dc31-4074-8d3c-732f7da4b6a5"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "dcb302d9a9b0cc9cc731b3012ab71161"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-cryptotrice"
    strings:
        $go = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }   // "\xff Go buildinf:"
        $r1 = "RtlAddFunctionTable" ascii
        $r2 = "NtQueryInformationThread" ascii
        $r3 = "CreateActCtxW" ascii
        $r4 = "ActivateActCtx" ascii
        $r5 = "VirtualProtect" ascii
    condition:
        uint16(0) == 0x5A4D and pe.is_pe and pe.machine == pe.MACHINE_AMD64
        and pe.number_of_imports == 1 and pe.imports("kernel32.dll")
        and $go and all of ($r*)
}
