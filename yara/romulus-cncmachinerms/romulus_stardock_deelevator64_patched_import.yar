/*
  Patched Stardock DeElevator64.dll (extra non-system import) used for the ROMULUS side-load.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

import "pe"

rule MAL_ROMULUS_Stardock_DeElevator64_Patched_Import
{
    meta:
        description = "Patched Stardock DeElevator64.dll as used in the ROMULUS chain: a De-elevation DLL (exports RunNonElevated and RunNonElevatedRunDllW) with one extra, non-system import (I++u.dll!contentsStroke) added so the signed DeElevate64.exe loads the loader from the same folder. The remaining imports of the patched sample are only KERNEL32/USER32/ADVAPI32/SHELL32."
        author = "Harper Johns"
        date = "2026-11-24"
        hash = "0457414c4504b70115798eee9c8384a8bf9e793461ffb2e0661a6dcc6ed4809f"
        family = "ROMULUS"
        score = 85
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
        yarahub_uuid = "697bb9e2-44bd-48ff-8687-8e480f123350"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "8986af3c278b5384af6d0f1d954ed5fc"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
    condition:
        uint16(0) == 0x5A4D and filesize < 200KB and pe.is_dll() and
        pe.exports("RunNonElevated") and pe.exports("RunNonElevatedRunDllW") and
        for any i in pe.import_details : (
            not (i.library_name matches /^(KERNEL32|USER32|ADVAPI32|SHELL32|OLE32|OLEAUT32|GDI32|SHLWAPI|MSVCRT|NTDLL|VERSION|COMCTL32|USERENV|WTSAPI32|CRYPT32|BCRYPT|WS2_32|RPCRT4|SECUR32|API-MS-[A-Z0-9-]+|VCRUNTIME[0-9_]*|UCRTBASE|MSVCP[0-9_]+)\.dll$/i)
        )
}
