/*
  Side-loaded unsigned decoy loader DLLs of the ROMULUS / BabaDeda chains.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

import "pe"

rule MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL
{
    meta:
        description = "Unsigned x64 DLL used by the ROMULUS/BabaDeda chains as the side-loaded stage-1 or shellcode trampoline: a decoy GUI/graphics body (GDI32 drawing imports, ole32 CoCreateGuid/MkParseDisplayName, SHLWAPI PathFileExistsW, MSVCP140 _Xlength_error) with 3+ random-looking exports, and either an import of another unsigned sibling DLL (stage-1, e.g. I++u.dll importing senddmp.resources.dll) or the EnumSystemCodePagesW + VirtualAlloc + BCryptGenRandom trampoline combination (stage-2, exports request/network_identity or RevertIconPacakge/RemoveInactualGroup), or the DispatchNetworkChain/InitializeNewSession export pair of the network module."
        author = "Harper Johns"
        date = "2026-11-24"
        hash = "3cd1484cc5bf10e22d79784beba58a75d7b126c46efb5e1a85d6aab884447621"
        family = "ROMULUS"
        score = 70
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
        yarahub_uuid = "9f4cad2e-f032-4ba7-824d-3667475833a5"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "06d5f06cd54c326750d1544290017174"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
    strings:
        $typo = "RevertIconPacakge" ascii fullword
    condition:
        uint16(0) == 0x5A4D and filesize > 20KB and filesize < 300KB and pe.is_dll() and pe.is_64bit() and
        pe.number_of_exports >= 3 and
        pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size == 0 and
        pe.imports("MSVCP140.dll", "?_Xlength_error@std@@YAXPEBD@Z") and
        (
            $typo or
            (pe.exports("DispatchNetworkChain") and pe.exports("InitializeNewSession")) or
            (
                pe.imports("WS2_32.dll", "WSAStartup") and pe.imports("WINMM.dll") and pe.imports("ole32.dll", "CoInitializeEx") and
                pe.imports("MSVCP140.dll", "?_Xout_of_range@std@@YAXPEBD@Z")
            ) or
            (
                pe.imports("KERNEL32.dll", "EnumSystemCodePagesW") and pe.imports("KERNEL32.dll", "VirtualAlloc") and
                pe.imports("bcrypt.dll", "BCryptGenRandom")
            ) or
            (
                (pe.imports("ole32.dll", "MkParseDisplayName") or pe.imports("ole32.dll", "CreateStreamOnHGlobal")) and
                pe.imports("GDI32.dll", "CreateCompatibleBitmap") and
                for any i in pe.import_details : (
                    i.library_name matches /^[A-Za-z0-9_+.-]+\.dll$/ and
                    not (i.library_name matches /^(KERNEL32|USER32|ADVAPI32|SHELL32|OLE32|GDI32|SHLWAPI|WINMM|WS2_32|BCRYPT|MSVCP140|VCRUNTIME140|VCRUNTIME140_1|COMCTL32|MSIMG32|D2D1|DWRITE|UXTHEME|DWMAPI|SHCORE|OLEAUT32|IMM32|API-MS-[A-Z0-9-]+)\.dll$/i)
                )
            )
        )
}
