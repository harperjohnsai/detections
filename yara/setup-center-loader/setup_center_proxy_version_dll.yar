import "pe"

/*
  "Setup Center" DLL-sideload chain used by REVSTEALER campaigns:
  a Microsoft-signed OneDrive client renamed Installer.exe, a malicious proxy version.dll
  and an encrypted payload container (localdata.db, sync.dat or config.dat depending on the build)
  that starts with "MSCF" but is not a real cabinet file.

  Matches the proxy version.dll of builds 25, 26 and 27. The loader is rebuilt for every build
  (different compiler output, payload name XOR-obscured from build 26 on, RC4 inlined in build 25),
  so the rule keys on what stays constant: the forwarded version.dll exports, the extra imports a
  real version.dll never has, the VM-check registry strings, the layout of the hollowing API table
  (module index + name length per entry; the names themselves are XOR-encrypted with a per-build key)
  and, as alternatives, the key-derivation / RC4 code of each compiler variant.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule SetupCenter_ProxyVersionDll_Loader
{
    meta:
        description = "Unsigned x64 proxy version.dll (REVSTEALER Setup Center builds 25-27) that re-loads the real System32 version.dll, reads an RC4-encrypted payload file and carries VM-check registry strings"
        author = "Harper Johns"
        date = "2026-11-13"
        modified = "2026-11-13"
        version = 2
        reference = "https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer"
        sample = "b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960"
        mitre_attack = "T1574.001, T1055.012"
        yarahub_uuid = "71c49906-d357-4906-bcb3-75911b28afd6"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "51061df0511cc9d758230ba75f3954b4"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        $sysver = "\\version.dll" wide
        $vm1 = "SOFTWARE\\VMware, Inc.\\VMware Tools" ascii
        $vm2 = "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters" ascii
        $bios = "HARDWARE\\DESCRIPTION\\System\\BIOS" ascii
        $sysman = "SystemManufacturer" ascii

        // Hollowing API table in .rdata, 24-byte entries {module index (8), name VA (8), name length (4+4)}.
        // First 8 entries: CreateProcessW, NtWriteVirtualMemory, NtAllocateVirtualMemory, NtReadVirtualMemory,
        // TerminateProcess, NtGetContextThread, NtSetContextThread, NtResumeThread. The names are XOR-encrypted
        // (key differs per build) but lengths and module indices are the same in builds 25, 26 and 27.
        $apitab = { 00 00 00 00 00 00 00 00 ?? ?? ?? 80 01 00 00 00 0E 00 00 00 00 00 00 00
                    01 00 00 00 00 00 00 00 ?? ?? ?? 80 01 00 00 00 14 00 00 00 00 00 00 00
                    01 00 00 00 00 00 00 00 ?? ?? ?? 80 01 00 00 00 17 00 00 00 00 00 00 00
                    01 00 00 00 00 00 00 00 ?? ?? ?? 80 01 00 00 00 13 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 ?? ?? ?? 80 01 00 00 00 10 00 00 00 00 00 00 00
                    01 00 00 00 00 00 00 00 ?? ?? ?? 80 01 00 00 00 12 00 00 00 00 00 00 00
                    01 00 00 00 00 00 00 00 ?? ?? ?? 80 01 00 00 00 12 00 00 00 00 00 00 00
                    01 00 00 00 00 00 00 00 ?? ?? ?? 80 01 00 00 00 0E 00 00 00 00 00 00 00 }

        // 32-byte RC4 key = two .data arrays XORed. Builds 26/27: scalar loop, key array offsets vary
        $kx_a = { 42 8A 84 02 ?? ?? ?? ?? 42 32 84 02 ?? ?? ?? ?? 88 04 0A 48 FF C2 48 83 FA 20 }
        // build 25: helper with a scalar tail loop ...
        $kx_b = { 42 0F B6 0C 08 42 32 0C 10 42 88 0C 00 48 FF C0 48 83 F8 20 }
        // ... and an SSE main loop (movdqu / pxor / movdqu, 16 bytes per round)
        $kx_c = { F3 42 0F 6F 0C 0A F3 42 0F 6F 04 12 66 0F EF C8 F3 42 0F 7F 0C 02 48 83 C2 10 48 83 FA 20 }

        // RC4 as compiled in builds 26/27 (separate routine, key length in a register): PRGA head ...
        $rc4_a = { 41 FE C2 45 0F B6 C2 42 8A 14 04 44 02 DA }
        // ... and as inlined in build 25: 32-byte key (index and 1Fh), then PRGA head
        $rc4_b1 = { 83 E1 1F 41 FF C0 02 44 0C 60 }
        $rc4_b2 = { 41 FE C1 48 8D 94 24 ?? ?? ?? ?? 41 0F B6 C1 48 8D 8C 24 ?? ?? ?? ?? 48 03 D0 }
    condition:
        uint16(0) == 0x5A4D and filesize < 1MB
        and pe.is_dll() and pe.machine == pe.MACHINE_AMD64
        and pe.exports("GetFileVersionInfoW") and pe.exports("VerQueryValueW")
        and pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size == 0  // unsigned; portable (no OpenSSL-dependent field)
        // never in a real version.dll: loader + environment-check imports
        and pe.imports("kernel32.dll", "GetSystemDirectoryW") and pe.imports("kernel32.dll", "LoadLibraryW")
        and pe.imports("kernel32.dll", "GlobalMemoryStatusEx") and pe.imports("user32.dll", "EnumDisplayDevicesA")
        and pe.imports("advapi32.dll", "RegQueryValueExA")
        and $sysver and $sysman and 2 of ($vm*, $bios)
        and ( $apitab or any of ($kx_*) or ($rc4_a or ($rc4_b1 and $rc4_b2)) )
}
