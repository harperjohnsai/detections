import "pe"

/*
  "Setup Center" DLL-sideload chain used by YouTube-lure campaigns that deliver REVSTEALER:
  a Microsoft-signed OneDrive client renamed Installer.exe, a malicious proxy version.dll
  and an encrypted payload container (localdata.db) that is not a real cabinet file.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule SetupCenter_ProxyVersionDll_Loader
{
    meta:
        description = "Unsigned x64 proxy version.dll that re-loads the real System32 version.dll, reads an encrypted payload file and carries VM-check registry strings"
        author = "Harper Johns"
        date = "2026-11-13"
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
        // 32-byte key = two .data arrays XORed: mov al,[rdx+r8+A]; xor al,[rdx+r8+B]; mov [rdx+rcx],al; inc rdx; cmp rdx,20h
        $keyxor = { 42 8A 84 02 ?? ?? ?? ?? 42 32 84 02 ?? ?? ?? ?? 88 04 0A 48 FF C2 48 83 FA 20 }
        // RC4 PRGA as compiled here: inc r10b; movzx r8d,r10b; mov dl,[rsp+r8]; add r11b,dl
        $rc4 = { 41 FE C2 45 0F B6 C2 42 8A 14 04 44 02 DA }
    condition:
        uint16(0) == 0x5A4D and pe.is_dll() and pe.machine == pe.MACHINE_AMD64
        and pe.exports("GetFileVersionInfoW") and pe.exports("VerQueryValueW")
        and pe.imports("kernel32.dll", "GetSystemDirectoryW") and pe.imports("kernel32.dll", "LoadLibraryW")
        and pe.number_of_signatures == 0
        and $sysver and 2 of ($vm*, $bios) and ($keyxor or $rc4)
}
