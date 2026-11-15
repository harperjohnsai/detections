/*
  "Setup Center" proxy version.dll loader (REVSTEALER campaigns): anti-VM / anti-sandbox gate.
  The loader checks the user and computer name, the display adapter string and the BIOS / system
  vendor strings against lists that are stored only as 32-bit hashes (FNV-1a, prime 0x01000193,
  custom offset basis 0x7c4e9f2b, plus an extra "x ^= x >> 16" per byte, input lower-cased).
  The tables are identical in builds 25, 26 and 27, so the rule keys on the basis constant, the
  hash-mix instruction pattern and the little-endian hash tables themselves.
  Companion to SetupCenter_ProxyVersionDll_Loader (different anchors: this one survives a
  recompile as long as the blocklists are unchanged).

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule SetupCenter_Loader_AntiVM_HashTables
{
    meta:
        author = "Harper Johns"
        description = "Setup Center version.dll sideload loader: anti-VM name/GPU/BIOS lists stored as FNV-1a(prime 0x01000193, basis 0x7c4e9f2b, xorshift16) hashes"
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-revstealer-setup-center"
        date = "2026-11-14"
        modified = "2026-11-15"
        sample = "b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960"
        mitre_attack = "T1497.001"
        yarahub_uuid = "08bd3b46-34eb-46ed-ab31-6f8ab3a4d1e8"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "51061df0511cc9d758230ba75f3954b4"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        $seed = { 41 BA 2B 9F 4E 7C }                 // mov r10d, 0x7c4e9f2b (custom offset basis)
        $mix  = { 69 ?? 93 01 00 01 [2-4] C1 E? 10 }  // imul r32, r32, 0x01000193 ; ... ; shr r32, 16
        $t_gpu_vm = { 71 B9 91 B6 7E 17 22 A7 4B 04 7B D5 }        // virtual, vmware, virtualbox
        $t_gpu_ok = { CE 6F 11 95 5F 7B 43 CF 1D 29 8A AB }        // nvidia, amd, radeon
        $t_names  = { 1F CC 73 AC 92 12 B8 DB DB 5E 50 83 }        // john, emily, hugo (exact)
        $t_sub    = { EF F9 EA 95 07 ?? ?? ?? 7C CD 60 4A 05 }     // sandbox(7), virus(5)
        $t_bios   = { 17 9E 1A 1B 04 ?? ?? ?? 6E 6E 46 56 03 }     // qemu(4), xen(3)
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        ( ($seed and $mix and 1 of ($t_*)) or 3 of ($t_*) )
}
