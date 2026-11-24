/*
  PowerShell stage with int64-array character decoding, ROMULUS ClickFix chain.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule MAL_ROMULUS_PS_IntArray_CharOffset_Stager
{
    meta:
        description = "PowerShell stage of the ROMULUS ClickFix chain (irm from a decimal-IP URL, MSI custom-action dropper): every API/type name is an int64 array decoded in a loop 'for(..){$s+=[char]([int64]$a[$i]+N)}' (N differs per string), followed by reflection (psobject.Assembly.GetType / DefineDynamicAssembly + DefinePInvokeMethod VirtualAlloc/VirtualProtect/CreateThread) or the MSIc31bd05a environment-variable handoff."
        author = "Harper Johns"
        date = "2026-11-24"
        hash = "7eb0d8e8f74b298885fa0ec0a0ee1e87b03e27fbff5fe41ae99edacfaac2d1a3"
        family = "ROMULUS"
        score = 70
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
        yarahub_uuid = "e43d704e-0dcf-4c1c-8e5d-b44fc97513ed"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "bfe4df50d25820185868df0ce873e183"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
    strings:
        $dec = /\+=\[char\]\(\[int64\]\$[A-Za-z0-9_]{3,30}\[\$[A-Za-z0-9_]{2,30}\]\+[0-9]{4,9}\)/
        $r1 = "[psobject].Assembly.GetType(" ascii
        $r2 = "DefineDynamicAssembly(" ascii
        $r3 = "DefineImportFunc" ascii
        $r4 = "[UIntPtr]::new([uint64]" ascii
        $e1 = "MSIc31bd05a" ascii
        $e2 = "$ErrorActionPreference='Stop'" ascii
        $e3 = "[Environment]::$" ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and #dec >= 3 and
        (($r1 and ($r2 or $r3 or $r4)) or ($e1 and $e2) or ($e2 and $e3))
}
