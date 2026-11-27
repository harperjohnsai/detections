rule MAL_EasyShell_Rust_Implant_ConfigSlots_AnyOS
{
    meta:
        description = "EasyShell red-team C2 framework Rust client (all listener transports: HTTP beacon, TCP, KCP, WebSocket, DNS, DoH, OSS, forward relays) for Windows, Linux and macOS: fixed-width !ES/<n>/<TAG>/ builder slots that the server patcher needs, plus framework markers in clear text and XOR 0x5A"
        author = "Harper Johns"
        date = "2026-11-27"
        version = "1"
        reference = "https://blog.malwaremustdie.org/2026/11/mmd-073-2026-linuxeasyshell-new-rust.html"
        reference_2 = "https://github.com/harperjohnsai/detections/tree/main/yara/easyshell"
        malware_family = "EasyShell"
        malware_type = "RAT / red-team implant (dual use)"
        os = "windows, linux, macos"
        hash_sha256_1 = "248b0fd54187153e49814aed72b03e52e7378d3af69f2e4e4e99d4abd2ef1f55"
        hash_sha256_2 = "4e73ec83c31dc4edbdb14e5c725ead561802c4a2e98536ba105ed0ab180fb7f2"
        hash_sha256_3 = "089ba7924720ebe38af4566e194c903610d183d3766fe0b3c847c1fdac3bafe9"
        score = 80
        license = "Detection Rule License (DRL) 1.1"
        note = "Builds made after 2026-11-21 lack the crate path easyshell-http-beacon-implant; this rule does not use it. Windows coverage is verified on the framework's own prebuilt templates only (no Windows client seen in the wild yet)."

    strings:
        // builder slots present in every client template and every patched build we hold (111/111)
        $slot1 = "!ES/1/PASS/" ascii
        $slot2 = "!ES/5/PROXY/" ascii
        $slot3 = "!ES/7/SBOX/" ascii
        $slot4 = "!ES/10/WAIT/" ascii
        $slot5 = "!ES/11/JITR/" ascii
        // transport/config slots present in subsets (template defaults)
        $slot6 = "!ES/0/HOST/" ascii
        $slot7 = "!ES/2/PKEY/" ascii
        $slot8 = "!ES/6/ENTR/" ascii
        $slot9 = "!ES/15/DNSP/" ascii
        // framework markers in clear text
        $m1 = "ESCH chunk:" ascii
        $m2 = "ES_SHELL_BATCH_MS" ascii
        $m3 = "redeploy latest listener payload" ascii
        $m4 = "es-mux-agg" ascii
        $m5 = "es-idle-reaper" ascii
        // single-byte XOR 0x5A string pool
        $x1 = "es-hop-wire-v1" xor(0x5a)
        $x2 = "folder zip prepare failed" xor(0x5a)

    condition:
        ( uint16(0) == 0x5a4d or uint32(0) == 0x464c457f or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xbebafeca )
        and filesize < 64MB
        and 4 of ($slot1, $slot2, $slot3, $slot4, $slot5)
        and ( 2 of ($m*) or 1 of ($x*) or 2 of ($slot6, $slot7, $slot8, $slot9) )
}
