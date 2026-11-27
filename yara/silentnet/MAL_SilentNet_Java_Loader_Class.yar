rule MAL_SilentNet_Java_Loader_Class
{
    meta:
        description = "SilentNet infostealer Java loader (trojanised Minecraft Fabric mods and fake cheat clients): loader class whose constant pool carries the prefire check-in and getDomain resolver members (EtherHiding C2 lookup) next to the ProcessBuilder relaunch or the Fabric ModInitializer entry point. Matches extracted .class files, unpacked archive members and JVM memory, not the compressed JAR on disk"
        author = "Harper Johns"
        date = "2026-11-27"
        version = "1"
        reference = "https://www.malwation.com/blog/inside-silentnet-analysis-of-a-java-based-infostealer-with-blockchain-based-c2"
        reference_2 = "https://jarscanner.github.io/silentnet.html"
        reference_3 = "https://github.com/harperjohnsai/detections/tree/main/yara/silentnet"
        malware_family = "SilentNet"
        malware_type = "Infostealer loader"
        hash_sha256_1 = "058458f1cc63a64159ca8b3384cd8b83969a3879bf3466021e1de15de0d9fc71"
        hash_sha256_2 = "659fada1cbf0ed66a13bbf11bfc2d7153f10c15c7753c3c9c3579762999cf232"
        hash_sha256_3 = "7564375fc4de22673fabf0708a47f06a514fc2a430fd6c6b8f78af2e8b98d262"
        score = 75
        license = "Detection Rule License (DRL) 1.1"
        note = "Class and member names are randomised per build; the rule keys on member names the loader keeps (constant-pool UTF8 entries with their length prefix) and on platform API references. Scan JAR members after extraction (YARAify-style archive unpacking)."

    strings:
        // constant-pool UTF8 entries: tag 0x01, big-endian length, bytes
        $cp_prefire   = { 01 00 07 70 72 65 66 69 72 65 }                    // "prefire"
        $cp_getdomain = { 01 00 09 67 65 74 44 6F 6D 61 69 6E }              // "getDomain"
        $cp_prefireid = "\"prefireId\":\"" ascii                            // early builds: JSON context template in clear text
        $api_redirect = "java/lang/ProcessBuilder$Redirect" ascii
        $api_modinit  = "net/fabricmc/api/ModInitializer" ascii
        $api_trust    = "javax/net/ssl/X509TrustManager" ascii
        $api_codesrc  = "getProtectionDomain" ascii

    condition:
        uint32be(0) == 0xCAFEBABE
        and filesize < 2MB
        and (
            ( $cp_prefire and $cp_getdomain and 1 of ($api_*) )
            or ( $cp_prefireid and $cp_getdomain )
        )
}
