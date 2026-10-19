/*
    YARA Rule: Ares Ransomware (tnlq.exe variant)
    Author: Mark Bahaa (Inspire HUB DFIR Team)
    Date: 2026-10-15
    Incident Reference: IR-2026-CLOUD-001
    Description: Detects Ares ransomware binary observed during cloud-hosted SQL server compromise.
    Reference: MITRE ATT&CK T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)
*/

rule Win_Ransomware_Ares_TNLQ {
    meta:
        author = "Mark Bahaa - Lead DFIR Investigator"
        organization = "Inspire HUB"
        description = "Detects Ares ransomware compiled binary (tnlq.exe) and related encryption routines"
        date = "2026-10-15"
        version = "1.0"
        threat_actor = "UNC-FinTarget"
        malware_family = "Ares"
        hash_sha256 = "c4fe220b9a8f27643b679a78bb15c71a39d89230554b79116e1e839e26e792e3"

    strings:
        // Encryption & Note Artifacts
        $note1 = "DECRYPT_NOTE.txt" ascii wide nocase
        $note2 = "YOUR FILES ARE ENCRYPTED" ascii wide nocase
        $note3 = "Ares Ransomware" ascii wide nocase
        $note4 = "support_decrypt@protonmail.com" ascii wide nocase

        // Shadow Copy & Recovery Inhibition Strings
        $cmd1 = "vssadmin.exe delete shadows /all /quiet" ascii wide nocase
        $cmd2 = "wbadmin delete catalog -quiet" ascii wide nocase
        $cmd3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $cmd4 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase

        // Cryptographic API Imports & Constants
        $crypto1 = "CryptGenRandom" ascii
        $crypto2 = "CryptAcquireContextW" ascii
        $crypto3 = "CryptEncrypt" ascii
        $crypto4 = "CryptImportKey" ascii

        // Targeted Extension Suppression
        $ext1 = ".mdf" ascii wide nocase
        $ext2 = ".ldf" ascii wide nocase
        $ext3 = ".bak" ascii wide nocase
        $ext4 = ".docx" ascii wide nocase
        $ext5 = ".xlsx" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and // PE header MZ
        filesize < 15MB and
        (
            (2 of ($note*)) or
            (2 of ($cmd*)) or
            (3 of ($crypto*) and 3 of ($ext*))
        )
}
