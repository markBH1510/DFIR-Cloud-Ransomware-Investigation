/*
    YARA Rule: Defender Control (dControl.exe) & AV Disabler
    Author: Mark Bahaa (Inspire HUB DFIR Team)
    Date: 2026-10-15
    Incident Reference: IR-2026-CLOUD-001
    Description: Detects Defender Control (dControl) utility used by threat actors to disable Windows Defender and tamper with AV engines.
    Reference: MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools)
*/

rule HackTool_Win_dControl_ImpairDefenses {
    meta:
        author = "Mark Bahaa - Lead DFIR Investigator"
        organization = "Inspire HUB"
        description = "Detects dControl.exe utility used to suppress Defender and tamper with security agents"
        date = "2026-10-15"
        version = "1.0"
        malware_category = "HackTool / Defense Evasion"

    strings:
        $s1 = "Defender Control" wide ascii nocase
        $s2 = "sordum.org" wide ascii nocase
        $s3 = "DisableAntiSpyware" wide ascii
        $s4 = "DisableRealtimeMonitoring" wide ascii
        $s5 = "DisableBehaviorMonitoring" wide ascii
        $s6 = "DisableOnAccessProtection" wide ascii
        $s7 = "DisableScanOnRealtimeEnable" wide ascii
        $reg_path = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" wide ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $s1 or $s2 or
            ($reg_path and 3 of ($s3, $s4, $s5, $s6, $s7))
        )
}
