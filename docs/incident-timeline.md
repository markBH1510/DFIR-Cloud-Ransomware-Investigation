# Comprehensive Forensic Incident Timeline

**Case Identifier:** IR-2026-CLOUD-001  
**Investigator:** Mark Bahaa (Lead DFIR Investigator, Inspire HUB)  
**Target Host:** `PROD-DB01.CORP.LOCAL` (`10.50.200.7`)  
**Threat Actor Source:** `198.51.100.133` (External Threat Node / AS60068, workstation hostname: `ATTACKER-NODE-01`)

---

## Chronological Attack Reconstruction (UTC vs. EEST)

| Phase | Timestamp (UTC) | Timestamp (EEST) | Observed Event / Forensic Artifact | MITRE ATT&CK |
|---|---|---|---|---|
| **Reconnaissance** | 13:54:12 | 16:54:12 | Inbound external port scanning against Azure Public IP (`20.50.100.15`). Ports probed: 1433 (TDS/MSSQL), 3389 (RDP), 443 (HTTPS). | T1595.001 |
| **Initial Access** | 13:54:45 | 16:54:45 | Perimeter Firewall Policy 28 matches inbound traffic from `198.51.100.133` -> VIP `10.50.20.4:1433`. Successful SQL authentication as `sa` after distributed dictionary brute-force. | T1110.001, T1190 |
| **Execution** | 13:56:02 | 16:56:02 | Threat actor enables `clr enabled` via `sp_configure`. Executes `CREATE ASSEMBLY` injecting unmanaged module `65538_CLR_module` (`db_0x2D09A3D6`). | T1059, T1546 |
| **Persistence** | 13:56:48 | 16:56:48 | CLR assembly initiates Windows API calls to spawn `cmd.exe /c net user Testings <REDACTED> /add` and adds account to `Administrators` and `Remote Desktop Users` groups (Event 4720 & 4732). | T1136.001, T1078 |
| **Lateral / Access** | 14:02:15 | 17:02:15 | Interactive RDP session established from `198.51.100.133` (Workstation `ATTACKER-NODE-01`) using account `Testings`. Shellbags reveal navigation through administrative utilities. | T1021.001 |
| **Defense Evasion** | 14:08:30 | 17:08:30 | Execution of `dControl.exe` (Defender Control) to disable Windows Defender real-time monitoring and Tamper Protection. Revo Uninstaller staged to purge secondary AV agents. | T1562.001 |
| **Inhibit Recovery** | 14:14:10 | 17:14:10 | Execution of batch script `Hash1.bat`: invokes `vssadmin.exe delete shadows /all /quiet`, `wbadmin delete catalog -quiet`, and `bcdedit` recovery disabling. | T1490 |
| **Command & Control**| 14:18:22 | 17:18:22 | AnyDesk remote administration utility staged and launched (`client ID: 1781172856`) to maintain redundant C2 channel. | T1219 |
| **Impact / Encryption**| 14:25:04 | 17:25:04 | Deployment and execution of Ares Ransomware binary (`tnlq.exe`). Encryption of enterprise databases (`.mdf`, `.ldf`), backups (`.bak`), and user documents. Drop of `DECRYPT_NOTE.txt`. | T1486 |
| **Spreading Sweep** | 14:31:50 | 17:31:50 | Threat actor stages `WormUtility.exe` to attempt automated SMB spreading across the spoke subnet (`10.50.200.0/24`). | T1046, T1021.002 |

---

## Forensic Evidence Confidence Summary

- **Total Forensically Verified Evidence Sources:** 159 extracted and parsed digital artifacts.
- **Root Cause Verified:** External firewall perimeter misconfiguration (Firewall Policy 28 with `srcaddr all` and `service ALL` mapped to VIP) exposing vulnerable database ports directly to public ingress.
- **Containment Status:** Isolated, revoked compromised credentials, neutralized persistence artifacts, and re-architected cloud network security group policies.
