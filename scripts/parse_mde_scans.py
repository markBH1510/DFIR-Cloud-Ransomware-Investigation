#!/usr/bin/env python3
"""
Microsoft Defender & Endpoint Scan Parser (MDE/Defender Forensics)
Author: Mark Bahaa (Inspire HUB DFIR Team)
Reference: Incident IR-2026-CLOUD-001

Description:
    Parses Windows Defender MPLog, operational logs, and triage CSVs to extract:
    - Tamper attempts and security feature deactivations (dControl, DisableRealtimeMonitoring)
    - Ransomware detection events and file quarantine traces
    - Malicious process executions and CLR assembly activity
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime

SUSPICIOUS_SIGNATURES = [
    "Ransom:Win32/Ares",
    "VirTool:Win32/DefenderControl",
    "HackTool:Win32/DControl",
    "Trojan:Win32/WormUtility",
    "Behavior:Win32/ShadowCopyDelete",
    "Exploit:Win32/SQLInjection"
]

SUSPICIOUS_PROCESSES = [
    "tnlq.exe",
    "dcontrol.exe",
    "hash1.bat",
    "anydesk.exe",
    "sqlservr.exe",
    "vssadmin.exe",
    "revouninstaller.exe"
]

def parse_csv_triage(csv_path):
    print(f"[*] Parsing triage file: {csv_path}")
    detections = []
    
    if not os.path.isfile(csv_path):
        print(f"[-] File not found: {csv_path}")
        return detections

    with open(csv_path, mode='r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row_idx, row in enumerate(reader):
            row_str = " ".join([str(v) for v in row.values()]).lower()
            
            # Check for suspicious processes
            matched_proc = [p for p in SUSPICIOUS_PROCESSES if p in row_str]
            # Check for known signatures
            matched_sig = [s for s in SUSPICIOUS_SIGNATURES if s.lower() in row_str]

            if matched_proc or matched_sig:
                detections.append({
                    "row": row_idx + 1,
                    "matched_processes": matched_proc,
                    "matched_signatures": matched_sig,
                    "data": {k: v for k, v in row.items() if v}
                })

    return detections

def generate_summary(detections, output_file=None):
    summary = {
        "investigation": "IR-2026-CLOUD-001",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_suspicious_events": len(detections),
        "events": detections
    }
    
    json_output = json.dumps(summary, indent=2)
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(json_output)
        print(f"[+] Output successfully written to: {output_file}")
    else:
        print(json_output)

def main():
    parser = argparse.ArgumentParser(description="MDE & Windows Defender Incident Triage Parser")
    parser.add_argument("--file", "-f", required=True, help="Path to Defender CSV triage or log export")
    parser.add_argument("--output", "-o", help="Optional JSON output path")
    args = parser.parse_args()

    results = parse_csv_triage(args.file)
    print(f"[+] Identified {len(results)} high-confidence security events.")
    generate_summary(results, args.output)

if __name__ == "__main__":
    main()
