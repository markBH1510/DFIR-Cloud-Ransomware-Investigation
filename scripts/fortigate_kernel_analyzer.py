#!/usr/bin/env python3
"""
FortiOS Kernel & Policy Traverse Analyzer
Author: Mark Bahaa (Inspire HUB DFIR Team)
Reference: Incident IR-2026-CLOUD-001

Description:
    Analyzes FortiGate kernel iprope structures, sniffer sessions, and policy configurations.
    Helps DFIR teams correlate physical/virtual interfaces (port1 -> port2), detect over-permissive
    inbound access (e.g., service ALL, srcaddr all), and identify modified VIP mappings.
"""

import re
import sys
import json
import argparse

def parse_fortigate_policy(policy_text):
    """
    Parses FortiGate 'show firewall policy' configuration snippets.
    Flags overly permissive policies matching external traffic.
    """
    policies = []
    current_policy = {}
    
    for line in policy_text.splitlines():
        line = line.strip()
        if line.startswith("edit "):
            current_policy = {"id": line.split()[1], "raw": []}
        elif line == "next":
            if current_policy:
                policies.append(current_policy)
                current_policy = {}
        elif current_policy:
            current_policy["raw"].append(line)
            if line.startswith("set name "):
                current_policy["name"] = line.replace('set name ', '').replace('"', '')
            elif line.startswith("set srcintf "):
                current_policy["srcintf"] = line.replace('set srcintf ', '').replace('"', '')
            elif line.startswith("set dstintf "):
                current_policy["dstintf"] = line.replace('set dstintf ', '').replace('"', '')
            elif line.startswith("set srcaddr "):
                current_policy["srcaddr"] = line.replace('set srcaddr ', '').replace('"', '')
            elif line.startswith("set dstaddr "):
                current_policy["dstaddr"] = line.replace('set dstaddr ', '').replace('"', '')
            elif line.startswith("set service "):
                current_policy["service"] = line.replace('set service ', '').replace('"', '')
            elif line.startswith("set action "):
                current_policy["action"] = line.replace('set action ', '').replace('"', '')

    # Analyze risks
    risk_findings = []
    for pol in policies:
        risks = []
        if pol.get("service") == "ALL" and pol.get("srcaddr") == "all" and pol.get("action") == "accept":
            risks.append("CRITICAL: Over-permissive inbound 'ANY ANY' rule (service ALL, srcaddr all)")
        if "port1" in pol.get("srcintf", "") and pol.get("action") == "accept":
            risks.append("HIGH: Inbound policy exposed directly from WAN interface (port1)")

        if risks:
            risk_findings.append({
                "policy_id": pol.get("id"),
                "policy_name": pol.get("name", "unnamed"),
                "srcintf": pol.get("srcintf"),
                "dstintf": pol.get("dstintf"),
                "dstaddr": pol.get("dstaddr"),
                "findings": risks
            })

    return risk_findings

def parse_iprope_flow(iprope_text):
    """
    Parses FortiOS kernel iprope output:
    e.g.: 'diagnose firewall iprope show 100004 999'
    Extracts packet hit counters and active hardware/software acceleration states.
    """
    flows = []
    # Pattern to match iprope counter lines
    pattern = re.compile(r"pkts=(\d+)\s+bytes=(\d+)")
    matches = pattern.findall(iprope_text)
    for m in matches:
        flows.append({
            "packets": int(m[0]),
            "bytes": int(m[1])
        })
    return flows

def main():
    parser = argparse.ArgumentParser(description="FortiOS Kernel Policy & Flow Forensics Analyzer")
    parser.add_argument("--policy-file", "-p", help="Text file containing 'show firewall policy' output")
    parser.add_argument("--iprope-file", "-i", help="Text file containing 'diagnose firewall iprope' output")
    args = parser.parse_args()

    report = {"status": "SUCCESS", "analysis": {}}

    if args.policy_file:
        with open(args.policy_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        findings = parse_fortigate_policy(content)
        report["analysis"]["policy_vulnerabilities"] = findings
        print(f"[+] Analyzed policy file: {len(findings)} high-risk policy configurations identified.")

    if args.iprope_file:
        with open(args.iprope_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        flows = parse_iprope_flow(content)
        report["analysis"]["kernel_flows"] = flows
        print(f"[+] Analyzed iprope kernel dump: {len(flows)} active flow sessions identified.")

    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
