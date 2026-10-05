#!/usr/bin/env python3
"""
Script Name: calculate_metrics.py
Description: Calculates security operational metrics (MTTD, alert volume, severity breakdown,
             MITRE ATT&CK coverage) generated during Attack vs Detection Lab execution.
Author: Senior Security & SOC Operations Engineer
"""

import json
import os
import sys
from datetime import datetime

# Consolidated Lab Data Matrix
LAB_DATA = {
    "hosts_monitored": [
        {"name": "lab-attacker", "ip": "192.168.56.10", "os": "Kali Linux Rolling", "role": "Attacker"},
        {"name": "lab-win11", "ip": "192.168.56.20", "os": "Windows 11 Enterprise", "role": "Victim 01 (Workstation)"},
        {"name": "lab-ubuntu", "ip": "192.168.56.30", "os": "Ubuntu Server 22.04 LTS", "role": "Victim 02 (Server)"},
        {"name": "lab-wazuh", "ip": "192.168.56.40", "os": "Ubuntu Server 22.04 LTS", "role": "SIEM / XDR Cluster"}
    ],
    "incidents": [
        {"id": "INC-001", "name": "Authentication Brute Force", "target": "lab-ubuntu", "technique": "T1110.001", "mttd_sec": 32, "severity": "High", "rule_id": "100001"},
        {"id": "INC-002", "name": "Suspicious PowerShell Execution", "target": "lab-win11", "technique": "T1059.001", "mttd_sec": 2, "severity": "High", "rule_id": "100010"},
        {"id": "INC-003", "name": "Account Creation & Promotion", "target": "lab-win11", "technique": "T1136.001", "mttd_sec": 15, "severity": "Critical", "rule_id": "100022"},
        {"id": "INC-004", "name": "Critical File Modification (FIM)", "target": "lab-ubuntu / win11", "technique": "T1565.001", "mttd_sec": 5, "severity": "High", "rule_id": "100030"},
        {"id": "INC-005", "name": "Suspicious System Discovery", "target": "lab-win11", "technique": "T1082", "mttd_sec": 8, "severity": "High", "rule_id": "100041"},
        {"id": "INC-006", "name": "Suspicious SSH Activity & Compromise", "target": "lab-ubuntu", "technique": "T1021.004", "mttd_sec": 1, "severity": "Critical", "rule_id": "100052"},
        {"id": "INC-007", "name": "Web Application Security Telemetry", "target": "lab-ubuntu:8080", "technique": "T1190", "mttd_sec": 10, "severity": "High", "rule_id": "100061"}
    ],
    "wazuh_rules_count": 14,
    "sigma_rules_count": 7,
    "mitre_techniques": [
        "T1110.001", "T1078.003", "T1059.001", "T1562.001", "T1136.001",
        "T1098", "T1565.001", "T1082", "T1087.001", "T1016", "T1049",
        "T1057", "T1021.004", "T1548.003", "T1595.002", "T1190"
    ]
}

def calculate_metrics():
    incidents = LAB_DATA["incidents"]
    total_incidents = len(incidents)
    total_mttd = sum(i["mttd_sec"] for i in incidents)
    avg_mttd = round(total_mttd / total_incidents, 1)

    # Severity distribution
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for i in incidents:
        sev = i["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("==================================================================")
    print("   ATTACK vs DETECTION LAB -- Security Metrics & KPI Dashboard   ")
    print("==================================================================")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("------------------------------------------------------------------")
    print(f"Total Hosts Monitored       : {len(LAB_DATA['hosts_monitored'])}")
    print(f"Incidents Detected & Proven : {total_incidents}")
    print(f"Custom Wazuh Rules Created  : {LAB_DATA['wazuh_rules_count']}")
    print(f"Portable Sigma Rules Created: {LAB_DATA['sigma_rules_count']}")
    print(f"MITRE ATT&CK Techniques     : {len(LAB_DATA['mitre_techniques'])}")
    print(f"Mean Time To Detect (MTTD)  : {avg_mttd} seconds")
    print("------------------------------------------------------------------")
    print("INCIDENT DETAILS & DETECTION LATENCY:")
    print(f"{'INCIDENT ID':<10} {'SCENARIO NAME':<34} {'SEVERITY':<10} {'MTTD':<8}")
    print(f"{'-----------':<10} {'-------------':<34} {'--------':<10} {'----':<8}")
    for i in incidents:
        print(f"{i['id']:<10} {i['name']:<34} {i['severity']:<10} {i['mttd_sec']:<2}s")

    print("\n------------------------------------------------------------------")
    print("ALERTS BY SEVERITY:")
    for sev, count in severity_counts.items():
        if count > 0:
            print(f"  - {sev:<10}: {count}")

    print("==================================================================\n")

if __name__ == "__main__":
    calculate_metrics()
