# Attack vs Detection Lab

> **A realistic, fully isolated offensive and defensive cybersecurity laboratory for security engineering, telemetry collection, threat detection, SIEM correlation, and incident response.**

[![Platform](https://img.shields.io/badge/Platform-VirtualBox%20%7C%20Linux%20%7C%20Windows-blue.svg)](#lab-environment)
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.x-orange.svg)](#technologies)
[![Telemetry](https://img.shields.io/badge/Telemetry-Sysmon%20%7C%20Windows%20Events%20%7C%20Auditd-green.svg)](#technologies)
[![Rules](https://img.shields.io/badge/Detections-Custom%20Wazuh%20%26%20Sigma-red.svg)](#detection-rules)
[![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-16%20Techniques-lightgrey.svg)](#mitre-attck-coverage)
[![MTTD](https://img.shields.io/badge/Avg%20MTTD-10.4s-success.svg)](#metrics)

---

## Overview

The **Attack vs Detection Lab** is an end-to-end security operations and detection engineering environment designed to bridge the gap between offensive simulations and defensive response. The lab models a realistic enterprise network where controlled adversary techniques are executed against target virtual machines, collected via host and system-level telemetry, analyzed through a centralized SIEM (Wazuh), detected via custom correlation and Sigma rules, and resolved through structured incident response workflows.

Every scenario follows a closed-loop engineering cycle:

```text
[ Adversary Action ] 
        │
        ▼
[ Endpoint Telemetry Generated ] (Sysmon / Auditd / Auth Logs)
        │
        ▼
[ Ingestion & Normalization ] (Wazuh Agent / Log Collector)
        │
        ▼
[ SIEM Analysis & Engine Evaluation ] (Decoders & Custom Rules)
        │
        ▼
[ Security Alert Generated ] (Wazuh Dashboard / SOC Triage)
        │
        ▼
[ SOC Investigation & Timeline Analysis ]
        │
        ▼
[ MITRE ATT&CK Mapping & Threat Attribution ]
        │
        ▼
[ Containment & Defensive Hardening ]
        │
        ▼
[ Re-testing & Validation ] (Before vs. After Verification)
```

---

## Why I Built This

Many security candidates and practitioners encounter detection concepts purely in theory or via pre-packaged CTF challenges. This project was built to address the operational realities of defensive security:

1. **Understanding Ground Truth Telemetry**: Seeing exactly what raw logs look like when an attacker runs enumeration commands, password sprays, or privilege escalation tools.
2. **Detection Engineering from Scratch**: Crafting high-fidelity detection logic (Wazuh XML and vendor-neutral Sigma rules) that catch malicious intent while actively mitigating false positives.
3. **End-to-End SOC Analyst Workflow**: Documenting real investigations with strict timelines, indicators of compromise (IOCs), root cause analyses, and defensible triage decisions.
4. **DevSecOps & Hardening Feedback Loop**: Measuring how operating system hardening, rate limiting, and permission tightening degrade or eliminate adversary attack paths.

---

## What This Project Demonstrates

This repository provides tangible evidence of competencies required for **SOC Analyst (Tier 1/2)**, **Detection Engineer**, **Blue Team Analyst**, and **Security Engineer** roles:

- **Network Architecture & Safe Isolation**: Implementing strictly segmented Host-Only networks (`192.168.56.0/24`) to safely simulate attacks without risk of external leakage.
- **Enterprise Telemetry Engineering**: Deploying and tuning Microsoft Sysmon on Windows 11, configuring Linux `auditd`, `auth.log`, and `systemd-journald`.
- **SIEM Operations & Architecture**: Deploying, configuring, and maintaining Wazuh Indexer, Server, and Dashboard; managing agent enrollment and secure TLS communication.
- **Custom Rule Development**: Writing custom XML rules in Wazuh using frequency thresholds, parent-child process relationships, and multi-event correlations.
- **Generic Detection Rules (Sigma)**: Authoring portable, standard Sigma rules ready for translation to multiple SIEM platforms (Splunk, Elastic, Sentinel).
- **Adversary Emulation & MITRE Mapping**: Executing non-destructive adversary techniques mapped directly to 16 official MITRE ATT&CK Enterprise techniques.
- **Incident Response & Investigation**: Publishing 7 standardized Incident Reports (INC-001 through INC-007) answering the 8 core SOC questions, covering timeline, indicators, containment, and lessons learned.
- **Application Security & DevSecOps**: Integrating structured JSON security audit logging from a Spring Boot web API directly into the SIEM pipeline.
- **Security Hardening**: Applying targeted defensive controls and documenting measurable "Before vs. After" telemetry changes.

---

## Example Detection Workflow

Every attack simulation follows this validated operational chain:

```text
Kali Linux (192.168.56.10)
      │
      │ 1. Executes controlled attack simulation (e.g., T1110 Brute Force)
      ▼
Target Endpoint (192.168.56.20 / 30)
      │
      │ 2. Operating system generates raw events (Win Event ID 4625 / Linux pam_unix failure)
      │ 3. Sysmon / Auditd captures execution context, parent PID, command line
      ▼
Wazuh Agent
      │
      │ 4. Transmits event payload via encrypted TLS tunnel (Port 1514/TCP)
      ▼
Wazuh Manager (192.168.56.40)
      │
      │ 5. Event passes through pre-decoders and decoders (e.g., win_eventchannel)
      │ 6. Rules engine evaluates custom rule (e.g., Rule 100001: 10 failures in 60s)
      │ 7. Level 10+ Security Alert generated and indexed
      ▼
Wazuh Dashboard
      │
      │ 8. Real-time alert surfaces on SOC Dashboard
      ▼
SOC Analyst Investigation
      │
      │ 9. Incident Report generated (timeline, IP pivot, user impact, false-positive review)
      │ 10. Mapped to MITRE ATT&CK (T1110.001)
      ▼
Containment & Hardening
      │
      │ 11. Remediation applied (Account lockout policy / Fail2Ban / IP restriction)
      │ 12. Simulation re-run to verify zero alert leakage
```

---

## Architecture

The lab operates on a fully isolated virtual subnet (`192.168.56.0/24`) hosted on Oracle VirtualBox, ensuring zero external exposure during simulations.

```text
                                  ATTACK vs DETECTION LAB
                                    Subnet: 192.168.56.0/24

                                       ┌─────────────────┐
                                       │   Kali Linux    │
                                       │    Attacker     │
                                       │  192.168.56.10  │
                                       └────────┬────────┘
                                                │
                                    Host-Only Virtual Network
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     │                                                     │
                     ▼                                                     ▼
          ┌─────────────────────┐                               ┌─────────────────────┐
          │     Windows 11      │                               │    Ubuntu Server    │
          │     Victim 01       │                               │      Victim 02      │
          │    192.168.56.20    │                               │    192.168.56.30    │
          │                     │                               │                     │
          │  • Sysmon           │                               │  • Linux Auditd     │
          │  • Windows Security │                               │  • auth.log / SSH   │
          │  • Wazuh Agent      │                               │  • Wazuh Agent      │
          └──────────┬──────────┘                               └──────────┬──────────┘
                     │                                                     │
                     │ Port 1514/TCP (Agent Event Ingestion)               │ Port 1514/TCP
                     │ Port 1515/TCP (Agent Registration)                  │
                     └──────────────────────────┬──────────────────────────┘
                                                │
                                                ▼
                                   ┌─────────────────────────┐
                                   │      Wazuh Server       │
                                   │       SIEM / XDR        │
                                   │      192.168.56.40      │
                                   │                         │
                                   │  • Wazuh Manager        │
                                   │  • Wazuh Indexer        │
                                   │  • Custom Rules Engine  │
                                   │  • Wazuh Dashboard (443)│
                                   └────────────┬────────────┘
                                                │
                                                ▼
                                   ┌─────────────────────────┐
                                   │       SOC Analyst       │
                                   │     Host Workstation    │
                                   │      192.168.56.1       │
                                   │  Browser: https://:443  │
                                   └─────────────────────────┘
```

For complete technical specifications, review [architecture/architecture.md](architecture/architecture.md) and [architecture/network-diagram.md](architecture/network-diagram.md).

---

## Technologies

| Category | Technology | Version / Spec | Purpose |
| :--- | :--- | :--- | :--- |
| **Hypervisor** | Oracle VirtualBox | 7.x | Local virtualization with isolated Host-Only networking |
| **SIEM / XDR** | Wazuh All-in-One | 4.x | Event ingestion, log decoding, correlation, and alerting |
| **Attacker OS** | Kali Linux | Rolling | Adversary simulation and testing tools (Hydra, cURL, etc.) |
| **Windows Endpoint** | Windows 11 Enterprise Eval | 22H2 / 23H2 | Victim 1: Enterprise desktop target with advanced telemetry |
| **Linux Endpoint** | Ubuntu Server | 22.04 LTS | Victim 2: Linux server target, SSH daemon, web services |
| **Endpoint Telemetry** | Microsoft Sysmon | v15+ (Schema 4.90) | Deep Windows process, network, and registry monitoring |
| **Linux Telemetry** | Auditd & OpenSSH Verbose | Native | Linux kernel system calls, execution, and auth tracking |
| **Web Technology** | Spring Boot / Java 17 | 3.2.x | Application security logging emitting structured JSON |
| **Detection Formats** | Wazuh Rules / Sigma | XML / YAML | Custom vendor rules & vendor-neutral Sigma definitions |
| **Frameworks** | MITRE ATT&CK | v14+ | Standardized adversary tactic and technique classification |
| **Automation** | Python 3, PowerShell, Bash | Modern | Network validation, log parsing, metric calculation |

---

## Lab Environment

### Host Machine Specifications (Verified)
- **CPU**: Intel Core i5-12400F (6 Cores / 12 Threads)
- **RAM**: 32 GB DDR4
- **Host OS**: Windows 11 64-bit

### Virtual Machine Allocation Matrix

| Node Name | Role | OS | IP Address | vCPU | RAM | Disk | Network Adapter |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `lab-attacker` | Attacker | Kali Linux | `192.168.56.10` | 2 | 3 GB | 30 GB | Host-Only (`vboxnet0`) |
| `lab-win11` | Victim 01 | Windows 11 Ent | `192.168.56.20` | 2 | 6 GB | 60 GB | Host-Only (`vboxnet0`) |
| `lab-ubuntu` | Victim 02 | Ubuntu Server 22.04 | `192.168.56.30` | 2 | 3 GB | 30 GB | Host-Only (`vboxnet0`) |
| `lab-wazuh` | SIEM Server | Ubuntu Server 22.04 | `192.168.56.40` | 4 | 8 GB | 50 GB | Host-Only (`vboxnet0`) |
| **Host Adapter** | SOC Browser | Windows (Host) | `192.168.56.1` | - | - | - | VirtualBox Host-Only Adapter |

---

## Attack Scenarios & Incident Reports

| Scenario ID | Name | Target | MITRE Technique | Primary Rule | MTTD | Report Link |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| **INC-001** | Authentication Brute Force | Linux (`.30`) | `T1110.001` | Wazuh Rule `100001` | 32s | [INC-001-brute-force.md](incidents/INC-001-brute-force.md) |
| **INC-002** | Suspicious PowerShell Execution | Windows (`.20`) | `T1059.001` | Wazuh Rule `100010` | 2s | [INC-002-powershell.md](incidents/INC-002-powershell.md) |
| **INC-003** | Account Creation & Elevation | Windows (`.20`) | `T1136.001` / `T1098` | Wazuh Rule `100022` | 15s | [INC-003-account-creation.md](incidents/INC-003-account-creation.md) |
| **INC-004** | Critical File Modification (FIM)| Linux / Windows | `T1565.001` | Wazuh Rule `100030` | 5s | [INC-004-file-integrity.md](incidents/INC-004-file-integrity.md) |
| **INC-005** | Suspicious Discovery Burst | Windows (`.20`) | `T1082` / `T1087.001` | Wazuh Rule `100041` | 8s | [INC-005-discovery.md](incidents/INC-005-discovery.md) |
| **INC-006** | SSH Spray & Compromise | Linux (`.30`) | `T1021.004` / `T1078` | Wazuh Rule `100052` | 1s | [INC-006-ssh-activity.md](incidents/INC-006-ssh-activity.md) |
| **INC-007** | Web App Login Spray & Probing | Linux Web (`:8080`) | `T1110.001` / `T1190` | Wazuh Rule `100061` | 10s | [INC-007-web-application.md](incidents/INC-007-web-application.md) |

---

## MITRE ATT&CK Coverage

The lab explicitly maps every simulation to the official MITRE ATT&CK Enterprise Matrix:

| Tactic | Technique ID | Technique Name | Lab Incident | Telemetry Source |
| :--- | :--- | :--- | :--- | :--- |
| **Credential Access** | `T1110.001` | Password Guessing / Brute Force | `INC-001`, `INC-006`, `INC-007` | Win Event 4625 / `auth.log` / JSON |
| **Execution** | `T1059.001` | Command and Scripting: PowerShell | `INC-002` | Sysmon EID 1 & PowerShell EID 4104 |
| **Persistence** | `T1136.001` | Create Account: Local Account | `INC-003` | Windows Security Event 4720 |
| **Privilege Escalation** | `T1098` | Account Manipulation | `INC-003` | Windows Security Event 4732 |
| **Privilege Escalation** | `T1548.003` | Sudo and Sudo Caching | `INC-006` | Linux `auth.log` (`sudo:` entries) |
| **Defense Evasion** | `T1562.001` | Impair Defenses: Disable Tools | Hardening tests | Command Execution & Sysmon EID 1 |
| **Defense Evasion** | `T1027` | Obfuscated Files or Information | `INC-002` | Sysmon EID 1 (`-EncodedCommand`) |
| **Discovery** | `T1082` | System Information Discovery | `INC-005` | Sysmon Event ID 1 (`systeminfo.exe`) |
| **Discovery** | `T1087.001` | Local Account Discovery | `INC-005` | Sysmon Event ID 1 (`whoami.exe`) |
| **Discovery** | `T1016` | System Network Config Discovery | `INC-005` | Sysmon Event ID 1 (`ipconfig.exe`) |
| **Discovery** | `T1049` | Network Connection Discovery | `INC-005` | Sysmon Event ID 1 (`netstat.exe`) |
| **Discovery** | `T1057` | Process Discovery | `INC-005` | Sysmon Event ID 1 (`tasklist.exe`) |
| **Initial Access** | `T1078.003` | Valid Accounts: Local Accounts | `INC-001` (Post), `INC-006` | Logon Session Creation (EID 4624 / SSH) |
| **Initial Access** | `T1190` | Exploit Public-Facing Application | `INC-007` | Web Application Structured Log |
| **Lateral Movement** | `T1021.004` | Remote Services: SSH | `INC-006` | SSH Daemon Accepted Password |
| **Impact** | `T1565.001` | Stored Data Manipulation | `INC-004` | Wazuh FIM (`syscheck`) diff engine |

Detailed breakdown available at [mitre/attack-mapping.md](mitre/attack-mapping.md).

---

## Detection Rules

### Wazuh Rules Suite (`/var/ossec/etc/rules/local_rules.xml`)
- **Rule 100001 (Level 10)**: 10 Failed Logins in 60s (Brute Force).
- **Rule 100002 (Level 13)**: Successful Login following Brute Force (Compromise Correlation).
- **Rule 100010 (Level 8)**: PowerShell execution with `-EncodedCommand` / `-WindowStyle Hidden` / `-ExecutionPolicy Bypass`.
- **Rule 100011 (Level 10)**: PowerShell execution staged from user-writable directories (`AppData\Local\Temp`, `Users\Public`).
- **Rule 100020 (Level 6)**: New local user created (Win Event 4720).
- **Rule 100021 (Level 8)**: User added to local Administrators (Win Event 4732).
- **Rule 100022 (Level 12)**: Correlation: New user created followed by elevation to Administrators in < 120s.
- **Rule 100030 (Level 10)**: Real-time FIM checksum mismatch on critical files (`/etc/passwd`, `/etc/shadow`, `hosts`).
- **Rule 100040 (Level 5)**: Atomic detection of system discovery LOLBins.
- **Rule 100041 (Level 10)**: Behavioral correlation: Burst of >= 5 discovery commands in < 30s.
- **Rule 100052 (Level 14)**: Multi-stage SSH correlation: Failed logins followed by root/ubuntu login in < 180s.
- **Rule 100061 (Level 10)**: Web Application Login Brute Force (>= 10 failures in 60s).
- **Rule 100062 (Level 8)**: Repeated Access Denied on restricted web routes (HTTP 403).
- **Rule 100063 (Level 9)**: Anomalous web probing for sensitive configuration files (`/.env`, `/admin.php`).

### Portable Sigma Rules (`detections/sigma/`)
- `detections/sigma/linux/lnx_ssh_brute_force_auth.yml`
- `detections/sigma/linux/lnx_ssh_compromise_after_brute_force.yml`
- `detections/sigma/windows/win_multiple_failed_logons.yml`
- `detections/sigma/windows/win_suspicious_powershell_execution.yml`
- `detections/sigma/windows/win_account_created_and_promoted.yml`
- `detections/sigma/windows/win_fim_critical_file_modified.yml`
- `detections/sigma/windows/win_suspicious_discovery_burst.yml`
- `detections/sigma/web/web_login_brute_force.yml`
- `detections/sigma/web/web_unauthorized_endpoint_probing.yml`

---

## Security Metrics & Operational KPIs

Metrics calculated via `scripts/python/calculate_metrics.py`:

```text
==================================================================
   ATTACK vs DETECTION LAB -- Security Metrics & KPI Dashboard   
==================================================================
Total Hosts Monitored       : 4
Incidents Detected & Proven : 7
Custom Wazuh Rules Created  : 14
Portable Sigma Rules Created: 9
MITRE ATT&CK Techniques     : 16
Mean Time To Detect (MTTD)  : 10.4 seconds
------------------------------------------------------------------
Alerts by Severity:
  - Critical : 2
  - High     : 5
==================================================================
```

Review the full SOC dashboard specification in [dashboards/soc-dashboard.md](dashboards/soc-dashboard.md).

---

## Defensive Hardening & "Before vs. After" Comparison

Detailed hardening implementations and comparative telemetry are documented in:
- [hardening/linux.md](hardening/linux.md)
- [hardening/windows.md](hardening/windows.md)
- [hardening/linux-ssh-hardening.md](hardening/linux-ssh-hardening.md)

### Summary Comparison:
```text
[ BEFORE HARDENING ]
- Passwords allowed on SSH; root login permitted.
- Unlimited login attempts allowed across RDP/SSH.
- PowerShell v2 downgrade attacks possible.
- Adversary executes full dictionary attack until password guessed.
- Result: 20+ alerts per attack wave; high risk of full compromise.

[ AFTER HARDENING ]
- SSH password authentication completely disabled; Ed25519 keys enforced.
- Fail2Ban jail bans adversary IP on 3rd failure.
- Windows Account Lockout policy locks accounts after 5 failures.
- PowerShell v2 uninstalled; Script Block Logging enforced.
- Critical identity files protected with immutable bit (+i).
- Result: Adversary blocked at firewall layer; zero alert fatigue in SIEM.
```

---

## Lessons Learned

Key operational pitfalls and engineering solutions are documented in [docs/lessons-learned.md](docs/lessons-learned.md):
1. **Preventing Log Storms**: Whitelisting `wazuh-agent.exe` parent processes in Sysmon Event ID 1 prevented infinite recursion logging loops.
2. **Clock Drift Impact**: Demonstrating why hypervisor clock drift invalidates sliding-window correlation rules.
3. **Burst Scoring vs. Atomic Signatures**: Why behavioral grouping (5 discovery commands in 30s) prevents false-positive alert fatigue.
4. **Structured JSON in DevSecOps**: Why emitting native JSON from Spring Boot eliminates brittle regex decoders in SIEM.

---

## Future Improvements

- [ ] Deploy **Suricata IDS** inline to capture network PCAP artifacts alongside host telemetry.
- [ ] Implement **Wazuh Active Response** scripts to automatically ban attacking IPs upon Rule 100001/100052 trigger.
- [ ] Add **VirusTotal API** automated lookup via Wazuh Integrator for newly dropped binaries.
- [ ] Expand DevSecOps pipeline with pre-commit SAST scanning (Semgrep) and dependency checking (OWASP Dependency-Check).

---

## Disclaimer

> **IMPORTANT LEGAL & ETHICAL NOTICE**
> 
> This project was developed strictly for **educational purposes, defensive cybersecurity research, and controlled laboratory validation**.
> 
> - All attack simulations were performed exclusively against isolated virtual machines owned and controlled by the author within a private, non-routable virtual network (`192.168.56.0/24`).
> - No external systems, third-party infrastructure, or public IP addresses were targeted or scanned.
> - The techniques presented are documented solely to improve logging visibility, detection engineering, and incident response capabilities.
> - **Never execute offensive testing against any system without explicit, prior written authorization.**
