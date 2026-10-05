# Attack vs Detection Lab

> **A realistic, fully isolated offensive and defensive cybersecurity laboratory for security engineering, telemetry collection, threat detection, SIEM correlation, and incident response.**

[![Platform](https://img.shields.io/badge/Platform-VirtualBox%20%7C%20Linux%20%7C%20Windows-blue.svg)](#lab-environment)
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.x-orange.svg)](#technologies)
[![Telemetry](https://img.shields.io/badge/Telemetry-Sysmon%20%7C%20Windows%20Events%20%7C%20Auditd-green.svg)](#technologies)
[![Rules](https://img.shields.io/badge/Detections-Custom%20Wazuh%20%26%20Sigma-red.svg)](#detection-rules)
[![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-lightgrey.svg)](#mitre-attck-coverage)

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

- **Network Architecture & Safe Isolation**: Implementing strictly segmented Host-Only networks to safely simulate attacks without risk of external leakage.
- **Enterprise Telemetry Engineering**: Deploying and tuning Microsoft Sysmon on Windows 11, configuring Linux `auditd`, `auth.log`, and `systemd-journald`.
- **SIEM Operations & Architecture**: Deploying, configuring, and maintaining Wazuh Indexer, Server, and Dashboard; managing agent enrollment and secure communication.
- **Custom Rule Development**: Writing custom XML rules in Wazuh using frequency thresholds, parent-child process relationships, and multi-event correlations.
- **Generic Detection Rules (Sigma)**: Authoring portable, standard Sigma rules ready for translation to multiple SIEM platforms (Splunk, Elastic, Sentinel).
- **Adversary Emulation & MITRE Mapping**: Executing non-destructive adversary techniques mapped directly to MITRE ATT&CK Enterprise tactics and techniques.
- **Incident Response & Investigation**: Publishing standardized Incident Reports (INC-001 through INC-006) covering summary, timeline, indicators, containment, and lessons learned.
- **Security Hardening**: Applying targeted defensive controls and documenting measurable "Before vs. After" telemetry changes.

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
| **Endpoint Telemetry** | Microsoft Sysmon | v15+ | Deep Windows process, network, and registry monitoring |
| **Linux Telemetry** | Auditd & Systemd | Native | Linux kernel system calls, execution, and auth tracking |
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

> **Note on Resource Profiles**: While the configuration above is tuned for 32 GB host systems, an alternative 16 GB profile is documented in [architecture/architecture.md](architecture/architecture.md#hardware-profiles).

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

## Attack Scenarios

| Scenario ID | Name | Target | MITRE Technique | Telemetry Source | Primary Rule |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **[INC-001](incidents/INC-001-brute-force.md)** | Authentication Brute Force | Windows / Linux | T1110.001 | Win Event 4625 / `auth.log` | Threshold correlation (10 failed / 60s) |
| **[INC-002](incidents/INC-002-powershell.md)** | Suspicious PowerShell Execution | Windows 11 | T1059.001 | Sysmon Event ID 1 & ScriptBlock | Encoded / Hidden Window / Bypass |
| **[INC-003](incidents/INC-003-account-creation.md)** | Unauthorized Account & Group Addition | Windows 11 | T1136.001 / T1098 | Win Event 4720 & 4728 | New user created + added to Admins in < 2m |
| **[INC-004](incidents/INC-004-file-integrity.md)** | Critical File Modification (FIM) | Linux / Windows | T1565.001 | Wazuh `syscheck` (FIM) | File hash / permission tampering (`/etc/passwd`) |
| **[INC-005](incidents/INC-005-discovery.md)** | Rapid System & Network Discovery | Windows 11 | T1082 / T1087 | Sysmon Event ID 1 | Discovery command burst within 30s |
| **[INC-006](incidents/INC-006-ssh-activity.md)** | Suspicious SSH Spray & Compromise | Ubuntu Server | T1110 / T1078 | `sshd` / `auth.log` | Multiple failed logins followed by success |

---

## MITRE ATT&CK Coverage

The lab explicitly maps every simulation to the official MITRE ATT&CK Enterprise Matrix:

| Tactic | Technique ID | Technique Name | Lab Incident | Data Source |
| :--- | :--- | :--- | :--- | :--- |
| **Credential Access** | `T1110.001` | Password Guessing / Brute Force | `INC-001`, `INC-006` | Logon Session: Logon Session Creation |
| **Execution** | `T1059.001` | PowerShell | `INC-002` | Process: Process Creation, Script Execution |
| **Persistence** | `T1136.001` | Local Account | `INC-003` | User Account: User Account Creation |
| **Persistence** | `T1098` | Account Manipulation | `INC-003` | User Account: User Account Modification |
| **Defense Evasion** | `T1562.001` | Impair Defenses: Disable Tools | Hardening tests | Command: Command Execution |
| **Discovery** | `T1082` | System Information Discovery | `INC-005` | Process: Process Creation |
| **Discovery** | `T1087.001` | Local Account Discovery | `INC-005` | Process: Process Creation |
| **Discovery** | `T1016` | System Network Configuration Discovery| `INC-005` | Process: Process Creation |
| **Impact** | `T1565.001` | Stored Data Manipulation | `INC-004` | File: File Modification |

Detailed breakdown and layer visualization available at [mitre/attack-mapping.md](mitre/attack-mapping.md).

---

## Repository Structure

```text
DetectLab/
├── .gitignore                      # Excludes disk images, credentials, dumps
├── README.md                       # Project overview and documentation
│
├── architecture/                   # Architecture, network diagrams, data flows
│   ├── architecture.md             # Detailed specs, sizing, hypervisor justification
│   ├── data-flow.md                # Event pipeline from generation to indexing
│   └── network-diagram.md          # Network topology and port matrix
│
├── setup/                          # Step-by-step infrastructure provisioning
│   ├── networking/                 # Host-only setup, IP assignment, firewall rules
│   ├── wazuh/                      # Wazuh All-in-One deployment guides
│   ├── windows/                    # Windows 11 configuration & Sysmon setup
│   ├── ubuntu/                     # Ubuntu Server setup & Auditd configuration
│   └── kali/                       # Attacker tooling and simulation environment
│
├── attacks/                        # Documented, safe simulation procedures
│   ├── T1110-brute-force/          # Safe authentication brute-force simulations
│   ├── suspicious-powershell/      # Simulated malicious PowerShell executions
│   ├── account-creation/           # Local account backdoor & admin promotion
│   ├── privilege-escalation/       # Local privilege escalation telemetry simulations
│   ├── suspicious-file/            # FIM triggering & critical file tampering
│   ├── web-authentication/         # Application log telemetry simulation
│   └── discovery/                  # Discovery command sequence execution
│
├── detections/                     # Custom detection logic
│   ├── wazuh/                      # Wazuh XML rules and custom decoders
│   ├── sigma/                      # Portable YAML Sigma rules (Windows, Linux, Web)
│   └── correlation/                # Multi-event correlation rules
│
├── incidents/                      # Full SOC Incident Reports (INC-001 to INC-006)
│
├── mitre/                          # Official MITRE ATT&CK mapping tables
│
├── scripts/                        # Automation & testing utilities
│   ├── python/                     # Log parsing, metric calculations, report gen
│   ├── bash/                       # Linux setup, network validation, lab reset
│   └── powershell/                 # Windows telemetry validation, audit checks
│
├── dashboards/                     # SOC dashboard metrics and visualization configs
├── evidence/                       # Curated sanitized event logs and artifacts
├── hardening/                      # Before vs. After remediation guides
└── docs/                           # Detection engineering & IR methodology docs
```

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
