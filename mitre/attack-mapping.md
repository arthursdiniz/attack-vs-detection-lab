# MITRE ATT&CK Enterprise Mapping Matrix (Master Suite)

This document maps all laboratory attack scenarios and defensive detections to the official **MITRE ATT&CK Enterprise Matrix** (v14+).

---

## 1. Laboratory Technique Coverage Overview

| Incident ID | Incident Name | Tactic | Technique Name | MITRE ID | Telemetry / Data Source | Detection Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **INC-001** | Authentication Brute Force | Credential Access (`TA0006`) | Brute Force: Password Guessing | `T1110.001` | Logon Session: Logon Session Creation | Wazuh Rule `100001` (>=10 failures in 60s) & Sigma rule |
| **INC-001** (Post) | Compromise via Brute Force | Initial Access (`TA0001`) | Valid Accounts: Local Accounts | `T1078.003` | User Account: User Account Authentication | Wazuh Rule `100002` (Login success after Rule 100001 in <5m) |
| **INC-002** | Suspicious PowerShell Execution | Execution (`TA0002`) | Command and Scripting Interpreter: PowerShell | `T1059.001` | Process: Process Creation, Script Execution | Sysmon EID 1 (`-enc`, `-w hidden`, `-ep bypass`) & EID 4104 |
| **INC-003** | Suspicious Account Creation & Promotion | Persistence (`TA0003`) / Privilege Escalation (`TA0004`) | Create Account: Local Account / Account Manipulation | `T1136.001` / `T1098` | User Account: User Account Creation, Modification | Correlated Win Event 4720 -> 4732 within 120s (Rule `100022`) |
| **INC-004** | Critical File Modification | Impact (`TA0040`) / Defense Evasion (`TA0005`) | Data Manipulation: Stored Data Manipulation | `T1565.001` | File: File Modification | Wazuh Syscheck (FIM realtime sha256/md5 diff on `/etc/passwd`) |
| **INC-005** | Suspicious System Discovery | Discovery (`TA0007`) | System Information Discovery / Account Discovery | `T1082` / `T1087.001` / `T1016` | Process: Process Creation | Burst sequence of discovery LOLBins (`whoami`, `netstat`, `ipconfig`) in <30s |
| **INC-006** | Suspicious SSH Activity & Compromise | Initial Access (`TA0001`) / Lateral Movement (`TA0008`) | Remote Services: SSH / Valid Accounts | `T1021.004` / `T1078.003` | Logon Session: Logon Session Creation | Rule `100052` (SSH spray followed by root session creation in <180s) |
| **INC-007** | Web Application Brute Force & Probing | Credential Access (`TA0006`) / Reconnaissance (`TA0043`) | Brute Force / Active Scanning: Vulnerability Scanning | `T1110.001` / `T1595.002` | Application Log: Application Log Content | Structured JSON ingestion (Rules `100061`, `100062`, `100063`) |

---

## 2. Technical Validation of Official MITRE Technique IDs

- `T1110.001` (**Password Guessing**): Confirmed in MITRE Enterprise Matrix under Credential Access. Adversaries systematically guess passwords on a target system using automated wordlists.
- `T1078.003` (**Local Accounts**): Confirmed. Adversaries obtain and abuse credentials of default or newly created local accounts.
- `T1059.001` (**PowerShell**): Confirmed. Adversaries abuse PowerShell execution engines to run code in memory and execute commands.
- `T1136.001` (**Local Account Creation**): Confirmed. Adversaries create local accounts to maintain persistence.
- `T1098` (**Account Manipulation**): Confirmed. Adversaries modify account attributes or add users to privileged security groups.
- `T1565.001` (**Stored Data Manipulation**): Confirmed. Adversaries insert, delete, or manipulate files on victim systems.
- `T1082` (**System Information Discovery**): Confirmed. Adversaries query operating system version and hardware.
- `T1087.001` (**Local Account Discovery**): Confirmed. Adversaries enumerate local accounts and group members.
- `T1016` (**System Network Configuration Discovery**): Confirmed. Adversaries look for details about the network configuration and interfaces.
- `T1049` (**System Network Connections Discovery**): Confirmed. Adversaries attempt to get a listing of network connections via netstat.
- `T1057` (**Process Discovery**): Confirmed. Adversaries attempt to get information about running processes on a system.
- `T1021.004` (**Remote Services: SSH**): Confirmed. Adversaries log into remote systems using SSH.
- `T1548.003` (**Sudo and Sudo Caching**): Confirmed. Adversaries execute commands with elevated privileges via sudo.
- `T1595.002` (**Vulnerability Scanning**): Confirmed. Adversaries scan for vulnerabilities or probe endpoints on public-facing applications.
