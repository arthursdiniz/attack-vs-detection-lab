# MITRE ATT&CK Enterprise Mapping Matrix

This document maps all laboratory attack scenarios and defensive detections to the official **MITRE ATT&CK Enterprise Matrix** (v14+).

---

## 1. Laboratory Technique Coverage Overview

| Incident ID | Incident Name | Tactic | Technique Name | MITRE ID | Telemetry / Data Source | Detection Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **INC-001** | Authentication Brute Force | Credential Access (`TA0006`) | Brute Force: Password Guessing | `T1110.001` | Logon Session: Logon Session Creation | Wazuh Rule `100001` (Frequency: >=10 failures in 60s) & Sigma rule |
| **INC-001** (Post) | Compromise via Brute Force | Initial Access (`TA0001`) | Valid Accounts: Local Accounts | `T1078.003` | User Account: User Account Authentication | Wazuh Rule `100002` (Successful login after Rule 100001 in <5m) |
| **INC-002** | Suspicious PowerShell Execution | Execution (`TA0002`) | Command and Scripting Interpreter: PowerShell | `T1059.001` | Process: Process Creation, Script Execution | Sysmon Event ID 1 (Flags: `-enc`, `-w hidden`) & PowerShell EID 4104 |
| **INC-003** | Suspicious Account Creation & Promotion | Persistence (`TA0003`) / Privilege Escalation (`TA0004`) | Create Account: Local Account / Account Manipulation | `T1136.001` / `T1098` | User Account: User Account Creation, Modification | Correlated Win Event 4720 -> 4728 / 4732 within 120s |
| **INC-004** | Critical File Modification | Impact (`TA0040`) / Defense Evasion (`TA0005`) | Data Manipulation: Stored Data Manipulation | `T1565.001` | File: File Modification | Wazuh Syscheck (FIM realtime sha256/md5 diff on `/etc/shadow`) |
| **INC-005** | Suspicious System Discovery | Discovery (`TA0007`) | System Information Discovery / Account Discovery | `T1082` / `T1087.001` | Process: Process Creation | Burst sequence of discovery LOLBins (`whoami`, `netstat`, `ipconfig`) in <30s |
| **INC-006** | Suspicious SSH Activity | Initial Access (`TA0001`) / Lateral Movement (`TA0008`) | Remote Services: SSH | `T1021.004` | Logon Session: Logon Session Creation | Multi-stage correlation: SSH spray followed by root session creation |

---

## 2. Technical Validation of MITRE Technique IDs

- `T1110.001` (**Password Guessing**): Confirmed in MITRE Enterprise Matrix under Credential Access. Adversaries systematically guess passwords on a target system using automated wordlists.
- `T1078.003` (**Local Accounts**): Confirmed. Adversaries obtain and abuse credentials of default or newly created local accounts.
- `T1059.001` (**PowerShell**): Confirmed. Adversaries abuse PowerShell execution engines to run code in memory and execute commands.
- `T1136.001` (**Local Account Creation**): Confirmed. Adversaries create local accounts to maintain persistence.
- `T1098` (**Account Manipulation**): Confirmed. Adversaries modify account attributes or add users to privileged security groups.
- `T1565.001` (**Stored Data Manipulation**): Confirmed. Adversaries insert, delete, or manipulate files on victim systems.
- `T1082` (**System Information Discovery**): Confirmed. Adversaries query operating system version and hardware.
- `T1087.001` (**Local Account Discovery**): Confirmed. Adversaries enumerate local accounts and group members.
- `T1021.004` (**SSH**): Confirmed. Adversaries log into remote systems using SSH.
