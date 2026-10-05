# Enterprise Telemetry Sources & Event Catalog

## 1. Overview & Telemetry Architecture

Effective detection engineering requires an intimate understanding of the exact event identifiers, structure, and fields produced by host operating systems under both benign baseline conditions and adversary activity.

This document serves as the comprehensive telemetry catalog for the **Attack vs Detection Lab**, documenting every monitored log source across Windows and Linux, the specific event IDs, critical fields for detection engineers, and the MITRE ATT&CK techniques they illuminate.

---

## 2. Windows 11 Telemetry Sources

### 2.1 Native Windows Security Event Log (`Security.evtx`)

Ingested via the `win_eventchannel` decoder in Wazuh:

| Event ID | Event Name | Category | Critical Fields | Threat Context / MITRE |
| :---: | :--- | :--- | :--- | :--- |
| **4625** | An account failed to log on | Authentication | `TargetUserName`, `IpAddress`, `FailureReason`, `SubStatus`, `LogonType` | T1110 (Brute Force / Password Spray). SubStatus `0xC000006A` = bad password; `0xC0000064` = user does not exist. |
| **4624** | An account was successfully logged on | Authentication | `TargetUserName`, `IpAddress`, `LogonType`, `LogonGuid` | T1078 (Valid Accounts). LogonType 2 = Interactive; 3 = Network (SMB); 10 = RemoteInteractive (RDP). |
| **4720** | A user account was created | Account Mgmt | `TargetUserName`, `SubjectUserName`, `SamAccountName`, `SidHistory` | T1136.001 (Create Local Account). Identifies rogue backdoor user creation. |
| **4726** | A user account was deleted | Account Mgmt | `TargetUserName`, `SubjectUserName` | Defense Evasion / cleanup after intrusion. |
| **4728** | Member added to security-enabled global group | Account Mgmt | `MemberName`, `TargetUserName` (Group), `SubjectUserName` | T1098 (Account Manipulation). |
| **4732** | Member added to security-enabled local group | Account Mgmt | `MemberSid`, `TargetUserName` ("Administrators"), `SubjectUserName` | T1098 / T1078 (Local Privilege Escalation). Correlated with 4720 in INC-003. |
| **4688** | A new process has been created | Detailed Tracking | `NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserName` | T1059 (Command Execution). Requires `ProcessCreationIncludeCmdLine_Enabled` = 1. |
| **7045** | A new service was installed in the system | System (`System.evtx`) | `ServiceName`, `ImagePath`, `ServiceType`, `AccountName` | T1543.003 (Windows Service Persistence). |
| **4698** | A scheduled task was created | Task Scheduler | `TaskName`, `TaskContent` (XML payload with action path) | T1053.005 (Scheduled Task Persistence). |

---

### 2.2 Microsoft Sysmon Operational Log (`Microsoft-Windows-Sysmon/Operational.evtx`)

Deep system-level telemetry filtered through [sysmonconfig.xml](../setup/windows/sysmonconfig.xml):

| Event ID | Event Name | Critical Fields for Detection Engineering | Threat Context / MITRE |
| :---: | :--- | :--- | :--- |
| **1** | Process Create | `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `CommandLine`, `CurrentDirectory`, `User`, `ParentProcessId`, `ParentImage`, `ParentCommandLine`, `Hashes` (SHA256, MD5) | T1059, T1082, T1105. Reveals command-line obfuscation, LOLBins, and anomalous parent-child relationships (e.g., `cmd.exe` spawned by `w3wp.exe`). |
| **3** | Network Connection | `UtcTime`, `ProcessId`, `Image`, `User`, `Protocol`, `Initiated`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort` | T1071 (Application Layer Protocol), T1049, C2 beaconing. Connects process lineage directly to network sockets. |
| **11** | File Create | `UtcTime`, `ProcessId`, `Image`, `TargetFilename`, `CreationUtcTime` | T1105 (Ingress Tool Transfer). Catches dropping of `.ps1`, `.exe`, or `.bat` in staging directories. |
| **12 / 13 / 14** | Registry Event | `EventType`, `UtcTime`, `ProcessId`, `Image`, `TargetObject`, `Details` | T1547.001 (Run keys), T1112 (Modify Registry). Catches persistence implants and security setting tampering. |

---

### 2.3 PowerShell Operational Log (`Microsoft-Windows-PowerShell/Operational.evtx`)

| Event ID | Event Name | Critical Fields | Threat Context / MITRE |
| :---: | :--- | :--- | :--- |
| **4104** | Execute a Remote Command (Script Block Logging) | `ScriptBlockText`, `ScriptBlockId`, `Path`, `UserId` | T1059.001 (PowerShell). De-obfuscates runtime code: captures actual code executed even if invoked with Base64 encoding (`-EncodedCommand`) or string concatenation. |

---

## 3. Linux (Ubuntu Server) Telemetry Sources

### 3.1 Authentication & PAM Log (`/var/log/auth.log`)

Ingested via the `pam` and `sshd` decoders in Wazuh:

| Event Source | Pattern / Trigger | Key Extracted Fields | Threat Context / MITRE |
| :--- | :--- | :--- | :--- |
| **OpenSSH** (`sshd`) | `Failed password for [invalid user] <USER> from <IP> port <PORT> ssh2` | `srcip`, `dstuser`, `srcport` | T1110.001 (Brute Force). Core trigger for INC-001 & INC-006. |
| **OpenSSH** (`sshd`) | `Accepted password for <USER> from <IP> port <PORT> ssh2` | `srcip`, `dstuser`, `srcport` | T1078 (Valid Accounts). Correlated with preceding failures to catch compromise. |
| **PAM** (`pam_unix`) | `authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=<IP> user=<USER>` | `srcip`, `dstuser` | Pluggable Authentication Modules tracking local & remote auth attempts. |
| **Sudo** (`sudo`) | `<USER> : TTY=pts/0 ; PWD=/home/<USER> ; USER=root ; COMMAND=/bin/<CMD>` | `srcuser`, `dstuser` (root), `command` | T1548.003 (Sudo and Sudo Caching). Privileged command execution audit. |
| **Shadow** (`useradd`) | `new user: name=<USER>, UID=<UID>, GID=<GID>, home=<DIR>, shell=<SHELL>` | `dstuser` | T1136.001 (Local Account Creation). |

---

### 3.2 Linux Audit Daemon (`/var/log/audit/audit.log`)

Kernel-level syscall and file watch telemetry tagged with custom keys (`-k`):

| Audit Key (`key=`) | Watched Entity / Syscall | Recorded Event Fields | Threat Context / MITRE |
| :--- | :--- | :--- | :--- |
| `identity_tampering` | `/etc/passwd`, `/etc/shadow` (`-p wa`) | `syscall`, `exe`, `key`, `name`, `uid`, `auid` | T1565.001 (Data Manipulation), T1003.008 (/etc/shadow access). |
| `priv_escalation` | `/etc/sudoers`, `/etc/sudoers.d/` | `syscall`, `exe`, `key`, `name`, `auid` | T1548.003 (Sudoers file tampering). |
| `sshd_tampering` | `/etc/ssh/sshd_config` (`-p wa`) | `syscall`, `exe`, `key`, `name`, `auid` | T1098.004 (SSH authorized_keys tampering / config modification). |
| `account_manipulation` | `/usr/sbin/useradd`, `usermod` (`-p x`) | `exe`, `comm`, `a0`, `a1`, `auid` | T1136 / T1098 (Account tools execution). |
| `discovery_execution` | `/bin/uname`, `/usr/bin/whoami`, `id` (`-p x`)| `exe`, `comm`, `uid`, `auid` | T1082 / T1087 (Local Discovery burst in INC-005). |
| `persistence_cron` | `/etc/crontab`, `/var/spool/cron/` (`-p wa`) | `syscall`, `exe`, `name`, `auid` | T1053.003 (Cron persistence). |

---

### 3.3 File Integrity Monitoring (FIM / `syscheck`)

Directly generated by the Wazuh Agent FIM engine:

| Field Name | Description | Example Value |
| :--- | :--- | :--- |
| `syscheck.path` | Full canonical file path | `/etc/shadow` |
| `syscheck.event` | Modification lifecycle state | `modified`, `added`, `deleted` |
| `syscheck.md5_before` / `md5_after` | MD5 cryptographic digest delta | `c4ca4238...` -> `eccbc87e...` |
| `syscheck.sha256_before` / `sha256_after` | SHA256 cryptographic digest delta | `e3b0c442...` -> `f2ca1bb6...` |
| `syscheck.uname_after` | File owner | `root` |
| `syscheck.perm_after` | UNIX file permission octal | `0640` |
| `syscheck.diff` | Exact line-by-line unified diff | `+lab-backdoor:$6$rounds=...` |
