# Phase 2 — Telemetry & Ingestion Validation Checklist

This checklist verifies that all telemetry sensors, audit policies, and SIEM agents are operational and forwarding enriched logs before starting attack simulations.

---

## 1. Windows 11 Endpoint (`lab-win11` - `192.168.56.20`)

- [ ] **Advanced Audit Policies**:
  - `auditpol /get /subcategory:"Logon"` reports **Success and Failure**.
  - `auditpol /get /subcategory:"User Account Management"` reports **Success and Failure**.
  - `auditpol /get /subcategory:"Security Group Management"` reports **Success and Failure**.
  - `auditpol /get /subcategory:"Process Creation"` reports **Success**.
- [ ] **Command Line Ingestion**:
  - Registry key `ProcessCreationIncludeCmdLine_Enabled` is set to `1` in `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`.
- [ ] **PowerShell Script Block Logging**:
  - Registry key `EnableScriptBlockLogging` is set to `1` in `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`.
  - Event ID `4104` observed in `Microsoft-Windows-PowerShell/Operational`.
- [ ] **Microsoft Sysmon Operational**:
  - Sysmon service (`Sysmon64` or `Sysmon`) is running (`Get-Service Sysmon64`).
  - Active configuration loaded from `sysmonconfig.xml` (`Sysmon64.exe -s`).
  - Validation script `validate-sysmon.ps1` successfully captures Event ID `1` with SHA256 and MD5 hashes.
- [ ] **Wazuh Windows Agent**:
  - `Wazuh` service is running (`Get-Service Wazuh`).
  - Agent successfully enrolled with Manager at `192.168.56.40`.
  - Channels `Security`, `Microsoft-Windows-Sysmon/Operational`, and `Microsoft-Windows-PowerShell/Operational` configured in `ossec.conf`.

---

## 2. Ubuntu Server Endpoint (`lab-ubuntu` - `192.168.56.30`)

- [ ] **Auditd Daemon & Rules**:
  - Daemon active (`systemctl is-active auditd` returns `active`).
  - Rules loaded via `augenrules --load`.
  - Active rule tags verified with `auditctl -l`:
    - `identity_tampering` (watches on `/etc/passwd`, `/etc/shadow`)
    - `priv_escalation` (watches on `/etc/sudoers`)
    - `discovery_execution` (watches on `/bin/uname`, `/usr/bin/whoami`)
    - `account_manipulation` (watches on `useradd`, `usermod`)
  - Validation script `linux-audit-check.sh` reports success.
- [ ] **OpenSSH Telemetry**:
  - `LogLevel VERBOSE` confirmed in `/etc/ssh/sshd_config`.
  - Password attempts generate descriptive entries in `/var/log/auth.log`.
- [ ] **Wazuh Linux Agent**:
  - Daemon active (`systemctl is-active wazuh-agent` returns `active`).
  - Agent enrolled with Manager at `192.168.56.40`.
  - Ingestion of `/var/log/auth.log` and `/var/log/audit/audit.log` active in `ossec.conf`.
  - Real-time File Integrity Monitoring active on `/etc/passwd` and `/etc/shadow`.

---

## 3. Wazuh SIEM Manager (`lab-wazuh` - `192.168.56.40`)

- [ ] **Agent Connectivity**:
  - Running `/var/ossec/bin/agent_control -l` lists:
    - ID: `001`, Name: `lab-win11`, Status: `Active`
    - ID: `002`, Name: `lab-ubuntu`, Status: `Active`
- [ ] **Event Flow Validation**:
  - Ingestion verified via `python scripts/python/verify_wazuh_telemetry.py`.
  - Raw event stream verified in `/var/ossec/logs/archives/archives.json` (if `<logall>yes</logall>` enabled) or alerts in `/var/ossec/logs/alerts/alerts.json`.
- [ ] **Wazuh Dashboard Display**:
  - Navigating to **Endpoints Summary** displays both endpoints in **Active** status.

---

## 4. Phase 2 Sign-Off

Once all items above are confirmed, the telemetry pipeline is fully operational. The environment is officially ready for **Phase 3 — First Detection: INC-001 Authentication Brute Force**.
