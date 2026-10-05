# Windows 11 Endpoint Provisioning & Telemetry Setup

## 1. Overview & Host Specifications

The primary Windows victim endpoint is `lab-win11`, running **Windows 11 Enterprise Evaluation (x64)**. This machine acts as the enterprise workstation target, equipped with deep telemetry collection via Windows Event Channels, Advanced Audit Policies, Microsoft Sysmon, and the Wazuh Agent.

### System Specifications
- **Hostname**: `lab-win11`
- **IP Address**: `192.168.56.20` (`Host-Only` adapter)
- **vCPUs**: 2
- **RAM**: 6 GB (or 4 GB under Profile B)
- **Disk**: 60 GB VDI (Dynamic allocation)

---

## 2. Advanced Windows Audit Policy Configuration

Native Windows logging is unconfigured by default. To capture authentication attacks, account tampering, and process launches, run the following commands in an **Elevated PowerShell** session:

```powershell
# 1. Audit Process Creation (Success)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable

# 2. Audit Logon & Logoff (Success and Failure - Crucial for Brute Force T1110)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

# 3. Audit User Account Management (User creation, modification, deletion)
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# 4. Audit Security Group Management (Domain/Local Admin additions)
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# 5. Enable Command Line Auditing in Process Creation (Event ID 4688 commandline field)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" `
    -Value 1 -PropertyType DWord -Force

# 6. Enable PowerShell Script Block Logging (Event ID 4104)
$psAuditPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
If (!(Test-Path $psAuditPath)) { New-Item -Path $psAuditPath -Force | Out-Null }
Set-ItemProperty -Path $psAuditPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord
```

---

## 3. Microsoft Sysmon Installation & Baseline

Microsoft Sysmon extends Windows telemetry by logging process trees, hashes, parent PIDs, and network socket bindings.

### Installation Procedure
1. Temporarily enable internet access (NAT Adapter 2) or copy the Sysmon executable via VirtualBox Shared Folders.
2. Download Sysmon from Microsoft Sysinternals:
   ```powershell
   Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
   Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force
   ```
3. Install Sysmon with hashing algorithms enabled:
   ```powershell
   # Initial installation with SHA256 and network connection monitoring
   & "$env:TEMP\Sysmon\Sysmon64.exe" -i -n -h md5,sha256 -accepteula
   ```
4. Verify the Sysmon service:
   ```powershell
   Get-Service -Name Sysmon64
   ```

*(A tuned, production-grade `sysmonconfig.xml` will be applied and analyzed in detail during Phase 2).*

---

## 4. Wazuh Windows Agent Installation & Enrollment

### Step 1: Install the Agent
Download and install the Wazuh Windows Agent via PowerShell:

```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.0-1.msi" -OutFile "$env:TEMP\wazuh-agent.msi"

# Install with automatic enrollment targeting lab-wazuh
msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q `
    WAZUH_MANAGER="192.168.56.40" `
    WAZUH_REGISTRATION_SERVER="192.168.56.40" `
    WAZUH_AGENT_NAME="lab-win11"
```

### Step 2: Configure Event Channel Ingestion
Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` to ensure Sysmon and Windows Security channels are active:

```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.56.40</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <!-- Windows Security Event Channel -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Microsoft Sysmon Operational Channel -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- PowerShell Script Block Logging Channel -->
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

### Step 3: Start the Wazuh Agent Service
```powershell
Restart-Service -Name "Wazuh"
Get-Service -Name "Wazuh"
```

---

## 5. Verification
Confirm that the agent is registered and actively communicating:
```powershell
Test-NetConnection -ComputerName 192.168.56.40 -Port 1514
Test-NetConnection -ComputerName 192.168.56.40 -Port 1515
```

On `lab-wazuh`, run:
```bash
sudo /var/ossec/bin/wazuh-control-agent list
# Expected: ID: 001, Name: lab-win11, IP: 192.168.56.20, Status: Active
```
