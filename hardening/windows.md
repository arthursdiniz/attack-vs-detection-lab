# Windows 11 Enterprise Hardening & Defensive Controls

## 1. Baseline Assessment (Before Hardening)

In default test deployments, Windows workstations present significant exposure to credential attacks and living-off-the-land techniques:
- Local administrator password shared or statically defined across systems.
- Standard users able to execute arbitrary scripts in `\AppData\Local\Temp` and `\Users\Public`.
- Legacy PowerShell v2 installed, enabling downgrade attacks that bypass AMSI and Script Block Logging.
- No rate limiting on RDP or SMB authentication attempts.

---

## 2. Implemented Defensive Controls (After Hardening)

### Control 1: Block Script Execution in User-Writable Paths
Using Software Restriction Policies or AppLocker / WDAC, block executable and script execution originating from non-administrative directories:

```powershell
# Block script execution in AppData\Local\Temp via PowerShell ExecutionPolicy and AppLocker rule
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force
```

### Control 2: Disable Legacy Windows PowerShell v2.0
Adversaries use PowerShell v2.0 downgrade attacks to execute commands without triggering Event ID 4104 (Script Block Logging) or AMSI:

```powershell
# Check state
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2

# Permanently disable legacy engine
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
```

### Control 3: Enable Account Lockout Policy
Enforce deterministic threshold locking to prevent SMB and RDP password sprays:

```powershell
# Set account lockout threshold to 5 attempts with 15-minute reset window
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
```

### Control 4: Enforce Windows Defender Credential Guard & LAPS
- Deploy Microsoft LAPS (Local Administrator Password Solution) to rotate random passwords per endpoint.
- Enable Credential Guard to isolate LSASS memory into a virtualization-based security (VBS) container, preventing Mimikatz memory scraping.

---

## 3. Before vs. After Hardening Comparison

| Security Parameter | Before Hardening (Vulnerable) | After Hardening (Hardened) |
| :--- | :--- | :--- |
| **Account Lockout Threshold** | None (Unlimited attempts) | Locked after 5 failed attempts |
| **PowerShell Downgrade Attack** | Possible (v2.0 available) | Blocked (v2.0 uninstalled) |
| **Script Execution in Temp** | Allowed | Blocked via AppLocker / Restricted |
| **Adversary Brute Force Result** | Eventual password discovery | Account locked; attacker stalled |
| **Telemetry Impact** | High log volume from sprays | Lockout Event 4740 alerts SOC instantly |
