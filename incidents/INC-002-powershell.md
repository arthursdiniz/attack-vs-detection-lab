# INC-002 — Suspicious PowerShell Execution

## Summary
At 15:10:02 UTC, Sysmon telemetry on `lab-win11` alerted on anomalous PowerShell process creations utilizing flags commonly associated with adversary tradecraft: `-EncodedCommand` (Base64 payload execution), `-WindowStyle Hidden`, and `-ExecutionPolicy Bypass`. Analysis of the parent process lineage revealed an execution originating from a user staging directory (`\AppData\Local\Temp`). Wazuh custom rule `100010` triggered, logging a High Severity alert. Investigation confirmed the commands were non-destructive adversary simulations. The host was contained by auditing AppLocker/Constrained Language Mode policies and validating Script Block Logging.

---

## Severity
- **Severity Rating**: **HIGH** (Wazuh Rule Level 8 to 10)
- **Confidence**: **High** (Direct Sysmon Event ID 1 command line inspection)
- **Calculated MTTD**: **2 seconds** (Near real-time process creation ingestion)

---

## Date
- **Incident Date**: 2026-10-05
- **Detection Timestamp**: 2026-10-05T15:10:02Z
- **Containment Timestamp**: 2026-10-05T15:18:00Z

---

## Affected Asset
- **Hostname**: `lab-win11`
- **IP Address**: `192.168.56.20`
- **Role**: Windows 11 Enterprise (Victim 01)
- **Operating User**: `LAB-WIN11\analyst`

---

## Data Source
- **Primary Source**: Microsoft Sysmon (`Microsoft-Windows-Sysmon/Operational`, Event ID 1)
- **Secondary Source**: Windows PowerShell Operational Log (Event ID 4104 - Script Block Logging)
- **Ingestion Channel**: Wazuh Windows Agent (`win_eventchannel` decoder) -> Port 1514/TCP.

---

## Attack Simulation
The simulation was executed locally via PowerShell on `lab-win11`:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\attacks\suspicious-powershell\simulate_powershell_telemetry.ps1
```
The script safely tested:
1. Base64-encoded string execution (`-EncodedCommand`).
2. Hidden window creation (`-WindowStyle Hidden`).
3. Staged script execution from `AppData\Local\Temp`.
4. In-memory download simulation via `Net.WebClient`.

---

## Timeline

```text
15:10:02 UTC - Sysmon Event ID 1: powershell.exe executed with -EncodedCommand (PID 6840).
15:10:02 UTC - Wazuh Engine evaluates win_eventdata.commandLine: Rule 100010 triggers (Level 8).
15:10:04 UTC - Sysmon Event ID 1: powershell.exe executed with -WindowStyle Hidden -ExecutionPolicy Bypass (PID 7012).
15:10:06 UTC - Sysmon Event ID 1: powershell.exe executing script staged in \AppData\Local\Temp (PID 7180). Rule 100011 triggers (Level 10).
15:10:08 UTC - Sysmon Event ID 3: powershell.exe attempts outbound connection to 192.168.56.30:8080.
15:11:00 UTC - SOC Analyst begins triage in Wazuh Dashboard; extracts decoded Base64 payload.
15:18:00 UTC - Investigation closed as verified simulation; hardening recommendations enacted.
```

---

## Evidence
- **Sysmon Event ID 1 Record ID**: `6840` / `7012`
- **Full Process Lineage**:
  - `ParentImage`: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (PID 5124)
  - `Image`: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (PID 6840)
  - `CommandLine`: `powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABl...`
- **Computed Image Hash**: `SHA256=DE96A68E93E240B330F323DA02F44CB5066262842ED40486100DA71E793A233D`
- **Raw Evidence Archive**: `evidence/logs/inc-002-raw-powershell.json`

---

## Logs
Excerpt from Sysmon Event ID 1 ingested in Wazuh:
```json
{
  "win": {
    "system": { "eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational" },
    "eventdata": {
      "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "commandLine": "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"Write-Output 'DetectLab_Hidden_Execution'\"",
      "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "user": "LAB-WIN11\\analyst"
    }
  }
}
```

---

## Detection

### Detection Strategy
Detecting suspicious PowerShell requires filtering for adversarial execution flags in process command-line arguments while leveraging Script Block Logging (Event ID 4104) to de-obfuscate in-memory content.

### Detection Rule Specification
- **Rule ID**: `100010` (Suspicious Execution Flags) and `100011` (Execution from Staging Directory)
- **File**: `/var/ossec/etc/rules/local_rules.xml`
- **Portable Sigma Rule**: `detections/sigma/windows/win_suspicious_powershell_execution.yml`

---

## MITRE ATT&CK Mapping
- **Tactic**: Execution (`TA0002`)
- **Technique**: Command and Scripting Interpreter: PowerShell (`T1059.001`)
- **Tactic**: Defense Evasion (`TA0005`)
- **Technique**: Obfuscated Files or Information (`T1027`) / Impair Defenses (`T1562.001`)

---

## Investigation (SOC Analyst Analysis)
1. **Qual comando exato foi executado?**
   - De-obfuscando a string Base64 (`[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(...))`):
     `Write-Output 'DetectLab_Adversary_Emulation_Safe_Payload'; Start-Sleep -Milliseconds 200`
   - O payload foi confirmado como inofensivo.
2. **Quem iniciou o processo?**
   - Usuário `LAB-WIN11\analyst` interativamente via script de laboratório.
3. **Houve conexões de rede associadas?**
   - Sysmon Event ID 3 registrou tentativa de conexão à porta `8080` de `192.168.56.30`, que falhou/encerrada sem handshake válido.
4. **Houve persistência criada?**
   - Nenhuma chave de registro Run/RunOnce ou serviço foi criado durante a execução.

---

## Indicators of Compromise (IOCs)

| Type | Indicator | Context | Action |
| :--- | :--- | :--- | :--- |
| **SHA256** | `DE96A68E93E240B330F323DA...` | Legitimate Microsoft PowerShell hash | Baseline verified |
| **Command Fragment** | `-EncodedCommand VwByAGkAdABl...` | Base64 encoded test script | Alert signature tuned |
| **File Path** | `\AppData\Local\Temp\detectlab_staged_script.ps1` | Staged script artifact | Cleaned |

---

## False Positives
- Scripts corporativos de inventário (ex: SCCM, Dell Command Update) utilizando `-WindowStyle Hidden` para não exibir janelas durante logon de usuários.
- Solução: Adicionar filtros de exclusão baseados em assinatura de código do binário pai (`ParentImage`) e caminhos autorizados em `C:\Program Files\`.

---

## Response & Mitigation
1. **Enforce PowerShell Constrained Language Mode (CLM)** via AppLocker ou WDAC:
   - Impede que scripts executem métodos .NET arbitrários como `Net.WebClient` ou chamadas de API do Windows.
2. **Mandatory Script Block Logging (EID 4104)**:
   - Já habilitado pelo script `configure-windows-telemetry.ps1`.
3. **Disable PowerShell v2**:
   - Desinstalar o recurso legado do Windows PowerShell 2.0 (`Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`) para evitar que atacantes façam downgrade para contornar o logging moderno.

---

## Lessons Learned
1. Bloquear o PowerShell completamente em ambientes corporativos modernos é frequentemente impraticável devido a rotinas de administração legítimas.
2. A verdadeira defesa em profundidade consiste em monitorar **comportamentos combinados**: processo pai incomum + argumentos de evasão (`-enc`, `-w hidden`) + diretórios graváveis por usuários.
