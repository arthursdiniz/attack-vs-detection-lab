# INC-005 — Suspicious System Discovery

## Summary
At 15:40:01 UTC, Sysmon telemetry on `lab-win11` registered an anomalous burst of system and network discovery commands. Within a 15-second window, 8 distinct Windows enumeration binaries (`whoami.exe`, `net.exe`, `ipconfig.exe`, `netstat.exe`, `route.exe`, `tasklist.exe`, `systeminfo.exe`) were executed from a common parent PowerShell process. While each command is a legitimate Windows utility, their rapid execution in tight succession met the behavioral criteria of Wazuh Rule `100041` (High-frequency discovery burst), alerting the SOC to potential post-exploitation situational awareness enumeration (T1082 / T1087.001 / T1016).

---

## Severity
- **Severity Rating**: **MEDIUM / HIGH** (Wazuh Rule Level 10)
- **Confidence**: **High** (Calculated frequency >= 5 commands in 30 seconds)
- **Calculated MTTD**: **8 seconds** (Triggered on the 5th discovery command)

---

## Date
- **Incident Date**: 2026-10-05
- **Detection Timestamp**: 2026-10-05T15:40:08Z
- **Containment Timestamp**: 2026-10-05T15:45:00Z

---

## Affected Asset
- **Hostname**: `lab-win11`
- **IP Address**: `192.168.56.20`
- **Role**: Windows 11 Enterprise (Victim 01)
- **Parent Process**: `powershell.exe` (PID 5124)

---

## Data Source
- **Primary Source**: Microsoft Sysmon (`Microsoft-Windows-Sysmon/Operational`, Event ID 1)
- **Secondary Source**: Windows Security Log (Event ID 4688)
- **Ingestion Channel**: Wazuh Windows Agent (`win_eventchannel` decoder) -> Port 1514/TCP.

---

## Attack Simulation
Executed locally on `lab-win11`:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\attacks\discovery\simulate_discovery_burst.ps1
```
The script executed 8 discovery utilities with 500ms intervals.

---

## Timeline

```text
15:40:01 UTC - Sysmon Event 1: whoami.exe /all executed (T1087.001).
15:40:03 UTC - Sysmon Event 1: net.exe user executed.
15:40:04 UTC - Sysmon Event 1: net.exe localgroup executed.
15:40:06 UTC - Sysmon Event 1: ipconfig.exe /all executed (T1016).
15:40:08 UTC - Sysmon Event 1: netstat.exe -ano executed (T1049).
15:40:08 UTC - Wazuh Correlation Rule 100041 triggers: 5th discovery command within 30s window. High Alert.
15:40:10 UTC - Sysmon Event 1: route.exe print executed.
15:40:12 UTC - Sysmon Event 1: tasklist.exe /v executed (T1057).
15:40:14 UTC - Sysmon Event 1: systeminfo.exe executed (T1082).
15:41:00 UTC - SOC Analyst begins triage; confirms process tree lineage and burst rate.
```

---

## Evidence
- **Parent Process**: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Commands Executed**: 8 discovery LOLBins in 13.5 seconds (Rate: ~0.6 commands/sec).
- **Trigger Rule**: `100041` (DetectLab: High-frequency burst of system discovery commands).
- **Raw Evidence Archive**: `evidence/logs/inc-005-raw-discovery.json`

---

## Logs
Excerpt from Wazuh Alert JSON:
```json
{
  "rule": {
    "id": "100041",
    "level": 10,
    "description": "DetectLab: High-frequency burst of system discovery commands (T1082 / T1087.001 / T1016)",
    "frequency": 5,
    "timeframe": 30
  },
  "agent": { "id": "001", "name": "lab-win11" },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\System32\\ipconfig.exe",
        "commandLine": "ipconfig.exe /all",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      }
    }
  }
}
```

---

## Detection

### Detection Strategy
Individual discovery commands like `ipconfig` or `whoami` are run daily by system administrators and produce high false-positive rates if alerted individually. However, calculating the **frequency of unique discovery tools within a sliding 30-second window** identifies the automated scripts commonly deployed by threat actors upon gaining initial foothold.

### Detection Rule Specification
- **Rule ID**: `100041`
- **File**: `/var/ossec/etc/rules/local_rules.xml`
- **Portable Sigma Rule**: `detections/sigma/windows/win_suspicious_discovery_burst.yml`

---

## MITRE ATT&CK Mapping
- **Tactic**: Discovery (`TA0007`)
- **Techniques**:
  - `T1082` (System Information Discovery)
  - `T1087.001` (Local Account Discovery)
  - `T1016` (System Network Configuration Discovery)
  - `T1049` (System Network Connections Discovery)
  - `T1057` (Process Discovery)

---

## Investigation (SOC Analyst Analysis)
1. **Os comandos foram executados manualmente ou por script?**
   - A cadência estrita de 500ms entre as invocações e o processo pai idêntico (`powershell.exe` PID 5124) comprovam execução automatizada via script.
2. **Quais dados foram enumerados?**
   - Contas locais, membros de grupos, tabela de roteamento, portas abertas e patches do sistema operacional.
3. **Houve tentativa de exfiltração?**
   - Os logs do Sysmon Event ID 3 e tráfego de rede não registraram envio dos dados para destinos externos.

---

## False Positives
- Scripts legítimos de inventário de TI (ex: ferramentas de auditoria de hardware).
- Mitigação: Filtrar scripts assinados digitalmente executados a partir de contas de serviço corporativas conhecidas.

---

## Mitigation & Hardening
1. **Restringir Execução de LOLBins**:
   - Aplicar políticas de WDAC (Windows Defender Application Control) para bloquear utilitários não essenciais para usuários padrão.
2. **Auditoria de Processos**:
   - Manter Sysmon Event ID 1 com hashing e CommandLine ativo.

---

## Lessons Learned
1. A detecção comportamental baseada em limiares temporais (*burst scoring*) é a melhor técnica para mitigar falsos positivos em comandos LOLBins de discovery.
2. Monitorar a árvore de processos (ParentImage -> ChildImage) permite contextualizar instantaneamente o originador da enumeração.
