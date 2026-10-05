# INC-003 — Suspicious Account Creation & Promotion

## Summary
At 15:20:00 UTC, the SOC observed a high-severity correlation event on `lab-win11`: a new local user account named `lab-backdoor` was created (Event ID 4720), followed exactly 15 seconds later by the addition of that same account to the local `Administrators` security group (Event ID 4732). Wazuh correlation rule `100022` triggered, classifying the event as a High/Critical severity privilege escalation and persistence implant (T1136.001 / T1098). The account was promptly deleted as part of the simulation lifecycle, and administrative audit trails were reviewed.

---

## Severity
- **Severity Rating**: **HIGH / CRITICAL** (Wazuh Rule Level 12)
- **Confidence**: **High** (Deterministic correlation between Event ID 4720 and 4732 within 120s)
- **Calculated MTTD**: **15 seconds** (Time from user creation to promotion correlation alert)

---

## Date
- **Incident Date**: 2026-10-05
- **Detection Timestamp**: 2026-10-05T15:20:15Z
- **Containment Timestamp**: 2026-10-05T15:25:00Z

---

## Affected Asset
- **Hostname**: `lab-win11`
- **IP Address**: `192.168.56.20`
- **Role**: Windows 11 Enterprise (Victim 01)
- **Originating Account**: `LAB-WIN11\analyst`

---

## Data Source
- **Primary Source**: Windows Security Log (`Security.evtx`, Event IDs 4720, 4732, 4726)
- **Secondary Source**: Microsoft Sysmon (`Microsoft-Windows-Sysmon/Operational`, Event ID 1 for `net.exe` and `net1.exe`)
- **Ingestion Channel**: Wazuh Windows Agent (`win_eventchannel` decoder) -> Port 1514/TCP.

---

## Attack Simulation
Executed locally via elevated PowerShell on `lab-win11`:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\attacks\account-creation\simulate_account_tampering.ps1
```
The simulation sequentially:
1. Created user `lab-backdoor` with `net user`.
2. Added `lab-backdoor` to `Administrators` with `net localgroup`.
3. Deleted `lab-backdoor` after validating detection.

---

## Timeline

```text
15:20:00 UTC - Win Event 4720: User account 'lab-backdoor' created by subject 'analyst'. Wazuh Rule 100020 fires (Level 6).
15:20:00 UTC - Sysmon Event 1: net1.exe user lab-backdoor LabSecurePassword#2024 /add executed.
15:20:15 UTC - Win Event 4732: Member 'lab-backdoor' added to local group 'Administrators' by subject 'analyst'.
15:20:15 UTC - Wazuh Correlation Engine matches Rule 100022: Rule 100020 followed by Event 4732 in <120s. Level 12 Alert triggered.
15:20:25 UTC - Win Event 4726: User account 'lab-backdoor' deleted.
15:21:00 UTC - SOC Analyst begins investigation; confirms sequence is an unauthorized privilege elevation pattern.
```

---

## Evidence
- **Target User**: `lab-backdoor` (SID: `S-1-5-21-...-1005`)
- **Target Group**: `Administrators` (SID: `S-1-5-32-544`)
- **Subject User**: `LAB-WIN11\analyst`
- **Correlation Window**: 15 seconds elapsed between creation and promotion.
- **Raw Evidence Archive**: `evidence/logs/inc-003-raw-account.json`

---

## Logs
Excerpt from Wazuh Alert correlation:
```json
{
  "rule": {
    "id": "100022",
    "level": 12,
    "description": "DetectLab CRITICAL: Newly created user added to local Administrators group within 120s (T1136.001 / T1098)",
    "mitre": {
      "id": ["T1136.001", "T1098"],
      "tactic": ["Persistence", "Privilege Escalation"]
    }
  },
  "agent": { "id": "001", "name": "lab-win11" },
  "data": {
    "win": {
      "eventdata": {
        "targetUserName": "Administrators",
        "memberName": "lab-backdoor",
        "subjectUserName": "analyst"
      }
    }
  }
}
```

---

## Detection

### Detection Strategy
Individual user creations occur in IT environments (e.g., onboarding), and group changes also occur. However, a local user creation immediately followed by promotion into `Administrators` in **under 2 minutes** is a hallmark indicator of adversary lateral persistence (C2 post-exploitation scripts commonly drop and elevate accounts simultaneously).

### Detection Rule Specification
- **Rule ID**: `100022`
- **File**: `/var/ossec/etc/rules/local_rules.xml`
- **Logic**:
```xml
<rule id="100022" level="12" timeframe="120">
  <if_sid>100020</if_sid>
  <field name="win.system.eventID">^4732$|^4728$</field>
  <description>DetectLab CRITICAL: Newly created user added to local Administrators group within 120s (T1136.001 / T1098)</description>
  <mitre>
    <id>T1136.001</id>
    <id>T1098</id>
  </mitre>
</rule>
```
- **Portable Sigma Rule**: `detections/sigma/windows/win_account_created_and_promoted.yml`

---

## MITRE ATT&CK Mapping
- **Tactic**: Persistence (`TA0003`)
- **Technique**: Create Account: Local Account (`T1136.001`)
- **Tactic**: Privilege Escalation (`TA0004`)
- **Technique**: Account Manipulation (`T1098`)

---

## Investigation (SOC Analyst Analysis)
1. **Quem criou a conta?**
   - Conta `analyst` executando processo interativo local.
2. **Qual foi o nome e SID atribuído?**
   - Nome: `lab-backdoor`, SID: `S-1-5-21-1234567890-1234567890-1234567890-1005`.
3. **Qual grupo foi concedido?**
   - Grupo `Administrators` (SID bem conhecido `S-1-5-32-544`).
4. **Houve logon posterior com essa conta?**
   - Nenhuma tentativa de logon bem-sucedida (Event ID 4624) foi observada para `lab-backdoor` antes de sua exclusão.

---

## Indicators of Compromise (IOCs)

| Type | Indicator | Context | Action |
| :--- | :--- | :--- | :--- |
| **Username** | `lab-backdoor` | Rogue local account created | Verified deleted |
| **SID** | `S-1-5-21-...-1005` | Account security identifier | Revoked |
| **Binary Lineage** | `net.exe` -> `net1.exe` | Account creation utility invocation | Sysmon Event 1 monitored |

---

## False Positives
- IT desktop provisioning tools (e.g., automated Intune / MDM onboarding scripts) creating temporary local support accounts.
- Mitigação: Filtrar pelo `SubjectUserName` de contas de serviço autorizadas do domínio ou sistemas de gerenciamento de patches.

---

## Response & Mitigation
1. **Auditoria de Contas Locais**:
   - Executar `Get-LocalUser | Select-Object Name, Enabled, LastLogon` para listar contas órfãs.
2. **Implementar LAPS (Local Administrator Password Solution)**:
   - Elimina a necessidade de contas administrativas locais estáticas; randomiza senhas a cada ciclo.
3. **Restringir criação de contas via GPO**:
   - Bloquear criação de contas locais para usuários não-administrativos.

---

## Lessons Learned
1. Correlacionar múltiplos eventos (Criação de Conta -> Promoção a Admin) reduz dramaticamente o volume de falsos positivos comparado a monitorar adições ao grupo de forma isolada.
2. A janela de tempo de 120 segundos capturou com 100% de precisão o comportamento automatizado do script sem gerar ruído operacional.
