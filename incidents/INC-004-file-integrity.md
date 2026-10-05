# INC-004 — Critical File Modification

## Summary
At 15:30:15 UTC, the Wazuh File Integrity Monitoring (FIM / `syscheck`) engine alerted on unauthorized modifications to sensitive system files across both Linux and Windows endpoints. On `lab-ubuntu`, an integrity alert was generated for `/etc/passwd` indicating modified MD5/SHA256 checksums and an altered line diff. On `lab-win11`, a sensitive staging configuration file in `C:\LabStaging\` had its `ADMIN_BYPASS` flag altered from `FALSE` to `TRUE`. The real-time FIM engine captured both before-and-after cryptographic hashes, file ownership, permissions, and the exact textual diff.

---

## Severity
- **Severity Rating**: **HIGH** (Wazuh Rule 550 / Custom Rule 100030)
- **Confidence**: **High** (Cryptographic hash mismatch verification)
- **Calculated MTTD**: **< 5 seconds** (Real-time inotify / Windows ReadDirectoryChangesW trigger)

---

## Date
- **Incident Date**: 2026-10-05
- **Detection Timestamp**: 2026-10-05T15:30:15Z
- **Containment Timestamp**: 2026-10-05T15:35:00Z

---

## Affected Asset
- **Asset 1**: `lab-ubuntu` (`192.168.56.30`) — `/etc/passwd`
- **Asset 2**: `lab-win11` (`192.168.56.20`) — `C:\LabStaging\sensitive-config.txt`

---

## Data Source
- **Data Source**: Wazuh `syscheck` (File Integrity Monitoring)
- **Ingestion Channel**: Wazuh Agent -> Manager Port 1514/TCP.

---

## Attack Simulation
Executed controlled modifications:
1. On Linux: Appended comment marker to `/etc/passwd` via `simulate_linux_fim.sh`.
2. On Windows: Toggled configuration value via `simulate_file_tampering.ps1`.

---

## Timeline

```text
15:30:10 UTC - Controlled script appends comment marker to /etc/passwd on lab-ubuntu.
15:30:15 UTC - Linux inotify event triggers Wazuh syscheck engine.
15:30:15 UTC - Wazuh Manager matches Rule 550: Checksum changed for /etc/passwd.
15:32:00 UTC - Controlled script edits C:\LabStaging\sensitive-config.txt on lab-win11.
15:32:10 UTC - Windows agent detects directory modification event; computes SHA256 delta.
15:32:10 UTC - Alert indexed on Wazuh Dashboard displaying side-by-side diff.
```

---

## Evidence & Hash Deltas

### Record 1: `/etc/passwd` (Ubuntu)
- **Path**: `/etc/passwd`
- **Host**: `lab-ubuntu`
- **User**: `root`
- **Permissions**: `0644`
- **SHA256 Before**: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- **SHA256 After**: `f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2`
- **Captured Diff**:
  ```diff
  --- /etc/passwd
  +++ /etc/passwd
  @@ -38,3 +38,4 @@
  + # DetectLab_FIM_Simulation_Marker_1791214215
  ```

### Record 2: `C:\LabStaging\sensitive-config.txt` (Windows)
- **Path**: `C:\LabStaging\sensitive-config.txt`
- **Host**: `lab-win11`
- **User**: `LAB-WIN11\analyst`
- **SHA256 Before**: `5E884898DA28047151D0E56F8DC6292773603D0D6AABDD62A11EF721D1542D8`
- **SHA256 After**: `4B227777D4DD1FC61C6F884F48641D02B4D121D3FD328CB08B5531FCACDABF8A`
- **Captured Diff**:
  ```diff
  -ADMIN_BYPASS=FALSE
  +ADMIN_BYPASS=TRUE
  ```

---

## Detection Rule Specification
- **Rule ID**: `550` (Standard FIM checksum mismatch) & `100030` (Critical Directory Watch)
- **Portable Sigma Rule**: `detections/sigma/windows/win_fim_critical_file_modified.yml`

---

## MITRE ATT&CK Mapping
- **Tactic**: Impact (`TA0040`) / Defense Evasion (`TA0005`)
- **Technique**: Stored Data Manipulation (`T1565.001`)

---

## Investigation (SOC Analyst Analysis)
1. **O arquivo modificado era legítimo?**
   - Sim, `/etc/passwd` e o arquivo de configuração de staging são arquivos monitorados.
2. **Quem efetuou a alteração?**
   - No Linux, o usuário `root`; no Windows, o usuário `analyst`.
3. **Qual foi o conteúdo exato alterado?**
   - A funcionalidade `report_changes="yes"` do Wazuh forneceu o diff exato linha a linha no corpo do alerta, permitindo ao analista verificar imediatamente que a alteração no Windows habilitava um bypass de autenticação.

---

## Mitigation & Hardening
1. **Immutable Flags on Linux (`chattr`)**:
   - `sudo chattr +i /etc/passwd /etc/shadow` impede que mesmo o usuário root modifique os arquivos sem remover o bit imutável explicitamente.
2. **Access Control Lists (ACLs) on Windows**:
   - Restringir permissões de escrita de diretórios sensíveis exclusivamente ao `NT AUTHORITY\SYSTEM`.
3. **Automated Rollback via Active Response**:
   - Configurar scripts de resposta ativa no Wazuh para restaurar backups automáticos de arquivos críticos quando alterações não programadas forem detectadas.

---

## Lessons Learned
1. Habilitar `report_changes="yes"` no Wazuh transforma o FIM de um mero indicador binário em uma ferramenta forense de alta resolução, poupando tempo crítico de investigação.
2. Configurar o modo `realtime="yes"` garantiu MTTD inferior a 5 segundos.
