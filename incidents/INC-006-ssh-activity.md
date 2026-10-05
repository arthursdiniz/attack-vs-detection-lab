# INC-006 — Suspicious SSH Activity & Account Compromise

## Summary
At 15:50:25 UTC, the SOC triggered a **CRITICAL** severity correlation alert on `lab-ubuntu`: a successful SSH authentication was established for the administrative account `ubuntu` originating from `192.168.56.10` (`lab-attacker`), immediately following 5 failed password attempts from that exact same IP within a 25-second window. Three seconds after logging in, the session executed `sudo /usr/bin/id` to confirm root administrative privileges. Wazuh correlation rule `100052` triggered at Level 14, classifying the incident as an **Active Account Compromise via Password Guessing** (`T1110.001` -> `T1078.003` -> `T1021.004`).

---

## Severity
- **Severity Rating**: **CRITICAL** (Wazuh Rule Level 14)
- **Confidence**: **High** (Deterministic correlation of failed logins immediately followed by valid login and privilege escalation from identical source IP)
- **Calculated MTTD**: **< 1 second** from successful auth to correlation alert.

---

## Date
- **Incident Date**: 2026-10-05
- **Detection Timestamp**: 2026-10-05T15:50:25Z
- **Containment Timestamp**: 2026-10-05T15:53:00Z

---

## Affected Asset
- **Hostname**: `lab-ubuntu`
- **IP Address**: `192.168.56.30`
- **Role**: Ubuntu Server 22.04 LTS (Victim 02)
- **Compromised User**: `ubuntu` (UID: 1000, Sudoers member)

---

## Data Source
- **Primary Source**: OpenSSH Daemon & Linux PAM (`/var/log/auth.log`)
- **Secondary Source**: Linux Audit Daemon (`/var/log/audit/audit.log` - `key=priv_escalation`)
- **Ingestion Channel**: Wazuh Linux Agent (`pam` & `sshd` decoders) -> Port 1514/TCP.

---

## Attack Simulation
Executed from `lab-attacker` (`192.168.56.10`):
```bash
python3 attacks/ssh-compromise/simulate_ssh_compromise.py \
    --target 192.168.56.30 \
    --port 22 \
    --user ubuntu \
    --valid-pwd "LabPassword2024!"
```

---

## Timeline

```text
15:50:01 UTC - Failed SSH authentication attempt for user 'ubuntu' from 192.168.56.10 (sshd PID 16100).
15:50:05 UTC - 2nd failed attempt from 192.168.56.10.
15:50:10 UTC - 3rd failed attempt from 192.168.56.10.
15:50:14 UTC - 4th failed attempt from 192.168.56.10.
15:50:18 UTC - 5th failed attempt from 192.168.56.10.
15:50:25 UTC - ACCEPTED password for 'ubuntu' from 192.168.56.10 port 49822 ssh2 (sshd PID 16110).
15:50:25 UTC - Wazuh Engine evaluates Rule 100052: Multi-stage correlation triggers. LEVEL 14 CRITICAL ALERT.
15:50:28 UTC - Sudo execution recorded: ubuntu executed /usr/bin/id with root privileges.
15:51:00 UTC - SOC Analyst begins immediate containment.
15:53:00 UTC - Session terminated; source IP banned via iptables.
```

---

## Evidence
- **Source IP**: `192.168.56.10`
- **Target User**: `ubuntu` (Member of `sudo` group)
- **Failure Window**: 5 failures between 15:50:01 and 15:50:21 UTC.
- **Success Timestamp**: 15:50:25 UTC.
- **Subsequent Activity**: Execution of `sudo /usr/bin/id` 3 seconds post-authentication.
- **Raw Evidence Archive**: `evidence/logs/inc-006-raw-ssh.log`

---

## Detection

### Correlation Logic
$$\text{Multiple Failed Logins (Rule 5716 / 5503)} \xrightarrow[\text{same } srcip]{\le 180 \text{ s}} \text{Successful Login (Rule 5715)} \Longrightarrow \mathbf{\text{Alerta Crítico (Rule 100052 - Level 14)}}$$

```xml
<rule id="100052" level="14" timeframe="180">
  <if_sid>5715</if_sid>
  <if_matched_sid>5710, 5716, 5503</if_matched_sid>
  <same_srcip />
  <description>DetectLab CRITICAL: Successful SSH authentication following multiple failures from same IP (Possible Account Compromise - T1078 / T1021.004).</description>
  <mitre>
    <id>T1078.003</id>
    <id>T1021.004</id>
    <id>T1110.001</id>
  </mitre>
</rule>
```
- **Portable Sigma Rule**: `detections/sigma/linux/lnx_ssh_compromise_after_brute_force.yml`

---

## MITRE ATT&CK Mapping
- **Tactic**: Credential Access (`TA0006`) -> Technique: Brute Force (`T1110.001`)
- **Tactic**: Initial Access (`TA0001`) -> Technique: Valid Accounts: Local Accounts (`T1078.003`)
- **Tactic**: Lateral Movement (`TA0008`) -> Technique: Remote Services: SSH (`T1021.004`)
- **Tactic**: Privilege Escalation (`TA0004`) -> Technique: Sudo and Sudo Caching (`T1548.003`)

---

## Investigation (SOC Analyst Analysis)
1. **O login foi legítimo ou invasivo?**
   - A sequência imediata de 5 falhas nos 24 segundos anteriores provenientes do mesmo IP comprova que o logon bem-sucedido resultou de adivinhação automatizada e não de um acesso administrativo programado.
2. **Qual nível de privilégio foi obtido?**
   - O usuário `ubuntu` possui acesso irrestrito ao `sudo` sem restrição de comando, conferindo controle total de superusuário (root) ao atacante.
3. **Quais ações foram tomadas após o login?**
   - O comando `sudo /usr/bin/id` foi executado para confirmar privilégios de root antes de qualquer tentativa de persistência.

---

## Incident Response & Containment
1. **Kill Active TTY Sessions**:
   ```bash
   sudo pkill -KILL -u ubuntu
   ```
2. **Dynamic Firewall Drop**:
   ```bash
   sudo iptables -I INPUT -s 192.168.56.10 -j DROP
   ```
3. **Rotate Compromised Credentials**:
   ```bash
   sudo passwd ubuntu
   ```

---

## Mitigation & Hardening
- Desabilitar totalmente a autenticação por senha no SSH:
  ```bash
  PasswordAuthentication no
  PubkeyAuthentication yes
  ```
- Exigir autenticação baseada exclusivamente em chaves criptográficas Ed25519/RSA.

---

## Lessons Learned
1. A correlação de falhas seguidas por sucesso é um dos alertas de maior fidelidade em um SOC corporativo, com taxa de falso positivo próxima de zero.
2. Permitir autenticação SSH por senha em contas com privilégios `sudo` cria um risco existencial para servidores de produção.
