# INC-001 — Authentication Brute Force

## Summary
At 14:30:01 UTC, the Security Operations Center (SOC) detected an automated, high-frequency authentication brute-force attack originating from `192.168.56.10` (`lab-attacker`) targeting the SSH service on `192.168.56.30` (`lab-ubuntu`). Within a 40-second window, 20 consecutive authentication failures were observed against the local user account `lab-target`. Wazuh custom correlation rule `100001` triggered at the 10th failure, generating a High Severity alert. No subsequent successful logons were identified for the attacker IP. The host was contained by implementing rate limiting and Fail2Ban jail policies.

---

## Severity
- **Severity Rating**: **HIGH** (Wazuh Rule Level 10)
- **Confidence**: **High** (Deterministic threshold match across PAM and OpenSSH logs)
- **Calculated MTTD (Mean Time to Detect)**: **32 seconds** from first probe to threshold alert.

---

## Date
- **Incident Date**: 2026-10-05
- **Detection Timestamp**: 2026-10-05T14:30:33Z
- **Containment Timestamp**: 2026-10-05T14:38:00Z

---

## Affected Asset
- **Hostname**: `lab-ubuntu`
- **IP Address**: `192.168.56.30`
- **Role**: Ubuntu Server 22.04 LTS (Victim 02)
- **Monitored Services**: OpenSSH Daemon (Port 22/TCP)

---

## Data Source
- **Primary Source**: Linux PAM & System Authentication Log (`/var/log/auth.log`)
- **Secondary Source**: Linux Audit Daemon (`/var/log/audit/audit.log`)
- **Ingestion Channel**: Wazuh Linux Agent (Agent ID `002`) -> Wazuh Manager via Port 1514/TCP (`sshd` & `pam` decoders).

---

## Attack Simulation
The adversary simulation was executed from `lab-attacker` (`192.168.56.10`) using the controlled simulation script:
```bash
python3 attacks/T1110-brute-force/simulate_brute_force.py \
    --target 192.168.56.30 \
    --port 22 \
    --username lab-target \
    --attempts 20 \
    --delay 2.0
```
The script cycled through a list of 15 dictionary passwords, transmitting one authentication attempt every ~2 seconds.

---

## Timeline

```text
14:30:01 UTC - Initial failed SSH authentication attempt observed from 192.168.56.10 for user 'lab-target' (sshd PID 14501).
14:30:05 UTC - 3rd consecutive failed attempt recorded.
14:30:13 UTC - 7th failed attempt recorded.
14:30:32 UTC - 10th consecutive failed authentication attempt recorded within 31 seconds.
14:30:33 UTC - Wazuh Engine evaluates threshold: Rule 100001 triggers (Level 10 - High Alert).
14:30:33 UTC - OpenSearch indexes alert document into 'wazuh-alerts-4.x-*'.
14:30:35 UTC - Alert appears on Wazuh SOC Dashboard.
14:30:41 UTC - Attacker simulation concludes after 20 attempts (PID 14519).
14:32:00 UTC - SOC Analyst begins active triage and IP pivoting.
14:38:00 UTC - Remediation applied: IP temporarily isolated via iptables, SSH hardening enacted.
```

---

## Evidence
- **Alert ID**: `wazuh-alert-100001-20261005-001`
- **Triggering Rule**: `100001` (DetectLab: High frequency of failed authentications from same source IP)
- **Source IP**: `192.168.56.10`
- **Target User**: `lab-target`
- **Failure Count**: 20 attempts total (10 attempts triggered the correlation threshold)
- **Raw Evidence Archive**: `evidence/logs/inc-001-raw-auth.log`

---

## Logs

### Excerpt from `/var/log/auth.log` on `lab-ubuntu`:
```text
2026-10-05T14:30:01.102345+00:00 lab-ubuntu sshd[14501]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.10  user=lab-target
2026-10-05T14:30:03.220194+00:00 lab-ubuntu sshd[14501]: Failed password for lab-target from 192.168.56.10 port 49152 ssh2
...
2026-10-05T14:30:32.902011+00:00 lab-ubuntu sshd[14515]: Failed password for lab-target from 192.168.56.10 port 49166 ssh2
```

### Indexed Wazuh Alert JSON:
```json
{
  "timestamp": "2026-10-05T14:30:33.004+0000",
  "rule": {
    "level": 10,
    "description": "DetectLab: High frequency of failed authentications from same source IP (Possible Brute Force / Spray - T1110.001).",
    "id": "100001",
    "mitre": {
      "id": ["T1110.001"],
      "tactic": ["Credential Access"],
      "technique": ["Password Guessing"]
    },
    "frequency": 10
  },
  "agent": {
    "id": "002",
    "name": "lab-ubuntu",
    "ip": "192.168.56.30"
  },
  "data": {
    "srcip": "192.168.56.10",
    "dstuser": "lab-target"
  }
}
```

---

## Detection

### Detection Strategy
The detection combines atomic log matching (PAM and OpenSSH password failures) with stateful sliding-window frequency counting. When the count of failed events sharing the identical `<same_srcip />` reaches **10** within **60 seconds**, the threshold is satisfied.

### Detection Rule Specification
- **Rule ID**: `100001`
- **File**: `/var/ossec/etc/rules/local_rules.xml`
- **Logic**:
```xml
<rule id="100001" level="10" frequency="10" timeframe="60">
  <if_matched_sid>5710, 5716, 5760, 5503, 60122</if_matched_sid>
  <same_srcip />
  <description>DetectLab: High frequency of failed authentications from same source IP (Possible Brute Force / Spray - T1110.001).</description>
  <mitre>
    <id>T1110.001</id>
    <tactic>Credential Access</tactic>
    <technique>Password Guessing</technique>
  </mitre>
</rule>
```
- **Portable Sigma Rule**: `detections/sigma/linux/lnx_ssh_brute_force_auth.yml`

---

## MITRE ATT&CK Mapping
- **Tactic**: Credential Access (`TA0006`)
- **Technique**: Brute Force (`T1110`)
- **Sub-Technique**: Password Guessing (`T1110.001`)
- **Data Source**: `Logon Session: Logon Session Creation`

---

## Investigation (SOC Analyst Analysis)

To ensure exhaustive incident analysis, the investigation addressed the 8 critical SOC questions:

1. **Quem realizou as tentativas?**
   - IP de Origem: `192.168.56.10` (resolvido para o host `lab-attacker` na sub-rede do laboratório).
2. **Qual usuário foi alvo?**
   - Usuário: `lab-target` (conta local configurada para o teste).
3. **Quantas tentativas ocorreram?**
   - Total de 20 tentativas consecutivas de autenticação falha.
4. **Quando começaram?**
   - Início: `14:30:01 UTC`.
5. **Quando terminaram?**
   - Término: `14:30:41 UTC` (duração total: 40 segundos; cadência de ~1 tentativa a cada 2 segundos).
6. **Houve autenticação bem-sucedida depois?**
   - **Não**. Uma busca de 30 minutos pós-ataque por eventos de sucesso (`sshd: Accepted password` ou `rule.id: 5715`) com `srcip: 192.168.56.10` retornou **zero resultados**. A regra de correlação crítica `100002` (Compromise after Brute Force) não disparou.
7. **O IP realizou outras atividades?**
   - Verificou-se o tráfego nos logs de firewall e outros nós. O IP `192.168.56.10` executou apenas varreduras prévias de porta SYN (Port 22/80) 5 minutos antes do ataque, confirmando fase de reconhecimento prévio (T1046 Network Service Scanning).
8. **Outros usuários foram testados?**
   - **Não**. Todas as 20 tentativas focaram exclusivamente em `lab-target`. Não se tratou de um *Password Spray* horizontal (múltiplos usuários com uma senha), mas sim de um *Brute Force / Password Guessing* vertical (um usuário com múltiplos palpites de senha - T1110.001).

---

## Indicators of Compromise (IOCs)

| Type | Indicator | Context | Action |
| :--- | :--- | :--- | :--- |
| **IPv4** | `192.168.56.10` | Origin of brute-force dictionary attacks | Added to temporary blocklist |
| **User Account** | `lab-target` | Target of brute-force campaign | Monitored, password verified |
| **User-Agent / Banner** | `SSH-2.0-DetectLab_Adversary_Simulation_T1110` | Adversary tool client banner | Signature added to network monitoring |

---

## False Positives Analysis
1. **Misconfigured Automation Services**: Scripts Ansible ou pipelines de CI/CD utilizando credenciais desatualizadas ou chaves expiradas podem gerar rajadas rápidas de falha.
2. **User Password Typos**: Usuários humanos raramente erram a senha 10 vezes em 60 segundos; tipicamente erram 2 a 3 vezes antes de pausar para verificar Caps Lock.
3. **Mitigação do Falso Positivo**: Threshold de 10 tentativas em 60s filtra 99% dos erros humanos convencionais, mantendo alta sensibilidade para ferramentas automatizadas como Hydra e scripts Python.

---

## Response (NIST IR Lifecycle)

1. **Triage**: Alerta classificado como Prioridade Alta; verificado que não houve logon bem-sucedido.
2. **Containment**: Bloqueio temporário da porta 22 para a origem via iptables:
   ```bash
   sudo iptables -I INPUT -s 192.168.56.10 -p tcp --dport 22 -j DROP
   ```
3. **Eradication**: Verificação de que nenhuma sessão residual ou processo backdoor foi deixado em execução.
4. **Recovery**: Verificação da integridade da conta `lab-target` e liberação após hardening.
5. **Lessons Learned**: Implementar bloqueio automático no endpoint com Fail2Ban e desabilitar autenticação por senha para mitigar o vetor na raiz.

---

## Mitigation & Hardening
Ver guia completo de hardening defensivo em [hardening/linux-ssh-hardening.md](../hardening/linux-ssh-hardening.md).
- Instalação do Fail2Ban com jail SSH (bloqueio automático após 3 falhas).
- Limitação de tentativas no `sshd_config` (`MaxAuthTries 3`).
- Desabilitação de login de root via senha.

---

## Validation (Before vs. After Hardening)

| Metric / Parameter | Before Hardening (Baseline) | After Hardening (Hardened) |
| :--- | :--- | :--- |
| **Password Auth** | Enabled | Restricted / Rate Limited |
| **Max Auth Tries** | Default (6) | 3 |
| **Fail2Ban Protection** | None | Active (Jail `sshd` enabled) |
| **Adversary Attempts Allowed** | 20+ uninterrupted attempts | Connection dropped at 3rd attempt |
| **SIEM High Alert** | Rule `100001` triggered (10 failures) | Blocked by Fail2Ban at failure #3 |
| **Credential Attack Risk** | High (Dictionary attack succeeds if pwd in list) | Negligible (Attacker banned for 10m) |

---

## Lessons Learned
1. A correlação de frequência baseada em tempo (`frequency="10" timeframe="60"`) provou ser altamente eficaz para detectar ferramentas automatizadas como Hydra.
2. Aumentar a verbosidade do OpenSSH (`LogLevel VERBOSE`) foi o fator decisivo para registrar o endereço IP de origem exato em cada falha. Sem essa configuração, alguns logs agregam falhas sem expor a origem do socket.
3. A integração entre SIEM (Wazuh) e mitigação ativa no host (Fail2Ban ou Wazuh Active Response) é necessária para conter ataques em tempo real antes que o limiar de alerta seja atingido.
