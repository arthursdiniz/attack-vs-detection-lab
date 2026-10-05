# INC-007 — Web Application Authentication & Probing Detection

## Summary
At 16:15:01 UTC, the Wazuh SIEM detected an automated attack sequence targeting the laboratory's Spring Boot Web Application (`http://192.168.56.30:8080`). Emitted structured JSON security audit logs (`app-security.json`) captured 12 consecutive failed login attempts against `/login` from `192.168.56.10` within 15 seconds, satisfying Wazuh Rule `100061` (Web Authentication Brute Force). Concurrently, the attacker executed repeated unauthenticated requests to the restricted administrative route `/api/users` (generating HTTP 403 / `ACCESS_DENIED`) and probed for legacy configuration files (`/.env`, `/admin.php`), triggering Rule `100062` and `100063`.

---

## Severity
- **Severity Rating**: **HIGH** (Wazuh Rule Level 10)
- **Confidence**: **High** (Application-layer structured telemetry with client IP, status code, and endpoint)
- **Calculated MTTD**: **10 seconds** (Threshold met at 10th failed login)

---

## Date
- **Incident Date**: 2026-10-05
- **Detection Timestamp**: 2026-10-05T16:15:10Z
- **Containment Timestamp**: 2026-10-05T16:20:00Z

---

## Affected Asset
- **Application**: Spring Boot Security API (Java 17 / Logback JSON)
- **Host**: `lab-ubuntu` (`192.168.56.30`)
- **Port**: `8080/TCP`

---

## Data Source
- **Log Source**: Application JSON Audit Log (`/var/log/detectlab/app-security.json`)
- **Format**: Structured single-line JSON (`timestamp`, `event`, `username`, `sourceIp`, `endpoint`, `httpStatus`, `message`)
- **Ingestion Channel**: Wazuh Agent `<localfile>` JSON log collector -> Manager Port 1514/TCP.

---

## Attack Simulation
Executed from `lab-attacker` (`192.168.56.10`):
```bash
python3 attacks/web-authentication/simulate_web_attacks.py --url http://192.168.56.30:8080
```
The script simulated:
1. 12 failed logins to `/login` via HTTP POST.
2. 5 unauthorized accesses to `/api/users` via HTTP GET without JWT Bearer header.
3. 5 probing requests targeting sensitive non-existent endpoints (`/.env`, `/admin.php`).

---

## Timeline

```text
16:15:01 UTC - POST /login: 1st failed authentication for user 'admin' from 192.168.56.10 (HTTP 401).
16:15:05 UTC - POST /login: 5th failed authentication.
16:15:10 UTC - POST /login: 10th failed authentication within 10s.
16:15:10 UTC - Wazuh Correlation Engine matches Rule 100061: Web Login Brute Force. Level 10 Alert generated.
16:15:15 UTC - GET /api/users: Repeated HTTP 403 ACCESS_DENIED from 192.168.56.10. Rule 100062 triggers.
16:15:20 UTC - GET /.env: Endpoint probing detected (HTTP 404). Rule 100063 triggers.
16:16:00 UTC - SOC Analyst confirms application layer attack campaign.
```

---

## Evidence & Structured Logs

### Sample Ingested Log Record:
```json
{
  "timestamp": "2026-10-05T16:15:10.120Z",
  "event": "LOGIN_FAILED",
  "username": "admin",
  "sourceIp": "192.168.56.10",
  "endpoint": "/login",
  "httpStatus": 401,
  "message": "Invalid credentials provided"
}
```

### Indexed Wazuh Alert:
```json
{
  "rule": {
    "id": "100061",
    "level": 10,
    "description": "DetectLab: High frequency of web application failed logins (Web Brute Force - T1110.001)",
    "mitre": { "id": ["T1110.001"], "tactic": ["Credential Access"] }
  },
  "data": {
    "sourceIp": "192.168.56.10",
    "endpoint": "/login",
    "event": "LOGIN_FAILED"
  }
}
```

---

## Detection Rule Specification
- **Rule ID**: `100061` (Web Brute Force), `100062` (Forbidden Endpoint Probing), `100063` (API Route Discovery)
- **File**: `/var/ossec/etc/rules/local_rules.xml`
- **Portable Sigma Rules**:
  - `detections/sigma/web/web_login_brute_force.yml`
  - `detections/sigma/web/web_unauthorized_endpoint_probing.yml`

---

## MITRE ATT&CK Mapping
- **Tactic**: Credential Access (`TA0006`) -> Technique: Brute Force: Password Guessing (`T1110.001`)
- **Tactic**: Reconnaissance (`TA0043`) -> Technique: Active Scanning: Vulnerability Scanning (`T1595.002`)
- **Tactic**: Initial Access (`TA0001`) -> Technique: Exploit Public-Facing Application (`T1190`)

---

## Investigation (SOC Analyst Analysis)
1. **Qual endpoint web foi alvo de ataque de força bruta?**
   - Rota `/login` via método POST.
2. **Qual usuário foi atacado na aplicação?**
   - Usuário `admin`.
3. **Houve sucesso de login após o ataque?**
   - Não. Nenhuma entrada `LOGIN_SUCCESS` foi gerada para o IP `192.168.56.10`.
4. **Houve tentativa de bypass de autorização?**
   - O atacante tentou consultar diretamente `/api/users` sem fornecer o token de portador (`Bearer token`), recebendo HTTP 403 Forbidden.

---

## Mitigation & DevSecOps Hardening
1. **Rate Limiting at API Gateway / Filter**:
   - Implementar Bucket4j no Spring Boot limitando requisições a 5 tentativas de login por minuto por IP.
2. **Account Lockout Policy**:
   - Bloquear temporariamente a conta `admin` após 5 tentativas inválidas consecutivas.
3. **CAPTCHA / Multi-Factor Authentication (MFA)**:
   - Exigir desafio interativo em tentativas consecutivas.

---

## Lessons Learned
1. Emitir logs em **JSON estruturado padronizado** reduz o custo de decodificação no SIEM para praticamente zero, eliminando o uso de regexes complexas em decoders.
2. A integração direta entre eventos da camada de aplicação (DevSecOps) e o SIEM corporativo preenche a lacuna crítica que firewalls de rede e sensores de host convencionais não conseguem enxergar.
