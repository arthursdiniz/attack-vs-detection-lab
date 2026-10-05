# Detection Engineering Methodology & Lifecycle

## 1. Overview & Detection Engineering Philosophy

Detection Engineering is the disciplined software engineering practice applied to threat detection. Rather than treating detection as an ad-hoc collection of static signatures, this laboratory implements a closed-loop, hypothesis-driven lifecycle adapted from industry standards (Palantir Alerting and Detection Strategy framework, MITRE ATT&CK, and Sigma).

```text
       ┌────────────────────────┐
       │ 1. Threat Intelligence │
       │    & Hypothesis        │
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │ 2. Controlled Attack   │
       │    Emulation (Lab)     │
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │ 3. Telemetry Gap       │
       │    Analysis & Sensing  │
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │ 4. Detection Logic     │
       │    (Wazuh XML / Sigma) │
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │ 5. False Positive      │
       │    Tuning & Resiliency │
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │ 6. Production Staging  │
       │    & Metric Validation │
       └────────────────────────┘
```

---

## 2. The 6-Stage Detection Engineering Pipeline

### Stage 1: Threat Hypothesis & MITRE ATT&CK Mapping
- **Input**: Threat intelligence or adversary emulation plans.
- **Process**: Define the threat actor objective (e.g., "Adversary will attempt to discover domain and local users via living-off-the-land commands").
- **Output**: Selection of specific MITRE ATT&CK Technique ID (`T1087.001 - Local Account Discovery`).

### Stage 2: Controlled Adversary Simulation
- **Principle**: Never write detection rules against theoretical logs. Generate ground truth telemetry in an isolated sandbox.
- **Execution**: Run reproducible scripts (e.g., `simulate_discovery_burst.ps1` or `simulate_powershell_telemetry.ps1`).
- **Safety**: Ensure 100% network isolation with Host-Only adapters (`192.168.56.0/24`).

### Stage 3: Telemetry Ingestion & Sensor Tuning
- **Inspection**: Examine the raw operating system artifacts.
  - Windows: Verify if `CommandLine`, `ParentImage`, and `Hashes` are captured in Sysmon Event ID 1.
  - Linux: Verify if `auditd` tags the syscall with the expected key (`-k discovery_execution`).
- **Optimization**: Filter out internal monitoring noise (e.g., excluding `wazuh-agent.exe` parent processes).

### Stage 4: Authoring Detection Logic (Atomic vs. Correlation)
- **Format 1 (Vendor-Neutral)**: Author portable Sigma YAML rules with explicit conditions (`count() by src_ip >= 10 timeframe: 1m`).
- **Format 2 (Wazuh SIEM)**: Implement XML rule definitions utilizing stateful sliding windows (`timeframe="60" frequency="10"`) and parent-child rule inheritance (`<if_sid>`, `<if_matched_sid>`).

### Stage 5: False Positive Mitigation & Stress Testing
- Every detection rule must undergo a false-positive review:
  1. **Administrative Tool Collision**: Do legitimate scripts (SCCM, Ansible, Puppet, Backup) use these flags?
  2. **Developer Workflows**: Do developers compile or stage scripts in `\AppData\Local\Temp\`?
  3. **Mitigation Strategy**: Combine parameters (e.g., alert only when `-EncodedCommand` is coupled with a non-standard parent process or an unauthorized user account).

### Stage 6: Validation, Deployment & Metrics
- Re-run the emulation suite to verify:
  - **Zero Alert Leakage**: The alert fires reliably across repeated runs.
  - **MTTD (Mean Time to Detect)**: Telemetry latency remains below 10 seconds.
  - **Alert Level Proportion**: Appropriate severity grading (Informational: 3-5, Medium: 6-8, High: 9-11, Critical: 12-16).
