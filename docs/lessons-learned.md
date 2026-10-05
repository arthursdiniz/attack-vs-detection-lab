# Engineering Lessons Learned & SOC Pitfalls

## 1. Overview

Building this laboratory from bare-metal hypervisor to full SIEM detection engineering provided operational insights that theoretical study cannot replicate. Below are the key engineering lessons and operational pitfalls documented during the development of this project.

---

## 2. Critical Engineering Insights

### Lesson 1: Monitoring Agent Recursion Loops (The "Log Storm" Threat)
- **The Problem**: When Sysmon was initially configured to log all process creations and network connections without exclusions, Wazuh's internal monitoring daemon (`wazuh-agent.exe`) launched subprocesses to check system state. Each subprocess spawned a Sysmon Event ID 1 log. That log was written to disk, which prompted the Wazuh Agent to open a network socket on port 1514 to transmit it, triggering a Sysmon Event ID 3 (Network Connection). This generated a cascading loop that flooded 50,000+ events per minute, consuming 100% CPU.
- **The Solution**: Explicitly whitelist the monitoring agent's parent process and transmission socket in [setup/windows/sysmonconfig.xml](../setup/windows/sysmonconfig.xml):
  ```xml
  <ParentImage condition="is">C:\Program Files (x86)\ossec-agent\wazuh-agent.exe</ParentImage>
  <DestinationPort condition="is">1514</DestinationPort>
  ```

### Lesson 2: Clock Drift Kills Time-Sliding Correlation Rules
- **The Problem**: Multi-event correlation rules (e.g., Rule `100022` correlating user creation to admin elevation within 120s, or Rule `100052` correlating failed logins to success) rely on accurate event arrival timestamps. When a virtual machine pauses or suffers hypervisor clock drift by even 90 seconds, the SIEM's sliding-window evaluation engine discards the preceding events as expired, causing correlation rules to fail silently.
- **The Solution**: Ensure strict guest-to-host clock synchronization using VirtualBox Guest Additions and local NTP time-servers before running time-sensitive tests.

### Lesson 3: Default OpenSSH Logging is Insufficient for SOC Triage
- **The Problem**: Default Debian/Ubuntu OpenSSH configurations (`LogLevel INFO`) log authentication attempts, but frequently truncate client protocol details and aggregate failures.
- **The Solution**: Setting `LogLevel VERBOSE` in `/etc/ssh/sshd_config` forces OpenSSH to explicitly log client IP addresses, ephemeral ports, key algorithms, and detailed PAM failure codes for every single attempt.

### Lesson 4: Atomic vs. Burst Behavioral Scoring (LOLBin Detection)
- **The Problem**: Alerting on every execution of living-off-the-land binaries (LOLBins) like `ipconfig.exe`, `whoami.exe`, or `net.exe` produces an unmanageable false-positive rate. Sysadmins and automated software utilities run these commands hundreds of times a day.
- **The Solution**: Implement **Frequency Burst Scoring** (Wazuh Rule `100041`). By setting `frequency="5" timeframe="30"`, individual commands remain informational (Level 5), but any automated script executing 5 distinct discovery tools in under 30 seconds triggers an immediate High Severity alert (Level 10).

### Lesson 5: Structured JSON Logging Accelerates DevSecOps Triage
- **The Problem**: Legacy text logs (syslog, IIS format) require fragile regular expressions in SIEM decoders that break whenever developers alter log punctuation or whitespace.
- **The Solution**: Emitting structured JSON logs from the Spring Boot application directly into `/var/log/detectlab/app-security.json` allows the Wazuh JSON decoder to automatically parse and index all fields (`sourceIp`, `event`, `username`, `endpoint`) without writing a single line of custom regex.
