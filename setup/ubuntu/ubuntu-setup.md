# Ubuntu Server Endpoint Provisioning & Telemetry Setup

## 1. Overview & Host Specifications

The Linux victim endpoint is `lab-ubuntu`, running **Ubuntu Server 22.04 LTS**. This server acts as an enterprise Linux host running services such as SSH and a test Web API, monitored via Linux Auditd, PAM authentication logs, and the Wazuh Linux Agent.

### System Specifications
- **Hostname**: `lab-ubuntu`
- **IP Address**: `192.168.56.30` (`Host-Only` adapter)
- **vCPUs**: 2
- **RAM**: 3 GB (or 2 GB under Profile B)
- **Disk**: 30 GB VDI

---

## 2. Linux Audit Daemon (`auditd`) & Log Baseline

Linux system calls, process executions, and security modifications are monitored via `auditd`:

### Step 1: Install auditd
```bash
sudo apt update && sudo apt install -y auditd audispd-plugins
sudo systemctl enable --now auditd
```

### Step 2: Configure Audit Rules for Security Monitoring
Add custom audit rules to `/etc/audit/rules.d/detect-lab.rules`:

```bash
sudo tee /etc/audit/rules.d/detect-lab.rules << 'EOF'
# Monitor modification of critical authentication files
-w /etc/passwd -p wa -k identity_modification
-w /etc/shadow -p wa -k identity_modification
-w /etc/group -p wa -k identity_modification
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/ssh/sshd_config -p wa -k sshd_tampering

# Monitor account creation tools
-w /usr/sbin/useradd -p x -k account_creation
-w /usr/sbin/adduser -p x -k account_creation
-w /usr/sbin/usermod -p x -k account_modification

# Monitor discovery commands
-w /bin/uname -p x -k system_discovery
-w /usr/bin/id -p x -k user_discovery
-w /usr/bin/whoami -p x -k user_discovery
EOF

# Reload audit rules
sudo augenrules --load
sudo auditctl -l
```

---

## 3. SSH Telemetry Enrichment

By default, OpenSSH logs minimal details. Increase verbosity to capture complete authentication artifacts:

```bash
# Set LogLevel to VERBOSE in /etc/ssh/sshd_config
sudo sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
sudo sed -i 's/LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config

# Ensure password authentication is initially enabled for brute-force baseline simulation
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Restart SSH service
sudo systemctl restart ssh
```

---

## 4. Wazuh Linux Agent Installation & Enrollment

### Step 1: Add Wazuh Repository and Install Agent
```bash
# Add Wazuh GPG key and repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt update

# Install agent with auto-enrollment targeting lab-wazuh
sudo WAZUH_MANAGER="192.168.56.40" WAZUH_AGENT_NAME="lab-ubuntu" apt install -y wazuh-agent
```

### Step 2: Validate Monitored Log Sources
Inspect `/var/ossec/etc/ossec.conf` to confirm that the following log sources are enabled:

```xml
<!-- System Authentication Logs -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>

<!-- Auditd Log Stream -->
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>

<!-- File Integrity Monitoring (Syscheck) -->
<syscheck>
  <directories check_all="yes" realtime="yes">/etc/passwd,/etc/shadow,/etc/ssh/sshd_config</directories>
</syscheck>
```

### Step 3: Enable and Start Agent Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo systemctl status wazuh-agent
```

---

## 5. Verification
Verify connection to the Wazuh Manager:
```bash
sudo /var/ossec/bin/agent-auth -m 192.168.56.40
nc -zv 192.168.56.40 1514
```
Expected output: Connection to `192.168.56.40` port `1514` [tcp] succeeded!
