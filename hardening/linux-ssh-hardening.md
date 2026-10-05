# Linux SSH Defensive Hardening & Mitigation Guide

## 1. Vulnerability Baseline (Before Hardening)

In the initial laboratory baseline, the SSH service on `lab-ubuntu` was intentionally configured with relaxed controls to observe brute-force telemetry:
- **Password Authentication**: Enabled.
- **Root Login**: Permitted via password.
- **Max Authentication Tries**: Default (6 attempts per session).
- **Rate Limiting**: None.
- **Automated Host Banning**: None.

Under this configuration, an adversary could execute hundreds of dictionary attacks uninterrupted until either the target service crashed or the password was guessed.

---

## 2. Hardening Implementation (After Hardening)

### Step 1: Deploy and Configure Fail2Ban
Fail2Ban monitors log files (`/var/log/auth.log`) and dynamically updates firewall rules to block IPs exceeding failure thresholds:

```bash
# Install Fail2Ban
sudo apt update && sudo apt install -y fail2ban

# Create custom local jail configuration
sudo tee /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 10m
findtime = 60s
maxretry = 3
backend  = systemd

[sshd]
enabled = true
port    = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 10m
EOF

# Restart and enable Fail2Ban
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

### Step 2: OpenSSH Server Hardening (`/etc/ssh/sshd_config`)
Apply the following defensive directives:

```bash
sudo tee -a /etc/ssh/sshd_config.d/99-hardened.conf << 'EOF'
# Limit authentication attempts per connection to 3
MaxAuthTries 3

# Disallow direct root authentication
PermitRootLogin no

# Reduce login grace window to mitigate connection exhaustion
LoginGraceTime 30

# Restrict authentication to verified lab accounts only
AllowUsers lab-target analyst ubuntu
EOF

# Validate SSH syntax and restart service
sudo sshd -t
sudo systemctl restart ssh
```

### Step 3: Firewall Rate Limiting via iptables
Enforce a network-level threshold preventing port scanning bursts:

```bash
# Rate limit new SSH connections to 3 per minute per source IP
sudo iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH_BURST
sudo iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH_BURST -j DROP
```

---

## 3. Validation & Comparative Results

### Re-running the Adversary Simulation
From `lab-attacker` (`192.168.56.10`):
```bash
python3 attacks/T1110-brute-force/simulate_brute_force.py --target 192.168.56.30 --attempts 12
```

### Telemetry Comparison Table

| Metric | Before Hardening | After Hardening |
| :--- | :--- | :--- |
| **Max Failed Attempts Reached** | 20+ uninterrupted attempts | Banned at attempt #3 |
| **Fail2Ban Action** | None | IP `192.168.56.10` added to `f2b-sshd` iptables chain |
| **Attacker Experience** | Continued password guesses | `Connection refused` / `Operation timed out` |
| **Wazuh Log Storm** | 20 separate failure logs | 3 failure logs + 1 Fail2Ban ban alert |
| **Account Compromise Probability** | High (Dictionary depth) | Near Zero (Dynamic IP throttling) |

### Fail2Ban Verification Command
```bash
sudo fail2ban-client status sshd
# Output:
# Status for the jail: sshd
# |- Filter
# |  |- Currently failed: 0
# |  |- Total failed:     3
# `- Actions
#    |- Currently banned: 1
#    `- Banned IP list:   192.168.56.10
```
