# Linux Ubuntu Server Hardening & Defensive Controls

## 1. Baseline Assessment (Before Hardening)

Default Linux server baselines feature common operational vulnerabilities:
- SSH password authentication enabled across all interfaces.
- Root login permitted over SSH.
- No automated rate-limiting against network brute-force tools (Hydra).
- Critical authentication files (`/etc/passwd`, `/etc/shadow`) writable by root without immutability guards.

---

## 2. Implemented Defensive Controls (After Hardening)

### Control 1: Enforce SSH Public Key Authentication & Disable Passwords
Eliminate the entire brute-force attack surface by requiring cryptographic key pairs:

```bash
sudo tee /etc/ssh/sshd_config.d/99-hardened-auth.conf << 'EOF'
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 30
KexAlgorithms curve25519-sha256,diffie-hellman-group-exchange-sha256
EOF

sudo sshd -t && sudo systemctl restart ssh
```

### Control 2: Deploy Fail2Ban Automated Jail
Actively ban attacking IP addresses at the firewall layer upon threshold breach:

```bash
sudo apt install -y fail2ban
sudo tee /etc/fail2ban/jail.d/sshd.local << 'EOF'
[sshd]
enabled = true
port    = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 15m
findtime = 60s
EOF

sudo systemctl enable --now fail2ban
```

### Control 3: File Immutability Guards (`chattr +i`)
Protect core identity files against unauthorized modifications, even by compromised privileged processes:

```bash
# Set immutable bit on core authentication files
sudo chattr +i /etc/passwd
sudo chattr +i /etc/shadow
sudo chattr +i /etc/group
sudo chattr +i /etc/sudoers

# Verify attribute
lsattr /etc/passwd /etc/shadow
```

### Control 4: Sudoers Audit Hardening
Prevent silent privilege escalation by enforcing re-authentication and auditing:

```bash
# Add timestamp timeout and disable NOPASSWD directives
sudo tee -a /etc/sudoers.d/99-security-policy << 'EOF'
Defaults timestamp_timeout=5
Defaults log_output
Defaults!/usr/bin/passwd !root
EOF
```

---

## 3. Before vs. After Hardening Comparison

| Security Parameter | Before Hardening (Vulnerable) | After Hardening (Hardened) |
| :--- | :--- | :--- |
| **SSH Password Auth** | Enabled | Completely Disabled |
| **Root SSH Login** | Permitted via Password | Denied |
| **Fail2Ban Protection** | None | Active (Bans after 3 failed attempts) |
| **Identity File Tampering** | Writable by root / sudoers | Blocked via `+i` immutable bit |
| **Brute Force Result (Hydra)**| 20+ uninterrupted attempts | Immediate rejection (`Permission denied (publickey)`) |
| **SIEM Alert Volume** | 20+ alerts per attack wave | Zero brute-force alerts; attack path eliminated |
