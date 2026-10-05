#!/usr/bin/env bash
# ==============================================================================
# Script Name: configure-linux-telemetry.sh
# Description: Automated Linux telemetry and audit configuration script for
#              the Attack vs Detection Lab (Ubuntu Server 22.04 LTS).
# Author: Senior Security & Detection Engineer
# ==============================================================================

set -o errexit
set -o pipefail
set -o nounset

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

echo -e "${CYAN}==========================================================${NC}"
echo -e "${CYAN}   ATTACK vs DETECTION LAB -- Linux Telemetry Setup       ${NC}"
echo -e "${CYAN}==========================================================${NC}"

# 1. Require Root Privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Error: This script must be run as root (sudo).${NC}"
   exit 1
fi

echo -e "${GREEN}[+] Confirmed root privileges.${NC}"

# 2. Install & Enable Auditd
echo -e "${YELLOW}[*] Installing and verifying auditd daemon...${NC}"
apt-get update -qq
apt-get install -y -qq auditd audispd-plugins

systemctl enable auditd
systemctl restart auditd
echo -e "${GREEN}[+] Auditd is active and enabled.${NC}"

# 3. Deploy Customized Audit Rules
echo -e "${YELLOW}[*] Deploying custom audit rules to /etc/audit/rules.d/99-detectlab.rules...${NC}"
cat << 'EOF' > /etc/audit/rules.d/99-detectlab.rules
# ==============================================================================
# Attack vs Detection Lab - Custom Auditd Rule Suite
# ==============================================================================

# Delete all existing rules and set buffer
-D
-b 8192
-f 1

# 1. Identity & Credential Store Tampering (INC-004 / T1565 / T1003)
-w /etc/passwd -p wa -k identity_tampering
-w /etc/shadow -p wa -k identity_tampering
-w /etc/group -p wa -k identity_tampering
-w /etc/gshadow -p wa -k identity_tampering
-w /etc/security/opasswd -p wa -k identity_tampering

# 2. Privilege Escalation & Sudoers Tampering (T1548.003)
-w /etc/sudoers -p wa -k priv_escalation
-w /etc/sudoers.d/ -p wa -k priv_escalation

# 3. SSH Configuration & Keys Tampering (INC-006 / T1098.004)
-w /etc/ssh/sshd_config -p wa -k sshd_tampering
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_tampering
-w /root/.ssh/ -p wa -k ssh_key_tampering

# 4. Account & Group Manipulation Tools (INC-003 / T1136.001 / T1098)
-w /usr/sbin/useradd -p x -k account_manipulation
-w /usr/sbin/adduser -p x -k account_manipulation
-w /usr/sbin/usermod -p x -k account_manipulation
-w /usr/sbin/userdel -p x -k account_manipulation
-w /usr/sbin/groupadd -p x -k account_manipulation
-w /usr/sbin/groupmod -p x -k account_manipulation

# 5. Scheduled Tasks & Persistence (T1053.003)
-w /etc/crontab -p wa -k persistence_cron
-w /etc/cron.d/ -p wa -k persistence_cron
-w /etc/cron.daily/ -p wa -k persistence_cron
-w /etc/cron.hourly/ -p wa -k persistence_cron
-w /var/spool/cron/crontabs/ -p wa -k persistence_cron

# 6. System Discovery Binaries Execution (INC-005 / T1082 / T1087)
-w /bin/uname -p x -k discovery_execution
-w /usr/bin/whoami -p x -k discovery_execution
-w /usr/bin/id -p x -k discovery_execution
-w /usr/bin/w -p x -k discovery_execution
-w /usr/bin/last -p x -k discovery_execution

# Make configuration immutable until reboot (optional for strict compliance)
# -e 2
EOF

# Load rules
augenrules --load
echo -e "${GREEN}[+] Custom audit rules successfully loaded.${NC}"

# 4. Enrich SSH Daemon Telemetry (OpenSSH)
echo -e "${YELLOW}[*] Configuring OpenSSH daemon for VERBOSE telemetry...${NC}"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak."$(date +%s)"

# Ensure LogLevel is set to VERBOSE
if grep -q "^LogLevel" /etc/ssh/sshd_config; then
    sed -i 's/^LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
elif grep -q "^#LogLevel" /etc/ssh/sshd_config; then
    sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
else
    echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
fi

# Ensure password authentication is enabled for baseline simulations
sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true

# Test configuration and restart SSH
sshd -t
systemctl restart ssh
echo -e "${GREEN}[+] SSH daemon configured with LogLevel VERBOSE and restarted.${NC}"

# 5. Verification Output
echo -e "\n${CYAN}====================== ACTIVE AUDIT RULES ======================${NC}"
auditctl -l
echo -e "${CYAN}================================================================${NC}"
echo -e "${GREEN}[+] Linux Endpoint Telemetry Configuration Completed Successfully!${NC}\n"
