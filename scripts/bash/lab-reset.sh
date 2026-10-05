#!/usr/bin/env bash
# ==============================================================================
# Script Name: lab-reset.sh
# Description: Resets temporary evidence, purges Fail2Ban bans, flushes iptables,
#              and restores system baselines for fresh laboratory test executions.
# Author: Senior Security Operations Engineer
# ==============================================================================

set -o errexit
set -o pipefail
set -o nounset

echo "=========================================================="
echo "   ATTACK vs DETECTION LAB -- Environment Reset Utility   "
echo "=========================================================="
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"

if [[ $EUID -ne 0 ]]; then
   echo "[!] Error: Must be run as root (sudo)."
   exit 1
fi

# 1. Unban all IPs in Fail2Ban
if command -v fail2ban-client >/dev/null 2>&1; then
    echo "[*] Unbanning all IPs in Fail2Ban sshd jail..."
    fail2ban-client unban --all 2>/dev/null || true
    echo "[+] Fail2Ban unban completed."
fi

# 2. Flush custom iptables rules
echo "[*] Flushing test iptables rules..."
iptables -F
iptables -X
echo "[+] iptables flushed to default accept."

# 3. Restore /etc/passwd if immutable
if command -v chattr >/dev/null 2>&1; then
    echo "[*] Clearing immutable attributes on /etc/passwd and /etc/shadow..."
    chattr -i /etc/passwd /etc/shadow 2>/dev/null || true
fi

# 4. Remove test accounts
if id "lab-target" >/dev/null 2>&1; then
    echo "[*] Resetting test user lab-target password..."
    echo "lab-target:LabPassword2024!" | chpasswd
fi

# 5. Clear application test log
if [[ -f "/var/log/detectlab/app-security.json" ]]; then
    echo "[*] Truncating web application log..."
    > /var/log/detectlab/app-security.json
fi

echo "[+] Lab reset completed successfully. Ready for next simulation wave."
echo "=========================================================="
