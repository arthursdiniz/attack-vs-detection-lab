#!/usr/bin/env bash
# ==============================================================================
# Script Name: simulate_linux_fim.sh
# Scenario: INC-004 - File Integrity Monitoring (FIM) Simulation (Linux)
# Target: lab-ubuntu (192.168.56.30)
# Purpose: Safely appends and removes a marker comment to /etc/passwd or /etc/shadow
#          to generate real-time Syscheck and Auditd integrity tampering events.
# ==============================================================================

set -o errexit
set -o pipefail
set -o nounset

TARGET_FILE="/etc/passwd"
BACKUP_FILE="/tmp/passwd.detectlab.bak"

echo "=========================================================="
echo "   ATTACK vs DETECTION LAB -- INC-004 Linux FIM Test      "
echo "=========================================================="
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"

if [[ $EUID -ne 0 ]]; then
   echo "[!] Error: Must be run as root (sudo)."
   exit 1
fi

# 1. Capture Original Hash
cp "$TARGET_FILE" "$BACKUP_FILE"
HASH_BEFORE_SHA256=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
HASH_BEFORE_MD5=$(md5sum "$TARGET_FILE" | awk '{print $1}')

echo "[*] Baseline captured for: $TARGET_FILE"
echo "  [-] SHA256 Before : $HASH_BEFORE_SHA256"
echo "  [-] MD5 Before    : $HASH_BEFORE_MD5"

# 2. Perform Controlled Modification
MARKER="# DetectLab_FIM_Simulation_Marker_$(date +%s)"
echo "[*] Simulating unauthorized modification: Appending marker to $TARGET_FILE..."
echo "$MARKER" >> "$TARGET_FILE"

HASH_AFTER_SHA256=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
HASH_AFTER_MD5=$(md5sum "$TARGET_FILE" | awk '{print $1}')

echo "  [-] SHA256 After  : $HASH_AFTER_SHA256"
echo "  [-] MD5 After     : $HASH_AFTER_MD5"
echo "[+] Modification generated. Waiting 5s for Wazuh realtime Syscheck..."
sleep 5

# 3. Restore Original State (Safe hygiene)
echo "[*] Restoring $TARGET_FILE to clean baseline..."
cp "$BACKUP_FILE" "$TARGET_FILE"
rm -f "$BACKUP_FILE"
echo "[+] Baseline restored."
echo "=========================================================="
