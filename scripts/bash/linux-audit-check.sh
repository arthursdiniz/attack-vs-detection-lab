#!/usr/bin/env bash
# ==============================================================================
# Script Name: linux-audit-check.sh
# Description: Automated validator for Linux Auditd and auth.log telemetry in
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
echo -e "${CYAN}   ATTACK vs DETECTION LAB -- Linux Telemetry Validator   ${NC}"
echo -e "${CYAN}==========================================================${NC}"
echo -e "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"

# 1. Verify Auditd Daemon State
if ! systemctl is-active --quiet auditd; then
    echo -e "${RED}[!] Error: auditd service is NOT running! Start with: sudo systemctl start auditd${NC}"
    exit 1
fi
echo -e "${GREEN}[+] auditd daemon is active and running.${NC}"

# 2. Check Loaded Audit Rules
echo -e "${YELLOW}[*] Auditing loaded kernel rules...${NC}"
TOTAL_RULES=$(auditctl -l | wc -l)
echo -e "  - Total active rules: ${TOTAL_RULES}"

if ! auditctl -l | grep -q "discovery_execution"; then
    echo -e "${YELLOW}[!] Notice: 'discovery_execution' key not found in active auditctl rules.${NC}"
    echo -e "    Ensure /etc/audit/rules.d/99-detectlab.rules was loaded with 'augenrules --load'."
else
    echo -e "${GREEN}[+] Detected custom 'discovery_execution' audit rule.${NC}"
fi

# 3. Trigger Controlled Test Command
TEST_MARKER="DetectLab_Check_$(date +%s)"
echo -e "${YELLOW}[*] Triggering test command (/bin/uname) to test telemetry generation...${NC}"
/bin/uname -a >/dev/null

sleep 1

# 4. Search Audit Log
echo -e "${YELLOW}[*] Querying /var/log/audit/audit.log via ausearch...${NC}"
AUDIT_RECORD=$(ausearch -k discovery_execution -ts recent 2>/dev/null | tail -n 15 || true)

echo -e "\n${CYAN}====================== VALIDATION RESULTS ======================${NC}"
if [[ -n "$AUDIT_RECORD" ]]; then
    echo -e "${GREEN}[+] SUCCESS: Linux auditd telemetry verified! Matching audit record:${NC}\n"
    echo "$AUDIT_RECORD"
else
    echo -e "${YELLOW}[!] Test command was executed, but no recent record with key 'discovery_execution' was returned.${NC}"
    echo -e "    Check /var/log/audit/audit.log permissions or run with sudo."
fi

# 5. Check auth.log Readability
if [[ -r "/var/log/auth.log" ]]; then
    AUTH_LINES=$(wc -l < /var/log/auth.log)
    echo -e "\n${GREEN}[+] /var/log/auth.log is readable (${AUTH_LINES} entries). Ready for Wazuh ingestion.${NC}"
else
    echo -e "\n${YELLOW}[!] Warning: /var/log/auth.log is not readable by current user. Wazuh agent must run as root.${NC}"
fi

echo -e "${CYAN}================================================================${NC}\n"
