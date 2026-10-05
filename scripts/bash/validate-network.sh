#!/usr/bin/env bash
# ==============================================================================
# Script Name: validate-network.sh
# Description: Automated ICMP and TCP service connectivity validator for the
#              Attack vs Detection Lab (Subnet: 192.168.56.0/24).
# Author: Senior Security Engineering & SOC Analyst
# ==============================================================================

set -o errexit
set -o pipefail
set -o nounset

# Colors for terminal output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

SUBNET_PREFIX="${1:-192.168.56}"

echo -e "${CYAN}==========================================================${NC}"
echo -e "${CYAN}   ATTACK vs DETECTION LAB — Linux Network Validator      ${NC}"
echo -e "${CYAN}==========================================================${NC}"
echo -e "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "Testing Subnet: ${SUBNET_PREFIX}.0/24\n"

# Node Definitions: Hostname:IP:Role:Ports
declare -a NODES=(
    "lab-attacker:${SUBNET_PREFIX}.10:Attacker (Kali):"
    "lab-win11:${SUBNET_PREFIX}.20:Victim 01 (Win11):3389 445"
    "lab-ubuntu:${SUBNET_PREFIX}.30:Victim 02 (Ubuntu):22"
    "lab-wazuh:${SUBNET_PREFIX}.40:SIEM (Wazuh):443 1514 1515"
)

test_tcp_port() {
    local host="$1"
    local port="$2"
    if command -v nc >/dev/null 2>&1; then
        nc -z -w 2 "$host" "$port" >/dev/null 2>&1
        return $?
    elif (echo >/dev/tcp/"$host"/"$port") >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

printf "%-14s %-16s %-20s %-12s %-25s\n" "HOSTNAME" "IP ADDRESS" "ROLE" "ICMP" "PORTS"
printf "%-14s %-16s %-20s %-12s %-25s\n" "--------" "----------" "----" "----" "-----"

ALL_PINGS_PASSED=true

for entry in "${NODES[@]}"; do
    IFS=":" read -r hostname ip role ports <<< "$entry"
    
    # Test ICMP
    if ping -c 1 -W 2 "$ip" >/dev/null 2>&1; then
        icmp_status="${GREEN}REACHABLE${NC}"
    else
        icmp_status="${RED}FAILED${NC}"
        ALL_PINGS_PASSED=false
    fi

    # Test Ports
    port_status_str=""
    if [[ -n "$ports" ]]; then
        for port in $ports; do
            if test_tcp_port "$ip" "$port"; then
                port_status_str+="${port}/TCP:${GREEN}UP${NC} "
            else
                port_status_str+="${port}/TCP:${YELLOW}DOWN${NC} "
            fi
        done
    else
        port_status_str="N/A"
    fi

    printf "%-14s %-16s %-20s %-21b %-25b\n" "$hostname" "$ip" "$role" "$icmp_status" "$port_status_str"
done

echo -e "\n${CYAN}----------------------------------------------------------${NC}"
if [[ "$ALL_PINGS_PASSED" == true ]]; then
    echo -e "${GREEN}[+] Network verification completed successfully! All nodes are reachable.${NC}"
else
    echo -e "${YELLOW}[!] Notice: One or more nodes failed ICMP ping. Verify VM execution status.${NC}"
fi
echo -e "${CYAN}==========================================================${NC}\n"
