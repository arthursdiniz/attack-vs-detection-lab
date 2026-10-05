# Kali Linux Attacker Station Provisioning Guide

## 1. Overview & Host Specifications

The adversary station is `lab-attacker`, running **Kali Linux**. This machine hosts the attack tools and emulation scripts used to trigger security events across the lab endpoints.

### System Specifications
- **Hostname**: `lab-attacker`
- **IP Address**: `192.168.56.10` (`Host-Only` adapter)
- **vCPUs**: 2
- **RAM**: 3 GB (or 2 GB under Profile B)
- **Disk**: 30 GB VDI

---

## 2. Tooling & Dependencies

Install the simulation tools required for the lab scenarios:

```bash
sudo apt update && sudo apt install -y \
    hydra \
    nmap \
    curl \
    netcat-traditional \
    python3 \
    python3-pip \
    smbclient \
    sshpass

# Optional Python libraries for scripted simulations
pip3 install requests
```

---

## 3. Strict Confinement & Safety Enforcement

To ensure zero risk of accidental external traffic generation:

### Rule 1: Static Route & Scope Binding
All scripts developed in this laboratory must explicitly target the lab IP space:
- Windows Target: `192.168.56.20`
- Ubuntu Target: `192.168.56.30`
- SIEM Server: `192.168.56.40` (Explicitly excluded from offensive actions)

### Rule 2: Disable Internet Adapter (Adapter 2)
Ensure NAT Adapter 2 is disconnected before running simulation suites:
```bash
# Check link state
ip link show

# If eth1/enp0s8 (NAT) is active, take it down
sudo ip link set enp0s8 down 2>/dev/null || true
```

---

## 4. Connectivity Validation

Verify network access to the target nodes:

```bash
# Ping test to Windows 11 target
ping -c 3 192.168.56.20

# Ping test to Ubuntu target
ping -c 3 192.168.56.30

# Verify open services
nmap -Pn -p 22,80,443,445,3389 192.168.56.20 192.168.56.30
```
