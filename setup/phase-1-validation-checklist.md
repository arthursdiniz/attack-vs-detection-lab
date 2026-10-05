# Phase 1 — Infrastructure Validation Checklist

This checklist provides a structured procedure to verify that all components of **Phase 1: Infrastructure** are deployed, configured, and communicating properly before proceeding to telemetry and detection engineering.

---

## 1. Hypervisor & Virtual Network Validation

- [ ] **VirtualBox Installed**: VirtualBox 7.x installed on the host.
- [ ] **Host-Only Adapter Active**:
  - Name: `VirtualBox Host-Only Ethernet Adapter` (or `vboxnet0`).
  - IP Address: `192.168.56.1`
  - Subnet Mask: `255.255.255.0`
- [ ] **DHCP Server Disabled**: Verified that the VirtualBox internal DHCP server for `192.168.56.0/24` is disabled to ensure deterministic static IPs.
- [ ] **Dual-NIC Configuration**:
  - Adapter 1 (Host-Only): Enabled on all 4 VMs.
  - Adapter 2 (NAT): Disconnected (`cableconnected2 off`) on all 4 VMs during lab simulations.

---

## 2. Virtual Machine Provisioning & Sizing

| Node | Hostname | Expected IP | OS | Allocated vCPU | Allocated RAM | Allocated Disk | Status |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| Attacker | `lab-attacker` | `192.168.56.10` | Kali Linux | 2 vCPUs | 3 GB | 30 GB | [ ] |
| Victim 01 | `lab-win11` | `192.168.56.20` | Windows 11 Enterprise | 2 vCPUs | 6 GB | 60 GB | [ ] |
| Victim 02 | `lab-ubuntu` | `192.168.56.30` | Ubuntu Server 22.04 | 2 vCPUs | 3 GB | 30 GB | [ ] |
| SIEM | `lab-wazuh` | `192.168.56.40` | Ubuntu Server 22.04 | 4 vCPUs | 8 GB | 50 GB | [ ] |

---

## 3. Network Connectivity & Routing Verification

Run the validation script from the host or within any VM:
- On Host: `powershell -ExecutionPolicy Bypass -File scripts/powershell/validate-network.ps1`
- On Linux: `bash scripts/bash/validate-network.sh`

- [ ] **ICMP Ping from Host (`192.168.56.1`)**:
  - `ping 192.168.56.10` (Kali) -> Success
  - `ping 192.168.56.20` (Windows 11) -> Success
  - `ping 192.168.56.30` (Ubuntu) -> Success
  - `ping 192.168.56.40` (Wazuh) -> Success
- [ ] **ICMP Ping from Kali (`192.168.56.10`)**:
  - `ping -c 2 192.168.56.20` (Windows 11) -> Success
  - `ping -c 2 192.168.56.30` (Ubuntu) -> Success
- [ ] **External Isolation Confirmed**:
  - Kali cannot route to public IPs (e.g., `ping -c 1 8.8.8.8` fails or network is unreachable when Adapter 2 is disconnected).

---

## 4. Wazuh SIEM Deployment Verification

On `lab-wazuh` (`192.168.56.40`):
- [ ] **Indexer Service Active**: `sudo systemctl is-active wazuh-indexer` returns `active`.
- [ ] **Manager Service Active**: `sudo systemctl is-active wazuh-manager` returns `active`.
- [ ] **Dashboard Service Active**: `sudo systemctl is-active wazuh-dashboard` returns `active`.
- [ ] **Filebeat Service Active**: `sudo systemctl is-active filebeat` returns `active`.
- [ ] **Port Verification**:
  - Port `1514/TCP` open (Remoted - Agent communication).
  - Port `1515/TCP` open (Authd - Agent registration).
  - Port `9200/TCP` open (Indexer REST API).
  - Port `443/TCP` open (Dashboard Web UI).
- [ ] **Web UI Access**: Browser from host navigates to `https://192.168.56.40` and loads login screen cleanly.
- [ ] **Admin Authentication**: Login successful with credentials from `wazuh-passwords.txt`.

---

## 5. Phase 1 Sign-Off

Once all items above are checked, Phase 1 is officially complete and the environment is ready for **Phase 2: Telemetry & Ingestion Engineering**.
