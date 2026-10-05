# Network Architecture & Isolation Topology

## 1. Network Topology Diagram

```mermaid
graph TD
    subgraph HostHypervisor ["Host System (Windows 11)"]
        Browser["Analyst Workstation Browser<br/>192.168.56.1"]
    end

    subgraph LabIsolatedNetwork ["Isolated Virtual Network (Host-Only: 192.168.56.0/24)"]
        direction TB
        
        Kali["Kali Linux (Attacker)<br/>Hostname: lab-attacker<br/>IP: 192.168.56.10<br/>NIC1: Host-Only<br/>NIC2: NAT (Disabled)"]
        
        Win11["Windows 11 Enterprise (Victim 01)<br/>Hostname: lab-win11<br/>IP: 192.168.56.20<br/>NIC1: Host-Only<br/>NIC2: NAT (Disabled)<br/>Telemetry: Sysmon + EventLogs"]
        
        Ubuntu["Ubuntu Server 22.04 (Victim 02)<br/>Hostname: lab-ubuntu<br/>IP: 192.168.56.30<br/>NIC1: Host-Only<br/>NIC2: NAT (Disabled)<br/>Telemetry: Auditd + auth.log"]
        
        Wazuh["Wazuh All-in-One (SIEM/XDR)<br/>Hostname: lab-wazuh<br/>IP: 192.168.56.40<br/>NIC1: Host-Only<br/>NIC2: NAT (Disabled)<br/>Services: Manager, Indexer, Dashboard"]
    end

    %% Attack Flows
    Kali -.->|"SSH Brute Force (TCP 22)<br/>Web Probing (TCP 8080)"| Ubuntu
    Kali -.->|"RDP/SMB Spray (TCP 3389/445)<br/>Simulated Exploit Traffic"| Win11

    %% Telemetry Collection Flows
    Win11 ==>|"Wazuh Agent Tunnel (TCP 1514)<br/>Enrollment (TCP 1515)"| Wazuh
    Ubuntu ==>|"Wazuh Agent Tunnel (TCP 1514)<br/>Enrollment (TCP 1515)"| Wazuh

    %% Analyst Access Flow
    Browser ==>|"HTTPS Management (TCP 443)<br/>Wazuh Web Dashboard"| Wazuh

    classDef host fill:#2b2d42,stroke:#8d99ae,stroke-width:2px,color:#edf2f4;
    classDef attacker fill:#d90429,stroke:#ef233c,stroke-width:2px,color:#ffffff;
    classDef victim fill:#0077b6,stroke:#90e0ef,stroke-width:2px,color:#ffffff;
    classDef siem fill:#38b000,stroke:#70e000,stroke-width:2px,color:#ffffff;

    class Browser host;
    class Kali attacker;
    class Win11,Ubuntu victim;
    class Wazuh siem;
```

---

## 2. Network Segmentation & Firewall Policy Matrix

The following matrix documents the allowed inter-node network flows within the lab. Any traffic outside these designated flows is considered extraneous:

```text
┌─────────────────┬─────────────────┬─────────────────────┬──────────────┬────────────────────────────────────────────┐
│ Source Node     │ Target Node     │ Destination Port(s) │ Protocol     │ Purpose                                    │
├─────────────────┼─────────────────┼─────────────────────┼──────────────┼────────────────────────────────────────────┤
│ Host (192.168.56.1) │ Wazuh (.40) │ 443                 │ TCP (HTTPS)  │ SOC Analyst Web Dashboard access           │
│ Host (192.168.56.1) │ Ubuntu (.30)│ 22                  │ TCP (SSH)    │ Administrative lab management              │
│ Host (192.168.56.1) │ Win11 (.20) │ 3389                │ TCP (RDP)    │ Administrative lab management              │
│ Windows (.20)   │ Wazuh (.40)     │ 1514, 1515          │ TCP          │ Wazuh Agent telemetry & enrollment         │
│ Ubuntu (.30)    │ Wazuh (.40)     │ 1514, 1515          │ TCP          │ Wazuh Agent telemetry & enrollment         │
│ Kali (.10)      │ Ubuntu (.30)    │ 22, 8080            │ TCP          │ Attack simulation (SSH Brute Force, Web)   │
│ Kali (.10)      │ Windows (.20)   │ 445, 3389, 5985     │ TCP          │ Attack simulation (Auth Spray, SMB, WinRM) │
│ Kali (.10)      │ Wazuh (.40)     │ NONE (Blocked)      │ -            │ SIEM infrastructure must remain untouched  │
└─────────────────┴─────────────────┴─────────────────────┴──────────────┴────────────────────────────────────────────┘
```

---

## 3. Network Isolation Mechanics

### VirtualBox Host-Only Adapter Configuration
- **Interface Name**: `VirtualBox Host-Only Ethernet Adapter` (`vboxnet0` on Linux hosts)
- **IPv4 Address**: `192.168.56.1`
- **Subnet Mask**: `255.255.255.0` (`/24`)
- **DHCP Server**: **Disabled**. All lab systems must utilize deterministic, static IP configurations to prevent IP drift across test runs.

### Dual-NIC Safeguard Command Reference
To ensure total isolation during attack execution, verify and disable the secondary NAT interfaces on all lab VMs:

```powershell
# Verify network status of lab VMs in PowerShell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" list runningvms

# Disconnect the Internet NAT adapter (Adapter 2) while keeping Host-Only (Adapter 1) active
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "lab-attacker" setlinkstate2 off
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "lab-win11" setlinkstate2 off
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "lab-ubuntu" setlinkstate2 off
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "lab-wazuh" setlinkstate2 off
```

To reconnect Adapter 2 temporarily for repository updates or package installation:

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "<VM_NAME>" setlinkstate2 on
```
