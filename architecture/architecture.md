# Attack vs Detection Lab — Architecture Specification

## 1. Executive Summary

The **Attack vs Detection Lab** architecture is engineered to provide an authentic, isolated, and repeatable enterprise security operations simulation. It models a modern defensive perimeter comprising an attacker station, two target endpoints running major enterprise operating systems (Microsoft Windows 11 Enterprise and Ubuntu Server 22.04 LTS), and a centralized SIEM/XDR cluster powered by Wazuh.

Every architectural decision in this design prioritizes three engineering principles:
1. **Zero External Blast Radius**: Total containment of offensive traffic within a private virtual network.
2. **Deterministic Telemetry**: Static IP addressing, synchronized clocks (NTP), and standardized audit baselines to guarantee reproducible logs.
3. **Resource Efficiency**: Optimized resource allocation supporting multi-VM concurrent operation on standard developer hardware.

---

## 2. Hypervisor Selection & Justification

### Selected Platform: Oracle VirtualBox (v7.x)

After evaluating the three primary local desktop hypervisors, **Oracle VirtualBox** was selected as the reference platform for this laboratory.

```text
┌─────────────────────────┬───────────────────────┬─────────────────────────┬─────────────────────────┐
│ Evaluation Criteria     │ Oracle VirtualBox 7.x │ VMware Workstation Pro  │ Microsoft Hyper-V       │
├─────────────────────────┼───────────────────────┼─────────────────────────┼─────────────────────────┤
│ License / Cost          │ Free & Open Source    │ Free for Personal Use   │ Included in Win Pro/Ent │
│ Predictable Static IP   │ Native Host-Only      │ Custom VMnet editor     │ Dynamic on Default Sw.  │
│ Portability / OVA Export│ Universal OVF/OVA     │ VMware OVA/OVF format   │ VHDX / Export script    │
│ CLI Automation          │ VBoxManage (complete) │ vmrun (limited)         │ PowerShell Hyper-V cmd  │
│ Host Isolation Support  │ Built-in Host-Only    │ Built-in Host-Only      │ Requires Internal Switch│
│ Cross-Platform Support  │ Windows, Linux, macOS │ Windows, Linux          │ Windows only            │
└─────────────────────────┴───────────────────────┴─────────────────────────┴─────────────────────────┘
```

### Detailed Justification

1. **Deterministic Host-Only Networking**: VirtualBox provides a pre-configured `VirtualBox Host-Only Ethernet Adapter` operating by default on `192.168.56.0/24`. Unlike Hyper-V's "Default Switch", which recalculates the subnet and internal gateway on every host reboot, VirtualBox guarantees that static IP assignments (`.10`, `.20`, `.30`, `.40`) remain permanent across reboots without requiring custom PowerShell NAT scripts.
2. **Universal Open-Source Availability**: Replicating this portfolio project requires zero commercial licensing barriers for recruiters, students, or reviewers running Windows, Linux, or Intel macOS.
3. **Robust Command-Line Management (`VBoxManage`)**: Every VM property (CPU, RAM, NIC attachment, cable state, shared folders, snapshots) can be automated via CLI, enabling reproducible setup scripts.
4. **Verified Local Footprint**: The host system is already equipped with VirtualBox 7.2.6 and active interface `192.168.56.1`.

---

## 3. Hardware Requirements & Resource Allocation

### Host Machine Baseline
- **Processor**: Intel Core i5-12400F (6 Cores / 12 Threads)
- **Host RAM**: 32 GB DDR4
- **Host Storage**: NVMe SSD (fast I/O for concurrent disk writes from Indexer and Sysmon)

### Virtual Machine Sizing Profiles

#### Profile A: 32 GB Host (Recommended / Primary Profile)
This profile runs all 4 VMs simultaneously with zero disk paging on the host:

| VM Name | Role | Base OS | vCPUs | RAM | Storage | Primary Purpose |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `lab-attacker` | Attacker | Kali Linux 2024.x | 2 | 3 GB | 30 GB | Hydra, Nmap, curl, simulation scripts |
| `lab-win11` | Victim 01 | Windows 11 Enterprise | 2 | 6 GB | 60 GB | Sysmon, Win Event Channel, PowerShell |
| `lab-ubuntu` | Victim 02 | Ubuntu Server 22.04 LTS| 2 | 3 GB | 30 GB | Auditd, SSH, auth.log, test web API |
| `lab-wazuh` | SIEM Server | Ubuntu Server 22.04 LTS| 4 | 8 GB | 50 GB | Wazuh Manager, Indexer (JVM), Dashboard |
| **Total Allocated** | | | **10 vCPUs** | **20 GB** | **170 GB** | Host retains 12 GB RAM & 2 physical cores |

#### Profile B: 16 GB Host (Constrained / Alternative Profile)
For running on 16 GB machines, the following adjustments maintain full functionality:

| VM Name | Role | Base OS | vCPUs | RAM | Storage | Optimizations Applied |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `lab-attacker` | Attacker | Kali Linux (Headless/CLI)| 1 | 2 GB | 25 GB | Run in CLI mode (`systemctl set-default multi-user.target`) |
| `lab-win11` | Victim 01 | Windows 10 LTSC / Win 11 | 2 | 4 GB | 50 GB | Disable visual effects, telemetry services |
| `lab-ubuntu` | Victim 02 | Ubuntu Server 22.04 LTS| 1 | 2 GB | 25 GB | Minimal installation, no GUI |
| `lab-wazuh` | SIEM Server | Ubuntu Server 22.04 LTS| 2 | 4.5 GB| 40 GB | Limit JVM heap to 2 GB (`-Xms2g -Xmx2g`) in `jvm.options` |
| **Total Allocated** | | | **6 vCPUs** | **12.5 GB**| **140 GB** | Host retains 3.5 GB RAM |

---

## 4. Network Design & Isolation Strategy

### Network Topology: `192.168.56.0/24`

```text
               192.168.56.1 (Host Workstation - Browser & Management)
                                        │
           ═════════════════════════════╪═════════════════════════════
           VirtualBox Host-Only Ethernet Adapter (vboxnet0 - 192.168.56.0/24)
           ═════════════════════════════╪═════════════════════════════
                 │                      │                      │                      │
                 ▼                      ▼                      ▼                      ▼
        ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
        │  lab-attacker   │    │   lab-win11     │    │   lab-ubuntu    │    │   lab-wazuh     │
        │  192.168.56.10  │    │  192.168.56.20  │    │  192.168.56.30  │    │  192.168.56.40  │
        └─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

### IP Allocation Table

| Hostname | Role | IP Address | Subnet Mask | Gateway | DNS |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `soc-analyst` | Host Hypervisor | `192.168.56.1` | `255.255.255.0` | N/A | Local Host DNS |
| `lab-attacker` | Kali Linux | `192.168.56.10` | `255.255.255.0` | `192.168.56.1` | `192.168.56.1` |
| `lab-win11` | Windows 11 Victim | `192.168.56.20` | `255.255.255.0` | `192.168.56.1` | `192.168.56.1` |
| `lab-ubuntu` | Ubuntu Victim | `192.168.56.30` | `255.255.255.0` | `192.168.56.1` | `192.168.56.1` |
| `lab-wazuh` | Wazuh SIEM | `192.168.56.40` | `255.255.255.0` | `192.168.56.1` | `192.168.56.1` |

### Dual-NIC Architecture for Safe Maintenance

To satisfy safety and isolation requirements, each virtual machine uses a **Dual-NIC Strategy**:

1. **Adapter 1: Host-Only Network (Attached to `VirtualBox Host-Only Ethernet Adapter`)**:
   - Status: **Always Enabled & Connected**.
   - Handles all inter-VM communication, attack traffic, telemetry forwarding, and Wazuh Dashboard access.
   - Traffic never exits the host physical network adapter.
2. **Adapter 2: NAT (Network Address Translation)**:
   - Status: **Disconnected by Default during Lab Execution**.
   - Used **only** during initial provisioning (e.g., `apt update`, downloading Sysmon from Microsoft Sysinternals, installing Wazuh repository packages).
   - Once provisioning is verified, the virtual cable is disconnected via:
     ```powershell
     & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "lab-attacker" setlinkstate2 off
     & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "lab-win11" setlinkstate2 off
     & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "lab-ubuntu" setlinkstate2 off
     & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "lab-wazuh" setlinkstate2 off
     ```

### Risk Analysis: Bridged vs. Host-Only vs. Internal Network

```text
┌────────────────────┬──────────────────────────────────┬─────────────────────────────────────────────────────────┐
│ Network Mode       │ Connectivity                     │ Security Risk Assessment                                │
├────────────────────┼──────────────────────────────────┼─────────────────────────────────────────────────────────┤
│ Bridged Adapter    │ VM joins physical LAN directly   │ CRITICAL RISK: Attack traffic (brute-force sprays,      │
│                    │ Gets IP from home/corporate DHCP │ ARP scans) broadcasts onto real home/office Wi-Fi.      │
│                    │                                  │ Exposes victim VMs to external threat actors.           │
├────────────────────┼──────────────────────────────────┼─────────────────────────────────────────────────────────┤
│ Internal Network   │ VMs communicate only with VMs    │ ZERO LEAKAGE: Complete isolation, but requires manual   │
│                    │ Host cannot reach VMs easily     │ routing VM to access Wazuh Web UI from the host browser.│
├────────────────────┼──────────────────────────────────┼─────────────────────────────────────────────────────────┤
│ Host-Only (Chosen) │ VMs communicate with each other  │ OPTIMAL BALANCE: No packet can escape to the physical   │
│                    │ and with the Host hypervisor     │ network, yet the Host browser can cleanly navigate to   │
│                    │ No internet access without NAT   │ https://192.168.56.40:443 for SOC dashboard analysis.   │
└────────────────────┴──────────────────────────────────┴─────────────────────────────────────────────────────────┘
```

---

## 5. Wazuh SIEM Deployment Topology

The SIEM runs on `lab-wazuh` (`192.168.56.40`) utilizing the **Wazuh Central Components (All-in-One)** architecture:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                     lab-wazuh Server (192.168.56.40)                    │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ Wazuh Manager (Core Engine)                                     │   │
│   │  • Analysisd (Decoders & Rules Engine: Level 0 to 16)           │   │
│   │  • Remoted (TCP 1514 encrypted communication with agents)        │   │
│   │  • Authd (TCP 1515 automatic key registration / enrollment)     │   │
│   │  • Execd (Active Response handler)                              │   │
│   │  • Syscheck (File Integrity Monitoring database)                │   │
│   └────────────────────────────────┬────────────────────────────────┘   │
│                                    │                                    │
│                                    ▼ Logstash / Filebeat Pipeline       │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ Wazuh Indexer (OpenSearch Engine)                               │   │
│   │  • Port 9200 (Internal HTTPS)                                   │   │
│   │  • Indexes: wazuh-alerts-4.x-*, wazuh-monitoring-*              │   │
│   │  • Dedicated JVM Heap: 4 GB (-Xms4g -Xmx4g)                     │   │
│   └────────────────────────────────┬────────────────────────────────┘   │
│                                    │                                    │
│                                    ▼ Internal REST API                  │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ Wazuh Dashboard (Web UI / Kibana Fork)                          │   │
│   │  • Port 443 (HTTPS)                                             │   │
│   │  • Visualizations, MITRE ATT&CK mapping dashboard, SOC triage   │   │
│   └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Network Port Matrix

| Port | Protocol | Source | Destination | Purpose |
| :--- | :---: | :--- | :--- | :--- |
| **1514** | TCP/UDP | Agents (`.20`, `.30`) | Wazuh Manager (`.40`) | Encrypted agent event data stream |
| **1515** | TCP | Agents (`.20`, `.30`) | Wazuh Manager (`.40`) | Agent auto-enrollment / auth service |
| **55000** | TCP | Wazuh Dashboard (`.40`) | Wazuh Manager (`.40`) | Wazuh RESTful Management API |
| **9200** | TCP | Wazuh Manager / Filebeat | Wazuh Indexer (`.40`) | OpenSearch REST API / document indexing |
| **443** | TCP | SOC Analyst (`192.168.56.1`) | Wazuh Dashboard (`.40`) | SOC Web Interface & visualization |
| **22** | TCP | Kali (`.10`) / Host (`.1`) | Ubuntu Victim (`.30`) | SSH service (target of INC-001/006) |
| **3389** | TCP | Kali (`.10`) / Host (`.1`) | Windows Victim (`.20`) | RDP service (target of auth tests) |
| **445** | TCP | Kali (`.10`) | Windows Victim (`.20`) | SMB service (target of auth tests) |

---

## 6. Security Principles of the Lab

1. **Controlled Scope**: Attacks are confined to the `192.168.56.0/24` subnet. Scripts explicitly bind targets to `.20` or `.30`.
2. **Deterministic Artifacts**: Every simulated attack outputs reproducible telemetry with known usernames (e.g., `lab-target`, `analyst_test`), predictable commands, and recorded timestamps.
3. **No Malicious Payloads**: Attacks simulate the *behavior* and *telemetry footprint* of malicious techniques (e.g., encoded PowerShell switches `-EncodedCommand` with harmless Base64 echo strings) rather than executing destructive exploit code.
