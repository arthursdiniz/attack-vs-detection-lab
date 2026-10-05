# Network Configuration & Isolation Guide

## 1. Overview & Objectives

This guide details the procedure for establishing a strictly isolated **Host-Only** virtual network (`192.168.56.0/24`) in Oracle VirtualBox and configuring persistent static IP addresses across all nodes.

---

## 2. Host-Only Network Setup in Oracle VirtualBox

### Option A: Automated via PowerShell (`VBoxManage`)
Run the following commands on the Windows host in an elevated PowerShell session:

```powershell
# 1. Define VBoxManage path
$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

# 2. Check existing host-only interfaces
& $vbox list hostonlyifs

# 3. If "VirtualBox Host-Only Ethernet Adapter" does not exist, create it:
# & $vbox hostonlyif create

# 4. Configure static IP and Subnet mask on the Host-Only adapter
& $vbox hostonlyif ipconfig "VirtualBox Host-Only Ethernet Adapter" --ip 192.168.56.1 --netmask 255.255.255.0

# 5. Disable internal VirtualBox DHCP server to prevent IP drift
& $vbox dhcpserver remove --netname "HostInterfaceNetworking-VirtualBox Host-Only Ethernet Adapter"
```

### Option B: Graphical User Interface (GUI)
1. Open Oracle VirtualBox.
2. Navigate to **File** -> **Tools** -> **Network Manager** (or press `Ctrl + H`).
3. Under the **Host-only Networks** tab, select `VirtualBox Host-Only Ethernet Adapter` (or click **Create**).
4. Set the **Adapter** tab:
   - **IPv4 Address**: `192.168.56.1`
   - **IPv4 Network Mask**: `255.255.255.0`
5. Set the **DHCP Server** tab:
   - Uncheck **Enable Server** (guarantees static configuration across the lab).
6. Click **Apply**.

---

## 3. Virtual Machine Network Adapter Configuration

Each virtual machine in the lab must be configured with **two adapters**:
- **Adapter 1**: Attached to **Host-only Adapter** -> Name: `VirtualBox Host-Only Ethernet Adapter`. Promiscuous Mode: `Deny` (or `Allow VMs` if packet capture experiments are performed). Cable Connected: `Checked`.
- **Adapter 2**: Attached to **NAT**. Cable Connected: `Unchecked` (Disconnected by default; enable temporarily only for updates).

PowerShell automation to configure adapters on a VM:
```powershell
$vm = "lab-win11" # Repeat for lab-ubuntu, lab-attacker, lab-wazuh
& $vbox modifyvm $vm --nic1 hostonly --hostonlyadapter1 "VirtualBox Host-Only Ethernet Adapter" --cableconnected1 on
& $vbox modifyvm $vm --nic2 nat --cableconnected2 off
```

---

## 4. Static IP Assignment per Operating System

### Node 1: Kali Linux (`lab-attacker` - `192.168.56.10`)
Edit `/etc/network/interfaces` or apply using NetworkManager:

```bash
# Verify interface name (typically eth0 or enp0s3)
ip link

# Configure static IP via nmcli
sudo nmcli connection add type ethernet ifname eth0 con-name "Lab-HostOnly" ip4 192.168.56.10/24
sudo nmcli connection up "Lab-HostOnly"

# Verify
ip addr show eth0
```

### Node 2: Windows 11 Enterprise (`lab-win11` - `192.168.56.20`)
Open PowerShell as Administrator inside the Windows 11 VM:

```powershell
# Identify the network adapter index
Get-NetAdapter

# Assuming InterfaceIndex is 1 (replace with your index)
$ifIndex = (Get-NetAdapter | Where-Object Status -eq 'Up').InterfaceIndex

# Assign static IP and subnet
New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress 192.168.56.20 -PrefixLength 24 -DefaultGateway 192.168.56.1

# Configure local DNS
Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses ("192.168.56.1")

# Allow ICMP Echo Requests (Ping) for lab connectivity validation
netsh advfirewall firewall add rule name="Allow Lab ICMP" protocol=icmpv4:8,any dir=in action=allow
```

### Node 3: Ubuntu Server 22.04 (`lab-ubuntu` - `192.168.56.30`)
Edit Netplan configuration at `/etc/netplan/01-netcfg.yaml`:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 192.168.56.30/24
      routes:
        - to: default
          via: 192.168.56.1
      nameservers:
        addresses:
          - 192.168.56.1
```

Apply the configuration:
```bash
sudo chmod 600 /etc/netplan/01-netcfg.yaml
sudo netplan apply
ip addr show enp0s3
```

### Node 4: Wazuh SIEM Server (`lab-wazuh` - `192.168.56.40`)
Edit Netplan configuration at `/etc/netplan/01-netcfg.yaml`:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 192.168.56.40/24
      routes:
        - to: default
          via: 192.168.56.1
      nameservers:
        addresses:
          - 192.168.56.1
```

Apply the configuration:
```bash
sudo chmod 600 /etc/netplan/01-netcfg.yaml
sudo netplan apply
ip addr show enp0s3
```

---

## 5. Connectivity Verification Checklist

From each VM, perform ping and TCP connectivity checks:

1. **Ping Test from Host**:
   ```powershell
   ping 192.168.56.10 # Kali
   ping 192.168.56.20 # Windows 11
   ping 192.168.56.30 # Ubuntu Server
   ping 192.168.56.40 # Wazuh SIEM
   ```
2. **Ping Test from Kali Attacker**:
   ```bash
   ping -c 3 192.168.56.20 # Windows 11
   ping -c 3 192.168.56.30 # Ubuntu Server
   ```
3. **Wazuh Port Check**:
   ```bash
   nc -zv 192.168.56.40 1514 # Agent Event Port
   nc -zv 192.168.56.40 1515 # Agent Enrollment Port
   ```
