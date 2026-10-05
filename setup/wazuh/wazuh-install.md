# Wazuh All-in-One SIEM Deployment Guide

## 1. Overview & Architecture

The SIEM cluster runs on `lab-wazuh` (`192.168.56.40`), installed on Ubuntu Server 22.04 LTS. This deployment uses the official **Wazuh Central Components (All-in-One)** model, consolidating the three core pillars into a single virtual appliance:

1. **Wazuh Indexer**: A highly scalable, document-oriented search and analytics engine based on OpenSearch. It indexes security events into `wazuh-alerts-4.x-*`.
2. **Wazuh Server**: The core security engine containing:
   - `wazuh-analysisd`: Normalizes and matches logs against custom decoders and XML detection rules.
   - `wazuh-remoted`: Receives TLS-encrypted event streams from agents on port `1514/TCP`.
   - `wazuh-authd`: Automates mutual-TLS agent enrollment and key distribution on port `1515/TCP`.
   - `wazuh-modulesd`: Manages vulnerability detection and MITRE ATT&CK database integration.
3. **Wazuh Dashboard**: The web-based graphical interface for real-time visualization, security analytics, SOC incident triage, and MITRE mapping.

---

## 2. System Prerequisites

Before initiating installation on `lab-wazuh`:
- **CPU**: 4 vCPUs allocated.
- **RAM**: 8 GB RAM allocated (JVM Heap for Indexer requires 4 GB).
- **Disk**: 50 GB virtual storage.
- **Network**: Static IP set to `192.168.56.40` on Host-Only adapter.
- **Internet Access**: Temporarily enable NAT adapter (Adapter 2) to download packages during setup.

---

## 3. Automated All-in-One Installation (Wazuh Quickstart)

The official Wazuh Quickstart script configures certificates, services, and default users automatically.

### Step 1: Update and install prerequisites
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl apt-transport-https lsb-release gnupg tar net-tools
```

### Step 2: Download and execute the Wazuh Quickstart Script
```bash
# Download the official installation script
curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.11/config.yml

# Execute the All-in-One installation
sudo bash ./wazuh-install.sh -a
```

> **Note on Wazuh Versions**: Wazuh 4.10+ and 4.11+ feature native support for OpenSearch 2.x and enhanced MITRE ATT&CK v14+ matrix tagging.

### Step 3: Record Admin Credentials
Upon completion, the installer outputs the administrative credentials and saves them to a tarball:

```bash
# Extract and review credentials
sudo tar -xvf wazuh-install-files.tar
sudo cat wazuh-install-files/wazuh-passwords.txt
```

Example output:
```text
The password for 'admin' user in Wazuh Dashboard is: <GENERATED_PASSWORD>
```

---

## 4. Service Verification & Health Checks

Verify that all four critical daemons are active and running:

```bash
# Check service states
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-dashboard
sudo systemctl status filebeat

# Verify listening ports
sudo netstat -tulpn | grep -E '1514|1515|9200|55000|443'
```

Expected port mapping:
- `0.0.0.0:1514` -> `wazuh-remoted` (Agent event traffic)
- `0.0.0.0:1515` -> `wazuh-authd` (Agent auto-enrollment)
- `127.0.0.1:9200` -> `wazuh-indexer` (OpenSearch document indexing)
- `127.0.0.1:55000` -> `wazuh-apid` (Wazuh Management API)
- `0.0.0.0:443` -> `wazuh-dashboard` (Web user interface)

---

## 5. Tuning Memory & JVM Heap for the Lab

If running on constrained resources (Profile B - 16 GB Host), adjust the Indexer JVM heap size to prevent out-of-memory errors:

```bash
# Edit JVM options for Wazuh Indexer
sudo nano /etc/wazuh-indexer/jvm.options

# Locate and adjust the initial and maximum heap size lines:
-Xms2g
-Xmx2g

# Restart the indexer
sudo systemctl restart wazuh-indexer
```

---

## 6. Accessing the SOC Dashboard

1. From the host workstation (`192.168.56.1`), open a modern web browser.
2. Navigate to: `https://192.168.56.40`
3. Accept the self-signed SSL/TLS certificate warning.
4. Log in using:
   - **Username**: `admin`
   - **Password**: `<Password from wazuh-passwords.txt>`
5. Confirm that the dashboard loads cleanly and reports **Cluster status: Green**.

---

## 7. Isolating the Wazuh Node

Once installation and package downloads are complete:
1. Shut down or disable the NAT interface (Adapter 2):
   ```bash
   sudo ip link set enp0s8 down
   ```
2. Confirm that only `enp0s3` (`192.168.56.40`) remains active.
