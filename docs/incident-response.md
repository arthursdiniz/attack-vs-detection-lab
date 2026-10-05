# Incident Response Methodology (NIST SP 800-61r2)

## 1. Overview & Framework Alignment

This laboratory structures its incident handling procedures following the **NIST SP 800-61 Rev. 2** (Computer Security Incident Handling Guide) lifecycle. Every investigated scenario (INC-001 through INC-007) is processed through this standardized 4-phase workflow.

```text
       ┌────────────────────────────────────────────────────────┐
       │                 1. PREPARATION                         │
       │  • NTP synchronization across all VMs                  │
       │  • Sysmon, Auditd, and Wazuh Agents deployed           │
       │  • Pre-configured incident report templates            │
       └───────────────────────────┬────────────────────────────┘
                                   │
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │             2. DETECTION & ANALYSIS (TRIAGE)           │
       │  • Real-time alert surfacing on Wazuh Dashboard        │
       │  • Ground-truth log extraction and field decoding      │
       │  • Timeline construction and pivoting on IOCs          │
       │  • Resolution of the 8 Core SOC Questions              │
       └───────────────────────────┬────────────────────────────┘
                                   │
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │     3. CONTAINMENT, ERADICATION & RECOVERY             │
       │  • Short-term isolation (iptables drop, netsh isolate) │
       │  • Termination of rogue processes and TTY sessions     │
       │  • Remediation of unauthorized user accounts / keys    │
       │  • Restoration of system baselines                     │
       └───────────────────────────┬────────────────────────────┘
                                   │
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │           4. POST-INCIDENT ACTIVITY                    │
       │  • Formal Incident Report publication                  │
       │  • Hardening implementation (Before vs. After)         │
       │  • Detection rule threshold refinement                 │
       │  • Root cause analysis & lessons learned archiving     │
       └────────────────────────────────────────────────────────┘
```

---

## 2. The 8 Core SOC Investigation Questions

During **Phase 2 (Detection & Analysis)**, every SOC Analyst must answer eight deterministic questions to build a defensible incident timeline:

1. **Who performed the activity?**
   - Identify the source IP address, hostname, MAC address, and operating user context.
2. **What asset and user account was targeted?**
   - Confirm the target system, affected service port, and destination user identity.
3. **How many attempts or actions occurred?**
   - Quantify total events, burst rate, and threshold breaches.
4. **When did the intrusion start?**
   - Pinpoint the exact UTC timestamp of the first reconnaissance probe or authentication failure.
5. **When did the intrusion conclude?**
   - Record the end timestamp and total dwell time.
6. **Was there subsequent successful authentication or execution?**
   - Perform retroactive correlation for `Logon Success` (EID 4624 / sshd Accepted) or new process creations originating from the threat actor IP.
7. **Did the source IP execute other activities across the network?**
   - Pivot on the source IP to identify lateral movement, network service scans, or alternate target probing.
8. **Were other user accounts or endpoints targeted?**
   - Determine whether the activity represents targeted password guessing or a distributed spray campaign.

---

## 3. Operational Containment Playbook

### Windows Containment Procedures (`lab-win11`)
```powershell
# 1. Isolate endpoint from network (Drop all non-SIEM traffic)
netsh advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="Block-Attacker-IP" dir=in action=block remoteip=192.168.56.10

# 2. Terminate malicious process tree
Stop-Process -Id <PID> -Force

# 3. Disable compromised user account
Disable-LocalUser -Name "lab-backdoor"

# 4. Remove account from privileged security group
Remove-LocalGroupMember -Group "Administrators" -Member "lab-backdoor"
```

### Linux Containment Procedures (`lab-ubuntu`)
```bash
# 1. Terminate active adversary sessions
sudo pkill -KILL -u ubuntu

# 2. Apply immediate host firewall drop
sudo iptables -I INPUT -s 192.168.56.10 -j DROP

# 3. Lock compromised account password
sudo passwd -l ubuntu

# 4. Audit and purge rogue cron jobs
sudo crontab -u ubuntu -r
```
