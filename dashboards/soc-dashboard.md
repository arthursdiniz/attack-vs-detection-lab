# SOC Operations Center Dashboard & Metrics

> **Real-time Security Operations Center (SOC) Operational View based on telemetry and alerts generated across the Attack vs Detection Lab environment.**

---

## 1. Executive Operations Overview

```text
========================================================================================
                      SECURITY OPERATIONS CENTER (SOC) DASHBOARD
========================================================================================

  [ ALERT DISTRIBUTION ]                     [ MONITORED ASSET HEALTH ]
  CRITICAL ALERTS :  2                        lab-win11   (192.168.56.20) : ONLINE / ACTIVE
  HIGH ALERTS     :  5                        lab-ubuntu  (192.168.56.30) : ONLINE / ACTIVE
  MEDIUM ALERTS   :  4                        lab-wazuh   (192.168.56.40) : HEALTHY (Green)
  INFORMATIONAL   : 12                        lab-attacker(192.168.56.10) : ISOLATED

----------------------------------------------------------------------------------------
  [ TOP ATTACK TECHNIQUES DETECTED ]         [ MOST TARGETED ACCOUNTS ]
  1. T1110.001 Brute Force / Spray   (32 ev)  1. lab-target (SSH Brute Force) : 20 attempts
  2. T1059.001 Suspicious PowerShell (14 ev)  2. admin      (Web Login Spray) : 12 attempts
  3. T1082 / T1087 Discovery Burst    (8 ev)  3. ubuntu     (Compromised)     :  6 attempts
  4. T1136.001 Account Manipulation   (2 ev)  4. lab-backdoor (Backdoor SID)  :  1 creation
  5. T1565.001 Critical File Tampering(2 ev)
========================================================================================
```

---

## 2. Mean Time To Detect (MTTD) by Incident Scenario

```text
┌───────────┬──────────────────────────────────────────┬──────────┬────────────┬─────────────┐
│ Incident  │ Scenario Description                     │ Severity │ MTTD (sec) │ Alert Rule  │
├───────────┼──────────────────────────────────────────┼──────────┼────────────┼─────────────┤
│ INC-001   │ SSH Authentication Brute Force           │ High     │ 32s        │ Rule 100001 │
│ INC-002   │ Suspicious Encoded PowerShell Execution  │ High     │ 2s         │ Rule 100010 │
│ INC-003   │ Local Account Created & Promoted to Admin│ Critical │ 15s        │ Rule 100022 │
│ INC-004   │ Real-time File Integrity Checksum Mismatch│ High    │ 5s         │ Rule 100030 │
│ INC-005   │ Rapid Behavioral Discovery Burst         │ High     │ 8s         │ Rule 100041 │
│ INC-006   │ SSH Spray Followed by Account Takeover   │ Critical │ 1s         │ Rule 100052 │
│ INC-007   │ Web Application Login Spray & Probing    │ High     │ 10s        │ Rule 100061 │
├───────────┴──────────────────────────────────────────┴──────────┴────────────┴─────────────┤
│ AVERAGE MEAN TIME TO DETECT (MTTD): 10.4 SECONDS                                           │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Wazuh Dashboard Visual Configuration

### Filter Presets for SOC Triage
To surface the highest priority incidents on the Wazuh Dashboard, apply the following OpenSearch Query DSL filters:

1. **Active Intrusions & Critical Correlations**:
   ```json
   {
     "query": {
       "bool": {
         "should": [
           { "term": { "rule.id": "100002" } },
           { "term": { "rule.id": "100022" } },
           { "term": { "rule.id": "100052" } }
         ],
         "minimum_should_match": 1
       }
     }
   }
   ```
2. **All Custom DetectLab Alerts**:
   ```json
   {
     "query": {
       "range": {
         "rule.id": {
           "gte": 100001,
           "lte": 100099
         }
       }
     }
   }
   ```
