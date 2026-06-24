# 🛡️ SOC Home Lab — Brute Force Attack Detection (Splunk SIEM)

> **Analyst:** Gaurav | Cybersecurity Enthusiast  
> **Tool:** Splunk Enterprise 10.4  
> **Technique Detected:** T1110 — Brute Force (MITRE ATT&CK)  
> **Verdict:** ✅ True Positive — HIGH Severity

---

## 📌 Project Overview

This project simulates a real-world SOC L1 triage workflow. A brute-force login attack was detected and investigated using **Splunk SIEM** by writing custom **SPL (Search Processing Language)** queries to identify suspicious login patterns in Windows Security Event Logs.

The full investigation follows the standard SOC triage process:
- Alert detection → Validation → IOC analysis → Verdict → Remediation recommendation

---

## 🎯 What Was Detected

A **brute-force attack** against the `admin` account was identified:

| Detail | Value |
|---|---|
| Target Account | `admin` |
| Source IP | `192.168.1.50` (internal) |
| Failed Attempts | **6 consecutive failures** (EventCode 4625) |
| Time Window | 29 seconds (10:01:02 → 10:01:31) |
| Outcome | **Successful login (EventCode 4624)** — Account Compromised |
| Classification | ✅ True Positive — HIGH Severity |

---

## 🔍 Detection Methodology

### Log Source
Windows Security Event Logs ingested into **Splunk Enterprise 10.4**

### Key Windows Event IDs Used

| EventCode | Meaning |
|---|---|
| `4625` | Failed login attempt |
| `4624` | Successful login |

### SPL Query 1 — Brute Force Detection
```spl
index=main sourcetype=csv EventCode=4625
| stats count by user, src_ip
| where count > 3
```
**Result:** `admin` account flagged — 6 failed logins from `192.168.1.50`

### SPL Query 2 — Attack Timeline (Confirm Compromise)
```spl
index=main sourcetype=csv user=admin
| table _time, EventCode, status
| sort _time
```
**Result:** 6 failures (4625) immediately followed by 1 success (4624) — confirms brute-force succeeded

---

## 📊 Attack Timeline

```
10:01:02  ❌ 4625 FAILURE  — Attempt #1
10:01:05  ❌ 4625 FAILURE  — Attempt #2
10:01:09  ❌ 4625 FAILURE  — Attempt #3
10:01:14  ❌ 4625 FAILURE  — Attempt #4
10:01:20  ❌ 4625 FAILURE  — Attempt #5
10:01:25  ❌ 4625 FAILURE  — Attempt #6
10:01:31  ✅ 4624 SUCCESS  — ⚠️ ACCOUNT COMPROMISED
```

---

## 🔎 IOC Analysis

| IOC | Value | Tool Used | Result |
|---|---|---|---|
| Source IP (Internal) | `192.168.1.50` | AbuseIPDB | Private/RFC1918 range — internal host |
| Target Account | `admin` | Manual | High-privilege account |

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |
| Initial Access | Valid Accounts (post-compromise) | T1078 |

---

## ✅ Recommended Remediation Actions

| Priority | Action |
|---|---|
| 🔴 IMMEDIATE | Reset admin password, invalidate active sessions |
| 🔴 IMMEDIATE | Isolate source host 192.168.1.50 pending investigation |
| 🟠 HIGH | Block external IP 45.33.22.11 at firewall |
| 🟠 HIGH | Enable account lockout policy (lock after 5 failures) |
| 🟠 HIGH | Enable MFA on all privileged accounts |
| 🔵 MEDIUM | Review all post-compromise activity under admin account |
| 🔵 MEDIUM | Add IOC patterns as SIEM correlation rules |

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| Splunk Enterprise 10.4 | SIEM — log ingestion, SPL querying, alert detection |
| AbuseIPDB | IP reputation / IOC lookup |
| Kali Linux | Lab environment |
| Windows Security Event Logs | Log source (EventCode 4625/4624) |

---

## 📁 Repository Structure

```
soc-bruteforce-lab/
├── README.md                            # Project overview & investigation summary
├── SOC_Incident_Report_BruteForce.pdf  # Full investigation report
├── brute_force_sample.csv              # Simulated log data used in lab
├── preview1.png                        # Splunk SPL query + detection result
├── preview2.png                        # Full attack timeline in Splunk
└── preview3.png                        # AbuseIPDB IOC reputation check
```

---

## 📄 Full Report

The complete incident investigation report (PDF) is available in this repository. It includes:
- Executive summary
- Detection methodology with SPL queries
- Full attack timeline
- IOC analysis with screenshots
- Verdict and remediation recommendations

---

## 🎓 Skills Demonstrated

- SIEM (Splunk) — log ingestion, SPL query writing, detection
- Windows Event Log analysis (4625/4624 — brute force pattern)
- IOC lookup and threat intelligence (AbuseIPDB)
- MITRE ATT&CK framework mapping
- SOC triage workflow (alert → validate → investigate → recommend)
- Incident report writing

---

*This project demonstrates hands-on SOC detection and investigation 
skills using Splunk SIEM in a Kali Linux lab environment.*
