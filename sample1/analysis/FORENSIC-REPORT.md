# FORENSIC ANALYSIS REPORT
## Case: DNS-RemoteShell — Covert Remote Shell via DNS Port Misuse

---

| Field | Value |
|---|---|
| **Case ID** | IR-2024-001-DNS-RSHELL |
| **Analyst** | [shadowciper] |
| **Date of Analysis** | July 5, 2024 |
| **Evidence File** | dns-remoteshell.pcap |
| **Evidence Hash (SHA-256)** | 8c89c0d2d5b91695a03d05a451897f583a99d2379afac0822af0d8f390163d95 |
| **Evidence Hash (MD5)** | 3451fc588eb703545b4ecd26d203acb5 |
| **File Size** | 25 KB (25,005 bytes) |
| **Packet Count** | 131 |
| **Capture Duration** | 99.733 seconds |
| **Classification** | Unauthorized Remote Access — Covert Channel |
| **Severity** | HIGH |
| **Confidence Level** | HIGH |

---

## 1. EXECUTIVE SUMMARY

A network forensic investigation of captured traffic (`dns-remoteshell.pcap`) revealed a compromised Windows XP host (192.168.1.2) being accessed by an internal attacker (192.168.1.3) via three covert remote shell sessions on ports 53 (DNS), 23 (Telnet), and 80 (HTTP). The attacker successfully executed filesystem enumeration commands. The use of TCP port 53 for non-DNS traffic constitutes a DNS port misuse covert channel designed to bypass network firewalls. Sixteen custom Snort rules were developed and validated against the captured traffic, producing a 100% detection rate.

---

## 2. AFFECTED ASSETS

| Asset | IP Address | MAC Address | Role | OS |
|---|---|---|---|---|
| Attacker | 192.168.1.3 | N/A | Internal threat actor | Linux-based (inferred) |
| Victim | 192.168.1.2 | 00:80:48:24:33:32 | Compromised host | Windows XP [5.1.2600] |
| Gateway | 192.168.1.1 | 00:90:d0:eb:46:e7 | Thomson SpeedTouch router | N/A |

### External Infrastructure Observed

| IP Address | Domain | Port | Protocol | Activity |
|---|---|---|---|---|
| 83.170.75.178 | web1.goals365.com | 80 | HTTP | GET /images/empty.gif (304) |
| 205.227.136.203 | Unknown | 443 | SSL/TLS | Encrypted session (tail-end) |
| 140.112.253.189 | Unknown | 22604 | TCP | Bare ACK (no handshake) |

---

## 3. TIMELINE OF EVENTS

| Timestamp (s) | Duration | Event | Source | Destination | Details |
|---|---|---|---|---|---|
| 0.000 | 2.9s | Network Reconnaissance | 192.168.1.3 | 192.168.1.1 | ARP requests + DNS reverse lookup for gateway (SpeedTouch.lan) + DNS query for www.www.com (63.215.91.200) |
| 1.116 | — | Anomalous ACK | 192.168.1.2 | 140.112.253.189:22604 | Bare TCP ACK with no prior handshake — possible artifact of prior session |
| 25.493 | 5.3s | Covert Shell on Port 53 | 192.168.1.3:1396 | 192.168.1.2:53 | TCP session established on DNS port. No DNS protocol present. Windows XP banner sent. `dir` command executed. `exit` sent. Session terminated with RST. |
| 48.475 | 6.1s | FTP Port Scan | 192.168.1.3 | 192.168.1.2:21 | 6 SYN packets sent to port 21 (FTP). All received RST — service closed. Attacker moved on. |
| 48.951 | 0.005s | Encrypted Session | 205.227.136.203:443 | 192.168.1.2:1109 | SSLv3 tail-end session — content unknown, established prior to capture. |
| 73.102 | 0.03s | HTTP Fetch | 192.168.1.2 | 83.170.75.178:80 | GET /images/empty.gif → 304 Not Modified. Legitimate-looking web request. |
| 75.776 | 9.8s | Telnet Shell on Port 23 | 192.168.1.3:1403 | 192.168.1.2:23 | Full interactive Telnet session. Banner → `dir` → `ls -la` (failed) → `exit`. RST sent. |
| 96.444 | 3.3s | Shell on Port 80 | 192.168.1.3:1404 | 192.168.1.2:80 | TCP session on HTTP port. No HTTP protocol. Banner → `dir` → `exit`. RST sent. |

---

## 4. TECHNICAL ANALYSIS

### 4.1 Protocol Overview

The capture contains 131 frames over 99.7 seconds. Protocol breakdown:

| Protocol | Frame Count | Observation |
|---|---|---|
| ARP | 6 | Gateway discovery and MAC resolution |
| DNS (UDP) | 6 | Reverse lookup + A record queries (www.www.com → 63.215.91.200) |
| TCP (port 53) | 24 | **Non-DNS traffic — covert remote shell** |
| TCP (port 21) | 12 | SYN scan — all RST (FTP closed) |
| TCP (port 23) | 33 | Telnet session with remote shell |
| TCP (port 80) | 23 | Non-HTTP traffic — remote shell on web port |
| HTTP (port 80) | 5 | Legitimate GET request to goals365.com |
| SSL/TLS | 3 | Encrypted session tail-end |
| TCP (anomalous) | 1 | Bare ACK to external IP |

### 4.2 Session 1 — Covert Shell on TCP Port 53

**Frames:** 14–38  
**Connection:** 192.168.1.3:1396 → 192.168.1.2:53  
**Protocol:** TCP (NOT DNS)

This connection uses TCP port 53 (the DNS port) but contains **no DNS protocol data**. The payload is a raw Windows command shell session. This is a deliberate technique to bypass firewalls that typically allow DNS traffic.

**Decoded payload (server → client):**
```
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\>
```

**Decoded payload (client → server):**
```
dir
```

**Decoded payload (server → client, truncated):**
```
Volume in drive C has no label.
Volume Serial Number is FD47-80EB
Directory of C:\

01/12/2005  11:59 AM                0 aierrorlog.txt
01/19/2004  09:45 PM                0 AUTOEXEC.BAT
...
```

**Decoded payload (client → server):**
```
exit
```

### 4.3 Session 2 — Remote Shell via Telnet (Port 23)

**Frames:** 76–108  
**Connection:** 192.168.1.3:1403 → 192.168.1.2:23

Standard Telnet session with an interactive Windows command shell. The attacker issued three commands:

| Command | Result |
|---|---|
| `dir` | Full C:\ directory listing returned |
| `ls -la` | **ERROR**: `'ls' is not recognized as an internal or external command` |
| `exit` | Session terminated with RST |

**Forensic significance of `ls -la` failure:** The attacker typed a Linux command on a Windows system, indicating their primary operating environment is Linux/Unix. This is an operational security mistake that profiles the attacker.

**Directory listing extracted (C:\):**
```
aierrorlog.txt          0 bytes  (12/01/2005)
AUTOEXEC.BAT            0 bytes  (01/19/2004)
CONFIG.SYS              0 bytes  (01/19/2004)
installer-debug.txt    11,531 bytes (02/29/2004)
s37g                    7,241 bytes
s3fs                    0 bytes
systemscandata.txt    123 bytes  (06/02/2004)
temp.mpg           94,135,944 bytes (12/12/2004)
Folders: Documents and Settings, EasyBoot, mga, mgafold, mnt, movie,
         My Downloads, Program Files, quarantine, Temp, WINDOWS, WUTemp
```

### 4.4 Session 3 — Remote Shell on HTTP Port 80

**Frames:** 109–131  
**Connection:** 192.168.1.3:1404 → 192.168.1.2:80

Identical shell pattern to Sessions 1 and 2. No HTTP headers present — confirming this is not a web request but a raw shell on the HTTP port. Attacker issued `dir`, received listing, then `exit`.

### 4.5 FTP Port Scan (Port 21)

**Frames:** 39–65  
**Connection attempts:** 6 SYN packets from 192.168.1.3 to 192.168.1.2:21  
**Responses:** All RST/ACK — FTP service not available

The attacker sent six SYN packets to port 21 (FTP) across three source ports (1399, 1402 reused). All were rejected with RST. This indicates the attacker was enumerating available services on the victim.

---

## 5. ATTACK CHAIN ANALYSIS (MITRE ATT&CK)

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | ARP requests, DNS queries, FTP port scan |
| Reconnaissance | Scanning IP Blocks | T1595.001 | SYN scan to port 21 |
| Initial Access | Remote Services | T1021 | Established shell on ports 53, 23, 80 |
| Execution | Command and Scripting Interpreter | T1059 | `dir`, `ls`, `exit` commands executed |
| Discovery | File and Directory Discovery | T1083 | `dir` command for filesystem enumeration |
| Discovery | System Information Discovery | T1082 | Windows XP version banner obtained |
| Command and Control | Non-Standard Port | T1571 | Shell on TCP 53 (DNS port) |
| Command and Control | Web Protocols | T1071.001 | Shell on TCP 80 (HTTP port) |

---

## 6. INDICATORS OF COMPROMISE (IOCs)

### Network IOCs

| Type | Value | Context | Confidence |
|---|---|---|---|
| IP | 192.168.1.3 | Attacker — internal lateral movement source | HIGH |
| IP | 192.168.1.2 | Victim — Windows XP compromised host | HIGH |
| IP | 83.170.75.178 | External — web1.goals365.com | MEDIUM |
| IP | 205.227.136.203 | External — encrypted SSL session | MEDIUM |
| IP | 140.112.253.189 | External — anomalous bare ACK | LOW |
| Port | TCP 53 | Covert shell channel (non-DNS) | HIGH |
| Port | TCP 23 | Telnet backdoor | HIGH |
| Port | TCP 80 | Non-HTTP backdoor shell | HIGH |
| Port | TCP 21 | Port scan target (closed) | HIGH |
| MAC | 00:80:48:24:33:32 | Victim NIC (Premier Imaging Technologies) | HIGH |
| MAC | 00:90:d0:eb:46:e7 | Gateway (Thomson SpeedTouch) | HIGH |

### Behavioral IOCs

| Indicator | Context |
|---|---|
| Windows XP banner on non-standard ports | Remote shell active on ports 53, 80 |
| `dir` command execution | Filesystem enumeration |
| `ls -la` command attempt | Linux-based attacker (muscle memory error) |
| TCP 53 without DNS protocol | Covert channel — DNS port misuse |
| RST after `exit` command | Clean session termination pattern |
| 6 SYN to port 21 without session | Port scan / service enumeration |

### Host IOCs (from `dir` output)

| File/Artifact | Significance |
|---|---|
| `quarantine/` folder | Antivirus was active on victim |
| `systemscandata.txt` | Security scanning tool present |
| `installer-debug.txt` | Debug log — potential attack artifact |
| `WUTemp/` folder | Windows Update temp — system was updating |

---

## 7. SNORT DETECTION RULES

Sixteen custom Snort rules were developed based on the forensic findings above. All rules were validated against the captured traffic, producing 16 alerts with 100% detection coverage.

### Rule Summary

| SID | Rule Name | Detection |
|---|---|---|
| 1000001 | Covert shell on TCP 53 — XP banner | Windows XP banner on DNS port |
| 1000002 | Telnet shell — XP banner | Windows XP banner on Telnet port |
| 1000003 | `dir` via Telnet | Filesystem enumeration command |
| 1000004 | Non-HTTP shell on port 80 — XP banner | Windows XP banner on HTTP port |
| 1000005 | FTP port scan — repeated SYN | 5+ SYN to port 21 in 15s |
| 1000006 | XP banner on any TCP | Generic remote shell detector |
| 1000007 | `ls` command on Windows | Attacker profiling — Linux user |
| 1000008 | TCP to port 53 (internal) | Covert channel — SYN to DNS port |
| 1000009 | `dir` on port 80 (non-HTTP) | Shell command on HTTP port |
| 1000010 | SYN scan on FTP port 21 | 6+ SYN to port 21 in 10s |
| 1000011 | `dir` on covert port 53 | Shell command on DNS port |
| 1000012 | `exit` on port 53 | Covert session termination |
| 1000013 | `exit` on port 80 | Backdoor session termination |
| 1000014 | Dir output on port 53 | Covert shell output confirmed |
| 1000015 | Dir output on port 80 | HTTP port shell output confirmed |
| 1000016 | Dir output on port 23 | Telnet shell output confirmed |

### Detection Results

```
Total alerts generated: 16
Unique rules triggered: 16/16 (100%)
False positives: 0
Missed detections: 0
```

---

## 8. IMPACT ASSESSMENT

| Category | Assessment |
|---|---|
| **Confidentiality** | COMPROMISED — Attacker obtained full C:\ directory listing |
| **Integrity** | UNKNOWN — No modification commands observed (no `del`, `copy`, `write`) |
| **Availability** | NOT AFFECTED — No denial of service observed |
| **Data Exfiltration** | POSSIBLE — `dir` output reveals file names, sizes, dates. SSL session to external IP may contain exfiltrated data. |
| **Lateral Movement** | CONFIRMED — Attacker is internal (192.168.1.3) and accessing another internal host |

---

## 9. RECOMMENDATIONS

### Immediate (Containment)
1. Isolate compromised host (192.168.1.2) from the network immediately
2. Identify and isolate attacker host (192.168.1.3)
3. Block TCP port 53 inbound from all internal hosts except authorized DNS servers
4. Disable Telnet (port 23) on all hosts — use SSH instead
5. Capture volatile evidence (memory dump) from both hosts before powering off

### Short-Term (Remediation)
1. Conduct full forensic investigation of host 192.168.1.2 — identify backdoor mechanism
2. Investigate host 192.168.1.3 — determine if it's the attacker's machine or a pivot point
3. Deploy the 16 custom Snort rules to production IDS/IPS
4. Review firewall rules — restrict outbound DNS to authorized DNS servers only
5. Patch or decommission Windows XP systems — end-of-life since 2014

### Long-Term (Improvement)
1. Implement network segmentation — restrict internal-to-internal communication
2. Deploy DNS tunneling detection (length-based, entropy-based, frequency-based)
3. Establish baseline network behavior for anomaly detection
4. Implement endpoint detection and response (EDR) on all critical assets
5. Conduct regular network security assessments and penetration tests

---

## 10. EVIDENCE APPENDIX

### Evidence Chain of Custody

| Field | Value |
|---|---|
| Evidence File | dns-remoteshell.pcap |
| SHA-256 | 8c89c0d2d5b91695a03d05a451897f583a99d2379afac0822af0d8f390163d95 |
| MD5 | 3451fc588eb703545b4ecd26d203acb5 |
| File Size | 25,005 bytes |
| Packet Count | 131 |
| Capture Duration | 99.733 seconds |
| Working Copy | dns-remoteshell.pcap.bak (hash verified) |

### Evidence Files

| File | Location | Purpose |
|---|---|---|
| dns-remoteshell.pcap | pcap/ | Original capture (evidence) |
| dns-remoteshell.pcap.bak | pcap/ | Working copy |
| snort_custom.conf | snort/ | Snort configuration |
| dns-remoteshell.rules | rules/ | 16 custom detection rules |
| snort_alerts_output.txt | snort/ | Alert output from Snort run |
| IR-Playbook-Network-Forensics.pdf | playbook/ | Methodology reference |
| evidence1.png — evidence4.png | evidence/ | Wireshark screenshots |

---

## 11. ANALYST NOTES

### Attacker Profile
Based on the `ls -la` muscle memory error, the attacker's primary operating environment is Linux/Unix. The attacker demonstrated methodical behavior (recon → probe → exploit on multiple ports) and knowledge of firewall evasion techniques (port 53 covert channel). This suggests an experienced operator, possibly automated (worm-like behavior checking multiple backdoor ports).

### Attack Pattern
The identical sequence (banner → `dir` → `exit`) on three different ports (53, 23, 80) suggests either:
1. An attacker testing which backdoor access points are available, OR
2. A worm verifying multiple propagation vectors

The filename `dns-remoteshell` and the presence of `slammer.pcap` in the same directory suggest this may be related to worm propagation analysis, specifically the SQL Slammer worm or similar malware that uses multiple network vectors.

---

*Report generated: July 5, 2024*  
*Classification: Confidential — Training Material*  
*Tools used: Wireshark 4.x, tshark 4.x, Snort 2.9.20*
