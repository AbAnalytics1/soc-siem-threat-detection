# SOC with SIEM-Based Threat Detection

A functional Security Operations Centre (SOC) built around a **Splunk Enterprise SIEM**, featuring **14 detection rules mapped to the MITRE ATT&CK framework**, a real-time analyst dashboard, and a fully instrumented Windows endpoint — implemented end-to-end on **Apple Silicon (ARM64)**, a platform the standard tooling does not officially support.

> MSc Cybersecurity capstone project. Scenario: threat detection for a financial-services organisation, where credential theft, privilege escalation, and anti-forensic activity carry direct regulatory and financial consequences.

---

## Overview

This project implements the core detection-and-response lifecycle of a modern SOC:

1. **Collect** — heterogeneous security telemetry ingested from a monitored Windows endpoint into Splunk.
2. **Detect** — 14 analytics mapped to MITRE ATT&CK techniques, each validated against a live simulated attack.
3. **Visualise** — a dark-themed SOC analyst dashboard surfacing alerts, trends, and technique coverage.
4. **Respond** — incident-response playbooks aligned to NIST SP 800-61 *(in progress)*.
5. **Measure** — adversary emulation and mean-time-to-detect (MTTD) measurement *(in progress)*.

---

## Architecture

| Component | Platform | Role |
|-----------|----------|------|
| Splunk Enterprise (x86-64 Docker) | Ubuntu 24.04 ARM VM + Rosetta | SIEM core — indexing, search, alerting |
| Windows 11 (ARM) endpoint | Parallels VM | Monitored workstation |
| Sysmon (ARM64) | On the endpoint | Process / network / registry telemetry |
| Custom PowerShell HEC shipper | On the endpoint | Log forwarding (replaces the unsupported Universal Forwarder) |
| Microsoft Defender | On the endpoint | Endpoint protection (defence-in-depth layer) |

### The Apple Silicon engineering angle

The reference materials assume x86 hardware and VirtualBox. Delivering this on an M-series MacBook required re-architecting the stack:

- **Splunk has no ARM build** → deployed as an x86-64 Docker container under Rosetta emulation, made reboot-resilient via a `systemd` service that re-registers the translation handler at boot.
- **The Universal Forwarder is unsupported on Windows ARM** → replaced with a custom PowerShell script shipping events to the Splunk HTTP Event Collector (HEC).
- A multi-layered ingestion fault (timezone offset, collector event-cap, source-side filtering, index routing) was diagnosed and resolved — documented as methodology in `/docs`.

---

## Detection Rules (MITRE ATT&CK)

Fourteen detection rules span the intrusion lifecycle — execution, persistence, privilege escalation, defence evasion, credential access, discovery, and lateral movement.

| # | Detection Rule | MITRE ID | Severity |
|---|----------------|----------|----------|
| 1 | Suspicious PowerShell Execution | T1059.001 | High |
| 2 | Brute-Force Authentication | T1110 | High |
| 3 | New Windows Service Creation | T1543.003 | Medium |
| 4 | Registry Run-Key Persistence | T1547.001 | High |
| 5 | Windows Event Log Cleared | T1070.001 | Critical |
| 6 | Account Creation / Privilege Escalation | T1136.001 / T1098 | High |
| 7 | Explicit-Credential Logon (Lateral Movement) | T1078 | Medium |
| 8 | Security Tooling Disabled | T1562.001 | High |
| 9 | LSASS Credential Dumping | T1003.001 | Critical |
| 10 | Scheduled Task Creation | T1053.005 | Medium |
| 11 | Certutil LOLBin Download | T1105 | High |
| 12 | Defender Malware Detection (defence-in-depth) | — | Critical |
| 13 | System & Account Discovery | T1082 / T1087 | Medium |
| 14 | Encoded / Obfuscated PowerShell | T1027 / T1059.001 | High |

Each rule was baselined against normal activity, tested against a simulated attack, and tuned to reduce false positives (e.g. Rule 1 was tuned from 714 to 29 matches by excluding benign activity).

---

## Repository Structure

```
.
├── detection-rules/   # The 14 SPL detection searches
├── scripts/           # HEC shipper, Rosetta registration, Sysmon config
├── dashboards/        # SOC analyst dashboard (Simple XML)
├── playbooks/         # NIST SP 800-61 incident-response playbooks
├── docs/              # Build logs, implementation report, lab journal
├── evidence/          # Screenshots
└── configs/           # Environment configuration
```

---

## Frameworks & Standards

- **MITRE ATT&CK** — technique mapping for all detections
- **NIST SP 800-61** — incident-response playbook structure
- **Atomic Red Team** — adversary emulation for validation *(in progress)*
- **Gibbs' Reflective Cycle (1988)** — reflective practice

---

## Status

- [x] SIEM deployed and reboot-resilient on Apple Silicon
- [x] Endpoint instrumented (Sysmon, audit policy)
- [x] Automated, time-accurate log ingestion
- [x] 14 MITRE ATT&CK detection rules (built, tuned, alerting)
- [x] SOC analyst dashboard
- [ ] Network IDS source (Suricata)
- [ ] NIST SP 800-61 playbooks
- [ ] Adversary emulation & MTTD measurement
- [ ] ATT&CK Navigator coverage heat map

---

## Security Note

All credentials, tokens, and secrets have been removed from the files in this repository and replaced with placeholders. Configure your own values before use.

---

*This repository is part of an academic project and is shared for portfolio and educational purposes.*
