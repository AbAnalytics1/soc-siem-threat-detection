# Detection Rules

16 detection rules mapped to the MITRE ATT&CK framework, spanning two log sources
(Windows endpoint telemetry and Suricata network IDS). Each was baselined against
normal activity, tuned to reduce false positives and saved as a scheduled Splunk
alert. Which rules have been validated with Atomic Red Team tests is recorded in
[evaluation/](../evaluation/README.md).

**Data model note:** process-creation telemetry is reliably available as Windows
Event 4688 in `windows_security`. Because events are ingested as JSON via HEC,
keyword-based SPL matches the data more reliably than field-wildcard expressions.

---

## Endpoint Detection Rules (windows_security / windows_sysmon)

### Rule 1 — Suspicious PowerShell Execution — T1059.001 — High
Detects PowerShell launched with attacker-associated flags. Tuned from 714 to 29
matches by excluding the log-shipper's own activity (~96% false-positive reduction).
```spl
index=windows_security EventCode=4688 powershell ("-enc " OR "-EncodedCommand" OR "IEX" OR "DownloadString" OR "Net.WebClient" OR "-w hidden") NOT "Send-LogsToHEC"
```

### Rule 2 — Brute-Force Authentication — T1110 — High
Detects more than 5 failed logons (Event 4625) for one account on one host within a 10-minute window.
```spl
index=windows_security EventCode=4625 | bin _time span=10m | stats count as failed_attempts by _time, TargetUserName, Computer | where failed_attempts > 5 | sort -failed_attempts
```

### Rule 3 — New Windows Service Creation — T1543.003 — Medium
Detects new service installation (Event 7045) — a common persistence technique.
```spl
index=windows_security EventCode=7045 | table _time, Computer, ServiceName, ImagePath, ServiceType, StartType | sort -_time
```

### Rule 4 — Registry Run-Key Persistence — T1547.001 — High
Detects values written to Run/RunOnce registry keys (Sysmon Event 13).
```spl
index=windows_sysmon EventCode=13 Run | table _time, Computer, TargetObject, Details, Image | sort -_time
```

### Rule 5 — Windows Event Log Cleared — T1070.001 — Critical
Detects clearing of the Windows Security log (Event 1102) — anti-forensic activity.
```spl
index=windows_security EventCode=1102 | table _time, Computer, SubjectUserName | sort -_time
```

### Rule 6 — Account Creation / Privilege Escalation — T1136.001 / T1098 — High
Detects new account creation (4720) and additions to privileged groups (4732).
```spl
index=windows_security (EventCode=4720 OR EventCode=4732) | table _time, Computer, EventCode, TargetUserName, SubjectUserName, MemberName | sort -_time
```

### Rule 7 — Explicit-Credential Logon — T1078 — Medium
Detects explicit-credential logons (Event 4648), excluding system processes and
machine accounts. Tuned from 37 to 25 matches.
```spl
index=windows_security EventCode=4648 NOT ProcessName IN ("*svchost.exe","*winlogon.exe","*wininit.exe","*lsass.exe","*services.exe") NOT TargetUserName IN ("DWM-*","UMFD-*","*$") | table _time, Computer, SubjectUserName, TargetUserName, ProcessName | sort -_time
```

### Rule 8 — Security Tooling Disabled — T1562.001 — High
Detects attempts to disable Windows Defender / AV via command line (Event 4688).
```spl
index=windows_security EventCode=4688 ("DisableRealtimeMonitoring" OR "Set-MpPreference" OR "WinDefend" OR "DisableAntiSpyware" OR "MpPreference") | table _time, Computer, SubjectUserName, CommandLine | sort -_time
```

### Rule 9 — LSASS Credential Dumping — T1003.001 — Critical
Detects non-system processes accessing LSASS memory (Sysmon Event 10).
```spl
index=windows_sysmon EventCode=10 lsass NOT SourceImage IN ("*lsass.exe","*csrss.exe","*wininit.exe","*services.exe","*svchost.exe","*MsMpEng.exe") | table _time, Computer, SourceImage, TargetImage, GrantedAccess | sort -_time
```

### Rule 10 — Scheduled Task Creation — T1053.005 — Medium
Detects scheduled task creation (Event 4698 / schtasks) — persistence.
```spl
index=windows_security (EventCode=4698 OR "schtasks") | table _time, Computer, SubjectUserName, TaskName, CommandLine | sort -_time
```

### Rule 11 — Certutil LOLBin Download — T1105 — High
Detects certutil.exe used with URL/cache flags — malware ingress via a
living-off-the-land binary.
```spl
index=windows_security EventCode=4688 certutil (urlcache OR "-split" OR http) | table _time, Computer, SubjectUserName, CommandLine | sort -_time
```

### Rule 12 — Defender Malware Detection (defence-in-depth) — Critical
Surfaces Windows Defender malware detections (Events 1116/1117) in the SIEM.
```spl
index=windows_security (EventCode=1116 OR EventCode=1117) | table _time, Computer, Threat_Name, Severity_Name, Path | sort -_time
```

### Rule 13 — System & Account Discovery — T1082 / T1087 — Medium
Detects reconnaissance commands (whoami, net user, systeminfo, net localgroup).
```spl
index=windows_security EventCode=4688 (whoami OR "net user" OR systeminfo OR "net localgroup" OR "net accounts" OR "net group") | table _time, Computer, SubjectUserName, CommandLine | sort -_time
```

### Rule 14 — Encoded / Obfuscated PowerShell — T1027 / T1059.001 — High
Detects base64-encoded PowerShell (-EncodedCommand / -enc).
```spl
index=windows_security EventCode=4688 powershell ("-enc" OR "-encodedcommand" OR "-e ") | table _time, Computer, SubjectUserName, CommandLine | sort -_time
```

---

## Network Detection Rules (Suricata / suricata index)

### Rule 15 — Network Intrusion Detected — High
Surfaces genuine Suricata IDS alerts (excludes low-level stream anomalies).
```spl
index=suricata | spath "alert.signature" | search NOT "alert.signature"="SURICATA STREAM*" | stats count by "alert.signature", src_ip, dest_ip | sort -count
```

### Rule 16 — Known CVE / Exploit Attempt — T1190 — Critical
Detects network traffic matching known CVE/exploit signatures (e.g. the observed
CVE-2018-11409 Splunk information-disclosure signature).
```spl
index=suricata | spath "alert.signature" | search "alert.signature"="*CVE*" OR "alert.signature"="*Exploit*" | table _time, src_ip, dest_ip, "alert.signature" | sort -_time
```
