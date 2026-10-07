# Evaluation: Adversary Emulation and Detection Metrics

The detections were tested with **Atomic Red Team** (Red Canary), a public library of repeatable tests mapped to MITRE ATT&CK techniques. Each test was mapped in advance to a technique, a detection rule and a log source, so the expected result was known before the test ran. A result was only accepted once it had been confirmed from the raw event in Splunk, not from the alert alone.

**Mean time to detect (MTTD)** was measured as the time the event became searchable in Splunk minus the execution time recorded in the Windows event.

## Results (20 August 2026)

| # | ATT&CK technique | Atomic test | Outcome | Detection path |
|---|---|---|---|---|
| 1 | T1059.001 PowerShell (encoded) | T1059.001-17 | Detected | Event 4688 (Rules 1 and 14) |
| 2 | T1082 System Information Discovery | T1082-1 | Detected | Event 4688 (Rule 13) |
| 3 | T1053.005 Scheduled Task | T1053.005-1 | Detected | Event 4688 (Rule 10) |
| 4 | T1547.001 Registry Run Keys | T1547.001-1 | Detected | Sysmon Event 13 (Rule 4) |
| 5 | T1003.001 LSASS Memory | T1003.001-2 | Blocked and logged | Defender 1116/1117 (Rule 12) |
| 6 | T1016 Network Configuration Discovery | T1016-1 | Detected | Event 4688 (Rule 13) |
| 7 | T1112 Modify Registry | T1112-1 | Detected | Sysmon Event 13 (Rule 4 family) |

"Detected" means a SIEM rule fired on the resulting event. "Blocked and logged" means Microsoft Defender stopped the technique and the block was recorded in the SIEM.

## Summary metrics

| Metric | Result |
|---|---|
| Techniques tested / tactics covered | 7 techniques across 5 tactics |
| Detected by SIEM analytics | 6 of 7 (86%) |
| Effective coverage (detected, or prevented and recorded) | 7 of 7 (100%) |
| Mean time to detect | Within one 60-second forwarding cycle |
| False-positive reduction, highest-volume rule | 714 to 29 matches (about 96%) |
| Telemetry sources exercised | Security 4688, Sysmon 13, Defender 1116/1117 |

Both detection figures are reported on purpose. A SOC should measure what the whole control set stops and records, but it should not claim a detection its own analytics did not make. In test 5, Defender stopped the LSASS dump before the process could access LSASS memory, so Rule 9 did not fire and is still unvalidated against a successful dump.

## Validation status by rule

| Rule | Status |
|---|---|
| 1, 14 Suspicious and encoded PowerShell | Validated (T1059.001-17) |
| 4 Registry Run-key persistence | Validated (T1547.001-1, T1112-1) |
| 10 Scheduled task creation | Validated (T1053.005-1) |
| 13 System and account discovery | Validated (T1082-1, T1016-1) |
| 12 Defender malware detection | Validated: recorded the blocked LSASS test (T1003.001-2) and an earlier blocked certutil download (T1105) |
| 15 Suricata network intrusion | Validated with a known-malicious user-agent test |
| 16 Suricata known CVE / exploit | Fired on real traffic; the 22 CVE-2018-11409 matches were triaged as benign lab management traffic |
| 2 Brute-force authentication | Logic exercised by real attacks on the cloud honeypot (Sentinel); on-premises rule not yet tested with Atomic Red Team |
| 9 LSASS credential dumping | Not yet validated: the test was blocked before LSASS was accessed |
| 3, 5, 6, 7, 8, 11 | Not yet validated with Atomic Red Team |

## Tuning

| Rule | Before | After | Change |
|---|---|---|---|
| 1 Suspicious PowerShell | 714 matches | 29 | Excluded the log forwarder's own activity (`NOT "Send-LogsToHEC"`) |
| 7 Explicit-credential logon | 37 matches | 25 | Excluded system processes and machine accounts |

Evidence: [PowerShell rule after tuning](../evidence/powershell-rule-tuned.png) · [ATT&CK coverage heat map](../evidence/attack-coverage-heatmap.png) · [Navigator layer](../attack-navigator/)

## Limitations

- **Small, favourable sample.** Seven techniques establish the method, but each was chosen because a matching rule existed, and Atomic tests are unobfuscated by design. The results show the rules work against known, standard behaviour, not against evasive variants.
- **Collection, not detection, sets MTTD.** Events are forwarded in 60-second batches, so the figure is an upper bound rather than a performance claim. Streaming collection would reduce it.
- **One endpoint, no domain.** False-positive rates in a real estate would be higher, and lateral movement and exfiltration could not be tested.
- **Single author.** In a production SOC, rules would be peer-reviewed and tested by someone other than their author.

## Next steps

Atomic tests are planned for the rules not yet validated, starting with brute force (T1110), log clearing (T1070.001) and account creation (T1136.001), followed by obfuscated and evasive variants of the techniques already tested.
