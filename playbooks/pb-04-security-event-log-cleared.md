# PB-04 Security event log cleared

[← Back to all playbooks](README.md)

Use this playbook when the Windows Security log is cleared. Legitimate clearing is rare and should be covered by an approved change; otherwise it usually indicates an attacker removing evidence of earlier activity. Because the SOC forwards events to the SIEM within about a minute, the events that the attacker tried to erase are normally still available in Splunk.

**Table D6.** *PB-04 at a Glance*

| Field | Detail |
|---|---|
| **Trigger** | Rule 5, Security event log cleared (Windows Event 1102) |
| **MITRE ATT&CK** | T1070.001 Indicator Removal: Clear Windows Event Logs |
| **Default severity** | Critical unless an approved change covers it |
| **Data sources** | Windows Security Event 1102; all events from the same host in the preceding hours |
| **Dashboard panels** | Critical & High Alerts tile; live detection feed |
| **Validation status** | Not yet tested with Atomic Red Team; shown as covered but not validated in Figure 4.3. Atomic test T1070.001 is planned. |

*Note.* Table D6 summarises the trigger, technique, severity, data sources and validation status for PB-04.

## 1. Trigger and triage
- Identify the host, the time and the account that cleared the log.
- Check the change-management record. If an approved change covers the action, record it and close; if not, treat it as an active intrusion.

```spl
index=windows_security EventCode=1102
| table _time Computer SubjectUserName
```

## 2. Analysis
- Rebuild the timeline from the copy of the events already held in Splunk, focusing on the hours before the log was cleared: process creation (Event 4688), logons (Events 4624 and 4648), new accounts (Event 4720) and new services (Event 7045).
- Identify what the attacker was trying to hide and how they gained the rights needed to clear the log.

```spl
index=windows_security Computer="<host>" earliest=-4h
  (EventCode=4688 OR EventCode=4624 OR EventCode=4648 OR EventCode=4720 OR EventCode=7045)
| sort _time | table _time EventCode SubjectUserName TargetUserName CommandLine
```

## 3. Containment
- Isolate the host and disable the account that cleared the log; treat its credentials as compromised.
- Confirm that log forwarding from the host is still working, since an attacker may also try to stop the forwarder.

## 4. Eradication and recovery
- Act on what the timeline reveals, following PB-02 or PB-03 where credential theft or malicious PowerShell is found.
- Rebuild the host from a known-good image if its integrity cannot be confirmed.

## 5. Communication and escalation
- Escalate to the incident manager and CISO immediately, and involve the data protection officer if personal data may have been accessed (ICO, 2024).

## 6. Evidence to preserve
- The Event 1102 record, the reconstructed timeline from the SIEM and the change-management check.

## 7. Lessons learned
- Restrict the right to clear security logs to a small number of administrators.
- Implement the collection-health alert in Recommendation R1, so that a forwarder stopped by an attacker is detected as quickly as a cleared log.
