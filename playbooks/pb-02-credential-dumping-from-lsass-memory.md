# PB-02 Credential dumping from LSASS memory

[← Back to all playbooks](README.md)

Use this playbook when a process attempts to read the memory of the Local Security Authority Subsystem Service (LSASS), or when Microsoft Defender detects a credential-dumping tool. An attacker who can do this already has administrative rights on the host and is attempting to obtain credentials to move further into the network, so it is always treated as Critical.

**Table D4.** *PB-02 at a Glance*

| Field | Detail |
|---|---|
| **Trigger** | Rule 9, LSASS credential dumping (Sysmon Event 10); Rule 12, Defender malware detection (Defender Events 1116 and 1117) |
| **MITRE ATT&CK** | T1003.001 OS Credential Dumping: LSASS Memory |
| **Default severity** | Critical, whether or not the attempt was blocked |
| **Data sources** | Sysmon Event 10; Microsoft Defender Events 1116 (detection) and 1117 (action taken); Windows Security Event 4688 |
| **Dashboard panels** | Critical & High Alerts tile; MITRE ATT&CK Techniques Detected; live detection feed |
| **Validation status** | Atomic Red Team test T1003.001-2 (comsvcs.dll method) was blocked and removed by Defender, and Events 1116/1117 with the full command line were received in Splunk. Rule 9 has not yet been validated against an unblocked attempt. |

*Note.* Table D4 summarises the trigger, technique, severity, data sources and validation status for PB-02. LSASS = Local Security Authority Subsystem Service.

## 1. Trigger and triage
- Treat the alert as Critical and notify the incident manager immediately; do not wait for confirmation.
- Establish whether Defender blocked the attempt (Event 1117 shows the action taken) and which process and account performed it.

```spl
index=windows_security (EventCode=1116 OR EventCode=1117)
| table _time Computer EventCode Message

index=windows_sysmon EventCode=10 TargetImage="*\\lsass.exe"
| table _time Computer SourceImage GrantedAccess
```

## 2. Analysis
- Reconstruct the process chain that led to the attempt using process-creation events, looking for known techniques such as comsvcs.dll MiniDump or procdump.
- Identify how the attacker gained administrative rights on the host: look back for suspicious logons (PB-01), PowerShell (PB-03) or new services and scheduled tasks.
- List every account that has logged on to the host recently, because any of their credentials may have been exposed.

```spl
index=windows_security EventCode=4688
  (CommandLine="*comsvcs*" OR CommandLine="*MiniDump*" OR CommandLine="*procdump*")
| table _time Computer SubjectUserName ParentProcessName CommandLine
```

## 3. Containment
- Isolate the host from the network immediately, keeping it powered on so that volatile evidence can be considered.
- Assume that credentials used on the host are compromised: disable or reset them, starting with privileged and service accounts.
- Block the file hashes of any tools identified.

## 4. Eradication and recovery
- Remove the attacker's tools and any persistence found during analysis, then rebuild the host from a known-good image (in the lab, restore the clean virtual-machine snapshot).
- Rotate all exposed credentials, including service accounts, before reconnecting the host.
- Monitor for reuse of the exposed credentials elsewhere, such as explicit-credential logons (Rule 7, Event 4648) or logons from unexpected hosts.

## 5. Communication and escalation
- Escalate to the incident manager and CISO immediately.
- Involve the data protection officer if the host or the exposed credentials give access to personal data, to assess the 72-hour notification requirement (ICO, 2024), and involve compliance to assess any other regulatory reporting.

## 6. Evidence to preserve
- Defender detection details (threat name, file path, command line and action taken), Sysmon Event 10 records and the process-creation chain.
- A memory image of the host if one can be captured safely, and the hashes of all exported files.

## 7. Lessons learned
- Validate Rule 9 against an unblocked test in a controlled, documented exception, so that detection does not rely on Defender alone.
- Review whether LSA protection and Credential Guard are enabled across the client estate to make LSASS harder to read.
