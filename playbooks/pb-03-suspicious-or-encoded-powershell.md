# PB-03 Suspicious or encoded PowerShell

[← Back to all playbooks](README.md)

Use this playbook when PowerShell is launched with an encoded command, a hidden window, or a download-and-execute pattern. Attackers favour these options because they hide what the command does from simple inspection, but the behaviour of launching PowerShell in this way is itself a strong signal.

**Table D5.** *PB-03 at a Glance*

| Field | Detail |
|---|---|
| **Trigger** | Rule 1, Suspicious PowerShell execution; Rule 14, Encoded PowerShell (both Windows Event 4688 with command-line auditing) |
| **MITRE ATT&CK** | T1059.001 Command and Scripting Interpreter: PowerShell; T1027 Obfuscated Files or Information |
| **Default severity** | High; Critical if the decoded command downloads or runs code, or contacts an external address |
| **Data sources** | Windows Security Event 4688; Sysmon Event 1; Suricata alerts for the same time window |
| **Dashboard panels** | Top Suspicious Command Lines; live detection feed |
| **Validation status** | Atomic Red Team test T1059.001-17 was detected, with the full parent-child chain (cmd.exe launching powershell.exe -e) recorded. The log forwarder is excluded as known-good after tuning reduced matches from 714 to 29. |

*Note.* Table D5 summarises the trigger, techniques, severity, data sources and validation status for PB-03.

## 1. Trigger and triage
- Retrieve the full command line, the parent process and the user account.

```spl
index=windows_security EventCode=4688 powershell
  ("-enc" OR "-EncodedCommand" OR "IEX" OR "DownloadString" OR "-w hidden")
  NOT "Send-LogsToHEC"
| table _time Computer SubjectUserName ParentProcessName CommandLine
```
- Check whether the activity matches a documented, approved administrative script. If it does, close as benign and record the reason; if not, continue.

## 2. Analysis
- Decode any encoded command. PowerShell's -EncodedCommand takes Base64-encoded UTF-16LE text, which can be decoded on an analysis workstation, for example with: [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<string>")).
- Assess the parent process: PowerShell started by an Office application or browser suggests a malicious document or download; started by a scheduled task or service suggests persistence.
- Look for follow-on activity on the same host in the minutes after execution: discovery commands (Rule 13), certutil downloads (Rule 11), new services, tasks or Run keys, and any Suricata alerts involving the host.

## 3. Containment
- If the command is malicious, isolate the host and stop the process.
- Block any domain or IP address the command contacted, and disable the user account if it appears to be compromised.

## 4. Eradication and recovery
- Remove any persistence created (Rules 3, 4 and 10) and run a full Microsoft Defender scan.
- If the integrity of the host cannot be confirmed, rebuild it from a known-good image (in the lab, restore the clean snapshot).

## 5. Communication and escalation
- High: inform the incident manager within the target time; escalate to Critical and inform the CISO if code was downloaded or executed.
- Involve the data protection officer if the host holds or can reach personal data (ICO, 2024).

## 6. Evidence to preserve
- The full original command line, the decoded script, the parent-child process chain and any related network alerts.

## 7. Lessons learned
- Add newly approved administrative scripts to a documented allow-list rather than weakening the rule.
- Consider enabling PowerShell Script Block Logging (Event 4104), which records the decoded content of scripts as they run.
