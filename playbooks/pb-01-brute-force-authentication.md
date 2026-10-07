# PB-01 Brute-force authentication

[← Back to all playbooks](README.md)

Use this playbook when an account receives repeated failed logons from one source, or when one source attempts to log on to many accounts. The cloud honeypot showed that internet-exposed Remote Desktop is attacked within hours, so this is the playbook most likely to be used.

**Table D3.** *PB-01 at a Glance*

| Field | Detail |
|---|---|
| **Trigger** | Rule 2, Brute-force authentication (Splunk, Windows Event 4625); for cloud assets, the Sentinel rule "RDP Brute Force from Single IP (T1110)" (10 or more failures from one IP address within its five-hour look-back window) |
| **MITRE ATT&CK** | T1110 Brute Force (including T1110.001 Password Guessing and T1110.003 Password Spraying) |
| **Default severity** | High; raise to Critical if any successful logon (Event 4624) follows from the same source |
| **Data sources** | Windows Security Events 4625, 4624 and 4740; Sentinel SecurityEvent table |
| **Dashboard panels** | Failed Logons tile; Failed Logons Over Time |
| **Validation status** | Detection logic exercised by real attacks on the cloud honeypot (at least 2,012 failed logons from at least five IP addresses in the first 25 hours; Section 3.7). The on-premises rule has not yet been tested with Atomic Red Team. |

*Note.* Table D3 summarises the trigger, technique, severity, data sources and validation status for PB-01. IP = Internet Protocol; RDP = Remote Desktop Protocol.

## 1. Trigger and triage
- Confirm the source IP address, the targeted account names, the number of failures and the time window from the alert.
- Run the search below to see every source with ten or more failures, the accounts it tried and when it started and stopped.

```spl
index=windows_security EventCode=4625
| stats count AS failures values(TargetUserName) AS accounts
        min(_time) AS first max(_time) AS last BY IpAddress, Computer
| where failures>=10 | convert ctime(first) ctime(last)
```
- **Key question: did any logon succeed?** Search for Event 4624 from the same source. If one exists after the failures, treat the account as compromised, raise the severity to Critical and escalate immediately.

```spl
index=windows_security EventCode=4624 IpAddress="<source IP>"
| table _time Computer TargetUserName LogonType IpAddress
```

## 2. Analysis
- Decide the pattern: many attempts against one account suggests password guessing; few attempts against many accounts suggests password spraying.
- Check whether the targeted names exist. On the honeypot, every attempt used generic names such as "Administrator" and "admin", which indicates untargeted, automated attack; attempts against real staff account names indicate reconnaissance and a more targeted attacker.
- Check for account lockouts (Event 4740) that may be disrupting legitimate users.
- Determine whether the source is internal or external. An internal source suggests that another host is already compromised and should be investigated under its own incident.

## 3. Containment
- Block the source address at the perimeter firewall or, for Azure assets, add a deny rule to the network security group.
- If a logon succeeded: disable the account, reset its password, end its active sessions and isolate the host it accessed.
- If Remote Desktop is exposed directly to the internet, remove that exposure and require access through a VPN or brokered remote-access service (Recommendation R7).

## 4. Eradication and recovery
- After any successful logon, check the accessed host for persistence created afterwards: new accounts (Rule 6, Events 4720/4732), new services (Rule 3, Event 7045) and scheduled tasks (Rule 10, Event 4698).
- Re-enable the account only after a password reset and confirmation that multi-factor authentication is enforced.
- Confirm account-lockout thresholds are in place and that the alert has stopped firing.

## 5. Communication and escalation
- High: inform the incident manager within the target time. Critical (successful logon): escalate to the incident manager and CISO immediately.
- If the compromised account or host gives access to personal data, inform the data protection officer, who will assess whether the breach must be reported to the Information Commissioner's Office within 72 hours (Information Commissioner's Office [ICO], 2024).

## 6. Evidence to preserve
- Exported 4625 and 4624 events, the searches used and their results.
- The list of source addresses and targeted accounts, and any firewall or network-security-group changes made.

## 7. Lessons learned
- Review whether the brute-force thresholds remain appropriate given the volume of legitimate failures.
- Add persistent attacking addresses to a watchlist with an expiry date, and review whether any other service is unnecessarily exposed to the internet.
