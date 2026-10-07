# Cloud Extension: Azure Honeypot and Microsoft Sentinel

The client's growing cloud estate sat outside the on-premises monitoring, so the SOC was extended into Microsoft Azure. A deliberately exposed Windows Server honeypot forwards its security events to a Log Analytics workspace, where **Microsoft Sentinel** provides cloud-native SIEM analytics. Because nobody legitimately uses the honeypot, every logon attempt against it is attacker activity, which gives the SOC real, uncontrolled attack data to complement the controlled Atomic Red Team tests.

## Design

| Component | Configuration |
|---|---|
| Honeypot VM | `vm-honeypot`, Windows Server 2022, Poland Central; only Remote Desktop (TCP 3389) exposed to the internet |
| Log collection | Azure Monitor Agent with a data collection rule, collecting the **Common** Windows security event set |
| Workspace | Log Analytics workspace `law-soc-honeypot`, Switzerland North; retention 90 days |
| SIEM | Microsoft Sentinel on the workspace |
| Detection | Scheduled analytics rule *RDP Brute Force from Single IP (T1110)* ([KQL](kql/sentinel-rdp-brute-force-rule.kql)) |
| Visualisation | *Honeypot Attack Map* workbook, plotting failed logons by geolocated source |

A subscription-level Azure policy blocked deployment to the UK regions, and the intended VM sizes were unavailable in two of the permitted regions. This is why the workspace and VM sit in different European regions ([evidence](../evidence/azure-region-policy.png)).

## Safeguards

- A budget with cost alerts was set before anything was deployed; the smallest suitable VM size was used, and the VM is stopped when not needed.
- A single service is exposed, with a long, unique, locally generated password. No data is held on the host, and it is completely separate from the on-premises lab.
- The honeypot is passive: it records attempts but never interacts with, traces or retaliates against their sources.
- Attacker IP addresses can be personal data under the UK GDPR, so results are reported only in aggregate. No individual addresses are published in this repository.

## Results

| Measure | Result |
|---|---|
| Honeypot live | 28 September 2026, about 16:06 UK time |
| First failed logon (Event 4625) | 01:36 UTC on 29 September, about **10.5 hours** after exposure |
| First 25 hours | At least 2,012 failed logons from at least five source addresses; two sustained brute-force sources geolocated to Russia (1,677 and 331 attempts) |
| Accounts tried | Generic names such as "Administrator" and "admin", neither of which existed on the honeypot |
| Full collection period (28 Sep – 6 Oct 2026) | **55,313** failed logons from **121** unique IP addresses, almost 7,000 a day |
| Successful remote logons (Event 4624) | **None** recorded |
| Largest sources by geolocation | Georgia (about 20,300 attempts), Bulgaria (about 13,500), Lithuania (about 8,040) |

Geolocation shows where an address is registered, not necessarily where the attacker is, because attacks are often launched from rented or compromised infrastructure.

Evidence: [failed-logon query and result](../evidence/honeypot-failed-logons-kql.png) · [attack map](../evidence/honeypot-attack-map.png) · [events arriving in Log Analytics](../evidence/honeypot-events-log-analytics.png)

## Sentinel analytics rule

| Setting | Value |
|---|---|
| Name | RDP Brute Force from Single IP (T1110) |
| Logic | Counts failed logons (Event 4625) by source IP address and host; alerts when one address reaches 10 or more failures |
| Schedule | Runs every 5 hours over the previous 5 hours of data |
| Severity / tactic | High / Credential Access |
| Alerting | One alert per result row; an incident is created for each alert |
| Entities | IP address and host |

The rule's results simulation against the collected data showed up to six source addresses meeting the threshold in a single evaluation, with Sentinel estimating about 11 alerts a day ([rule](../evidence/sentinel-rdp-brute-force-rule.png) · [simulation](../evidence/sentinel-rule-simulation.png)). The matching response steps are in playbook [PB-01](../playbooks/pb-01-brute-force-authentication.md).

## Queries

| File | Purpose |
|---|---|
| [sentinel-rdp-brute-force-rule.kql](kql/sentinel-rdp-brute-force-rule.kql) | The Sentinel analytics rule |
| [honeypot-failed-logon-summary.kql](kql/honeypot-failed-logon-summary.kql) | Totals for the whole collection period |
| [honeypot-analysis.kql](kql/honeypot-analysis.kql) | Failed-logon count, top sources with geolocation, most-tried usernames |

## Lessons for the client

- **Any service exposed to the internet is found and attacked within hours.** Remote Desktop should not be exposed directly; it should sit behind a VPN or brokered access, with multi-factor authentication and account lockout.
- **Cloud monitoring is quick to switch on but shaped by governance and cost.** Region policy decided where data could live, and collection scope was a cost decision. For a regulated firm, data residency and ingestion cost have to be designed in from the start.
- **The on-premises and cloud views are still separate.** The planned next step is a pull-based integration that brings honeypot detections into the Splunk dashboard without exposing the internal SIEM to the internet.
