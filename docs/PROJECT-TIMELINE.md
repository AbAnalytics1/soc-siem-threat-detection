# Project Timeline

Key milestones, compiled from the dated evidence in this repository and the Client Impact Report.

| Date | Milestone | Evidence |
|---|---|---|
| April 2026 | First supervisor meeting; project direction agreed | Report, Section 2.2 |
| 14 Aug 2026 | Suspicious-PowerShell rule tuned from 714 to 29 matches | [powershell-rule-tuned.png](../evidence/powershell-rule-tuned.png) |
| 16 Aug 2026 | GitHub repository created | Commit history |
| 18 Aug 2026 | Suricata alerts flowing into Splunk; first dashboard version | [suricata-signatures.png](../evidence/suricata-signatures.png), [soc-dashboard-v1.png](../evidence/soc-dashboard-v1.png) |
| 19 Aug 2026 | Optimised analyst dashboard; detection rules, scripts and dashboard committed | [soc-dashboard.png](../evidence/soc-dashboard.png); commit history |
| 20 Aug 2026 | Seven Atomic Red Team tests executed and measured | [evaluation/](../evaluation/README.md) |
| August 2026 | Supervisor progress meeting | Report, Section 2.2 |
| 14 Sep 2026 | Progress update presented to module staff and peers | Report, Section 2.2 |
| September 2026 | Supervisor progress meeting | Report, Section 2.2 |
| 28 Sep 2026 | Log Analytics workspace, Microsoft Sentinel and honeypot deployed; honeypot live at about 16:06 UK time | [azure-region-policy.png](../evidence/azure-region-policy.png), [honeypot-events-log-analytics.png](../evidence/honeypot-events-log-analytics.png) |
| 29 Sep 2026 | First failed logon at 01:36 UTC, about 10.5 hours after exposure | [cloud/](../cloud/README.md) |
| 6 Oct 2026 | Data collection ends (last failed logon 17:25 UTC); Sentinel brute-force rule and attack-map workbook created; incident-response playbooks completed; honeypot VM stopped | [honeypot-failed-logons-kql.png](../evidence/honeypot-failed-logons-kql.png), [sentinel-rdp-brute-force-rule.png](../evidence/sentinel-rdp-brute-force-rule.png), [playbooks/](../playbooks/README.md) |
| 10 Oct 2026 | Client Impact Report submitted | Planned |
| 11 Nov 2026 | Live demonstration | Planned |

Configuration commands, decisions and lessons learned for each component are recorded in [configs/SETUP.md](../configs/SETUP.md).
