# Environment Setup & Configuration Notes

This document records the key configuration decisions and commands used to build
the environment on Apple Silicon (ARM64).

## Architecture

| Component | Platform | Role |
|-----------|----------|------|
| Splunk Enterprise (x86-64 Docker) | Ubuntu 24.04 ARM VM + Rosetta | SIEM core |
| Windows 11 (ARM) endpoint | Parallels VM (10.211.55.14) | Monitored workstation |
| Sysmon (ARM64) | On the endpoint | Endpoint telemetry |
| PowerShell HEC shipper | On the endpoint | Log forwarding |
| Suricata (ARM64) | Ubuntu VM (enp0s5) | Network IDS |

## Splunk (x86-64 under Rosetta)

Splunk has no native ARM build, so it runs as an x86-64 Docker container pinned to
the linux/amd64 platform, executing under Rosetta translation. A systemd service
re-registers the Rosetta binfmt handler at boot so the container survives reboots.

Indexes created: `windows_security`, `windows_sysmon`, `firewall_logs`, `web_logs`,
`ad_logs`, `suricata`.

## Windows endpoint

- Sysmon installed (ARM64 build) with the Olaf Hartong `sysmon-modular` config
  (the default config excluded PowerShell process creation).
- Advanced audit policies enabled via `auditpol` (logon, credential validation,
  process creation, account management) plus command-line process auditing so
  Event 4688 records full command lines.
- Sysmon Operational log raised to 1 GB to prevent fast log rollover:
  `wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824`
- Logs shipped via `Send-LogsToHEC.ps1` (scheduled task, every 1 min).

## Suricata (ARM64-native)

```bash
sudo apt update && sudo apt install suricata -y
sudo suricata-update                                   # ET Open ruleset (~52k rules)
sudo sed -i 's/interface: eth0/interface: enp0s5/' /etc/suricata/suricata.yaml
sudo suricata -T -c /etc/suricata/suricata.yaml -v     # test config
sudo systemctl restart suricata
```

Noisy TCP-stream signatures suppressed via `/etc/suricata/threshold.config`.
Alerts forwarded to Splunk via `ship-suricata.sh` (cron, every 2 min).

Validated detection with a suspicious-user-agent test:
```bash
curl -A "BlackSun" http://testmynids.org/uid/index.html
```
Observed signatures included `ET USER_AGENTS Suspicious User Agent (BlackSun)`,
`GPL ATTACK_RESPONSE id check returned root`, and a real CVE signature
(`ET WEB_SPECIFIC_APPS Splunk Enterprise ... CVE-2018-11409`).

## Log-ingestion notes (lessons learned)

A multi-layered ingestion fault was diagnosed and resolved:
- **Timestamp offset** (UTC/BST) — fixed by sending explicit UTC-epoch time.
- **Event-selection cap / bookmark race** — fixed by processing all new events and
  advancing the bookmark only on confirmed (code 0) delivery.
- **Sysmon source filtering** — fixed by deploying the Olaf Hartong config.
- **Index routing** — process creation lands as Event 4688 in `windows_security`;
  keyword-based SPL matches the JSON more reliably than field-wildcards.
- **Bookmark clearing** — `Remove-Item *` fails on filenames with spaces; use
  `Get-ChildItem | Remove-Item`.
