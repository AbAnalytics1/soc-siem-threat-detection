# Incident-Response Playbooks

Five playbooks for the priority detections of the hybrid SOC, aligned to **NIST SP 800-61 Revision 3** and the **NIST Cybersecurity Framework (CSF) 2.0**. They are Appendix D of the project's Client Impact Report; section, table and figure numbers refer to that report.

| Playbook | Detection |
|---|---|
| [PB-01](pb-01-brute-force-authentication.md) | Brute-force authentication |
| [PB-02](pb-02-credential-dumping-from-lsass-memory.md) | Credential dumping from LSASS memory |
| [PB-03](pb-03-suspicious-or-encoded-powershell.md) | Suspicious or encoded PowerShell |
| [PB-04](pb-04-security-event-log-cleared.md) | Security event log cleared |
| [PB-05](pb-05-network-intrusion-or-exploit-attempt.md) | Network intrusion or exploit attempt |

A Word version of all five playbooks is in [Incident_Response_Playbooks.docx](Incident_Response_Playbooks.docx).

## D.1 Purpose and scope

These playbooks set out how the client's security operations centre (SOC) should respond when one of its priority detections fires. Each playbook turns a detection rule into a consistent sequence of decisions and actions, so that the response does not depend on the knowledge or experience of whichever analyst is on shift. They complete Objective 4 of the project (Section 3.9).

The five playbooks cover the detections that the project built and tested, rather than generic scenarios: brute-force authentication (PB-01), credential dumping from LSASS memory (PB-02), suspicious or encoded PowerShell (PB-03), clearing of the security event log (PB-04), and network intrusion or exploit attempts (PB-05). Each names the exact detection rule, data source, event identifiers and dashboard panel involved, and records how far the detection has been validated.

The playbooks are written for the hybrid SOC described in Section 4: a Windows 11 endpoint monitored by Splunk Enterprise (Windows Security, Sysmon and Microsoft Defender logs), a Suricata network sensor, and an Azure honeypot monitored by Microsoft Sentinel. Steps that refer to the lab, such as restoring a virtual-machine snapshot, map directly to their production equivalents, such as reimaging a host from a known-good build.

## D.2 How the playbooks are structured

NIST SP 800-61 Revision 3 recommends that incident response be integrated into an organisation's wider cybersecurity risk management and organised around the Functions of the NIST Cybersecurity Framework (CSF) 2.0, rather than treated as a stand-alone process (Nelson et al., 2025). Each playbook therefore follows the same stages, and each stage is mapped to the CSF 2.0 category it supports (Table D1).

**Table D1.** *Playbook Stages Mapped to NIST CSF 2.0 Categories*

| Playbook stage | CSF 2.0 category | Purpose of the stage |
|---|---|---|
| 1. Trigger and triage | DE.CM Continuous Monitoring; DE.AE Adverse Event Analysis | Confirm the alert is genuine and decide its severity. |
| 2. Analysis | RS.AN Incident Analysis | Establish what happened, its scope and its root cause. |
| 3. Containment | RS.MI Incident Mitigation | Stop the incident spreading or causing further harm. |
| 4. Eradication and recovery | RS.MI Incident Mitigation; RC.RP Incident Recovery Plan Execution | Remove the cause and restore normal, trusted operation. |
| 5. Communication and escalation | RS.MA Incident Management; RS.CO Incident Response Reporting and Communication; RC.CO Incident Recovery Communication | Inform the right people at the right time, including regulatory assessment. |
| 6. Evidence to preserve | RS.AN Incident Analysis | Keep the records needed for investigation, audit and any notification. |
| 7. Lessons learned | ID.IM Improvement | Feed what was learned back into detections, controls and the playbook itself. |

*Note.* Table D1 shows the seven stages used in every playbook and the NIST Cybersecurity Framework 2.0 category that each stage supports. CSF = Cybersecurity Framework.

### Roles
- **Level 1 SOC analyst:** monitors the dashboard, performs triage and opens the incident ticket.
- **Level 2 analyst / incident handler:** leads analysis, containment and evidence collection.
- **Incident manager (escalating to the CISO):** declares incidents, coordinates the response and owns communication.
- **IT operations:** carries out technical remediation such as isolating hosts, resetting credentials and rebuilding systems.
- **Data protection officer and compliance:** assess whether personal data is affected and whether regulatory notification is required.

### Severity and response targets

Table D2 proposes response targets for the client. They should be confirmed against the client's risk appetite and staffing before adoption.

**Table D2.** *Proposed Severity Levels and Response Targets*

| Severity | Meaning | Acknowledge within | Escalate to |
|---|---|---|---|
| Critical | Likely compromise of a host or privileged credentials, or loss of monitoring | 15 minutes | Incident manager immediately; CISO |
| High | Malicious activity that has not yet been confirmed as successful | 30 minutes | Level 2 analyst; incident manager if confirmed |
| Medium | Suspicious activity needing investigation | 4 hours | Level 2 analyst if not resolved at Level 1 |
| Low | Informational or confirmed benign activity | Next business day | Not escalated; used for tuning |

*Note.* Table D2 proposes how quickly each severity level should be acknowledged and to whom it should be escalated. The targets are a starting point for the client and are not drawn from a standard. CISO = chief information security officer.

### General evidence-handling rules
- Record every action with its time in UTC, the person who performed it and the reason, in the incident ticket.
- Export the raw events from the SIEM before any tuning, suppression or deletion, and keep the original search used.
- Where a host may be compromised, isolate it from the network but do not power it off until volatile evidence has been considered, because shutting down destroys memory contents.
- Store exported evidence in a restricted location and record a hash (for example SHA-256) of each file so its integrity can be shown later.

## D.8 Validation summary and maintenance

Table D8 summarises how far each playbook's detection has been tested. A playbook is only as reliable as the detection that triggers it, so the untested items form part of the continuous validation programme in Recommendation R3.

**Table D8.** *Validation Status of the Playbook Triggers*

| Playbook | Trigger rule(s) | Validated? | Evidence |
|---|---|---|---|
| PB-01 Brute force | Rule 2; Sentinel RDP rule | Partly | Real attacks on the honeypot (Section 3.7); on-premises Atomic test planned |
| PB-02 LSASS dumping | Rules 9 and 12 | Partly | Atomic T1003.001-2 blocked by Defender and logged (Table 5.1) |
| PB-03 PowerShell | Rules 1 and 14 | Yes | Atomic T1059.001-17 detected (Table 5.1) |
| PB-04 Log cleared | Rule 5 | No | Atomic T1070.001 planned |
| PB-05 Network intrusion | Rules 15 and 16 | Yes | Malicious user-agent test detected; CVE matches triaged (Section 3.5) |

*Note.* Table D8 shows whether the detection behind each playbook has been tested and where the evidence is reported. "Partly" means the detection path has been exercised but not every rule in it has been validated. CVE = Common Vulnerabilities and Exposures; LSASS = Local Security Authority Subsystem Service; RDP = Remote Desktop Protocol.

The playbooks should be reviewed after every significant incident, after any change to the detection rules they reference, and at least every six months. Before adoption, each should be rehearsed in a tabletop exercise with the people named in the roles above, so that gaps are found in practice rather than during a live incident.

## References

Information Commissioner's Office. (2024). *Guide to the UK General Data Protection Regulation*. https://ico.org.uk/for-organisations/guide-to-data-protection/

MITRE. (n.d.). *MITRE ATT&CK*. The MITRE Corporation. Retrieved October 6, 2026, from https://attack.mitre.org/

Nelson, A., Rekhi, S., Souppaya, M., & Scarfone, K. (2025). *Incident response recommendations and considerations for cybersecurity risk management: A CSF 2.0 community profile* (NIST Special Publication 800-61r3). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-61r3
