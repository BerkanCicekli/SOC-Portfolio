# Project 3: Incident Response Simulation

**Platform:** TryHackMe · **Tools:** Splunk, Sysmon, Windows Event Logs · **Status:** Planned

## Overview

Full-cycle incident investigations in Splunk: scoping alerts, correlating logs across sources, reconstructing attacker timelines, mapping activity to MITRE ATT&CK, and writing incident reports with recommendations. Followed by threat hunting and writing my own detection rules.

## What's in this folder

| File | Description |
|------|-------------|
| [investigations/](investigations/) | Incident reports (brute force, malware, ransomware/APT) |
| [spl-cheatsheet.md](spl-cheatsheet.md) | SPL queries I use, explained in my own words |
| [detection-rules/](detection-rules/) | Custom detection rules with rationale and testing notes |
| [threat-hunting/](threat-hunting/) | Hypothesis-driven hunt reports |
| [templates/](templates/) | Report templates |

## Investigations

| # | Incident | Key techniques | Report |
|---|----------|----------------|--------|
| 1 | Web server brute force, backdoor upload and defacement | Vulnerability scanning, brute force, web shell, reverse shell, defacement, threat intel pivoting | [report](investigations/01-web-brute-force/report.md) |
| 2 | Encoded PowerShell, WMI lateral movement and a lookalike backdoor account | PowerShell deobfuscation, AMSI bypass, WMIC remote execution, local account creation | [report](investigations/02-malicious-powershell/report.md) |
| 3 | Conti ransomware on an Exchange server | Web shell, process injection, LSASS credential dumping, backdoor admin, ransomware | [report](investigations/03-conti-ransomware/report.md) |

## TryHackMe rooms completed

| Room | Focus | Done |
|------|-------|------|
| Splunk basics | SPL fundamentals | ☐ |
| Investigating with Splunk | First investigation | ☑ |
| Conti | Ransomware investigation | ☑ |
| Sysmon | Endpoint logging | ☐ |
| Windows Event Logs | Security events | ☐ |
| Incident Handling with Splunk | Multi-stage attack | ☑ |

*(Room names on TryHackMe change)*

## Key lessons learned

*coming soon*
