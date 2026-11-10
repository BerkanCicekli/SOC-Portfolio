# Project 3: Incident Response Simulation

**Platform:** TryHackMe · **Tools:** Splunk, Sysmon, Windows Event Logs · **Status:** In progress

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
| Splunk basics | SPL fundamentals | ☑ |
| Investigating with Splunk | First investigation | ☑ |
| Conti | Ransomware investigation | ☑ |
| Sysmon | Endpoint logging | ☑ |
| Windows Event Logs | Security events | ☑ |
| Incident Handling with Splunk | Multi-stage attack | ☑ |

*(Room names on TryHackMe change)*

## Key lessons learned

1. **Start from the impact and work backwards.** In Conti, the ransom note led to the ransomware, its hash, and then each earlier stage. ([Conti](investigations/03-conti-ransomware/report.md))

2. **Correlate log sources.** Web traffic, IDS, firewall, Sysmon and threat intel each showed part of the web server attack; only together did they show all of it. ([Web server](investigations/01-web-brute-force/report.md))

3. **Know your Event IDs.** Sysmon 1, 8 and 11 and Windows 4720 and 4624/4625 each answer a different question, so knowing which to ask saves time. ([Conti](investigations/03-conti-ransomware/report.md), [PowerShell](investigations/02-malicious-powershell/report.md))

4. **Rare events are valuable.** There were only two remote-thread events in 28,000, and both were malicious. ([Conti](investigations/03-conti-ransomware/report.md))

5. **Lateral movement has two ends.** `WMIC /node:` on one host and `wmiprvse.exe` on the other were the same action. ([PowerShell](investigations/02-malicious-powershell/report.md))

6. **Names lie, context doesn't.** `cmd.exe` in a Documents folder, `A1berto` vs `Alberto`, `ab.exe` disguised as a benchmarking tool. ([Conti](investigations/03-conti-ransomware/report.md), [PowerShell](investigations/02-malicious-powershell/report.md), [Web server](investigations/01-web-brute-force/report.md))

7. **Reputation isn't a verdict.** The main attacker IP in the web server attack scored 0/92 on VirusTotal. ([Web server](investigations/01-web-brute-force/report.md))

8. **Check timestamps before trusting them.** Splunk's display time, the host's local time and UTC differed in Conti; in the PowerShell case every event shared one second, so order had to come from cause and effect. ([Conti](investigations/03-conti-ransomware/report.md), [PowerShell](investigations/02-malicious-powershell/report.md))

9. **State what the evidence proves.** When the logs didn't show the exploit used, I said so and cited published threat intel instead of guessing. ([Conti](investigations/03-conti-ransomware/report.md))
