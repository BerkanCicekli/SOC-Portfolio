# Project 1: Live SOC Alert Monitoring

**Platform:** LetsDefend · **Role simulated:** SOC Tier 1 Analyst · **Status:** In progress

## Overview

Monitoring, triaging and investigating security alerts in LetsDefend's simulated SOC. For each alert I form a hypothesis, gather evidence across log sources, classify the alert as a true or false positive, and document a recommended action.

## What's in this folder

| File | Description |
|------|-------------|
| [triage-log.md](triage-log.md) | Every alert I've worked, with evidence, verdict and reasoning |
| [case-studies/](case-studies/) | Detailed write-ups of my three most instructive investigations |
| [templates/](templates/) | Templates I use for triage entries and case studies |

## Progress

*Updated as I go — real numbers only.*

| Metric | Count |
|--------|-------|
| Alerts investigated | 5 |
| True positives | 5 |
| False positives | 0 |
| Verdicts correct (per platform scoring) | 5 / 5 |

## Triage workflow

1. **Review the alert** – rule name, severity, hosts, IPs, time
2. **Form a hypothesis** – is this consistent with known-good behaviour?
3. **Gather evidence** – Log Management, Endpoint Security, Email Security, threat intel
4. **Classify** – true positive or false positive, with reasoning
5. **Recommend** – escalate, contain, block IOCs, or close
6. **Document** – log it the same day, including what I got wrong

## Skills demonstrated

Alert triage · log correlation · IOC validation · escalation decisions · MITRE ATT&CK mapping · incident documentation

## Key lessons learned

1. **True Positive doesn't automatically mean isolate.** In my first alert I isolated a host just because the source IP was malicious. Isolation is for evidence of compromise – a successful logon, code running on the host, or malware on disk that I can't rule out executing. ([Alert #1](triage-log.md), [Alert #4](triage-log.md))

2. **Prove it with evidence, don't assume.** I confirm compromise with Event IDs (4625 failed, 4624 success, Logon Type 10 for RDP) and confirm privilege escalation by finding a process running as SYSTEM whose parent is the exploit. Where I couldn't confirm something, I label it as likely. ([Alert #2](triage-log.md), [Alert #5](triage-log.md))

3. **Check scope before answering it.** I got scope wrong once by assuming a brute force must have hit several hosts. Now I search Log Management for every destination the attacker IP reached, and filter by date and host so unrelated incidents don't get mixed in. ([Alert #2](triage-log.md), [Alert #4](triage-log.md))

4. **Behaviour matters more than reputation.** Several attacker IPs had no threat intel match, but the activity (brute force, then login, then tools run within minutes) made the verdict clear. A clean reputation doesn't make something safe. ([Alert #3](triage-log.md), [Alert #5](triage-log.md))

5. **Align timestamps before building a timeline.** Log sources on the same platform used different timezones (UTC vs UTC+2/+3). Lining them up showed attackers acting within seconds of logging in. ([Alert #2](triage-log.md), [Alert #3](triage-log.md), [Alert #5](triage-log.md))
