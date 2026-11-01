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
| Alerts investigated | 2 |
| True positives | 2 |
| False positives | 0 |
| Verdicts correct (per platform scoring) | 2 / 2 |

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

-
