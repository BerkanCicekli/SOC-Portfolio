# SOC Alert Triage Log

Every alert I've worked on LetsDefend, in order. Entries include alerts I classified incorrectly and what I learned from them.

**Format:** see [templates/triage-entry-template.md](templates/triage-entry-template.md)

---

<!-- Copy the template below this line for each new alert. Newest at the bottom. -->
## Alert #1 – SOC325 Unauthorized Cloud Region Access Attempt Detected
- **Date worked:** 2026-10-30
- **Severity:** Low
- **Alert type:** Web Attack
- **Hypothesis:** Traffic from a restricted region could be an attacker probing the server, or a legitimate user travelling/using a VPN.

**Evidence:**
- Alert: High volume of requests in a short time from 134[.]209[.]145[.]73 (India-located) to 52[.]15[.]206[.]21, a restricted region for this environment.
- Endpoint Security: Target host runs Linux (Ubuntu 20.04.2).
- Log Management: Attacker IP only communicated with 52[.]15[.]206[.]21, so the scope is limited to one host.
- Threat intel: Source IP reported on AbuseIPDB and VirusTotal for malicious activity, SSH abuse, phishing and brute force.

**Outcome:**
- **Verdict:** True Positive
- **Reasoning:** Known-malicious IP sending a burst of requests from a restricted region matches automated attack activity, not a legitimate user.
- **Recommended action:** Block source IP; monitor target host. No isolation, because there was no evidence the host was compromised.
- **MITRE ATT&CK:** T1535 – Unused/Unsupported Cloud Regions (per playbook); T1110 – Brute Force (per threat intel and request pattern)
- **Time taken:** 20 minutes
- **Platform feedback:** Score 25 (91%). Verdict correct. Missed the isolation question: I said Yes, correct was No. Lesson: malicious source = TP, but isolate only when there's evidence of successful compromise.

---
