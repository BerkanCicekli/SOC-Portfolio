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

## Alert #2 – SOC291 System Time Lookup Detected
- **Date worked:** 2026-11-01 (reinvestigated after first attempt)
- **Severity:** Low
- **Alert type:** Brute Force
- **Hypothesis:** Checking system time is often normal admin activity, but straight after a brute-force attempt it could be an attacker doing discovery.

**Evidence:**
- Alert: `net time \\EC2AMAZ-ILGVOIN` executed on host Campbell (172.16.17.213, Windows 10). L1 couldn't tell if it was a user or an attacker.
- Log Management: 7 RDP login attempts (port 3389) from 37[.]19[.]221[.]238 between 04:51:55 and 04:54:03. The first 6 failed (Event 4625, all verified); the 7th at 04:54:03 succeeded – Event ID 4624, user `LetsDefend`, Logon Type 10 (RDP).
- Endpoint Security: 10 discovery commands in ~3 minutes: whoami, whoami /groups, net user, hostname, net time, arp -a, ipconfig, ipconfig /all, netstat, tasklist /svc.
- Scope: Attacker IP only communicated with 172.16.17.213.
- Threat intel: 37[.]19[.]221[.]238 is a US VPN/web-hosting IP reported on AbuseIPDB for malware, brute force, SSH and malicious activity.
- Note: Log Management and terminal history timestamps differ by ~2 hours – likely a timezone offset, meaning discovery started ~1 minute after login.

**Timeline:**

| Time | Event |
|------|-------|
| 04:51:55–04:52:20 | 6 failed RDP login attempts from attacker IP (Event 4625) |
| 04:54:03 | Successful RDP login as `LetsDefend` (Event 4624, Type 10) |
| 06:55–06:58 (terminal time) | Discovery commands executed |

**Outcome:**
- **Verdict:** True Positive
- **Reasoning:** Repeated RDP attempts followed by a successful login and rapid discovery commands show a hands-on attacker, not a legitimate user. The IP's bad reputation supports this.
- **Recommended action:** Isolate host (attacker was already probing other machines via arp -a and net time); reset/disable the `LetsDefend` account; block the attacker IP; remove direct internet RDP exposure (VPN/RDP gateway); enforce MFA and account lockout; check host for persistence before restoring.
- **MITRE ATT&CK:**
  - Initial Access: T1133 External Remote Services; T1078 Valid Accounts
  - Credential Access: T1110 Brute Force
  - Execution: T1059.003 Windows Command Shell
  - Discovery: T1033 (whoami); T1069 (whoami /groups); T1087 (net user); T1082 (hostname); T1124 (net time); T1016 (arp, ipconfig); T1049 (netstat); T1057 (tasklist)
- **Time taken:** 13 min (platform timer, reinvestigation)
- **Platform feedback:** First attempt: 25 (92%), verdict and isolation correct, missed scope (said Yes, correct No). Reinvestigation: 30 points (100%). Lesson: check Log Management for every destination IP before answering scope; prove compromise with Event ID 4624 instead of assuming.

---
