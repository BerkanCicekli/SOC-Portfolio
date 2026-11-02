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
- **Time taken:** 20 min
- **Platform feedback:** Score 25 (91%). Verdict correct. Missed the isolation question: I said Yes, correct was No.
- **Lessons learned:**
  - A malicious source IP makes it a True Positive, but isolation is only for evidence of successful compromise.
  - Check whether the attack actually succeeded before deciding on containment.
  - Some ATT&CK mappings on the platform are loose: T1535 normally means an attacker using a victim's unused cloud regions, not traffic from a restricted region.

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
- **Platform feedback:** First attempt: 25 (92%), verdict and isolation correct, missed scope (said Yes, correct was No). Reinvestigation: 30 points (100%).
- **Lessons learned:**
  - Check Log Management for every destination IP before answering scope. Don't assume brute force means multiple hosts.
  - Prove compromise with Event IDs: 4625 = failed logon, 4624 = successful logon, Logon Type 10 = RDP.
  - Discovery commands map directly to ATT&CK techniques (whoami → T1033, net user → T1087, netstat → T1049).
  - Log sources can use different timezones. Align timestamps before building a timeline.

---

## Alert #3 – SOC344 EDR Tampering Attempt via EDR-Freeze
- **Date worked:** 2026-11-02
- **Severity:** High
- **Alert type:** Malware
- **Difficulty:** Medium
- **Hypothesis:** EDR-Freeze is a known tool for suspending security software. Combined with the L1 note of RDP brute force, this could be an attacker who got in and tried to blind the defences.

**Evidence:**
- Alert: `EDR-Freeze_1.0.exe 6080 10000` executed on WS-Prod-02 (172.16.20.69, Windows) from `C:\Users\LetsDefend\Downloads\`.
- Log Management (initial access): 4 failed RDP logons (Event 4625) from 212[.]8[.]243[.]56 between 12:59:43 and 13:00:02 UTC, trying usernames `admin` and `letsdefend`, then a successful logon at 13:00:08 (Event 4624, Logon Type 10, username recorded as `LetsDefendsuc`).
- Log Management (scope): Attacker IP communicated only with 172.16.20.69.
- Endpoint Security: Process chain `powershell.exe` → `EDR-Freeze_1.0.exe` (PID 1684) → `WerFaultSecure.exe /h /pid 6080 /tid 6076 ...` (PID 6648). PowerShell connected to GitHub IPs shortly before, so the tool was likely downloaded from GitHub. TightVNC server (`tvnserver.exe`) started at 13:02:15 during the attack.
- Threat intel: SHA256 970c7834…cd85f7 tagged **EDR-Freeze** in LetsDefend Threat Intel. Attacker IP: no match.
- Note: Log display time is 2 hours behind UtcTime; timeline below uses UTC.
- Logging gap: process logs only show `powershell.exe` launching, not the commands run inside it. PowerShell script block logging (Event 4104) would have captured them.

**Timeline (UTC):**

| Time | Event |
|------|-------|
| 12:59:43–13:00:02 | 4 failed RDP logons from attacker IP (Event 4625) |
| 13:00:08 | Successful RDP logon (Event 4624, Type 10) |
| 13:00:26 | PowerShell launched |
| 13:01:30 | PowerShell connects to GitHub (likely tool download) |
| 13:02:15 | TightVNC server starts |
| 13:03:28 | EDR-Freeze runs; WerFaultSecure suspends PID 6080 (Microsoft Defender) for 10 seconds |

**Outcome:**
- **Verdict:** True Positive
- **Reasoning:** RDP brute force followed by a successful logon, then within about 3 minutes the attacker used EDR-Freeze to abuse WerFaultSecure and suspend Microsoft Defender. Deliberately disabling defences straight after gaining access shows a hands-on, prepared attacker. Confirmed compromise.
- **Recommended action:** Isolate host; disable/reset the `LetsDefend` account; block 212[.]8[.]243[.]56; remove direct internet RDP exposure and enforce MFA and account lockout; verify Defender health; remove EDR-Freeze and investigate TightVNC as a possible backdoor; check for persistence before restoring.
- **MITRE ATT&CK:**
  - Initial Access: T1078 Valid Accounts
  - Credential Access: T1110 Brute Force
  - Execution: T1059.001 PowerShell
  - Defense Evasion: T1562.001 Impair Defenses – Disable or Modify Tools
- **Time taken:** 30 Min
- **Platform feedback:** 30 points (100%). All answers correct.
- **Lessons learned:**
  - Isolation is based on confirmed compromise.
  - T1562 Impair Defenses describes the effect (security tools stopped); Hijack Execution Flow means running attacker code inside a legitimate program.
  - GitHub IPs are legitimate infrastructure, so don't list them as malicious IOCs.
  - Match hashes to their type: MD5 = 32 characters, SHA256 = 64.

---
