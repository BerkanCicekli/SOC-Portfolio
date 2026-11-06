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
- Endpoint Security: Process chain `powershell.exe` → `EDR-Freeze_1.0.exe` (PID 1684) → `WerFaultSecure.exe /h /pid 6080 /tid 6076 ...` (PID 6648). PowerShell queried `github.com` (DNS) at 13:01:30 UTC and connected to GitHub IPs, so the tool was likely downloaded from GitHub. TightVNC server (`tvnserver.exe`) started at 13:02:15 during the attack.
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

**Screenshots:**

![RDP brute force](screenshots/alert03-rdp-bruteforce.png)

*4 failed RDP logons (4625) then a successful logon (4624, Type 10) from 212[.]8[.]243[.]56.*

![PowerShell DNS query for github.com](screenshots/alert03-github-dns.png)

*PowerShell (PID 8) queried github.com and connected to 140[.]82[.]113[.]4 at 13:01:30 UTC, shortly before EDR-Freeze appeared in Downloads.*

![Process tree](screenshots/alert03-process-tree.png)

*PowerShell launched EDR-Freeze (PID 1684), which launched WerFaultSecure (PID 6648). TightVNC started a minute earlier.*

![WerFaultSecure command line](screenshots/alert03-werfaultsecure-pid6080.png)

*WerFaultSecure invoked against PID 6080 (Microsoft Defender), suspending it for 10 seconds.*

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

## Alert #4 – SOC228 ZeroFont Phishing Detected
- **Date worked:** 2026-11-03
- **Severity:** High
- **Alert type:** Exchange (Phishing)
- **Difficulty:** Hard
- **Hypothesis:** An email that bypassed mail security using ZeroFont is likely phishing. The key questions are whether the user clicked, and whether anything ran.

**Evidence:**
- Email Security: From `noreply[@]googleone[.]com` to elliot@letsdefend.io, subject "You're Out of Storage And May Not Receive New mails!", delivered at 05:02 (Device Action: Allowed). SMTP source 206[.]189[.]190[.]128. Header shows a different Sender IP (172.16.17.241).
- Email content: Impersonates Google One with an urgent "Gmail is full" lure. The "Get More Space" button links to a zip on Amazon S3. `googleone.com` is a lookalike domain; real Google One emails come from google.com. ZeroFont (hidden zero-size text) used to evade the mail filter.
- Threat intel: Download URL flagged as malicious / malware in LetsDefend Threat Intel.
- Endpoint – Browser History: User accessed `hxxps://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/static/Order_Spesification.zip` at 07:22, about 20 minutes after delivery.
- Endpoint – Execution check: Processes after 07:22 show only legitimate activity (GoogleUpdate from Program Files, services.exe/UsoSvc, explorer.exe via userinit). No terminal commands.
- Endpoint – Network: Connections after the download go only to Google, Microsoft, internal and cloud metadata addresses. 35[.]209[.]92[.]19 (Google Cloud range) had no TI match and lines up with Google Update traffic.
- Log Management: No proxy log for the download, so it only appears in endpoint Browser History. Possible proxy logging gap.
- Scope: Only one recipient. The same S3 bucket appears in several earlier, unrelated malware incidents (e.g. `blackcat.bin.zip`), so it's a repeat malware source.

**Timeline:**

| Time | Event |
|------|-------|
| 05:02 | Phishing email delivered to Elliot (Allowed) |
| 07:22 | User downloads `Order_Spesification.zip` from the S3 bucket |
| 07:22 onwards | No malicious processes, commands or C2 traffic observed |

**Outcome:**
- **Verdict:** True Positive
- **Reasoning:** Lookalike sender domain, urgency lure and ZeroFont evasion delivered a link to a known-malicious zip, which the user downloaded. No evidence of execution, but malware is confirmed on the host.
- **Recommended action:** Delete the email from the mailbox; isolate the host as a precaution (malware on disk, execution can't be ruled out); remove the zip and run a full scan before release; block `googleone.com`, 206[.]189[.]190[.]128 and the `files-ld` S3 subdomain (not all of amazonaws.com); tune the email gateway for ZeroFont and lookalike domains; enable link rewriting/sandboxing; follow up with the user and run phishing awareness training.
- **MITRE ATT&CK:**
  - Initial Access: T1566.002 Phishing – Spearphishing Link
  - Execution: T1204.001 User Execution – Malicious Link (user clicked and downloaded)
  - Defense Evasion: T1027 Obfuscated Files or Information (ZeroFont)
- **Time taken:** 27 Min
- **Platform feedback:** 25 points (100%). All answers correct.
- **Lessons learned:**
  - Clicking a link isn't the same as running the file. Check processes, commands and network separately before deciding what happened.
  - Malware confirmed on disk with execution not ruled out is enough to isolate as a precaution.
  - When sources disagree (Browser History shows the download, proxy logs don't), say which source you relied on and note the gap.
  - Search results can include unrelated incidents. Filter by date and host before drawing conclusions about scope.
  - Block the specific malicious subdomain, not a whole cloud provider.

---

## Alert #5 – SOC335 CVE-2024-49138 Exploitation Detected
- **Date worked:** 2026-11-04
- **Severity:** Medium
- **Alert type:** Privilege Escalation
- **Difficulty:** Medium
- **Hypothesis:** A process named `svohost.exe` (lookalike of svchost.exe) running from `C:\temp` is likely an exploit, not a system process. The key question is whether the attacker reached SYSTEM.

**Evidence:**
- Alert: `svohost.exe` from `C:\temp\service_installer\` on host Victor (172.16.17.207, Windows 10), run by `LetsDefend`, parent `powershell.exe`, Device Action: Allowed.
- Log Management: RDP brute force from 185[.]107[.]56[.]141 – 4 failed logons (Event 4625, usernames `admin` and `guest`) then a successful logon at 11:35:50 UTC (Event 4624, Logon Type 10, username `Victor`). Attacker IP reached no other hosts.
- Endpoint – Terminal History: `whoami /priv` and `whoami` to check privileges, then a PowerShell one-liner that downloaded `service-installer.zip` from `hxxps://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com`, extracted it with 7-Zip using the password "infected", deleted the zip and ran `svohost.exe`. A second `whoami` followed.
- Endpoint – Processes: `svohost.exe` spawned `powershell.exe` (PID 6528) running as **NT AUTHORITY\SYSTEM**, which ran `whoami`, confirming successful escalation.
- Endpoint – Network: Connection to Amazon S3 (52.219.102.138) at the time of the download; otherwise only Microsoft/CDN (Defender activity), internal and cloud metadata traffic. No C2 or exfiltration seen.
- Threat intel: Attacker IP tagged **Brute Force**; file hash tagged **CVE-2024-49138** (30/72 on VirusTotal per platform feedback).
- Note: Log Management is in UTC; Terminal History is UTC+3.

**Timeline (UTC):**

| Time | Event |
|------|-------|
| 11:35:43–11:35:48 | 4 failed RDP logons (4625) from attacker IP |
| 11:35:50 | Successful RDP logon as `Victor` (4624, Type 10) |
| 11:36:06 | PowerShell launched |
| 11:36:26–11:36:38 | `whoami /priv`, `whoami` – privilege check |
| 11:37:10 | Exploit downloaded from S3, extracted, zip deleted, `svohost.exe` run |
| 11:37:59 | Exploit spawns PowerShell as SYSTEM; `whoami` confirms |

**Screenshots:**

![RDP brute force](screenshots/alert05-rdp-bruteforce.png)

*4 failed RDP logons (usernames admin, guest) then a successful logon as Victor (4624, Type 10) from 185[.]107[.]56[.]141.*

![Terminal history](screenshots/alert05-terminal-history.png)

*Privilege checks (`whoami /priv`, `whoami`), the exploit download and run, then a second `whoami` to confirm the result. Times are UTC+3.*

![Exploit running as Victor](screenshots/alert05-exploit-as-user.png)

*Before: svohost.exe (CVE-2024-49138 exploit) launched by PowerShell from C:\temp, running as the normal user Victor.*

![PowerShell running as SYSTEM](screenshots/alert05-system-powershell.png)

*After: the exploit spawned PowerShell running as NT AUTHORITY\SYSTEM, which ran whoami. Escalation confirmed.*

**Outcome:**
- **Verdict:** True Positive
- **Reasoning:** RDP brute force led to a successful logon, and within 2 minutes the attacker downloaded and ran a CVE-2024-49138 exploit, gaining NT AUTHORITY\SYSTEM. Full control of the host.
- **Recommended action:** Isolate host (SYSTEM compromise – host can't be trusted); reset credentials for `Victor`, `LetsDefend` and any account used on the host; rebuild the host; block 185[.]107[.]56[.]141 and the `files-ld` S3 subdomain; patch CVE-2024-49138 on all Windows hosts; hunt for the exploit hash elsewhere; remove internet-facing RDP; enforce MFA and account lockout.
- **MITRE ATT&CK:**
  - Initial Access: T1078 Valid Accounts
  - Credential Access: T1110 Brute Force
  - Execution: T1059.001 PowerShell
  - Command and Control: T1105 Ingress Tool Transfer (exploit download)
  - Defense Evasion: T1036.005 Masquerading (`svohost.exe`); T1027 Obfuscated Files (password-protected zip); T1070.004 File Deletion (zip removed)
  - Discovery: T1033 System Owner/User Discovery (`whoami`)
  - Privilege Escalation: T1068 Exploitation for Privilege Escalation
- **Time taken:** 18 Min
- **Platform feedback:** 15 points (100%). All answers correct.
- **Lessons learned:**
  - Proof of privilege escalation is a process running as SYSTEM whose parent is the exploit. The attacker's own `whoami` is a useful timestamp to look for.
  - Lookalike names apply to files as well as domains: `svohost.exe` in `C:\temp` isn't `svchost.exe` in System32.
  - "Antivirus was running" isn't the same as "antivirus stopped it". Look for evidence of the block.
  - A local privilege escalation exploit doesn't need C2. LetsDefend called the download server "C2", but it's really a staging server.
  - After a SYSTEM-level compromise, rebuild the host and reset every credential used on it.

---

## Alert #6 – SOC246 Forced Authentication Detected
- **Date worked:** 2026-11-05
- **Severity:** Medium
- **Alert type:** Web Attack
- **Difficulty:** Easy
- **Hypothesis:** Many POST requests from one IP to a login page suggests a brute force attempt. The host name "WebServer_Test" made me consider authorised testing, so I needed to rule out a planned test.

**Evidence:**
- Alert: Multiple POST requests from 120[.]48[.]36[.]175 to `http://test-frontend.letsdefend.io/accounts/login` on host WebServer_Test (104.26.15.61). Device Action: Permitted.
- Log Management – Firewall: Port scan from 10:50:44 to 11:02:57 UTC against at least 10 ports (21, 22, 23, 25, 53, 80, 110, 443, 3000, 3389). Only 80 and 3000 permitted; the rest denied.
- Log Management – Proxy: Dictionary attack on the login page from 11:05:34 to 11:15:48 UTC, with at least 11 attempts roughly one per minute using common usernames (root, admin, test, guest, info, adm, mysql, user, administrator) and common wordlist passwords (123456, 12345, iloveyou, princess, rockyou, abc123, abcd12345). Same User-Agent throughout (Firefox 78, Windows 10).
- Log Management – OS: "User Login Successful" for `admin` at 11:15:48 UTC, the same second as the `admin` / `password` attempt.
- Post-login: No further activity from the attacker IP after 11:15:48 in available logs.
- Scope: Attacker IP only targeted 104.26.15.61.
- Planned test check: Searched Email Security for the source IP, host name and domain – no notice of planned testing found. Source is an external IP, not an attack simulation product.
- Threat intel: No match for 120[.]48[.]36[.]175 in platform Threat Intel; located in China per playbook feedback.
- Note: The login page uses plain HTTP (port 80), so credentials were sent unencrypted and are visible in proxy logs.
- Note: Logs are in UTC; the OS log text ("02:15 PM") matches the alert time at UTC+3.

**Timeline (UTC):**

| Time | Event |
|------|-------|
| 10:50:44–11:02:57 | Port scan of at least 10 ports; 80 and 3000 permitted |
| 11:05:34 | First login attempt (`root` / `123456`) |
| 11:05:34–11:14:18 | Repeated failed attempts with common usernames and passwords |
| 11:15:48 | Successful login as `admin` / `password` |
| After 11:15:48 | No further activity observed |

**Outcome:**
- **Verdict:** True Positive
- **Reasoning:** Port scan followed by a wordlist attack on the login page, ending in a successful admin login. No evidence of authorised testing despite the "Test" host name.
- **Recommended action:** Escalate to Tier 2 (admin account compromised); reset the `admin` password and terminate its active sessions; block 120[.]48[.]36[.]175; review the app for any changes made by the admin account; enable HTTPS on the login page; add rate limiting / WAF rules and account lockout on `/accounts/login`; enforce MFA; rename or disable default usernames and ban common passwords; close unnecessary internet-facing ports (e.g. 3000). No host isolation, because there's no evidence the server itself was compromised.
- **MITRE ATT&CK:**
  - Discovery: T1046 Network Service Discovery (port scan)
  - Credential Access: T1110.001 Brute Force – Password Guessing
  - Initial Access: T1078 Valid Accounts (successful admin login)
  - Note: The platform tagged T1187 Forced Authentication, but the evidence fits brute force.
- **Time taken:** 20 min
- **Platform feedback:** 30 points (100%). All answers correct. Platform classified the attack type as "Other" – OWASP Broken Authentication (A07:2021 Identification and Authentication Failures).
- **Lessons learned:**
  - The port scan came first: the attacker checked which services were open, then attacked the one that was (the web login on port 80).
  - Web logins don't produce Event 4624. I confirmed success from the "User Login Successful" log matching the exact second of the last attempt.
  - The alert's ATT&CK tag didn't match the evidence. I map techniques from what the logs show, not from the label.
  - A "Test" host name isn't proof of a planned test. I checked the mailbox for planned work before ruling out a false positive.
  - A login page on plain HTTP exposes passwords in transit, which is a finding in itself.
  - For web attacks, the question is escalation rather than isolation: escalate when the attack succeeded.

---

