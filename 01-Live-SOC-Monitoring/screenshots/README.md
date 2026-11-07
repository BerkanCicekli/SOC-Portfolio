# Screenshots

Evidence screenshots referenced in the [triage log](../triage-log.md).

| Alert | File | Shows |
|-------|------|-------|
| #3 | [alert03-rdp-bruteforce.png](alert03-rdp-bruteforce.png) | 4 failed RDP logons then success |
| #3 | [alert03-github-dns.png](alert03-github-dns.png) | PowerShell DNS query for github.com |
| #3 | [alert03-process-tree.png](alert03-process-tree.png) | PowerShell → EDR-Freeze → WerFaultSecure |
| #3 | [alert03-werfaultsecure-pid6080.png](alert03-werfaultsecure-pid6080.png) | WerFaultSecure suspending PID 6080 (Defender) |
| #5 | [alert05-rdp-bruteforce.png](alert05-rdp-bruteforce.png) | 4 failed RDP logons then success as Victor |
| #5 | [alert05-terminal-history.png](alert05-terminal-history.png) | whoami checks, exploit download and run |
| #5 | [alert05-exploit-as-user.png](alert05-exploit-as-user.png) | Exploit running as normal user Victor |
| #5 | [alert05-system-powershell.png](alert05-system-powershell.png) | PowerShell spawned as SYSTEM by the exploit |
| #7 | [alert07-email.png](alert07-email.png) | Fake CV email with RAR attachment |
| #7 | [alert07-threatintel-hash.png](alert07-threatintel-hash.png) | Hash tagged ROMCOM / CVE-2025-8088 |
| #7 | [alert07-winrar-file-creation.png](alert07-winrar-file-creation.png) | Download, WinRAR extraction, files created, registry set |
| #7 | [alert07-dropped-files.png](alert07-dropped-files.png) | Decoy PDF, Updater.lnk in Startup, msedge.dll in Temp |
| #7 | [alert07-logon-persistence.png](alert07-logon-persistence.png) | cmd.exe launched by Explorer one second after logon |
| #7 | [alert07-com-hijack.png](alert07-com-hijack.png) | reg add pointing InprocServer32 at msedge.dll |
| #7 | [alert07-endpoint-verification.png](alert07-endpoint-verification.png) | Files present; registry rewritten to Temp\1 |
| #7 | [alert07-cleanup-verified.png](alert07-cleanup-verified.png) | All persistence and files confirmed removed |
| #8 | [alert08-email.png](alert08-email.png) | Phishing email with mail.rtf attachment |
| #8 | [alert08-process-chain.png](alert08-process-chain.png) | OUTLOOK.EXE → cmd.exe → regsvr32.exe |
| #8 | [alert08-regsvr32-command.png](alert08-regsvr32-command.png) | regsvr32 fetching shell.sct (Squiblydoo) |
| #8 | [alert08-proxy-request.png](alert08-proxy-request.png) | Proxy permitted the shell.sct request |
| #8 | [alert08-network-c2.png](alert08-network-c2.png) | Connection to malicious IP 84.38.130.118 |
| #8 | [alert08-threatintel-ip.png](alert08-threatintel-ip.png) | Attacker IP tagged Malicious |
| #9 | [alert09-ssh-bruteforce.png](alert09-ssh-bruteforce.png) | 6 failed SSH logins, then accepted; auditd grep record |
| #9 | [alert09-terminal-history.png](alert09-terminal-history.png) | Discovery, backdoor account, log and audit deletion |
| #9 | [alert09-abuseipdb.png](alert09-abuseipdb.png) | AbuseIPDB: 15% confidence, 58 reports |
| #9 | [alert09-virustotal.png](alert09-virustotal.png) | VirusTotal: 0/92, tagged VPN |
| #10 | [alert10-alert-details.png](alert10-alert-details.png) | ipconfig launched by 20.exe from Downloads |
| #10 | [alert10-email.png](alert10-email.png) | Security-themed phishing email |
| #10 | [alert10-browser-download.png](alert10-browser-download.png) | cleaner.zip download from files-ld S3 |
| #10 | [alert10-attack-commands.png](alert10-attack-commands.png) | Execution policy bypass, discovery, admin tampering |
| #10 | [alert10-vbs-ipconfig.png](alert10-vbs-ipconfig.png) | m2.ps1, ipconfig (alert), tmp.vbs |
