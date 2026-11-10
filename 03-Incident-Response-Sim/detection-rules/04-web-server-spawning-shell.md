# Rule: Web Server Process Spawning a Shell

**ATT&CK:** T1505.003 – Server Software Component: Web Shell · T1059.003 – Windows Command Shell · **Severity:** High · **Data source:** Sysmon Event ID 1 / Windows Security 4688

## What it detects
A web server process (IIS, PHP, Apache, Tomcat) starting a command shell or scripting engine. This is the classic sign of a web shell or of an exploited web application.

## Logic (SPL)
```spl
index=* (EventCode=1 OR EventCode=4688)
    (ParentImage="*\\w3wp.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\php.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\tomcat*.exe")
    (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe")
| table _time, host, User, ParentImage, Image, CommandLine
```

## Rationale
This behaviour appeared in two of my investigations:
- [Web server](../investigations/01-web-brute-force/report.md): `php-cgi.exe` → `cmd.exe /c "3791.exe 2>&1"` as `NT AUTHORITY\IUSR`, launching the uploaded backdoor.
- [Conti](../investigations/03-conti-ransomware/report.md): commands running as SYSTEM from `c:\windows\system32\inetsrv\` (the IIS folder) to prepare an Exchange web shell.

Web servers serve pages; they should almost never need to open a command prompt.

## Known false positives
- Some web applications legitimately call system commands (e.g. image processing or admin panels). Allow-list the exact command lines after review.
- Exchange and IIS maintenance can spawn processes during updates. Check against change windows.

## Testing
**Status:** written from investigation findings, not yet run as a saved search.
**Expected result on `botsv1`:** a hit for `php-cgi.exe` → `cmd.exe` at 21:56:18 on 10 August 2016 (`sourcetype=xmlwineventlog`).
