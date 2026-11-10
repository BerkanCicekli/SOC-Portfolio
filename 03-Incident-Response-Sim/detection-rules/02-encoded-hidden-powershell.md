# Rule: Encoded or Hidden PowerShell Execution

**ATT&CK:** T1059.001 – PowerShell · T1027 – Obfuscated Files or Information · **Severity:** High · **Data source:** Sysmon Event ID 1 / Windows Security 4688 (command line logging), PowerShell 4103

## What it detects
PowerShell started with an encoded command, especially when combined with a hidden window or with no profile loaded.

## Logic (SPL)
```spl
index=* (EventCode=1 OR EventCode=4688 OR EventID=1 OR EventID=4688)
    (Image="*\\powershell.exe" OR CommandLine="*powershell*")
    (CommandLine="* -enc *" OR CommandLine="* -e *" OR CommandLine="*-EncodedCommand*")
| eval hidden=if(match(CommandLine, "(?i)-w(indowstyle)?\s+(1|h)"), "yes", "no")
| table _time, host, User, ParentImage, CommandLine, hidden
```

## Rationale
In the [PowerShell investigation](../investigations/02-malicious-powershell/report.md), the attacker ran `powershell.exe -noP -sta -w 1 -enc <Base64>`. Decoded, it disabled logging, bypassed AMSI and downloaded a second stage. Encoding hides the command from casual review, and a hidden window hides it from the user. Legitimate scripts rarely need both.

## Known false positives
- Some management tools (SCCM, Intune, some backup or monitoring agents) launch encoded PowerShell. Baseline them by parent process and signed path, then exclude.
- Admin scripts that use `-enc` to avoid quoting problems. Review and allow-list by parent process and user.

## Follow-up when it fires
Decode the command (CyberChef: From Base64 → Decode text UTF-16LE) and look for download cradles (`DownloadString`, `DownloadData`, `IEX`), AMSI bypasses and logging changes.

## Testing
**Status:** written from investigation findings, not yet run as a saved search.
**Expected result on the "Investigating with Splunk" dataset:** hits on host James.browne for the Empire stager. That dataset logged PowerShell mostly through Event IDs 4103 and 800, so the rule may need adapting to search `ContextInfo` there.
