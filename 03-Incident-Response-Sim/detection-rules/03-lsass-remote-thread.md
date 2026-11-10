# Rule: Remote Thread Created in LSASS

**ATT&CK:** T1003.001 – OS Credential Dumping: LSASS Memory · T1055 – Process Injection · **Severity:** Critical · **Data source:** Sysmon Event ID 8 (CreateRemoteThread)

## What it detects
Any process creating a thread inside `lsass.exe`, the Windows process that holds password hashes and other credentials in memory.

## Logic (SPL)
```spl
index=* EventCode=8 TargetImage="*\\lsass.exe"
| table _time, host, SourceImage, TargetImage, SourceUser
```

Broader version, all remote threads (they are rare, so this is a useful hunting query too):
```spl
index=* EventCode=8 | stats count by SourceImage, TargetImage
```

## Rationale
In the [Conti investigation](../investigations/03-conti-ransomware/report.md), PowerShell injected into `unsecapp.exe`, which then injected into `lsass.exe` to dump hashes. Out of about 28,000 events there were **only two** Event ID 8 records, and both were malicious. Remote threads into LSASS are almost never legitimate.

## Known false positives
- Some security products (EDR, antivirus) access LSASS. Exclude their signed binaries by full path.
- Note: many credential-dumping tools read LSASS memory instead of creating a thread. A companion rule on **Sysmon Event ID 10** (process access) with `TargetImage="*\\lsass.exe"` covers those, but needs more tuning because legitimate processes also access LSASS.

## Testing
**Status:** written from investigation findings, not yet run as a saved search.
**Expected result on the Conti dataset:** one hit, `C:\Windows\System32\wbem\unsecapp.exe` → `C:\Windows\System32\lsass.exe`.
