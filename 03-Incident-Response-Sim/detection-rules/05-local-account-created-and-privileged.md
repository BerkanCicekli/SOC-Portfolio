# Rule: New Local Account Added to a Privileged Group

**ATT&CK:** T1136.001 – Create Account: Local Account · T1098 – Account Manipulation · **Severity:** High · **Data source:** Windows Security 4720 / 4732, or process command lines

## What it detects
A new account being created and, within a short time, added to Administrators or Remote Desktop Users. This is a common way for attackers to keep access.

## Logic (SPL)
Using command lines (works with Sysmon 1 or Security 4688):
```spl
index=* (EventCode=1 OR EventCode=4688 OR EventID=1 OR EventID=4688)
    CommandLine="*/add*" (CommandLine="*net* user *" OR CommandLine="*localgroup*")
| table _time, host, User, ParentImage, CommandLine
```

Using Security events (account created, then added to a local group):
```spl
index=* (EventCode=4720 OR EventCode=4732 OR EventID=4720 OR EventID=4732)
| stats values(EventCode) as events, values(EventID) as event_ids, min(_time) as first_seen by host
```

## Rationale
- [Conti](../investigations/03-conti-ransomware/report.md): `securityninja` was created and added to Administrators and Remote Desktop Users within one second, a minute before the ransomware ran.
- [PowerShell case](../investigations/02-malicious-powershell/report.md): `A1berto` was created remotely through WMI, with "Password Not Required" set.

## Known false positives
- IT staff creating accounts during onboarding. Domain accounts are normally created on domain controllers, so **local** accounts created on workstations or servers deserve a closer look.
- Build or provisioning scripts. Exclude by parent process and change window.

## Extra checks when it fires
- Compare the new name against existing users: lookalikes (`A1berto` vs `Alberto`) are a strong signal.
- Check the parent process: `wmiprvse.exe` means the command came from another machine.

## Testing
**Status:** written from investigation findings, not yet run as a saved search.
**Expected results:** Conti dataset, `securityninja` (3 commands at 13:04:10–11 in Splunk time); "Investigating with Splunk" dataset, `A1berto` on Micheal.Beaven.
