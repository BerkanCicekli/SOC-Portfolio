# SPL Cheatsheet

Queries I use regularly, with what each one is for. Field names vary between datasets — always check the field list first.

## Basics
```spl
# Search an index for a specific event
index=main EventCode=4625

# Choose the columns you see
index=main EventCode=4625 | table _time, user, src_ip, host

# Count and rank
index=main EventCode=4625 | stats count by user, src_ip | sort -count
```

## Multiple values — repeat the field name
```spl
# Correct
index=main (EventCode=4624 OR EventCode=4625)

# Wrong — the second term searches raw text, not the field
index=main EventCode=4624 OR 4625
```

## Time-based detection
```spl
# More than 10 failed logins from one IP within 5 minutes
index=main EventCode=4625
| bin _time span=5m
| stats count by _time, src_ip
| where count > 10
```

## Windows logon types (Event 4624 / 4625)
| Type | Meaning |
|------|---------|
| 2 | Interactive (at the keyboard) |
| 3 | Network (e.g. SMB share) |
| 10 | RemoteInteractive (RDP) |

## Key Sysmon Event IDs
| ID | Event |
|----|-------|
| 1 | Process creation |
| 3 | Network connection |
| 7 | Image (DLL) loaded |
| 10 | Process access (e.g. LSASS access) |
| 11 | File created |
| 13 | Registry value set |

## My queries
*Add queries from each investigation here, with a one-line explanation.*
