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

## Lessons from my investigations

Things that caught me out, and the fix:

| Problem | Fix |
|---|---|
| Search returns 0 events on historic data | Set the time picker to **All time**, not "All time (real-time)" or "Last 24 hours" |
| `stats ... by A, B` returns an empty table even though events matched | `stats` silently drops events where any `by` field is missing. Use `table`, or group by fewer fields |
| Count in the table doesn't match the event count | Same cause: some events lack the `by` field. The number under the search bar is the true total |
| Windows paths don't match | Double the backslashes inside quotes: `"C:\\Users\\..."` |
| A field name returns nothing | Field names differ between datasets (`EventCode` vs `EventID`, `src` vs `srcip`). Check the field list on the left first |
| Can't copy a long value from a table | Extract it into its own field with `rex`, then triple-click to select |

## My queries

### Overview of a new dataset
```spl
# What log sources do I have?
index=botsv1 | stats count by sourcetype

# Which sourcetype mentions this indicator?
index=botsv1 "3791.exe" | stats count by sourcetype
```

### Web attacks (stream:http, Suricata, FortiGate)
```spl
# Who is hitting the website, and how much?
index=botsv1 imreallynotbatman.com sourcetype=stream:http | stats count by src_ip

# Scanners often name themselves (or their payloads) in the User-Agent
index=botsv1 src_ip=40.80.148.42 sourcetype=stream:http | stats count by http_user_agent

# What did the IDS / firewall see from this IP?
index=botsv1 src_ip=40.80.148.42 sourcetype=suricata | stats count by alert.signature
index=botsv1 sourcetype=fortigate_utm src=40.80.148.42 | stats count by attack

# Most requested paths - shows the CMS and what was probed
index=botsv1 src_ip=40.80.148.42 sourcetype=stream:http | top limit=20 uri

# Traffic FROM a web server - servers rarely start connections, so this is high value
index=botsv1 src_ip=192.168.250.70 sourcetype=suricata | stats count by dest_ip
```

### Brute force against a web login
```spl
# Pull usernames and passwords out of the login form data
index=botsv1 sourcetype=stream:http http_method=POST uri="/joomla/administrator/index.php" form_data=*username*passwd*
| rex field=form_data "username=(?<user>[^&]+)"
| rex field=form_data "passwd=(?<creds>[^&]+)"
| table _time, src_ip, user, creds

# How many different passwords were tried? (dc = distinct count)
... | stats dc(creds) as unique_passwords

# The password that worked appears twice: once from the tool, once from the real login
... | stats count, values(src_ip) as ips, values(http_user_agent) as agents by creds | where count>1
```

### Process activity (Sysmon / Windows Security)
```spl
# Process creation for a suspicious file, with its hashes and parent
index=* Image="C:\\Users\\Administrator\\Documents\\cmd.exe" EventCode=1
| table _time, Image, Hashes, CommandLine, ParentImage

# Files written by a process - ransomware drops the same note everywhere
index=* EventCode=11 Image="*cmd.exe" | stats count by Image, TargetFilename

# Process injection - rare, so every hit deserves a look
index=* EventCode=8 | table _time, SourceImage, TargetImage

# Web shells on IIS/Exchange
index=* (TargetFilename="*.aspx" OR CommandLine="*.aspx*")
| table _time, EventCode, Image, TargetFilename, CommandLine, ParentImage
```

### Accounts and lateral movement
```spl
# User account created (Windows Security 4720)
index=main EventID=4720 | table _time, Hostname, Category, AccountName, Message

# Commands that add users or group members
index=* CommandLine="*/add*" | table _time, ParentImage, Image, CommandLine

# Remote command execution with WMIC
index=main CommandLine="*/node:*" | table _time, Hostname, EventID, CommandLine

# Did the backdoor account ever log in? (4624 success, 4625 failure)
index=main A1berto (EventID=4624 OR EventID=4625) | table _time, Hostname, EventID
```

### PowerShell
```spl
# Module logging volume per host
index=main EventID=4103 | stats count by Hostname

# Extract an encoded command so it can be decoded in CyberChef
# (From Base64, then Decode text UTF-16LE)
index=main EventID=4103 | rex field=ContextInfo "-enc (?<encoded>\S+)" | stats count by encoded
```

### Useful commands
| Command | What it does |
|---|---|
| `stats count by X` | Count events per value of X |
| `stats dc(X)` | Count distinct values of X |
| `values(X)` | List the distinct values of X inside a `stats` |
| `top limit=20 X` | Most common values of X, with percentages |
| `table A, B, C` | Show these columns, keeping events with missing fields |
| `where count>1` | Filter on a calculated value after `stats` |
| `rex field=X "...(?<name>...)"` | Extract part of a field into a new field with a regular expression |
| `bin _time span=5m` | Group events into 5-minute buckets for rate-based detection |
