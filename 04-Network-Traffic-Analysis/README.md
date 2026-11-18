# Project 4: Network Traffic Analysis

**Platform:** CyberDefenders (Network Forensics labs) · **Tool:** Wireshark
**Status:** In progress

Investigating attacks from packet captures (PCAPs): reading raw network traffic to work out who attacked what, which accounts and tools they used, and how they moved through the network.

> All data comes from simulated lab environments. No real organisation or user was involved.

## Cases

| # | Case | What it shows | Report |
|---|------|---------------|--------|
| 1 | PsExec Hunt: lateral movement over SMB | SMB2 and NTLM analysis, ADMIN$/IPC$ shares, PsExec fingerprint, two compromised accounts | [report](cases/01-psexec-hunt/report.md) |

## Approach

1. **Overview first:** Statistics → Conversations and Protocol Hierarchy, to see who talked to whom, how much and when.
2. **Filter by protocol:** narrow down to the traffic that matters (SMB2, NTLMSSP, HTTP, DNS).
3. **Read the details:** packet fields, Follow Stream, and exported objects only inside an isolated environment.
4. **Build the timeline** and map it to MITRE ATT&CK.
5. **Write it up:** evidence, IOCs, response and lessons learned.

## Useful Wireshark filters

| Filter | Shows |
|---|---|
| `smb2` | All SMB2 file-sharing traffic |
| `smb2.cmd == 3` | Tree Connects: which shares were accessed |
| `smb2.cmd == 5` | Create requests: which files and pipes were opened |
| `ntlmssp.messagetype == 0x00000002` | NTLM challenges: target machine names |
| `ntlmssp.messagetype == 0x00000003` | NTLM AUTH: usernames and source hosts |
| `ip.addr == 10.0.0.130` | All traffic to or from one machine |
