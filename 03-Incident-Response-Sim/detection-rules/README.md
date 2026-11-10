# Custom Detection Rules

Rules I've written from attacker behaviour seen in my own investigations. Each rule lists its logic, rationale, known false positives and testing status.

| # | Rule | ATT&CK | Based on | Status |
|---|------|--------|----------|--------|
| 1 | [Web login brute force](01-web-login-brute-force.md) | T1110.001 | Web server investigation | Written, not yet tested |
| 2 | [Encoded or hidden PowerShell](02-encoded-hidden-powershell.md) | T1059.001, T1027 | PowerShell investigation | Written, not yet tested |
| 3 | [Remote thread created in LSASS](03-lsass-remote-thread.md) | T1003.001, T1055 | Conti investigation | Written, not yet tested |
| 4 | [Web server process spawning a shell](04-web-server-spawning-shell.md) | T1505.003, T1059.003 | Web server and Conti investigations | Written, not yet tested |
| 5 | [New local account added to a privileged group](05-local-account-created-and-privileged.md) | T1136.001, T1098 | Conti and PowerShell investigations | Written, not yet tested |

Field names differ between datasets (`EventCode` vs `EventID`, `host` vs `Hostname`), so each rule may need small adjustments before running.

Template: [rule-template.md](rule-template.md)
