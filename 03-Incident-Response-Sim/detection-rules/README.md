# Custom Detection Rules

Rules I've written based on attacker behaviour seen in my investigations. Each rule lists its logic, rationale, known false positives and how I tested it.

| # | Rule | ATT&CK | Status |
|---|------|--------|--------|
| 1 | Brute force – >10 failed logons in 5 min | T1110 | Planned |
| 2 | Office application spawning cmd/PowerShell | T1059 | Planned |
| 3 | LSASS memory access by unusual process | T1003.001 | Planned |
| 4 | Registry Run key modification | T1547.001 | Planned |

Template: [rule-template.md](rule-template.md)
