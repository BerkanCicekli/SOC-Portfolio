# Phishing Cases

One folder per case, each with a `report.md` and, where useful, a `screenshots/` subfolder. Reports focus on method, evidence and reasoning; all IOCs are defanged.

| # | Case | Type | Key finding |
|---|------|------|-------------|
| 1 | [PhishStrike – fake invoice delivers BitRAT, AsyncRAT and a CoinMiner](01-phishstrike/report.md) | Malicious link / Multi-payload malware | SPF/DKIM failures caused by a gateway, not spoofing |
| 2 | [GrabThePhisher – inside a crypto wallet phishing kit](02-grabthephisher/report.md) | Credential phishing kit | Seed phrases exfiltrated via Telegram bot; author alias found in code |
| 3 | [BRabbit – fake employment contract delivers Bad Rabbit ransomware](03-brabbit/report.md) | Phishing to ransomware | Email passed SPF/DKIM/DMARC from an attacker-owned domain; lookalike company domain |
