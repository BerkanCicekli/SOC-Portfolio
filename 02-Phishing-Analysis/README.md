# Project 2: Phishing Email Analysis

**Platform:** CyberDefenders · **Status:** Complete

## Overview

Investigating phishing emails by analysing headers, authentication results, URLs and attachments to determine intent, extract indicators of compromise, and recommend defensive actions.

## What's in this folder

| File | Description |
|------|-------------|
| [cases/](cases/) | Analysis reports for each phishing case |
| [ioc-database.csv](ioc-database.csv) | All IOCs extracted across cases (defanged) |
| [phishing-indicators-cheatsheet.md](phishing-indicators-cheatsheet.md) | Quick-reference checklist built from my investigations |
| [templates/](templates/) | Report template |

## Cases

| # | Case | Type | Key finding |
|---|------|------|-------------|
| 1 | [PhishStrike – fake invoice delivers BitRAT, AsyncRAT and a CoinMiner](cases/01-phishstrike/report.md) | Malicious link / Multi-payload malware | SPF/DKIM failures caused by a gateway, not spoofing; one URL served three malware families |
| 2 | [GrabThePhisher – inside a crypto wallet phishing kit](cases/02-grabthephisher/report.md) | Credential phishing kit | Recovery phrases exfiltrated via a Telegram bot; author alias found in the code |
| 3 | [BRabbit – fake employment contract delivers Bad Rabbit ransomware](cases/03-brabbit/report.md) | Phishing to ransomware | Email passed SPF/DKIM/DMARC from an attacker-owned domain; lookalike company domain |

## Analysis workflow

1. **Headers** – From vs Return-Path, Received chain, originating IP
2. **Authentication** – SPF, DKIM, DMARC (and what a pass does *not* prove)
3. **URLs** – extract without clicking, check with urlscan.io / VirusTotal / WHOIS
4. **Attachments** – hash, look up, never open outside a sandbox
5. **Verdict & IOCs** – classify, defang and record indicators
6. **Recommendations** – blocking, scoping other recipients, user follow-up

## Key lessons learned

1. **Authentication results need context.** In PhishStrike, SPF and DKIM *failed* on a genuine (compromised) account because an email gateway sat in the delivery path. In BRabbit, all three checks *passed* for an attacker-owned domain. A result only tells you which domain vouches for an email, not whether to trust it. ([PhishStrike](cases/01-phishstrike/report.md), [BRabbit](cases/03-brabbit/report.md))

2. **Pivot from your own indicators.** Searching a malware tag returns the whole internet; following *this* URL's payloads kept the analysis on the right samples. ([PhishStrike](cases/01-phishstrike/report.md))

3. **Attackers hide in legitimate services.** Telegram bots, dynamic DNS and a public geolocation API all appeared across the cases. Reputation alone won't catch them, so detection has to look at context. ([PhishStrike](cases/01-phishstrike/report.md), [GrabThePhisher](cases/02-grabthephisher/report.md))

4. **Look closely at names.** `Drurnbo` vs `Drumbo`, `.pdf.exe`, a "JPEG" that was a payload, `Jzwvix.exe` copied into AppData. Deception is often in the details. ([BRabbit](cases/03-brabbit/report.md), [PhishStrike](cases/01-phishstrike/report.md))

5. **Sandbox output needs filtering.** Hundreds of "dropped" files were encryption noise, and vendors disagreed on labels. Cross-checking the process graph, registry and file list told the real story. ([BRabbit](cases/03-brabbit/report.md), [PhishStrike](cases/01-phishstrike/report.md))

6. **Handle sensitive data responsibly.** I analysed malware without running it, and withheld victims' recovery phrases and an attacker's live bot token from public reports. ([GrabThePhisher](cases/02-grabthephisher/report.md))

7. **The same entry point, very different impact.** Phishing led to remote access and crypto-mining, to stolen wallets, and to network-wide ransomware.
