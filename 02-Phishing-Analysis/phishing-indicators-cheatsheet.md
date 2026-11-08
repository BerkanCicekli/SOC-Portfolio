# Phishing Indicators Cheatsheet

Quick-reference checklist built from my investigations. Examples link to the case where I saw them.

## 1. Sender and headers
- [ ] **Display name vs address** – "Drumbo®" sent from `Drurnbo.com` ([BRabbit](cases/03-brabbit/report.md))
- [ ] **Lookalike domains** – `rn` vs `m`, `0` vs `o`, extra words (`-support`, `-secure`)
- [ ] **From vs Return-Path vs Reply-To** – unrelated domains are a red flag
- [ ] **Read `Received` headers bottom to top** – the first hop your own provider added shows the real sending IP
- [ ] **Don't trust hops below that** – the sender can forge them (fake twitter.com hops in [BRabbit](cases/03-brabbit/report.md))
- [ ] **Fake "trusted" headers** – e.g. a made-up `X-Google-Sender-Delegation: Trusted Sender`

## 2. Authentication (SPF / DKIM / DMARC)
- **SPF** checks the sending IP against the **Return-Path (envelope) domain**, not the display name.
- **DKIM** checks a signature from the domain in `header.d=`.
- **DMARC** ties results to the visible `From:` domain.
- **A pass isn't proof of safety** – an attacker-owned domain can pass all three ([BRabbit](cases/03-brabbit/report.md)).
- **A fail isn't proof of spoofing** – a security gateway in the path can break SPF/DKIM on genuine mail ([PhishStrike](cases/01-phishstrike/report.md)).
- Always ask: *which domain* passed or failed, and does it match who the email claims to be from?

## 3. Links
- [ ] Link text doesn't match the real destination
- [ ] **Executable on a raw IP address** – `hxxp://107[.]175[.]247[.]199/loader/install[.]exe` ([PhishStrike](cases/01-phishstrike/report.md))
- [ ] Folders like `/loader/` or `/uploads/`; files that don't match their extension (a ".jpeg" payload)
- [ ] Recently registered or dynamic DNS domains (`mywire.org` and similar)
- [ ] **Look them up, never visit** – URLhaus, VirusTotal, urlscan.io

## 4. Attachments
- [ ] **Double extensions** – `Urgent Contract Action.pdf.exe` ([BRabbit](cases/03-brabbit/report.md))
- [ ] Executables, archives (.rar, .zip) or scripts from external senders
- [ ] **Hash it and look it up** – never open it outside a sandbox

## 5. Content and lures
- [ ] **Urgency or deadlines** – "by the end of the day"
- [ ] **Authority** – CEO, HR, IT, finance
- [ ] **Fear or money** – job threats, large unexpected purchases ($625,000 invoice)
- [ ] **Fake reassurance** – "access codes", "secure document"
- [ ] **Requests no legitimate service makes** – wallet recovery phrases, passwords ([GrabThePhisher](cases/02-grabthephisher/report.md))
- [ ] Sent late on a Friday, or to undisclosed recipients

## 6. What the payload does
- [ ] **Persistence** – Registry Run keys, scheduled tasks, Startup folder
- [ ] **Evasion** – encoded PowerShell (`-enc`), long sleeps, invalid signatures
- [ ] **Exfiltration and C2** – Telegram bots, dynamic DNS, legitimate cloud services
- [ ] **Impact** – remote access, crypto-mining, credential theft, ransomware

## Defanging
`https://evil.com` → `hxxps://evil[.]com` · `1.2.3.4` → `1[.]2[.]3[.]4` · `user@evil.com` → `user[@]evil[.]com`
