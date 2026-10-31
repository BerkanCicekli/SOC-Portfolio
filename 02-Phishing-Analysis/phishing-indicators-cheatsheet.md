# Phishing Indicators Cheatsheet

Built from my own investigations. Add to it after each case.

## Header checks
- [ ] Display name vs actual sender address
- [ ] `From:` domain vs `Return-Path:` domain
- [ ] Originating IP in the earliest `Received:` header (read bottom to top)
- [ ] Reply-To pointing somewhere unexpected

## Authentication (SPF / DKIM / DMARC)
- **SPF** checks whether the sending IP is authorised for the **Return-Path (envelope) domain** — not the display name.
- A **pass is not proof of safety**: an attacker sending from their own lookalike domain can pass SPF and DKIM.
- **DMARC** ties the result back to the visible `From:` domain — a DMARC failure on a brand's real domain is a strong spoofing indicator.

## URL red flags
- [ ] Link text doesn't match the real destination
- [ ] Lookalike / typosquatted domain
- [ ] Recently registered domain (check WHOIS)
- [ ] URL shorteners or open redirects

## Content red flags
- [ ] Urgency or threats ("account locked in 24 hours")
- [ ] Authority impersonation (CEO, IT, bank)
- [ ] Request that bypasses normal process (payment, gift cards, credentials)

## Defanging
`https://evil.com` → `hxxps://evil[.]com` · `1.2.3.4` → `1.2.3[.]4`
