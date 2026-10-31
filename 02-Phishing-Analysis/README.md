# Project 2: Phishing Email Analysis

**Platform:** CyberDefenders · **Status:** Planned

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
| 1 | *coming soon* | Credential phishing | |
| 2 | *coming soon* | Malware delivery | |
| 3 | *coming soon* | Business email compromise | |

## Analysis workflow

1. **Headers** – From vs Return-Path, Received chain, originating IP
2. **Authentication** – SPF, DKIM, DMARC (and what a pass does *not* prove)
3. **URLs** – extract without clicking, check with urlscan.io / VirusTotal / WHOIS
4. **Attachments** – hash, look up, never open outside a sandbox
5. **Verdict & IOCs** – classify, defang and record indicators
6. **Recommendations** – blocking, scoping other recipients, user follow-up

## Key lessons learned

*Add as you complete cases.*
