---
name: recon-security
description: Conduct authorized external security reconnaissance with free and open-source tools. Use when assessing owned domains, IP ranges, subdomains, web apps, TLS, exposed services, or external attack surface; when the user mentions recon, OSINT, subdomain discovery, httpx, nuclei, nmap, ffuf, OWASP ZAP, or asks to probe a domain without commercial APIs.
---

# Recon Security

This skill guides an agent through authorized external reconnaissance. It is a workflow skill: establish scope, separate passive and active work, use only free/open-source tools, preserve evidence, and report confirmed exposures separately from leads.

Do not assume permission. Before any active probing, confirm the target scope, authorization, scan intensity, exclusions, and evidence location. If the user only wants advice or planning, stay in planning mode and provide commands as examples rather than executing them.

## Mental model

Recon is not exploitation. The goal is to build an accurate map of externally visible assets and identify likely security exposures with enough evidence for a human to verify and remediate.

Keep three boundaries clear:

- **Passive**: public data sources and third-party indexes. No packets to target infrastructure beyond normal DNS/public lookups.
- **Active**: resolving, probing, scanning, fuzzing, and template checks that contact target assets. Requires explicit authorization and rate limits.
- **Manual confirmation**: browser/proxy review, screenshots, and careful validation. Never dump data, exploit persistence, move laterally, or extract secrets as part of the default workflow.

The agent should prefer conservative, reproducible checks over noisy scans. A small confirmed exposure with clean evidence is more useful than a large pile of untriaged scanner output.

## Pass 0: scope and authorization gate

Before active testing, establish:

- In-scope domains, subdomains, IP ranges, ASNs, cloud assets, and web apps.
- Out-of-scope assets, third-party services, production limits, and blocked techniques.
- Written authorization or an explicit statement that the user owns/controls the targets.
- Allowed scan intensity: passive only, light active, standard active, or deep testing.
- Evidence directory and naming convention.
- Whether the user wants commands only, execution by the agent, or a final report.

If authorization is missing or ambiguous, do not run active commands. Provide a passive-only plan and ask for scope confirmation.

## Pass 1: passive recon

Build the target inventory without direct active testing:

- DNS records: `A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, DMARC.
- WHOIS/RDAP, RIPEstat, BGPView, ASN and netblock context.
- Certificate transparency through `crt.sh` and tool outputs from `subfinder`, `amass -passive`, and `assetfinder`.
- Historical URLs through `gau`, `waybackurls`, Common Crawl indexes, and public `urlscan.io`.
- Search-engine dorks and public code search for exposed files, old endpoints, admin paths, and leaked references.

Deduplicate aggressively. Track source and timestamp for each asset so the report can explain where it came from.

## Pass 2: normalize targets

Convert raw discoveries into working target lists:

- `domains.txt`: all candidate hostnames.
- `in_scope_domains.txt`: hostnames confirmed in scope.
- `resolved_hosts.txt`: live DNS names with resolved addresses.
- `web_targets.txt`: HTTP/HTTPS URLs for probing.
- `ips.txt`: IP addresses or ranges approved for scanning.

Filter parked domains, obvious CDNs if they are out of scope, unrelated certificate names, and third-party SaaS unless explicitly authorized. When in doubt, mark as `needs-scope-confirmation` instead of scanning it.

## Pass 3: active recon

Only run active recon after Pass 0 is satisfied. Keep scans rate-limited and focused.

Recommended flow:

1. Resolve and classify hosts with `dnsx` and `httpx`.
2. Probe HTTP services with status code, title, server, tech detection, redirects, and content length.
3. Scan approved IPs with `nmap`; start with top ports and service detection before any full-port scan.
4. Use `naabu` for fast port discovery where appropriate; use `masscan` only when explicitly approved and rate-limited.
5. Check WAF presence with `wafw00f`.
6. Analyze TLS with `testssl.sh` or `sslyze`.
7. Run `nuclei` with open templates and a clear severity filter. Treat template findings as leads until manually confirmed.

Save raw output and logs. Do not hide scanner failures; record them as limitations.

## Pass 4: web app checks

For approved web targets:

- Fingerprint headers, cookies, security headers, redirects, technologies, and interesting response bodies.
- Check common exposures: `.git`, `.env`, backups, config files, directory listing, `phpinfo`, `robots.txt`, `sitemap.xml`, server-status pages.
- Discover content with `ffuf` or `feroxbuster` using conservative wordlists and rate limits.
- Discover parameters with `arjun`, crawlers such as `katana` or `hakrawler`, and historical URLs.
- Use `sqlmap` only in detection/confirmation mode by default. Do not use dump/exfiltration options.
- Use `dalfox` for reflected XSS checks where inputs are known. Treat automated results as leads.
- Use OWASP ZAP or Burp Suite Community for manual proxy review.

Never attempt credential stuffing, destructive requests, persistence, lateral movement, or data extraction. If testing could modify state, pause and ask.

## Pass 5: triage and evidence

Separate results into:

- **Confirmed finding**: reproduced behavior with clear request/response or scanner evidence and impact.
- **Likely finding**: strong signal that needs manual confirmation.
- **Lead**: interesting asset, endpoint, port, or technology requiring follow-up.
- **Out of scope / false positive**: unrelated, third-party, duplicate, or not reproducible.

For every confirmed or likely finding, capture target, timestamp, tool, command or method, relevant output, impact, and recommended fix. Avoid including secrets or sensitive personal data in the report; describe exposure without copying protected content.

## Severity scale

- **P0**: Publicly reachable exposure of sensitive data, unauthenticated admin/control plane, exploitable critical CVE with clear evidence, or dangerous misconfiguration enabling immediate compromise.
- **P1**: High-impact weakness requiring limited conditions: exposed management service, serious TLS/auth/session weakness, confirmed injection without data extraction, high-severity nuclei result confirmed manually.
- **P2**: Medium-risk exposure or hardening gap: verbose errors, weak headers, directory listing without sensitive data, outdated service with no confirmed exploit path, broad attack surface.
- **P3**: Informational or hygiene: missing headers, low-risk fingerprinting leaks, stale DNS, parked assets, scan limitations, documentation gaps.

## Output format

When reporting, lead with findings by severity and keep raw scanner noise out of the main answer.

```
[P1] exposed-admin-panel on https://admin.example.com
  Evidence: httpx identified a reachable login panel; screenshot and headers saved.
  Impact: Public admin surface increases password-guessing and exploit exposure.
  Confirmation: Manual browser review confirmed this is an admin portal, not a static asset.
  Fix: Restrict by VPN or identity-aware proxy, enforce MFA, and monitor access logs.
```

If nothing material is found, say what was checked, what tools or phases ran, and what remains unverified.

## Reference files

- `references/tools.md` - free/open-source tools by phase, including excluded commercial replacements.
- `references/checklist.md` - full engagement checklist for scope, recon, web app checks, evidence, and report review.
- `references/report-template.md` - report structure and finding template.

## What this skill won't do

- It won't require Shodan, Censys, DeHashed, IntelX, Burp Pro, or other paid/commercial services.
- It won't treat scanner output as proof without triage.
- It won't perform exploitation, dumping, persistence, lateral movement, credential attacks, or destructive testing.
- It won't bypass authorization. If scope is unclear, it pauses before active testing.
