# Recon Security Checklist

Use this checklist for an authorized external recon engagement. Copy the relevant sections into working notes and mark each item as complete, skipped, or blocked.

## Scope and authorization

- [ ] Confirm the user owns or is authorized to test the target.
- [ ] Record in-scope domains.
- [ ] Record in-scope subdomains, if limited.
- [ ] Record in-scope IPs, CIDRs, ASNs, or cloud assets.
- [ ] Record out-of-scope assets and third-party services.
- [ ] Confirm whether production testing is allowed.
- [ ] Confirm allowed intensity: passive only, light active, standard active, or deep testing.
- [ ] Confirm blocked techniques, such as brute force, exploit attempts, denial-of-service risk, or state-changing requests.
- [ ] Confirm evidence directory and naming convention.
- [ ] Confirm whether the agent should execute commands or only provide command plans.

Do not proceed to active testing until the authorization and scope items are clear.

## Passive recon

- [ ] Collect DNS records: `A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, DMARC.
- [ ] Collect WHOIS/RDAP for domains.
- [ ] Collect WHOIS/RDAP for discovered IPs.
- [ ] Check RIPEstat or BGPView for ASNs, prefixes, and routing context.
- [ ] Query certificate transparency through `crt.sh`.
- [ ] Run passive subdomain discovery with `subfinder`.
- [ ] Run passive subdomain discovery with `amass -passive`.
- [ ] Run `assetfinder` if available.
- [ ] Collect historical URLs with `gau`.
- [ ] Collect historical URLs with `waybackurls`.
- [ ] Review public `urlscan.io` results if useful.
- [ ] Prepare search-engine dorks for exposed files, admin paths, login pages, APIs, and old endpoints.
- [ ] Review public code search for domains, endpoints, tokens, and configuration references without copying secrets.

## Target normalization

- [ ] Merge subdomain sources into `domains.txt`.
- [ ] Remove duplicates and wildcard noise.
- [ ] Remove obvious unrelated certificate names.
- [ ] Mark third-party SaaS and CDN assets for scope review.
- [ ] Resolve names with `dnsx` or equivalent.
- [ ] Create `resolved_hosts.txt`.
- [ ] Probe HTTP/HTTPS with `httpx`.
- [ ] Create `web_targets.txt`.
- [ ] Create `ips.txt` only from assets approved for IP scanning.
- [ ] Keep uncertain targets in a separate `needs-scope-confirmation.txt` list.

## Active recon

- [ ] Confirm active testing is authorized before running this section.
- [ ] Set conservative rate limits.
- [ ] Run `httpx` with status code, title, redirects, server, tech detection, and content length.
- [ ] Run `nmap` top-port scan on approved IPs.
- [ ] Run focused `nmap -sV` validation for interesting ports.
- [ ] Run full-port scans only if approved.
- [ ] Use `naabu` only where fast port discovery is appropriate.
- [ ] Use `masscan` only with explicit approval and strict rate limiting.
- [ ] Run `wafw00f` on approved web targets.
- [ ] Run `testssl.sh` or `sslyze` on approved TLS endpoints.
- [ ] Run `nuclei` with severity filters and open templates.
- [ ] Save raw output and command logs.
- [ ] Record failures, timeouts, and skipped scans as limitations.

## Web app testing

- [ ] Fingerprint headers and response bodies for approved web targets.
- [ ] Check security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
- [ ] Check cookies for `Secure`, `HttpOnly`, and `SameSite`.
- [ ] Check `.git`, `.env`, backups, config files, directory listing, `phpinfo`, `robots.txt`, `sitemap.xml`, and server-status pages.
- [ ] Run `ffuf` or `feroxbuster` with conservative wordlists and rate limits.
- [ ] Run `arjun` for parameter discovery where appropriate.
- [ ] Crawl with `katana` or `hakrawler`.
- [ ] Use historical URLs to identify old or hidden endpoints.
- [ ] Run `sqlmap` only in detection or confirmation mode by default.
- [ ] Run `dalfox` only against known/reflected parameters.
- [ ] Use OWASP ZAP or Burp Suite Community for manual proxy review.
- [ ] Stop and ask before any state-changing, authenticated, destructive, or data-extracting test.

## Triage

- [ ] Separate confirmed findings from likely findings and leads.
- [ ] Manually confirm high and critical scanner results.
- [ ] Deduplicate findings across tools.
- [ ] Remove out-of-scope and third-party false positives.
- [ ] Preserve raw evidence but keep sensitive data out of the final report.
- [ ] Assign severity using the skill's P0 to P3 scale.
- [ ] Write a concrete remediation for each confirmed finding.
- [ ] Note residual risk and untested areas.

## Report review

- [ ] Executive summary states what was assessed and the overall risk.
- [ ] Scope section lists included and excluded assets.
- [ ] Methodology separates passive, active, and manual work.
- [ ] Findings are ordered by severity.
- [ ] Each finding includes target, evidence, impact, and fix.
- [ ] Leads are clearly labeled as not confirmed.
- [ ] Limitations are explicit.
- [ ] No secrets, personal data, or unnecessary sensitive content are copied into the report.
