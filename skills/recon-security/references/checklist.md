# Pentest Engagement Checklist

Full workflow: recon through reporting. Mark each item complete, skipped, or blocked.

## Scope and authorization

- [ ] Confirm authorization to test the target.
- [ ] Record in-scope domains, subdomains, IPs, ASNs, apps.
- [ ] Record out-of-scope assets and third parties.
- [ ] Confirm production vs staging rules.
- [ ] Confirm intensity: passive, light active, standard, deep.
- [ ] Confirm whether exploitation and credential tests are allowed.
- [ ] Record blocked techniques (brute force, DoS, dump, lateral movement).
- [ ] Set `PROJECT_DIR` and evidence layout (`references/environment-setup.md`).
- [ ] Install required tools per `references/environment-setup.md` if missing.

## Environment

- [ ] Core tools installed (nmap, httpx, subfinder, nuclei, ffuf, etc.).
- [ ] `~/pentest-venv` activated when using Python tools.
- [ ] SecLists available at `~/wordlists/SecLists`.
- [ ] Burp Community or OWASP ZAP available for validation.

## Passive recon

- [ ] DNS, WHOIS/RDAP, RIPEstat/BGPView.
- [ ] Certificate transparency and passive subdomains.
- [ ] Historical URLs (gau, waybackurls).
- [ ] Public urlscan and search dorks.
- [ ] Public code search (no secret exfiltration).
- [ ] Passive recon commands executed or planned (DNS, CT, subdomains, historical URLs).

## Target normalization

- [ ] `domains.txt`, `in_scope_domains.txt`, `web_targets.txt`, `ips.txt`.
- [ ] `needs-scope-confirmation.txt` for uncertain assets.
- [ ] Resolve with `dnsx`; probe with `httpx`.

## Active recon

- [ ] Authorization confirmed.
- [ ] Rate limits set.
- [ ] `nmap` top ports, then focused service detection.
- [ ] Full-port / `masscan` only if approved.
- [ ] `wafw00f`, TLS checks, `nuclei` with triage.
- [ ] Active recon commands executed or planned (httpx, nmap, nuclei, TLS, WAF).

## Web app testing

- [ ] Fingerprint and security headers.
- [ ] Misconfiguration checks (.git, .env, backups, phpinfo).
- [ ] Content and parameter discovery.
- [ ] `sqlmap` detection-only; no dump by default.
- [ ] `dalfox` on known parameters.
- [ ] Web app baseline checks on each priority URL (fingerprint, misconfigs, params).

## Infrastructure (if in scope)

- [ ] SIP/VoIP ports and methods (5060/5061).
- [ ] NAS/SMB/NFS/WebDAV port scan.
- [ ] Share/export listing only when authorized; no customer data copy.

## Triage

- [ ] Queue prioritized in `evidence/triage/`.
- [ ] Confirmed vs likely vs lead vs false positive.
- [ ] Raw evidence preserved; secrets redacted from notes.

## Validation

- [ ] Burp/ZAP session for priority apps.
- [ ] Manual confirmation of critical/high scanner hits.
- [ ] Two-account authz tests where applicable.
- [ ] PoC meets bar in `references/validation.md`.
- [ ] Confirmed findings moved to `evidence/findings/confirmed/`.

## Scoped exploitation (only if RoE allows)

- [ ] RoE read (`references/exploitation-roe.md`).
- [ ] Minimum-impact proof only.
- [ ] No prohibited techniques (dump, persistence, DoS, OOS assets).
- [ ] Test artifacts cleaned up if required.

## Report

- [ ] Executive summary and scope.
- [ ] Methodology covers all phases run.
- [ ] Findings by severity with repro and fix.
- [ ] Leads and limitations documented.
- [ ] `references/report-template.md` applied.
