# Free/Open-Source Tool Map

Use this reference when choosing tools for an authorized recon workflow. Tools listed here are free, open source, or usable through public/free access without making them required commercial dependencies.

## Policy

- Prefer tools that run locally, can write raw evidence to disk, and do not require paid API keys.
- Do not make Shodan, Censys, DeHashed, IntelX, Burp Pro, or any proprietary scanner a required step.
- Treat public/free web services as optional sources. If they rate limit or require accounts, record the limitation and continue with local/open tools.
- Prefer smaller, scoped commands over broad scans. Rate limit anything that touches target infrastructure.

## Environment helpers

- `curl`: HTTP requests, API pulls, headers, and quick probes.
- `httpie`: readable HTTP requests when available.
- `jq`: JSON parsing and evidence cleanup.
- `sort`, `uniq`, `awk`, `sed`: target list normalization.
- `tee`: save command output while viewing progress.

## Passive recon

- `dig` / `host`: DNS records and resolver checks.
- `whois`: domain and IP registration context.
- RDAP endpoints: structured registration lookups.
- RIPEstat: prefix, ASN, routing, and delegated resource context.
- BGPView: ASN and prefix lookups.
- `crt.sh` via `curl` and `jq`: certificate transparency names.
- `subfinder`: passive subdomain discovery from public sources.
- `amass enum -passive`: passive asset discovery and graph context.
- `assetfinder`: fast passive subdomain collection.
- `gau`: historical and indexed URLs.
- `waybackurls`: Wayback Machine URL collection.
- Common Crawl indexes: historical URLs and public crawl references.
- Public `urlscan.io`: optional public search for submitted URLs and observed requests.
- Search-engine dorks: manual review for indexed files, old endpoints, login panels, and references.
- Public code search: manual review for exposed domains, endpoints, and configuration references.

## Target normalization

- `dnsx`: resolve and validate discovered names.
- `httpx`: identify live web services, status codes, titles, redirects, server headers, technologies, and content length.
- `unfurl`: split URLs into domains, paths, query keys, and components.
- `uro`: normalize and deduplicate URLs.
- `anew`: append only new lines to working target lists.

## Active service recon

- `nmap`: service detection, top-port scans, targeted scripts, and evidence-grade output.
- `naabu`: fast TCP port discovery before focused `nmap` validation.
- `masscan`: optional large-scale scanner; use only when explicitly approved and rate-limited.
- `wafw00f`: WAF detection.
- `testssl.sh`: TLS protocol, certificate, cipher, and misconfiguration checks.
- `sslyze`: structured TLS scanning alternative.
- `nuclei`: open-template vulnerability and exposure checks. Use severity filters and manual triage.

## Web app discovery and checks

- `ffuf`: content discovery, virtual host discovery, and parameter fuzzing with explicit rate limits.
- `feroxbuster`: recursive content discovery with controlled depth.
- `arjun`: parameter discovery.
- `katana`: crawling and endpoint discovery.
- `hakrawler`: lightweight web crawling.
- `nikto`: broad web server checks; noisy, use only when appropriate.
- `sqlmap`: injection detection and confirmation. Do not use dumping or data extraction by default.
- `dalfox`: reflected XSS checks for known parameters.
- OWASP ZAP: free/open-source manual proxy and active/passive scanning.
- Burp Suite Community: free manual proxy review. Do not rely on Burp Pro-only features.

## Useful wordlists

- SecLists: default source for web content, DNS, fuzzing, and discovery wordlists.
- `commonspeak2-wordlists`: useful for web and subdomain names when available.
- Small custom wordlists derived from target-specific passive recon: product names, paths, technologies, and historical URLs.

## Commercial or proprietary tools to exclude from the required workflow

- Shodan and Shodan CLI.
- Censys and Censys CLI.
- DeHashed.
- Intelligence X / IntelX.
- Burp Suite Professional.
- Paid SaaS attack-surface scanners.
- Paid breach-data providers.

If the user has access to one of these and asks about it, keep it optional. The core skill must still work without it.

## Replacement guidance

- Replace Shodan/Censys-style service intelligence with passive DNS/CT sources, RIPEstat/BGPView, `httpx`, `nmap`, `naabu`, public `urlscan.io`, and manual search.
- Replace paid breach-data lookups with public code search, search-engine dorks, HIBP domain verification where the user owns the domain, and careful documentation of limitations.
- Replace Burp Pro automation with OWASP ZAP, Burp Community manual testing, `ffuf`, `arjun`, `katana`, `hakrawler`, `sqlmap` detection mode, and `nuclei` open templates.
