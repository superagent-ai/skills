# Validation Phase

Use after recon and automated web checks. The goal is to turn scanner leads into confirmed findings with minimal, reproducible proof.

## When to enter this phase

- Recon passes produced a prioritized queue in `evidence/triage/queue.txt` or equivalent notes.
- Active testing was authorized in Pass 0.
- High/critical nuclei, ffuf, or misconfiguration signals are not yet confirmed.

## Validation principles

- One finding, one PoC. Prefer a single request/response pair or screenshot over bulk output.
- Reproduce twice when possible: once to discover, once to document cleanly.
- Use two test accounts when testing authorization (User A must not access User B's object).
- Do not copy secrets, full database rows, or regulated personal data into evidence. Describe impact without exfiltrating content.
- If a test might change production state, stop and confirm with the client.

## By finding type

### Web application

- Import live URLs into Burp Suite Community or OWASP ZAP.
- Map authentication, session cookies, and role boundaries.
- Confirm injection: error-based or boolean/time-based SQLi with `sqlmap --batch --level=3 --risk=2` only; no `--dump`.
- Confirm XSS with `dalfox` or manual payload in Repeater; verify reflection context (HTML, attribute, JS).
- Confirm IDOR/BOLA with two accounts and swapped object IDs. Pair with `authz-security` when source code is available.
- Confirm file exposure: fetch `.git/HEAD`, backup paths, or config files and verify sensitive content without archiving secrets.

### Infrastructure and services

- Re-run focused `nmap -sV -p <port> <ip>` on interesting ports from recon.
- Validate TLS issues with `testssl.sh` or `sslyze`; capture cipher/protocol downgrade only if reproducible.
- Confirm WAF presence with `wafw00f`; note bypass only if in scope and non-destructive.

### SIP / VoIP (when in scope)

- UDP/TCP probe on 5060/5061 with `nmap --script=sip-methods`.
- OPTIONS request via `nc` or `sipvicious` if installed; record banner and allowed methods.
- Do not register extensions or place calls unless explicitly authorized.

### Storage / NAS / file services (when in scope)

- Confirm open SMB/NFS/WebDAV ports with `nmap -sV`.
- List shares with `smbclient -N -L` or `showmount -e` only when authorized; do not download customer data.
- Treat anonymous read access as high severity; document share names and permissions, not file contents.

## PoC quality bar

A validated finding should include:

- Target URL or `host:port`
- Preconditions (unauthenticated vs authenticated role)
- Steps to reproduce (numbered)
- Observed result (status code, snippet, screenshot reference)
- Impact statement in business terms
- Suggested fix

## Closing validation

- Move confirmed items to `evidence/findings/confirmed/`.
- Leave unconfirmed items in `evidence/findings/leads/`.
- Update severity after manual confirmation; downgrade scanner-only criticals that do not reproduce.
