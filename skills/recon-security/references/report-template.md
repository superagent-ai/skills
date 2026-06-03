# Recon Report Template

Use this template after an authorized recon workflow. Keep scanner noise in appendices or raw evidence files; the main report should contain triaged findings and clear next steps.

## Executive summary

**Assessment:** `[domain / IP range / application]`

**Dates:** `[start]` to `[end]`

**Scope:** `[short list of in-scope assets]`

**Overall risk:** `[Low / Medium / High / Critical]`

**Summary:** `[One paragraph describing the external exposure, highest-risk findings, and main remediation themes.]`

## Methodology

Passive recon:

- DNS, WHOIS/RDAP, ASN and prefix review.
- Certificate transparency and subdomain discovery.
- Historical URL and public index review.
- Public search/code references.

Active recon:

- DNS resolution and HTTP probing.
- Approved port and service scanning.
- TLS and WAF checks.
- Template-based exposure checks.

Web app review:

- Header, cookie, redirect, and technology fingerprinting.
- Common file and configuration exposure checks.
- Content and parameter discovery.
- Manual confirmation of high-signal results.

Validation:

- Burp/ZAP manual testing, two-account authz checks, PoC reproduction.

Scoped exploitation (if performed):

- Techniques used, RoE constraints, minimum proof, cleanup performed.

Infrastructure (if performed):

- SIP/VoIP, NAS/SMB/NFS exposure summary without sensitive file content.

## Scope

In scope:

- `[asset]`
- `[asset]`

Out of scope:

- `[asset]`
- `[asset]`

Limitations:

- `[blocked source, rate limit, skipped scan, inaccessible target, or authorization limit]`

## Findings summary

- **P0 Critical:** `[count]`
- **P1 High:** `[count]`
- **P2 Medium:** `[count]`
- **P3 Informational:** `[count]`
- **Leads requiring follow-up:** `[count]`

## Finding template

```
[P1] short-finding-slug on target.example.com

Target:
  https://target.example.com/path

Status:
  Confirmed finding | Likely finding | Lead

Evidence:
  Tool/method: httpx, nmap, nuclei, manual browser review, etc.
  Timestamp: YYYY-MM-DD HH:MM TZ
  Raw evidence: evidence/path/to/file.txt
  Key observation: concise excerpt or behavior, without copying secrets.

Impact:
  Explain what an attacker could learn or do from the exposure.

Remediation:
  Provide concrete, owner-actionable fixes.

Validation:
  Describe how the owner can verify the fix.
```

## Leads and observations

Use this section for assets or signals that are not confirmed vulnerabilities:

- `[lead]`: why it matters, what evidence exists, and what confirmation is needed.
- `[lead]`: why it matters, what evidence exists, and what confirmation is needed.

## Evidence inventory

- `passive/`: DNS, CT logs, subdomains, historical URLs, public-source notes.
- `active/`: HTTP probing, port scans, TLS checks, WAF checks, nuclei output.
- `webapp/`: fingerprints, content discovery, parameter checks, manual notes.
- `infra/`: SIP, NAS, SMB/NFS scan output.
- `triage/`: prioritized queue and notes.
- `findings/confirmed/` and `findings/leads/`: validated vs unconfirmed.
- `screenshots/`: non-sensitive screenshots for confirmed findings.
- `logs/`: command logs and scan limitations.

## Remediation roadmap

Immediate:

- `[fix critical public exposure]`
- `[restrict management/admin surface]`

Short term:

- `[harden TLS/headers/configuration]`
- `[remove stale DNS or unused services]`

Long term:

- `[asset inventory ownership]`
- `[continuous monitoring with free/open-source tooling]`

## Final notes

This report reflects the authorized scope and methods listed above. A clean result does not prove the organization has no vulnerabilities; it means this workflow did not confirm material external exposures within the tested scope and limits.
