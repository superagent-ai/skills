# Crypto Secrets Audit Report Template

Use this structure for full audit deliverables. Keep findings concrete, redacted, and ordered by severity.

```markdown
# Crypto Secrets Audit: <target>

**Audit timestamp:** <UTC timestamp>  
**Scanner version:** <version>  
**Deployment risk:** <High | Medium | Low>  
**Scope:** <directories/files scanned>

## Executive Summary

- Confirmed findings: <P0 count> P0, <P1 count> P1, <P2 count> P2, <P3 count> P3, <Informational count> Informational
- Exposed secrets requiring rotation: <count>
- Top risks:
  1. <highest-risk finding>
  2. <second finding>
  3. <third finding>

## Findings Detail

### [<Severity>] <rule id>: <title>

**Category:** <Secrets | Hash | Symmetric | Random | KDF | TLS | JWT | KeyManagement | Serialization>  
**Location:** `<file>:<line>`  
**Confidence:** <High | Medium | Low>  
**Rotation required:** <Yes | No>

Current:

```text
<verbatim code with secrets redacted>
```

Fix:

```text
<concrete secure rewrite or remediation sequence>
```

Rationale: <why this is exploitable in this codebase>

Effort: <Quick Fix | Moderate | Complex>

References:
- <URL or internal reference>

## Secret Exposure Inventory

| Type | File | Redacted value | Rotation required | Rotation hint |
|---|---|---|---|---|
| <secret type> | `<file>:<line>` | `<prefix****suffix>` | Yes | <hint> |

## Remediation Roadmap

### Quick Fix

- <replace or remove local unsafe pattern>

### Moderate

- <refactor secret loading, crypto callsite, JWT validation, password hashing>

### Complex

- <rotate credentials, clean git history, re-encrypt data, coordinated key rollout>

## Compliance Notes

- **SOC 2:** Secret handling, access control, change management, and encryption controls.
- **PCI DSS:** Key management, cryptographic storage, transmission security, and credential handling.
- **HIPAA:** Access controls, transmission security, audit controls, and encryption/addressable safeguards.

## Clean-Scan and Static Limits

If no findings were confirmed, state:

> No findings against the crypto-secrets control set.

Also note what static analysis cannot verify:

- Whether runtime-injected credentials are scoped or rotated.
- Whether credentials were previously committed and removed.
- Whether deployed TLS and certificate settings match source.
- Whether external secret managers enforce least privilege.
- Whether a redacted candidate is live, expired, or fake.

## Appendix

- File inventory: <count by file type>
- Scanner options: `<command>`
- False positives suppressed: <count and reason>
- Files skipped: dependency, build, generated, binary, oversized, or ignored paths
```
