# Audit Report Template

The structure for the output document. Fill the placeholders, drop empty sections, and keep findings ordered by severity (P0 first). Default save path: `./infra-audit-report-<timestamp>.md`. Redact any live secret before saving.

---

```markdown
# IaC Security Audit — <target name or repo>

- **Scope:** <directory / files audited>
- **Date:** <YYYY-MM-DD HH:MM TZ>
- **Files scanned:** <N> (<terraform> Terraform, <k8s> K8s, <cfn> CloudFormation, <docker> Docker)
- **Scanner:** infra-security scan.py v<version>
- **Auditor:** <model / human>

## Executive summary

<2–4 sentences: the overall posture and the single most important thing to fix first.>

- **P0 Critical:** <n>
- **P1 High:** <n>
- **P2 Medium:** <n>
- **P3 Low:** <n>
- **Informational:** <n>

**Top 3 risks**

1. **[P0] <title>** — <one line: exposure + blast radius> (`<file>:<line>`)
2. **[P1] <title>** — <one line> (`<file>:<line>`)
3. **[P1] <title>** — <one line> (`<file>:<line>`)

## Deployment risk rating: <High | Medium | Low>

<Why: e.g. "High — 2 P0 findings expose customer data to the internet. Do not deploy until both are resolved.">

---

## Findings

### [P0] <control-id> — <short title>

- **Resource:** <type.name, e.g. aws_security_group.web>
- **Location:** `<file>:<line>`
- **Effort:** <Quick Fix | Moderate | Complex>
- **Compliance:** <SOC-2 CC6.6; PCI-DSS 1.3.1; ISO-27001 A.8.20>

**Current**

​```hcl
<verbatim bad snippet>
​```

**Fixed**

​```hcl
<corrected snippet>
​```

**Rationale**

<Exposure (can it be reached?) and blast radius (what falls if it is?), in 1–2 sentences. State any assumption that drives the severity.>

---

<repeat per finding, grouped by severity>

---

## Compliance mapping

| Finding | Control | SOC-2 | PCI-DSS | ISO-27001 |
|---------|---------|-------|---------|-----------|
| <id>    | <title> | CC6.6 | 1.3.1   | A.8.20    |
| ...     | ...     | ...   | ...     | ...       |

## Remediation roadmap

**Quick Fix (this PR)**
- [ ] <finding> — `<file>:<line>` — <one-line change>

**Moderate (next sprint)**
- [ ] <finding> — `<file>:<line>` — <new resource / refactor>

**Complex (planned work)**
- [ ] <finding> — `<file>:<line>` — <architectural change, owner>

## Appendix

**File inventory**

| File | Type | Findings |
|------|------|----------|
| <path> | Terraform | <n> |
| ...  | ...  | ... |

**What this audit did not cover**

- Live cloud state and drift — the deployed resources may differ from this IaC.
- Effective IAM permissions — policy *documents* were read, not the evaluated access graph.
- Runtime container behavior, and secrets injected outside the IaC.
- Modules / charts not present in the scanned tree.

A clean or remediated IaC read does not prove the running infrastructure is safe; confirm against the deployed environment.
```

---

## Notes on filling it in

- **One finding, one block.** Don't merge two resources into a single finding even if they share a control — each needs its own `file:line` and fix.
- **Lead with the worst.** The reader triages top-down; P0s must be the first thing after the summary.
- **Every finding gets a fix.** A finding without a corrected snippet is a ticket that rots. Pull the fix from `remediation-playbook.md` and adapt it to the resource.
- **Justify the severity.** When a rating departs from the control's default in `controls.md`, say why (exposure or blast radius) in the rationale — that is what survives review.
- **Drop what's empty.** No P0s? Remove the P0 finding blocks. No compliance scope? Remove the mapping table. Keep the document tight.
