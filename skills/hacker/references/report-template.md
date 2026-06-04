# Security Suite Report: <target>

**Generated:** <timestamp>  
**Target:** <target_dir>  
**Repo type:** <repo_type>  
**Overall risk:** <risk_rating>

## Executive Summary

<Three sentences: what was reviewed, highest-risk result, and recommended next move.>

## Scope And Methodology

- Target: <target_dir>
- Mode: read-only static review unless live recon scope is explicitly listed
- Skills selected: <skills_to_run>
- Skills completed: <skills_completed>
- Skills failed or skipped: <skills_failed_or_skipped>
- Static limits: no target-code execution, no credential validation, no cloud/API verification unless separately authorized

## Risk Dashboard

| Severity | Count |
|---|---:|
| P0 | <p0_count> |
| P1 | <p1_count> |
| P2 | <p2_count> |
| P3 | <p3_count> |
| Informational | <informational_count> |
| Total | <total_count> |

## Top Findings

For each top finding:

```text
[<severity>] <title>
File: <file>:<line>
Category: <category>
Source skills: <source_skills>
Issue: <description>
Recommendation: <recommendation>
Effort: <effort>
```

## Per-Skill Detail

For each skill:

```text
### <skill name>

Status: <completed | failed | skipped>
Runtime: <duration>
Findings: <count>
Notes: <limits or failure reason>
```

## Deduplication Log

For each merge:

```text
- Result <finding_id>: merged <source ids>
  Reason: <primary key | overlapping range | same root cause>
  Source skills: <skills>
```

## Remediation Roadmap

### Immediate

P0/P1 findings that block release or require urgent rotation.

### Short Term

P1/P2 findings that should be fixed in the next normal cycle.

### Long Term

P2/P3 hardening, tests, automation, and defense-in-depth work.

## Compliance Mapping

| Finding | Severity | SOC-2 | PCI-DSS | ISO-27001 | HIPAA | Other |
|---|---|---|---|---|---|---|
| <id> | <severity> | <controls> | <controls> | <controls> | <controls> | <controls> |

## Appendix

### Dispatch Plan

<repo type, detected surfaces, selected skills, skipped optional skills>

### File Inventory

<inventory counts and skipped directories>

### Run Log

<skill run status, durations, failures, timeouts>

### Limitations

- Static review cannot prove deployed configuration, runtime secrets, secret validity, cloud drift, or registry reputation.
- Clean output means no findings against the selected control set, not proof that the system is secure.
- Any unrun, failed, or skipped specialist leaves explicit coverage gaps.
