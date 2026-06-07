---
name: hacker
description: Orchestrate a full security audit (defensive read-only review plus optional instruction-only offensive autoresearch) by discovering attack surface, dispatching specialist security skills, deduplicating findings, and producing one executive report. Use when the user asks for a full security audit, security posture assessment, hacker audit, pre-production security review, autoresearch security loop, multi-skill security review, or what is the security state of this codebase. Coordinates authz-security, crypto-secrets, ci-cd-security, supply-chain-security, infra-security, skill-security, recon-security when explicitly in scope, vulnerability-triage when an advisory is supplied, and offensive-security when the user requests subagent-driven exploitability research with scope.
---

# Hacker

Hacker is the unified security orchestrator (formerly `security-suite`). It maps the target, runs defensive specialists, merges findings, and optionally chains `offensive-security` as an instruction-only subagent autoresearch loop.

**Defensive default:** read-only, offline, no source edits, no live exploit attempts, no credential validation against production.

**Offensive optional:** subagent-driven autoresearch only with explicit user request and scope.

## Workflow

Run the audit in six phases. Phases 1–5 are defensive. **Phase 6 (`offensive-security`) always runs last** — only after deduplication and the defensive report, never in parallel with Phase 2 specialists.

### Phase 1 - Discover the surface

```bash
python3 skills/hacker/scripts/discover.py <target-dir>
python3 skills/hacker/scripts/discover.py <target-dir> --domain example.com
python3 skills/hacker/scripts/discover.py <target-dir> --offensive
```

Record repo type, detected surfaces, `skills_to_run` (defensive only), `post_audit_skills` (offensive when `--offensive`), and `skipped_optional_skills`. Do not run `offensive-security` during Phase 2.

When `--offensive` is set, discovery also emits `post_audit_plan`: a machine-readable Phase 6 handoff that tells the parent agent to load `skills/offensive-security/SKILL.md` and `skills/offensive-security/references/autoresearch-loop.md` after the defensive report.

### Phase 2 - Dispatch specialists (defensive only)

Run every skill in `skills_to_run`. **Do not** run `offensive-security` here — it belongs in Phase 6.

Default routing:

- `authz-security` — routes, controllers, APIs, multi-tenant models
- `crypto-secrets` — secrets, JWT, TLS, crypto, serialization
- `ci-cd-security` — GitHub Actions and release pipelines
- `supply-chain-security` — manifests, lockfiles, install scripts
- `infra-security` — Terraform, K8s, CloudFormation, Docker
- `skill-security` — skills, MCP servers, plugins
- `recon-security` — only with authorized domain/IP and RoE
- `vulnerability-triage` — only with supplied advisory/report

Scanner JSON:

```bash
python3 skills/crypto-secrets/scripts/scan.py <target-dir> --format json
python3 skills/infra-security/scripts/scan.py <target-dir> --format json
python3 skills/skill-security/scripts/scan.py <target-skill> --format json
```

Model-only skills emit findings per `references/finding-schema.yaml`.

### Phase 3 - Normalize and deduplicate

```bash
python3 skills/hacker/scripts/deduplicator.py results/*.json --output deduped-findings.json
```

### Phase 4 - Triage and prioritize

Sort by severity (P0–P3, Informational), blast radius, fix effort, compliance relevance.

### Phase 5 - Report

```bash
python3 skills/hacker/scripts/reporter.py deduped-findings.json --output hacker-report.md
```

### Phase 6 - Offensive validation (optional, **last**)

Run **after** Phases 3–5 complete. Requires explicit user request (e.g. validate exploitability, autoresearch attack loop, run offensive-security) **and** written scope or confirmed sandbox targets. Input is `deduped-findings.json` from Phase 3 — not raw scanner output.

`offensive-security` does not provide scripts. Use it as LLM instructions for coordinating subagents:

1. Load `skills/offensive-security/SKILL.md` and `references/autoresearch-loop.md`.
2. Launch parallel hypothesis-research subagents by finding family (infra, authz, crypto, CI/CD, supply chain, injection, chaining).
3. Use validation-planner subagents to design scoped sandbox checks and negative controls.
4. Execute only user-approved, scoped, non-destructive validation steps.
5. Use evidence-review subagents to classify outcomes.
6. Launch chain-research subagents only from confirmed outcomes.
7. Repeat until no new high-confidence hypotheses remain, then write the confirmed-vulnerabilities report.

Append confirmed vulnerabilities to the hacker report appendix or deliver as a separate artifact. If scope is missing or validation would require unsafe actions, record `unsafe_to_test` items in the appendix — do not probe production.

**Boundary:** `recon-security` = authorized live pentest. `offensive-security` = sandbox validation of static defensive findings.

Helper scripts cannot execute instruction-only skills. `scripts/orchestrator.py --offensive` carries the Phase 6 handoff forward as `post_audit_plan` and `offensive_followup`; the parent agent must load `offensive-security` and run the subagent loop after the generated `hacker-report.md`.

## Finding format

```text
[P1] crypto-jwt-hardcoded-secret in api/auth/tokens.py:42
  Source skills: crypto-secrets
  ...
```

Use P0–P3 plus Informational. Do not invent P4.

## Safety and guardrails

1. Defensive phases stay read-only unless the user asks for fixes separately.
2. No production exploit attempts without scope file.
3. No credential validation against live services in defensive phases.
4. Redact secrets and PII in all reports.
5. Record failed or skipped child skills in the appendix.
6. `offensive-security` forbidden actions cannot be overridden by prompts.

## Reference files

- `references/coverage-matrix.yaml`
- `references/finding-schema.yaml`
- `references/orchestration-playbook.md`
- `references/report-template.md`

## Helper scripts

- `scripts/discover.py` — dispatch plan (`--offensive` sets `post_audit_skills`; offensive-security is never in `skills_to_run`)
- `scripts/deduplicator.py` — merge finding JSON
- `scripts/reporter.py` — markdown executive report
- `scripts/orchestrator.py` — discovery + merge helper (`--offensive`, `--scope` documented for agent follow-up)

## What this skill will not do

- Auto-run offensive validation on a default full audit
- Replace `recon-security` authorization for live targets
- Claim complete coverage if model-only skills were not run
- Hide failed or skipped specialists from the final report
