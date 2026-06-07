---
name: hacker
description: Orchestrate a full security audit (defensive read-only review plus optional instruction-only offensive autoresearch) by discovering attack surface, dispatching specialist security skills, deduplicating findings, and producing one executive report. Use when the user asks for a full security audit, security posture assessment, hacker audit, pre-production security review, autoresearch security loop, multi-skill security review, or what is the security state of this codebase. Coordinates authz-security, crypto-secrets, ci-cd-security, supply-chain-security, infra-security, skill-security, recon-security when explicitly in scope, vulnerability-triage when an advisory is supplied, offensive-security when the user requests subagent-driven exploitability research, and vulnerability-triage again after offensive-security for false-positive/by-design review.
---

# Hacker

Hacker is the unified security orchestrator (formerly `security-suite`). It maps the target, runs defensive specialists, merges findings, and optionally chains `offensive-security` as an instruction-only subagent autoresearch loop.

**Defensive default:** read-only, offline, no source edits, no live exploit attempts, no credential validation against production.

**Offensive optional:** subagent-driven autoresearch only with explicit user request. The loop starts from deduplicated findings; when written validation scope is missing, continue under a local-only planning boundary and mark live checks `unsafe_to_test`.

## Workflow

Run the audit in seven phases. Phases 1–5 are defensive. **Phase 6 (`offensive-security`) starts after the defensive report and loops until its stop criteria are met. Phase 7 (`vulnerability-triage`) reviews offensive outcomes for false positives and by-design behavior.** Never run Phase 6 in parallel with Phase 2 specialists.

### Phase 1 - Discover the surface

```bash
python3 skills/hacker/scripts/discover.py <target-dir>
python3 skills/hacker/scripts/discover.py <target-dir> --domain example.com
python3 skills/hacker/scripts/discover.py <target-dir> --offensive
```

Record repo type, detected surfaces, `skills_to_run` (defensive only), `post_audit_skills` (offensive when `--offensive`), and `skipped_optional_skills`. Do not run `offensive-security` during Phase 2.

When `--offensive` is set, discovery also emits `post_audit_plan`: a machine-readable Phase 6 and Phase 7 handoff. It tells the parent agent to load `skills/offensive-security/SKILL.md` and `skills/offensive-security/references/autoresearch-loop.md` after the defensive report, run the autoresearch loop to completion, then load `vulnerability-triage` for false-positive/by-design review.

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

### Phase 6 - Offensive autoresearch (optional)

Run **after** Phases 3–5 complete. Requires explicit user request (e.g. validate exploitability, autoresearch attack loop, run offensive-security). Input is `deduped-findings.json` from Phase 3 — not raw scanner output.

Do not stop after one pass. Run rounds until no new high-confidence hypotheses remain, all remaining hypotheses are `false_positive`, `mitigated`, or `unsafe_to_test`, the configured round limit is reached, or the user interrupts.

If written scope or confirmed sandbox targets are missing, do not ask before starting the loop. Continue under a local-only planning boundary inferred from the findings. Generate hypotheses, validation plans, evidence requirements, likely false-positive reasons, and chains; classify live or external validation as `unsafe_to_test`.

`offensive-security` does not provide scripts. Use it as LLM instructions for coordinating subagents:

1. Load `skills/offensive-security/SKILL.md` and `references/autoresearch-loop.md`.
2. Launch parallel hypothesis-research subagents by finding family (infra, authz, crypto, CI/CD, supply chain, injection, chaining).
3. Use validation-planner subagents to design scoped sandbox checks and negative controls.
4. Use evidence-review subagents to classify evidence, missing prerequisites, and unsafe-to-test items.
5. Execute only scoped, non-destructive validation steps when a local sandbox or written scope exists.
6. Launch chain-research subagents from confirmed outcomes.
7. Launch one reformulation round for inconclusive outcomes when a safe next path exists.
8. Repeat until the loop stop criteria are met, then write the offensive autoresearch report.

Append confirmed vulnerabilities to the hacker report appendix or deliver as a separate artifact. If scope is missing or validation would require unsafe actions, record `unsafe_to_test` items in the appendix — do not probe production.

**Boundary:** `recon-security` = authorized live pentest. `offensive-security` = sandbox validation of static defensive findings.

### Phase 7 - False-positive triage (post-offensive)

Run **after** Phase 6 completes. Load `skills/vulnerability-triage/SKILL.md`, `references/severity-rubric.md`, and `references/triage-report-template.md`.

Use `vulnerability-triage` as a post-offensive review over the offensive report:

1. Re-check `confirmed`, `inconclusive`, `mitigated`, `false_positive`, and `unsafe_to_test` outcomes against project intent and threat model.
2. Run the privilege-context check: confirm the actor crosses a real boundary rather than performing an action their role is designed to perform.
3. Downgrade or mark By-Design / false positive when evidence does not show a real boundary crossing.
4. Emit false-positive tuning notes for the defensive source skill and include them in the final hacker summary.

Helper scripts cannot execute instruction-only skills. `scripts/orchestrator.py --offensive` carries the Phase 6/7 handoff forward as `post_audit_plan` and `offensive_followup`; the parent agent must load `offensive-security`, run the subagent loop to completion, then run post-offensive `vulnerability-triage`.

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

- `scripts/discover.py` — dispatch plan (`--offensive` sets `post_audit_skills`; offensive-security and post-offensive vulnerability-triage are never in `skills_to_run`)
- `scripts/deduplicator.py` — merge finding JSON
- `scripts/reporter.py` — markdown executive report
- `scripts/orchestrator.py` — discovery + merge helper (`--offensive`, `--scope` documented for agent follow-up)

## What this skill will not do

- Auto-run offensive validation on a default full audit
- Replace `recon-security` authorization for live targets
- Claim complete coverage if model-only skills were not run
- Hide failed or skipped specialists from the final report
