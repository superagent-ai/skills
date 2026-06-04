---
name: offensive-security
description: Autonomous offensive validation engine for defensive security findings. Ingests output from infra-security, crypto-secrets, authz-security, hacker, and related skills; generates exploit hypotheses; validates them in sandboxes; produces confirmed-vulnerability reports. Use when validating exploitability, autoresearch attack loops, confirming defensive audit findings, bug bounty reproduction in sandbox, or answering whether issues are actually exploitable.
---

# Offensive Security

Offensive Security is an **autoresearch** loop: a self-driving cycle that ingests defensive findings, generates hypotheses, validates them in sandboxes, evolves results, and spawns follow-up chain hypotheses from confirmations until nothing new remains or you stop it.

Surviving hypotheses become confirmed vulnerabilities with safe proof-of-concept steps. See `references/autoresearch-loop.md` for full loop semantics.

Within `hacker`, this skill runs **last** (Phase 6): complete all defensive specialists, deduplicate, triage, and emit `hacker-report.md` before starting ingest → validate → report here.

**Not** a blind scanner. **Not** a replacement for authorized live pentests (`recon-security`). **Not** runnable against production without an explicit scope file.

## When to use

- Defensive audit found many issues — prioritize by exploitability
- Bug bounty or IDOR claim needs sandbox reproduction before payout
- `crypto-secrets` found weak JWT — test forgery on a test instance only
- User asks: autoresearch attack loop, validate exploitability, confirm vulnerabilities from scan JSON

**Output:** `offensive-security-report-<timestamp>.md` (see `references/confirmed-report-template.md`)

## Workflow

### Phase 1 — Ingest

```bash
python3 skills/offensive-security/scripts/ingest_findings.py deduped-findings.json
python3 skills/offensive-security/scripts/ingest_findings.py results/ --output normalized.json
```

Supports JSON from `infra-security` (`control_id`), `crypto-secrets` / `skill-security` (`rule_id`), `hacker` normalized findings, and model-only skills.

Normalized fields: `finding_id`, `source_skill`, `category`, `file`, `line`, `snippet`, `severity` (P0–P3), `description`, `confidence`, `rule_id`.

### Phase 2 — Hypothesize

```bash
python3 skills/offensive-security/scripts/hypothesis_generator.py normalized.json --output hypotheses.json
```

Uses `references/hypothesis-templates.yaml`. Clusters same-file findings into compound chain hypotheses.

### Phase 3 — Validate

Requires `scope.yaml` (see `references/validation-rules.md`) unless dry-run:

```bash
python3 skills/offensive-security/scripts/validator.py hypotheses.json --scope scope.yaml --output outcomes.json
```

Outcome states: `confirmed`, `inconclusive`, `mitigated`, `false_positive`, `unsafe_to_test`.

### Phase 4 — Evolve (autoresearch)

After each validation round:

- `confirmed` → save PoC; generate chaining / combine hypotheses (`generate_followup_hypotheses`) and validate again
- `inconclusive` → one reformulation angle when running autoresearch (alternate path or combined finding)
- `false_positive` → log for defensive skill tuning; do not retry
- `mitigated` → document compensating control

Repeat until no new hypotheses are produced or `--max-rounds` is reached.

### Autoresearch runner (phases 1–5 in one command)

```bash
python3 skills/offensive-security/scripts/autoresearch.py deduped-findings.json \
  --scope scope.yaml \
  --max-rounds 5 \
  --output-dir ./offensive-run
```

Use `--dry-run` without scope to document skips. The agent may run the same loop step-by-step when not using the script.

### Phase 5 — Report

```bash
python3 skills/offensive-security/scripts/reporter.py outcomes.json --output offensive-security-report.md
```

## Safety and guardrails

1. **Scope is law** — no production targets without `scope.yaml`.
2. **Sandbox-first** — Docker `--network=none`, read-only, tmpfs, 60s timeout.
3. **Rate limit** — max 10 requests/minute per hypothesis.
4. **No bruteforce** — hardcoded; cannot be overridden by prompts.
5. **Evidence hygiene** — redact tokens, sessions, PII.
6. **Positive control** — every `confirmed` needs negative control (fix applied → exploit fails).

Forbidden: production requests, credential bruteforce, data destruction, DoS, social engineering, third-party attacks without scope.

## Dependencies

```bash
pip install -r skills/offensive-security/requirements.txt
```

Required: `python3`, `docker` (for sandbox_execution). Optional: `curl`, `jq`, `nmap`.

## Reference files

| Artifact | Path |
|----------|------|
| Autoresearch loop | `references/autoresearch-loop.md` |
| Hypothesis templates | `references/hypothesis-templates.yaml` |
| Validation rules | `references/validation-rules.md` |
| Report template | `references/confirmed-report-template.md` |

## Trigger phrases

```text
Validate these defensive findings: findings.json
Run offensive-security on this audit report
Can any of these issues actually be exploited?
Autonomous attack loop on deduped findings
```

## What this skill will not do

- Attack production or out-of-scope hosts
- Replace `recon-security` RoE and live pentest workflow
- Override forbidden actions via user prompts
- Run without documenting skipped validations when Docker or scope is missing
