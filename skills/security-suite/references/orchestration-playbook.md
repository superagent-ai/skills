# Security Suite Orchestration Playbook

Use this playbook when `security-suite` needs more detail than the main `SKILL.md` should carry.

## Phase 1 - Discovery

Inputs:

- target directory or file
- optional live domain/IP scope
- optional advisory/report input
- optional user constraints such as passive-only, PR-only, or compliance focus

Outputs:

- repo type and confidence
- detected surfaces, languages, frameworks, and inventory counts
- selected specialist skills
- skipped optional skills and reasons

Success criteria:

- Dispatch is deterministic from the target tree plus explicit user inputs.
- `recon-security` is selected only when live scope and authorization are explicit.
- `vulnerability-triage` is selected only when a report/advisory is supplied.

## Phase 2 - Dispatch

Run specialists in read-only mode. The suite may use subagents for parallelism, but each child result must return either normalized findings or a clean-scan statement plus limits.

Suggested parallel groups:

- Group A: `authz-security`, `crypto-secrets`, `supply-chain-security`
- Group B: `ci-cd-security`
- Group C: `infra-security`, `skill-security`
- Group D: `recon-security`, only after scope/RoE is established
- Group E: `vulnerability-triage`, only for supplied reports/advisories

Timeout guidance:

- Small repo: 5 minutes per skill
- Medium repo: 10 minutes per skill
- Large monorepo: 20 minutes per skill, or split by package/app

Failure handling:

| Skill | Failure response |
|---|---|
| `authz-security` | Continue. Mark authorization coverage incomplete for application code. |
| `crypto-secrets` | Continue only if model manually reviews key security paths; otherwise mark secrets/crypto coverage incomplete. |
| `ci-cd-security` | Continue. Mark CI/CD coverage incomplete. |
| `supply-chain-security` | Continue. Mark dependency coverage incomplete. |
| `infra-security` | Continue. Mark IaC coverage incomplete. |
| `skill-security` | Continue. Mark agent/plugin coverage incomplete. |
| `recon-security` | Continue. Mark external attack-surface coverage incomplete. |
| `vulnerability-triage` | Continue. Mark report triage incomplete. |

No single specialist failure should abort the suite unless the user asked for strict all-skills coverage.

## Phase 3 - Normalize And Deduplicate

Normalize every finding to `references/finding-schema.yaml`.

Primary merge:

- Same `file`, same `line`, same `rule_id`.
- Keep the highest severity.
- Union `source_skill`.
- Merge rationale and recommendations only when they add distinct context.

Secondary merge:

- Same `file`, same `category`, overlapping or nearby line ranges.
- Use when two skills describe the same underlying weakness with different rule ids.
- Mark the result as compound and keep all original rule ids.

Examples:

Single finding found by two skills:

```text
crypto-secrets: [P1] jwt-hardcoded-secret in api/auth.py:41
authz-security: [P2] token-forgery-risk in api/auth.py:41

Result: [P1] jwt-hardcoded-secret in api/auth.py:41
Sources: crypto-secrets, authz-security
Merge reason: same file, line, and token-forgery root cause.
```

Compound finding:

```text
ci-cd-security: [P1] workflow-token-write in .github/workflows/release.yml:8
supply-chain-security: [P1] install-scripts-run-with-publish-token in .github/workflows/release.yml:34

Result: [P1] release-pipeline-secret-exposure in .github/workflows/release.yml:8-34
Sources: ci-cd-security, supply-chain-security
Merge reason: both findings describe publish-token exposure in the same workflow.
```

## Phase 4 - Severity And Business Context

Use P0-P3 plus Informational.

Severity upgrades:

- Authentication, authorization, login, session, token, payment, billing, checkout, release, deploy, public API, or shared library paths: upgrade one tier when the exploit path is plausible.
- Finding appears in both application code and CI/CD or release infrastructure: upgrade P2 to P1.
- Finding enables credential exposure plus code execution or publish/deploy authority: upgrade to P0 when reachable now.

Severity reducers:

- Test, fixture, example, demo, docs, sample, or tutorial path: downgrade one tier unless wired into production.
- Pure placeholder value with no production path: Informational.
- Admin-only route with visible strong role/MFA controls: downgrade one tier, floor P3.
- Feature-flagged beta code not deployed: downgrade one tier when the flag boundary is visible.

Path patterns:

```text
Boosters: auth/, login/, session/, token/, payment/, billing/, checkout/, admin/, api/, routes/, controllers/, release, deploy
Reducers: test/, tests/, spec/, fixtures/, example/, examples/, demo/, docs/, samples/
```

## Phase 5 - Report

The report is the deliverable. It should be useful to an executive, an engineering owner, and an auditor.

Required sections:

- Executive summary
- Scope and methodology
- Risk dashboard
- Top findings
- Per-skill detail
- Deduplication log
- Remediation roadmap
- Compliance mapping
- Appendix with run log, inventory, skipped files, and limitations

Clean report rule:

If no findings remain after confirmation, say "No findings against the selected security-suite control set." Also state which skills ran and what static analysis cannot prove.

## CI Integration

The helper CLI can be used after skill outputs are collected:

```bash
python3 skills/security-suite/scripts/orchestrator.py . \
  --findings results/crypto.json results/infra.json \
  --output security-suite-report.md \
  --strict
```

Strict mode should fail when P0 or P1 findings remain. It should not claim model-only skills were run unless their result files are present.

## Performance Guidelines

- Skip dependency/build directories by default: `.git`, `node_modules`, `vendor`, `.venv`, `dist`, `build`, `coverage`, `.terraform`, `target`.
- On repositories over 100k files, split by app/package and run specialist reviews per slice.
- Scanner-backed skills are high-recall candidates. Model confirmation is still required before final severity.
- Preserve failed/skipped skill status instead of rerunning indefinitely.
