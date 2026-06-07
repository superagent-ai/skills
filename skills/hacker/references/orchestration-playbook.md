# Hacker Orchestration Playbook

Use this playbook when `hacker` needs more detail than the main `SKILL.md` should carry.

## Phase 1 - Discovery

Inputs:

- target directory or file
- optional live domain/IP scope
- optional advisory/report input
- optional `--offensive` flag or explicit user request for exploit validation
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
- `offensive-security` appears in `post_audit_skills` only with `--offensive` or explicit user request; never in `skills_to_run` and never during Phase 2.
- When `offensive-security` is selected, discovery emits `post_audit_plan` with the exact skill files, loop controls, and Phase 6 agent action.
- `vulnerability-triage` appears in `post_audit_skills` after `offensive-security` for false-positive/by-design review of offensive outcomes.

## Phase 2 - Dispatch (defensive specialists only)

Run every skill in `skills_to_run` in read-only mode. **Exclude `offensive-security`** — it runs last in Phase 6.

The suite may use subagents for parallelism, but each child result must return either normalized findings or a clean-scan statement plus limits.

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
| `offensive-security` | Continue defensive report. Note offensive phase skipped in appendix. |

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

If no findings remain after confirmation, say "No findings against the selected hacker control set." Also state which skills ran and what static analysis cannot prove.

## Phase 6 - Offensive Autoresearch (optional)

Run **after** Phases 3, 4, and 5 — when `post_audit_skills` includes `offensive-security` and the user requests exploit validation/autoresearch. Use `deduped-findings.json` from Phase 3, not pre-dedupe scanner JSON.

`offensive-security` is an instruction-only skill. It ships no scanners, validator scripts, or exploit runners. The parent agent loads `skills/offensive-security/SKILL.md` and coordinates subagents through the autoresearch loop.

The helper scripts do not run instruction-only skills. `discover.py --offensive` emits a `post_audit_plan`, and `orchestrator.py --offensive` carries that into `offensive_followup` so the parent agent has an explicit Phase 6/7 handoff after the defensive report.

Missing written scope does not stop Phase 6. The parent agent should infer a local-only planning boundary from the findings, continue generating hypotheses and validation plans, and classify live/external validation as `unsafe_to_test`.

Steps:

1. Load `skills/offensive-security/SKILL.md` and `references/autoresearch-loop.md`.
2. Split deduped findings by family: infra/IAM, authz, crypto/secrets, CI/CD, supply chain, injection/deserialization, and chaining.
3. Launch parallel hypothesis-research subagents for independent families.
4. Deduplicate and rank hypotheses.
5. Launch validation-planner subagents for top hypotheses.
6. Launch evidence-review subagents to classify evidence, missing prerequisites, and unsafe-to-test items.
7. Execute only scoped, non-destructive sandbox checks when a local sandbox or written scope exists.
8. Launch chain-research subagents from confirmed outcomes.
9. Launch one reformulation round for inconclusive outcomes when a safe next path exists.
10. Repeat until no new high-confidence hypotheses remain, all remaining hypotheses are `false_positive`, `mitigated`, or `unsafe_to_test`, the round limit is reached, or the user stops the loop.
11. Write an offensive autoresearch report.

Default round limit: 3. Increase only when the user explicitly asks for a longer autonomous run.

Failure handling:

| Condition | Response |
|---|---|
| No scope or unclear authorization | Continue the loop under a local-only planning boundary; mark live/external validation `unsafe_to_test`; do not probe |
| Validation requires forbidden action | Reject it and document rationale |
| Subagent disagrees on evidence | Keep `inconclusive` unless success and negative-control evidence are clear |
| User interrupts loop | Stop, summarize completed rounds, and report residual hypotheses |

Do not merge confirmed offensive findings into executive risk rating without explicit user approval; prefer a separate offensive report section.

## Phase 7 - Post-Offensive False-Positive Triage

Run **after** Phase 6. This is a second use of `vulnerability-triage`, not the optional inbound advisory triage from Phase 2.

Steps:

1. Load `skills/vulnerability-triage/SKILL.md`, `references/severity-rubric.md`, and `references/triage-report-template.md`.
2. Treat the offensive autoresearch report as the submission to triage.
3. Review `confirmed`, `inconclusive`, `mitigated`, `false_positive`, and `unsafe_to_test` outcomes.
4. Run the privilege-context check for each confirmed or likely finding.
5. Downgrade By-Design or false-positive cases before the final hacker summary.
6. Produce false-positive tuning notes for the source defensive skill.
7. Append a post-offensive triage summary to the final report.

## CI Integration

The helper CLI can be used after skill outputs are collected:

```bash
python3 skills/hacker/scripts/orchestrator.py . \
  --findings results/crypto.json results/infra.json \
  --output hacker-report.md \
  --strict
```

Offensive follow-up (agent-run, not orchestrator-built-in):

```bash
python3 skills/hacker/scripts/discover.py . --offensive
```

Then load `skills/offensive-security/SKILL.md` and run the subagent autoresearch loop using the deduped findings. After the loop completes, load `skills/vulnerability-triage/SKILL.md` and run the post-offensive false-positive review.

If you use `orchestrator.py --offensive --scope <scope> --deduped-output deduped-findings.json --output hacker-report.md`, inspect the JSON `offensive_followup.status`. `ready_for_phase6` means load `offensive-security` and run the multi-round loop. Without `--scope`, use `offensive_followup.validation_boundary` and continue under the local-only planning boundary.

Strict mode should fail when P0 or P1 findings remain. It should not claim model-only skills were run unless their result files are present.

## Performance Guidelines

- Skip dependency/build directories by default: `.git`, `node_modules`, `vendor`, `.venv`, `dist`, `build`, `coverage`, `.terraform`, `target`.
- On repositories over 100k files, split by app/package and run specialist reviews per slice.
- Scanner-backed skills are high-recall candidates. Model confirmation is still required before final severity.
- Preserve failed/skipped skill status instead of rerunning indefinitely.
