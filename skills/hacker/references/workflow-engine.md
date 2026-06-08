# Workflow Engine

Use this reference when `hacker` runs in `engagement` mode. It adapts the `offensive-claude` Kill Chain workflow to Cursor Agent Skills without slash commands, settings changes, or automatic tool execution.

## Operating model

The parent agent owns state, safety, and phase transitions. Subagents provide focused plans, reviews, and evidence analysis. External commands or browser actions are proposed only after the scope gate is satisfied.

```text
request
  -> choose preset and mode
  -> establish scope and RoE
  -> create phase artifacts
  -> run phase work with role subagents
  -> validate gate
  -> proceed, stop, or report blocked items
```

## State to track

Track state in the conversation or in a user-approved engagement directory:

- engagement name, client, preset, start date
- current phase and completed phases
- scope file or explicit authorization summary
- in-scope and out-of-scope targets
- allowed intensity and forbidden actions
- artifact list with `draft`, `in_progress`, `complete`, or `blocked`
- findings with severity, evidence, and outcome
- skipped tests and `unsafe_to_test` rationale

Do not create an engagement directory unless the user asks for persisted artifacts.

## Phase gate protocol

Before moving phases:

1. Read the preset phase requirements.
2. Check required artifacts exist or are represented in the conversation.
3. Confirm each artifact has enough content to support the next phase.
4. Re-check scope, allowed intensity, and forbidden actions.
5. Ask for missing authorization only when the next step would be active, invasive, credential-dependent, or state-changing.
6. If the gate fails, report missing items and safe next steps.

Gate failure is not an error. It is a control point.

## Phase behavior

### Phase 0 - Scope

Required before active work:

- authorization, ownership, or contract summary
- targets, test accounts, environments, and data boundaries
- allowed and forbidden techniques
- testing windows, rate limits, emergency contacts
- evidence handling and cleanup rules

If unclear, produce a scope template and stop before active actions.

### Phase 1 - Recon

Passive recon can be planned without live probing. Active recon requires scope.

Outputs:

- target inventory
- technology and service notes
- attack surface map
- assumptions and limitations
- leads for validation

### Phase 2 - Weaponize

Design safe proof strategies. Prefer minimal validation over exploit expansion.

When several exploit hypotheses need iterative testing, run the bounded autoresearch loop in `autoresearch-loop.md`. Ask the user for a cycle budget first so it never runs indefinitely, and re-check the gate each cycle.

Outputs:

- exploit hypothesis
- prerequisites
- allowed proof level
- negative control
- rollback or cleanup plan

### Phase 3 - Delivery

Use only delivery paths allowed by RoE. If social engineering, client-side payloads, or external delivery are not explicitly allowed, mark the phase `blocked` or `skipped`.

Outputs:

- delivery method
- target boundary
- expected evidence
- operator approval point

### Phase 4 - Exploit

Validate findings with the least invasive proof. Do not dump data, brute force credentials, degrade service, or expand access beyond scope.

To iterate across multiple findings or chained hypotheses, drive validation with the bounded autoresearch loop in `autoresearch-loop.md`, using the same upfront cycle-budget question and per-cycle gate re-check.

Outputs:

- finding record
- redacted evidence
- negative control
- impact statement
- remediation and verification

### Phase 5 - Install

Persistence is skipped unless explicitly authorized. If authorized, require a cleanup plan before any persistence test is proposed.

### Phase 6 - C2

C2 is skipped unless explicitly authorized. If authorized, document callback boundaries, infrastructure ownership, logging, detection coordination, and teardown.

### Phase 7 - Actions

Objectives, lateral movement, or collection require explicit RoE. Simulate impact when possible instead of accessing real data.

### Phase 8 - Report

Report confirmed findings, inconclusive items, unsafe-to-test items, false positives, and limitations. Include remediation priorities and validation steps.

## Stop conditions

Stop or pause when:

- scope is missing for the requested action
- the next action is destructive, high-volume, evasive, or credential-dependent
- evidence would expose secrets, PII, or customer data
- a subagent identifies an unapproved escalation path
- the user interrupts or changes scope
- the phase gate cannot pass without user input

## Artifact status

Use these statuses in templates:

- `draft`: scaffold exists, not enough detail yet
- `in_progress`: partially filled and usable for planning
- `complete`: gate-ready
- `blocked`: missing scope, data, access, or approval
- `skipped`: intentionally omitted by preset or RoE

## Findings quality bar

A finding is `confirmed` only when:

- it stays inside scope
- success criteria are met
- evidence is reproducible and redacted
- a negative control or compensating-control check exists where practical
- impact is explained without overstating blast radius

Otherwise classify as `inconclusive`, `mitigated`, `false_positive`, or `unsafe_to_test`.
