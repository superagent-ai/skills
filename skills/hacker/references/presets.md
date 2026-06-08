# Presets

Use presets to choose a proportional workflow. Presets do not grant permission. Scope and RoE still control what can be planned, proposed, or executed.

## Preset summary

| Preset | Phases | Use case |
|---|---|---|
| `web-app` | scope, recon, weaponize, delivery, exploit, report | OWASP-style web app and API assessment |
| `network` | scope, recon, weaponize, exploit, install, C2, actions, report | Internal network pentest with explicit RoE |
| `red-team` | all phases | Full adversary simulation with mature authorization |
| `cloud` | scope, recon, exploit, report | AWS, Azure, GCP, Kubernetes, and IaC offensive review |
| `mobile` | scope, recon, weaponize, exploit, report | Android or iOS application assessment |
| `ad-domain` | scope, recon, weaponize, exploit, install, actions, report | Active Directory domain assessment |
| `bug-bounty` | scope, recon, exploit, report | Bug bounty or vulnerability hunting within program rules |
| `validate-findings` | ingest, hypothesize, validate, evolve, report | Exploitability validation from defensive findings |

## Web app

Use for web apps, APIs, GraphQL, auth flows, multi-tenant features, and business logic.

Required artifacts:

- scope definition
- recon plan
- attack surface
- exploit blueprint
- finding record
- technical report

Common role subagents:

- `redteam-planner` for test strategy
- `network-analyst` for exposed services and proxy evidence
- `exploit-researcher` for validation plans
- `security-reviewer` for finding quality

Allowed active work depends on RoE. Default to low-rate probes, two-account authorization checks, manual request review, and non-destructive validation.

## Network

Use for authorized internal network testing. Skip install, C2, or actions unless the contract explicitly allows them.

Required artifacts:

- scope definition with network ranges
- recon plan
- attack surface
- exploit blueprint
- cleanup plan for any post-exploitation simulation
- technical report

Common role subagents:

- `network-analyst`
- `redteam-planner`
- `security-reviewer`

Default limitations:

- no credential spraying or brute force
- no lateral movement without written RoE
- no data access beyond approved proof
- no persistence without cleanup plan and explicit approval

## Red team

Use only when the user has a full adversary simulation scope. This preset touches every phase and requires the most explicit guardrails.

Required artifacts:

- scope definition
- emergency contact
- OPSEC checklist
- attack plan
- delivery plan
- C2 plan, if allowed
- objectives plan
- cleanup plan
- executive and technical reports

Default limitations:

- social engineering is out of scope unless separately authorized
- stealth, persistence, and C2 are planning-only unless explicitly allowed
- objectives should prefer simulated impact over real data access

## Cloud

Use for AWS, Azure, GCP, Kubernetes, containers, and IaC-backed environments.

Required artifacts:

- cloud scope and account/project/subscription boundary
- identity and privilege map
- exposed services and storage inventory
- finding records
- remediation roadmap

Default limitations:

- no privilege changes in production
- no secret use against live services without approval
- no data listing beyond approved metadata
- validate with read-only APIs or local IaC where possible

## Mobile

Use for Android and iOS apps, APIs backing mobile apps, mobile auth, transport security, and local storage.

Required artifacts:

- app and backend scope
- test device or emulator boundary
- recon plan
- exploit blueprint
- finding record

Default limitations:

- no bypass of third-party services outside scope
- no collection of real user data
- dynamic instrumentation must stay on owned test devices or approved labs

## AD domain

Use for authorized Active Directory assessments.

Required artifacts:

- domain and OU scope
- test credentials and privilege boundaries
- recon plan
- attack path map
- cleanup plan
- report

Default limitations:

- no password spraying, hash cracking, ticket abuse, or delegation changes unless explicitly allowed
- no domain persistence unless the contract names the simulation
- prefer graph analysis and lab reproduction before live validation

## Bug bounty

Use for public programs or private bounty scopes. Program rules are the RoE.

Required artifacts:

- program scope and rules
- target list
- validation notes
- finding record ready for submission

Default limitations:

- no testing outside the program scope
- no social engineering
- no DoS
- no data exfiltration beyond minimum proof

## Validate findings

Use when defensive findings need exploitability validation.

Inputs:

- `deduped-findings.json`, an audit report, or a normalized findings list
- optional written scope or sandbox fixture

Outputs:

- hypothesis inventory
- validation plan
- evidence review
- confirmed-vulnerabilities report
- false-positive tuning notes

See `autoresearch-loop.md`.
