# Security Skills

Security skills for AI coding agents — distilled from real security work on codebases that serve 100M+ users a week.

Each skill ships in the open [Agent Skills](https://agentskills.io/) format and loads automatically when the agent hits a relevant task. They turn the model itself into the auditor: encoded rules and offline scanners, not another service to wire up.

## Skills

<details>
<summary><b>superagent</b>: configure and safely operate Superagent over MCP</summary>

Use it when you want to connect Cursor, Claude Code, Codex CLI, or another MCP client to Superagent, troubleshoot the connection, inspect findings and reports, scan context, check Contributor Trust, or manage Runtime Guardrails.

This is an explicit, opt-in remote integration. It never connects, sends data, changes MCP configuration, spends organization credits, deletes findings, or changes endpoint policy without the user's request and the required confirmation. API keys stay in environment variables rather than tracked configuration.

```
Connect Cursor to the Superagent MCP server
List my unresolved high-risk Superagent findings
Scan this skill with Superagent Context Guardrails
Troubleshoot a 401 from the Superagent MCP server
```

</details>

<details>
<summary><b>hacker</b>: offensive engagement and exploitability validation</summary>

Use it when you need an authorized offensive workflow for scoped web, network, cloud, mobile, Active Directory, bug bounty, or red-team engagement planning with phase gates, role handoffs, templates, and reports. Use `validate-findings` mode when defensive audits found issues and you need to know which are actually exploitable.

It is **instruction-only**: it ships no scanners, validators, payload builders, exploit runners, or local scripts. In `engagement` mode, it routes through Kill Chain style phases with scope gates and role-based subagent handoffs. In `validate-findings` mode, it ingests defensive JSON, then runs a bounded background autoresearch loop — hypothesize, experiment, observe, refine — for a user-defined number of cycles (it asks up front, so it never runs indefinitely), chaining confirmations and reformulating inconclusive paths on each pass.

Requires explicit written scope for live validation. Never attacks production by default. Without written scope, it stays in planning or local-only validation and marks live checks `unsafe_to_test`. `recon-security` remains the focused external recon/pentest workflow; `hacker` is the broader offensive engagement orchestrator.

```
Run a hacker web-app engagement for this scoped lab
Plan a red-team workflow with phase gates and templates
Validate these defensive findings: deduped-findings.json
Can any of these issues actually be exploited?
Autonomous attack loop on deduped findings with subagents
```

</details>

<details>
<summary><b>redteam-autoresearch</b>: generate LLM guardrail training data via a bounded red-team loop</summary>

Use it when you need to red-team an LLM and turn the results into a dataset — stress-testing a model for harmful content, jailbreaks, prompt injection, or backdoor/trigger behavior, and capturing every attempt as labeled JSONL for fine-tuning guardrails.

**You (the agent running the skill) are the attacker and the judge** — you craft the attacks and label every response. The only model the harness calls is the **target** under test, over any OpenAI-compatible API: OpenRouter, Moonshot/Kimi, Fireworks, Ubicloud, OpenAI, or a custom endpoint with its key in `.red-team/.env`. Model IDs are provider-specific, so copy them from the provider catalog. The loop is bounded and gated like `hacker`'s, with the `confirmed`/`mitigated`/`inconclusive`/`false_positive`/`unsafe_to_test` outcome taxonomy. A thin harness queries the target and records your judgments; every attempt (pass and fail) is saved under an isolated `.red-team/runs/<run_id>/` directory, and refusals become the `safe` negatives a guardrail needs. An exporter converts the log to Llama Guard (S1–S14) and chat-classification training formats.

It is authorization-first and local-only: run it against models you are authorized to test, and keep generated content local for guardrail training. It complements `hacker` (code/infra exploitability) by targeting model behavior and producing data.

```
Red-team this model for jailbreaks and prompt injection and build a dataset
Generate guardrail training data across harmful content, jailbreaks, backdoors
Run a bounded red-team autoresearch loop for N rounds against a Kimi, Nemotron, or OpenRouter model
Mine novel jailbreaks at scale and export Llama Guard training JSONL
```

</details>

<details>
<summary><b>ci-cd-security</b>: supply-chain and pwn-request bugs in GitHub Actions</summary>

Use it when you're reviewing `.github/workflows/`, hardening a release pipeline, or chasing `pull_request_target`, template injection, action pinning, or cache poisoning.

Every finding comes with a severity (P0–P3) and a concrete rewrite. It catches:

- Dangerous triggers — `pull_request_target`, `workflow_run`
- Over-broad `GITHUB_TOKEN` permissions
- Mutable action pins (tags/branches instead of a SHA)
- Shell/template injection in `run:` blocks
- Untrusted checkout, cache poisoning, artifact-borne injection
- Release hardening (OIDC, environments, provenance) and self-hosted runner risk

Rules track the consensus from Astral, OpenSSF, GitHub Security Lab, Chainguard, and zizmor — without running any of them.

```
Review this GitHub Actions workflow for security issues
Check .github/workflows/ci.yml for pull_request_target vulnerabilities
Audit our release workflow for cache poisoning risks
```

</details>

<details>
<summary><b>repo-security-posture</b>: GitHub repository hardening and maintainer-facing security todos</summary>

Use it when you're reviewing or hardening a GitHub repository's security posture — branch protection, CODEOWNERS, GitHub Actions, publish/release integrity, collaborator access, security features, and dependency review.

It collects read-only GitHub configuration and repository files into a JSON inventory, marks admin-gated settings as `not_verified` instead of guessing, then produces a prioritized maintainer todo list grouped by:

- Publish & release integrity
- Branch & merge protection
- Sensitive-path ownership
- CI/CD workflow hardening
- Account & access control
- Dependency & supply-chain review

```
Audit this GitHub repo's security posture: https://github.com/org/repo
Harden this repo against a compromised maintainer
Review branch protection, CODEOWNERS, and Actions security for owner/name
What should we fix first in this repo's GitHub security settings?
```

</details>

<details>
<summary><b>skill-security</b>: answer "is this skill safe to install?"</summary>

Use it before you install or trust a skill, plugin, `SKILL.md`, or agent tool — a local folder, a `.zip`/`.skill`, or a cloned repo.

It runs in two stages. First, a deterministic, offline scanner (`scripts/scan.py` — regex, Python AST, source-to-sink taint tracking, YARA signatures) does the high-recall pass and scores the skill 0–100. Then the model judges intent and runs the contract check: does what the skill *claims* to do match what its code *actually* does? It catches:

- Prompt injection and audit-manipulation attempts
- Credential/secret exfiltration and outbound data theft
- Persistence and agent-memory poisoning
- Malicious code, webshells, cryptominers (YARA)
- Supply-chain and dependency risk
- Description-vs-behavior mismatch

```
Is this skill safe to install? ~/Downloads/some-skill.zip
Audit ./vendor/skill-foo/SKILL.md for prompt injection or credential theft
```

</details>

<details>
<summary><b>authz-security</b>: broken access control (IDOR/BOLA) in your application code</summary>

Use it when you're reviewing routes, controllers, or resolvers, auditing a PR that adds or changes endpoints, or hardening a multi-tenant SaaS — anywhere you need to answer "can one user reach another user's data?"

It reads your source offline — routes, handlers, and data models — and reports the missing ownership or role check at `file:line` with a framework-correct fix. No running app, no credentials, no tools. Every finding comes with a severity (P0–P3) and a concrete rewrite. It catches:

- Object-level gaps — IDOR / Broken Object Level Authorization (OWASP API1): objects loaded by id with no owner scoping
- Function-level gaps — Broken Function Level Authorization (OWASP API5): privileged actions behind authentication but no role check
- Mass assignment (OWASP API3) — request bodies that can set `role`/`owner_id`/`tenant_id`
- Multi-tenant isolation leaks — unscoped collection and list endpoints
- Identity trusted from client input, and authentication mistaken for authorization

Rules encode OWASP's #1 web risk (A01) and top two API risks, applied as a source-code read rather than a live pentest — the defensive complement to a dynamic BOLA tester.

```
Review this endpoint for broken access control / IDOR
Can a user access another user's data through this controller?
Audit our multi-tenant API for BOLA and missing authorization
```

</details>

<details>
<summary><b>recon-security</b>: external pentest workflow with free/open-source tools</summary>

Use it when you're running an authorized external pentest: recon, validation, scoped exploitation, and reporting on domains, IPs, web apps, TLS, SIP/VoIP, or exposed storage — without commercial APIs.

It guides the agent end to end: scope/RoE, passive recon, normalization, active scanning, web and infrastructure checks, triage, manual validation (Burp/ZAP), scoped exploitation when approved, and final reporting. No bundled scripts — the model proposes commands and checklists; the user runs tools locally. It covers:

- Recon: DNS, WHOIS/RDAP, RIPEstat, CT, `subfinder`, `amass`, `gau`, `waybackurls`, `httpx`, `nmap`, `nuclei`
- Web: `ffuf`, `arjun`, `sqlmap` detection mode, `dalfox`, misconfiguration checks
- Infra: SIP/VoIP and NAS/SMB/NFS exposure checks when in scope
- Validation and PoC bar; exploitation boundaries in `references/exploitation-roe.md`
- Pairing with `authz-security` for IDOR/BOLA when source or two-account testing is available

```
Plan a full external pentest for example.com with free tools only
Run validation on these nuclei findings before we report
What exploitation is allowed under our RoE for this SQLi lead?
Give me passive recon commands for example.com and where to save evidence
```

</details>

<details>
<summary><b>supply-chain-security</b>: malicious or compromised dependencies before they land</summary>

Use it when you're adding or upgrading a dependency, reviewing a PR that changes `package.json`, `requirements.txt`, `go.mod`, or a lockfile, or deciding whether a package is safe to install — anywhere you need to answer "is this dependency safe to add?"

It reads your manifests, lockfiles, install scripts, and dependency diffs offline — across npm/pnpm/yarn, PyPI, Go, Cargo, RubyGems, Maven/Gradle, NuGet, and Composer — and reports each risk at `file:line` with a concrete fix. No install, no execution, no phoning home. Every finding comes with a severity (P0–P3). It catches:

- Malicious install scripts — `preinstall`/`postinstall` hooks that harvest and exfiltrate secrets (the Shai-Hulud and nx `s1ngularity` worm pattern), and **`binding.gyp`/`node-gyp` execution** that bypasses lifecycle-script scanners (June 2026 worm)
- Obfuscated payloads, credential harvesting, exfiltration, persistence, and worm self-propagation
- Typosquatting and slopsquatting (AI-hallucinated package names) of real dependencies
- Dependency / namespace confusion — unscoped internal names a public registry can hijack
- Maintainer account takeover, and version hygiene gaps (floating ranges, missing lockfile/integrity, no cooldown or provenance)

Rules track the consensus from OpenSSF, OSV, Socket, Datadog, and the 2025 npm worm post-mortems — applied as a pre-install source read, the defensive complement to a continuous SCA scanner.

```
Is this dependency safe to add?
Review this PR's package.json and lockfile changes for supply-chain risks
Check this package's postinstall script for Shai-Hulud / credential theft
```

</details>

<details>
<summary><b>security-disclosure-triage</b>: reporter-side advisory verification before disclosure</summary>

Use it when a researcher-side advisory, GHSA, scanner finding, or draft report needs an honest "is this worth disclosing?" decision against a target checkout.

It optimizes against false confirmations and inflated severity. The skill requires the agent to reproduce the implicated construct, trace the real asset guard, build a usable exploit path, check intended behavior and trust boundaries, ground the finding in shipped state, and run an adversary pass before recommending disclosure. It emits both `TRIAGE_REPORT.md` and `triage-result.json` using the reporter-side disposition taxonomy.

```
Verify this advisory before disclosure
Triage this scanner finding against the checked-out repository
Is this GHSA worth disclosing or by-design/operator responsibility?
```

</details>

<details>
<summary><b>vulnerability-triage</b>: is this advisory a real finding, by-design, or noise?</summary>

Use it when a GitHub Advisory (GHSA/CVE) lands against a dependency, a bug bounty or HackerOne/Bugcrowd/Intigriti report hits your inbox, or a researcher files an issue — anywhere you need to answer "is this real, by-design, or noise?"

It reads the report offline, cross-references the project's documented intent — `SECURITY.md`, README, code comments, closed issues, changelog — statically audits any PoC without executing it, and emits a structured markdown triage report. No Docker, no network, no PoC execution. Every verdict comes with a severity (P0–P3 / Informational / By-Design) and a recommended action. It catches:

- By-design behavior dressed up as a vuln — CORS preflight, documented rate limits, intentional public assets, debug verbosity, admin-only features
- Unreproduced or theoretical claims — gated to Informational until a PoC is confirmed
- Reporter severity inflation — scored independently from reproduced evidence
- Verdict-steering and prompt-injection attempts inside the report itself
- The real-bug twin of each by-design pattern, so genuine findings aren't waved through

Reproduction is model-audited and user-run: the model inspects the PoC for dangerous behavior and hands you safe, pinned-version steps to run in your own sandbox.

```
Triage this vulnerability report: <URL or file>
Is this advisory a real finding or by-design?
Reproduce and score this GitHub advisory: GHSA-xxxx
```

</details>

<details>
<summary><b>crypto-secrets</b>: hardcoded secrets and broken cryptography in application code</summary>

Use it when you're reviewing source that handles credentials, encryption, JWTs, TLS clients, sessions, or password hashing — anywhere you need to answer "are we leaking secrets or relying on broken crypto?"

It runs in two stages, like `infra-security` and `skill-security`. A deterministic, dependency-free scanner (`scripts/scan.py` — pure stdlib, no network, no `pip install`) finds high-signal candidates with `file:line` anchors; then the model confirms impact, suppresses fixtures/placeholders, redacts secret values, and writes concrete fixes. It catches:

- Exposed credentials — API keys, OAuth/Bearer tokens, Slack/GitHub/Stripe keys, database URLs, PEM private keys, committed `.env` values
- Weak crypto — MD5/SHA1 password hashing, DES/3DES/RC4, AES-ECB, CBC/CTR without authentication, static IVs/nonces
- Token and transport bugs — weak token randomness, hardcoded JWT secrets, `alg: none`, missing `exp`, disabled TLS verification, SSL/TLS 1.0/1.1
- Key-management and serialization risks — hardcoded encryption keys, private keys in source, unsafe `pickle`/`yaml.load`

Rules track OWASP, NIST, CWE, and language-specific crypto guidance — applied as an offline source read rather than a live credential validator.

```
Audit this repo for hardcoded secrets and weak crypto
Scan for exposed API keys in this codebase
Review JWT handling for algorithm confusion or weak secrets
Find verify=False / InsecureSkipVerify / rejectUnauthorized false
```

</details>

<details>
<summary><b>infra-security</b>: misconfigurations in your Terraform, Kubernetes, CloudFormation, and Docker</summary>

Use it when you're about to apply a Terraform plan, reviewing a PR that changes K8s/Helm manifests or a Dockerfile, checking CloudFormation before deploy, or prepping for a SOC-2 / PCI-DSS / ISO-27001 audit — anywhere you need to answer "what's the blast radius if this infra is wrong?"

It runs in two stages, like `skill-security`. A deterministic, dependency-free scanner (`scripts/scan.py` — pure stdlib, no `pip install`, no `hcl2`/`pyyaml`) does the high-recall first pass over every `.tf`/`.yaml`/`Dockerfile` with `file:line` anchors and a CI-friendly exit code; then the model adds the judgment a regex can't — blast radius, cross-resource chains, and false-positive suppression. Every finding comes with a severity (P0–P3) and a corrected snippet. It catches:

- Network — security groups open to `0.0.0.0/0` on SSH/RDP/database ports, all-ports ingress, unrestricted egress
- IAM — wildcard `Action`/`Resource`, `*` principals on resource and KMS policies, `PassRole` on `*`, over-broad roles on compute
- Storage — public S3 ACLs, missing public-access-block, encryption-at-rest disabled (S3/EBS/RDS)
- Containers — privileged/root pods, host namespaces, the Docker socket mounted in, `:latest` images, missing limits
- Secrets — plaintext credentials in variables/env/ConfigMaps, missing TLS, plaintext-HTTP endpoints

Rules track the CIS Benchmarks, AWS Well-Architected, and the Kubernetes Pod Security Standards — applied as a source read rather than another scanner to wire up.

```
Audit this Terraform for security issues: <dir>
Review these Kubernetes manifests before deploy: <dir>
Check this CloudFormation for public S3 buckets: <file>
What's the blast radius if this Terraform is wrong?
```

</details>

## Install

```bash
# everything
npx skills add superagent-ai/skills

# or pick one
npx skills add superagent-ai/skills --skill superagent -a cursor -y
npx skills add superagent-ai/skills --skill hacker -a cursor -y
npx skills add superagent-ai/skills --skill redteam-autoresearch -a cursor -y
npx skills add superagent-ai/skills --skill ci-cd-security -a cursor -y
npx skills add superagent-ai/skills --skill repo-security-posture -a cursor -y
npx skills add superagent-ai/skills --skill skill-security -a cursor -y
npx skills add superagent-ai/skills --skill authz-security -a cursor -y
npx skills add superagent-ai/skills --skill recon-security -a cursor -y
npx skills add superagent-ai/skills --skill supply-chain-security -a cursor -y
npx skills add superagent-ai/skills --skill security-disclosure-triage -a cursor -y
npx skills add superagent-ai/skills --skill vulnerability-triage -a cursor -y
npx skills add superagent-ai/skills --skill crypto-secrets -a cursor -y
npx skills add superagent-ai/skills --skill infra-security -a cursor -y
```

Once installed, skills load on their own when a task matches — nothing to remember or invoke by hand.

**Migration:** Use `--skill hacker` for the offensive engagement framework.

## Repo layout

```
skills/
  superagent/             SKILL.md (opt-in Superagent MCP integration)
  hacker/                 SKILL.md + references/ (instruction-only engagement framework)
  redteam-autoresearch/   SKILL.md + references/ + scripts/ (red-team autoresearch harness)
  ci-cd-security/         SKILL.md + references/
  repo-security-posture/  SKILL.md + references/ + scripts/ (GitHub repo posture collector)
  skill-security/         SKILL.md + scripts/ (scanner) + rules/ (YARA) + references/
  authz-security/         SKILL.md + references/
  recon-security/         SKILL.md + references/
  supply-chain-security/  SKILL.md + references/
  security-disclosure-triage/ SKILL.md
  vulnerability-triage/   SKILL.md + references/
  crypto-secrets/         SKILL.md + scripts/ (scanner) + references/
  infra-security/         SKILL.md + scripts/ (scanner) + references/
```

A skill is a `SKILL.md` (the agent's instructions) plus optional `references/`, `scripts/`, and `rules/`.

## Contributing

New skills and rule improvements are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The bar is a real security problem the model gets wrong by default, encoded as durable rules that run offline.

## License

Released under the [MIT License](LICENSE).
