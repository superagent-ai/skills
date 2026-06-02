# Security Skills

Security skills for AI coding agents — distilled from real security work on codebases that serve 100M+ users a week.

Each skill ships in the open [Agent Skills](https://agentskills.io/) format and loads automatically when the agent hits a relevant task. They turn the model itself into the auditor: encoded rules and offline scanners, not another service to wire up.

## Skills

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
<summary><b>supply-chain-security</b>: malicious or compromised dependencies before they land</summary>

Use it when you're adding or upgrading a dependency, reviewing a PR that changes `package.json`, `requirements.txt`, `go.mod`, or a lockfile, or deciding whether a package is safe to install — anywhere you need to answer "is this dependency safe to add?"

It reads your manifests, lockfiles, install scripts, and dependency diffs offline — across npm/pnpm/yarn, PyPI, Go, Cargo, RubyGems, Maven/Gradle, NuGet, and Composer — and reports each risk at `file:line` with a concrete fix. No install, no execution, no phoning home. Every finding comes with a severity (P0–P3). It catches:

- Malicious install scripts — `preinstall`/`postinstall` hooks that harvest and exfiltrate secrets (the Shai-Hulud and nx `s1ngularity` worm pattern)
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

## Install

```bash
# everything
npx skills add superagent-ai/skills

# or pick one
npx skills add superagent-ai/skills --skill ci-cd-security -a cursor -y
npx skills add superagent-ai/skills --skill skill-security -a cursor -y
npx skills add superagent-ai/skills --skill authz-security -a cursor -y
npx skills add superagent-ai/skills --skill supply-chain-security -a cursor -y
```

Once installed, skills load on their own when a task matches — nothing to remember or invoke by hand.

## Repo layout

```
skills/
  ci-cd-security/         SKILL.md + references/
  skill-security/         SKILL.md + scripts/ (scanner) + rules/ (YARA) + references/
  authz-security/         SKILL.md + references/
  supply-chain-security/  SKILL.md + references/
```

A skill is a `SKILL.md` (the agent's instructions) plus optional `references/`, `scripts/`, and `rules/`.

## Contributing

New skills and rule improvements are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The bar is a real security problem the model gets wrong by default, encoded as durable rules that run offline.

## License

Released under the [MIT License](LICENSE).
