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

## Install

```bash
# everything
npx skills add superagent-ai/skills

# or pick one
npx skills add superagent-ai/skills --skill ci-cd-security -a cursor -y
npx skills add superagent-ai/skills --skill skill-security -a cursor -y
```

Once installed, skills load on their own when a task matches — nothing to remember or invoke by hand.

## Repo layout

```
skills/
  ci-cd-security/    SKILL.md + references/
  skill-security/    SKILL.md + scripts/ (scanner) + rules/ (YARA) + references/
```

A skill is a `SKILL.md` (the agent's instructions) plus optional `references/`, `scripts/`, and `rules/`.

## Contributing

New skills and rule improvements are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The bar is a real security problem the model gets wrong by default, encoded as durable rules that run offline.

## License

Released under the [MIT License](LICENSE).
