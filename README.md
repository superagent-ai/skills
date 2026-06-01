# Agent Skills

A collection of agent skills for AI coding agents. Skills are packaged instructions that extend agent capabilities.

Skills follow the [Agent Skills](https://agentskills.io/) format.

## Available Skills

### ci-cd-security

Scan GitHub Actions workflow YAML for supply-chain and pwn-request vulnerabilities. Reads workflow files directly and reports findings with severity ratings and concrete fixes — no external tools required.

**Use when:**

- Reviewing `.github/workflows/` files in a PR
- Auditing CI/CD security posture
- Checking for `pull_request_target`, template injection, or cache poisoning
- Hardening release/publish workflows

**Covers:**

- Dangerous triggers (`pull_request_target`, `workflow_run`)
- `GITHUB_TOKEN` permissions and least privilege
- Action pinning (SHA vs tag vs branch)
- Shell/template injection in `run:` blocks
- Untrusted checkout, cache poisoning, artifact-borne injection
- Release hardening and self-hosted runner risks

### skill-security

Audit an AI agent skill for security risks before installing or trusting it. Runs a deterministic scanner (regex patterns, Python AST analysis, source-to-sink taint tracking, and YARA signatures) and then reasons about intent — catching what static analysis alone misses.

**Use when:**

- Vetting a skill, plugin, `SKILL.md`, or agent tool before installing it
- Answering "is this skill safe to install?"
- Scanning a local folder, a `.zip`/`.skill` archive, or a cloned repo
- Reviewing a skill for prompt injection, credential theft, or malicious code

**Covers:**

- Prompt injection and audit-manipulation attempts
- Credential/secret exfiltration and outbound data theft
- Persistence and agent-memory poisoning
- Malicious code, webshells, and cryptominers (YARA signatures)
- Supply-chain and dependency risks
- Description-vs-behavior contract mismatch

## Installation

```bash
npx skills add superagent-ai/skills
```

Install a specific skill:

```bash
npx skills add superagent-ai/skills --skill ci-cd-security -a cursor -y
npx skills add superagent-ai/skills --skill skill-security -a cursor -y
```

## Usage

Skills are automatically available once installed. The agent will use them when relevant tasks are detected.

**Examples:**

```
Review this GitHub Actions workflow for security issues
```

```
Check .github/workflows/ci.yml for pull_request_target vulnerabilities
```

```
Audit our release workflow for cache poisoning risks
```

```
Is this skill safe to install? ~/Downloads/some-skill.zip
```

```
Audit ./vendor/skill-foo/SKILL.md for prompt injection or credential theft
```

## Skill Structure

Each skill contains:

- `SKILL.md` — Instructions for the agent
- `references/` — Supporting documentation (optional)
- `scripts/` — Executable helpers the agent can run (optional)
- `rules/` — Detection signatures, e.g. YARA rules (optional)

## License

MIT
