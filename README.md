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

## Installation

```bash
npx skills add superagent-ai/skills
```

Install a specific skill:

```bash
npx skills add superagent-ai/skills --skill ci-cd-security -a cursor -y
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

## Skill Structure

Each skill contains:

- `SKILL.md` — Instructions for the agent
- `references/` — Supporting documentation (optional)

## License

MIT
