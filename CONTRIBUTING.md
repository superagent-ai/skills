# Contributing

Thanks for helping make agents safer. This is a small, curated set of security skills — we keep the bar high rather than the count high.

## What earns a place here

- Solves a real security problem the model gets wrong by default.
- Runs offline and without surprises — no phoning home, no installing tooling behind the user's back.
- Encodes durable rules or signatures, not the vuln-of-the-week.

## Add a skill

Skills live in `skills/<name>/` and follow the [Agent Skills](https://agentskills.io/) format:

```
skills/<name>/
  SKILL.md        # required — the agent's instructions
  references/     # optional — deeper docs the agent reads on demand
  scripts/        # optional — offline helpers the agent can run
  rules/          # optional — detection signatures (e.g. YARA)
```

Every `SKILL.md` opens with frontmatter:

```yaml
---
name: my-skill
description: What it does and — critically — when the agent should trigger it.
---
```

The `description` is the most important line you'll write: it's the only thing the model sees when deciding whether to load the skill. Be explicit about trigger conditions — file types, keywords, and the questions a user might ask.

## Before you open a PR

- Test it on a real example. Point an agent at something the skill should catch and confirm it fires.
- For scanner-backed skills, run the scanner against your changes — e.g. `python3 skills/skill-security/scripts/scan.py <target>`.
- Keep findings actionable: every flag ships with a severity and a concrete fix.
- Match the existing commit style — short and imperative ("Add X skill", "Fix Y rule").

## Reporting a vulnerability

Found a security issue in a skill — or a way to evade one? Please don't open a public issue. Use GitHub's private vulnerability reporting (the repo's **Security** tab → *Report a vulnerability*) so we can fix it before it's disclosed.

By contributing, you agree your contributions are licensed under the [MIT License](LICENSE).
