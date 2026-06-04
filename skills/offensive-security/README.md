# Offensive Security

Autonomous offensive validation for defensive security findings. Part of [superagent-ai/skills](https://github.com/superagent-ai/skills).

## Quick start (autoresearch loop)

```bash
pip install -r skills/offensive-security/requirements.txt

# After hacker Phases 1–5 (deduped-findings.json) + scope.yaml:
python3 skills/offensive-security/scripts/autoresearch.py deduped-findings.json \
  --scope scope.yaml --max-rounds 5 --output-dir ./offensive-run
```

The loop validates hypotheses, spawns chain follow-ups from confirmations, and stops when no new work remains. See `references/autoresearch-loop.md`.

Dry-run (no live probes):

```bash
python3 skills/offensive-security/scripts/validator.py hypotheses.json --dry-run -o outcomes.json
```

## Scope file

Authorize only sandbox targets. Example:

```yaml
version: 1
authorized_by: "your-name"
targets:
  sandbox-auth-endpoint: "http://127.0.0.1:9090"
  self-hosted-test-api: "http://127.0.0.1:8080"
  sandbox-instance-private-ip: "127.0.0.1"
allowed_targets:
  - sandbox-auth-endpoint
  - self-hosted-test-api
  - sandbox-instance-private-ip
forbidden_hosts:
  - "*.prod.example.com"
test_jwt_secret: "sandbox-only-secret"
```

## Safety guarantees

- Forbidden actions are hardcoded in `validator.py` (no bruteforce, no production, no destructive ops).
- Network/token tests require scope; otherwise `unsafe_to_test`.
- Docker sandboxes use `--network=none`, read-only rootfs, automatic teardown.
- Reports redact secrets in evidence blocks.

## Pairing with hacker

Run **last** in the hacker workflow (Phase 6): after all defensive skills, deduplication, triage, and `hacker-report.md`. Input must be `deduped-findings.json`. See `skills/hacker/SKILL.md`.
