# Offensive Security — Validation Rules

## Safe Validation Playbook

### network_probe

1. Confirm target IP/hostname is in `scope.yaml` `allowed_targets`.
2. Use Python `socket.create_connection((host, port), timeout=5)` or `nc -zv` via subprocess against sandbox only.
3. Record connect success, banner snippet (max 200 chars), and timestamp.
4. Max 5 probes per hypothesis; 1 request/second.

### token_forgery

1. Use only secrets redacted in defensive output or test vectors from scope file.
2. Build JWT with `pyjwt.encode(payload, secret, algorithm=alg)` matching finding context.
3. POST/GET sandbox auth endpoint from scope; never production domains.
4. Redact token values in evidence (`Bearer [REDACTED]`).

### parameter_tampering

1. Use `requests` against `self-hosted-test-api` base URL from scope.
2. Payloads must be harmless: ID swaps, `role=admin`, XSS strings only on sandbox.
3. Compare status codes and response shape; store redacted JSON snippets.

### config_exploit

1. Apply config change only inside Docker (`--network=none` or dedicated bridge).
2. Use `tmpfs` mounts; no host credential mounts.
3. Restart sandbox service; observe logs for privilege or policy bypass.

### sandbox_execution

1. `docker run --rm --network=none --read-only --tmpfs /tmp` with 60s timeout.
2. Run proof script that writes `/tmp/offensive-proof.txt` or benign marker.
3. Teardown container in `finally` block.

## Forbidden Actions (hardcoded — never overridden)

| Action | Rationale |
|--------|-----------|
| Requests to production endpoints or user-facing domains | Out of scope; legal and safety risk |
| Credential bruteforce | Abuse potential even on own infra |
| Data modification/deletion outside sandbox | Integrity risk |
| >10 requests/minute per hypothesis | DoS prevention |
| Social engineering / phishing | Human harm |
| Third-party SaaS without written scope | Authorization |
| Host privilege escalation | Agent environment safety |
| `delete`, `drop`, `rm -rf` on non-sandbox paths | Destructive |
| `sqlmap --dump`, `--os-shell` | Excessive data access |

Validator rejects hypotheses listing any forbidden action in `safe_scope.forbidden_actions` when scope does not explicitly allow (scope cannot override core forbidden list).

## Sandbox Spec

```bash
docker run --rm \
  --network=none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --memory=512m \
  --cpus=1 \
  --pids-limit=100 \
  --security-opt=no-new-privileges \
  <image> <cmd>
```

- Timeout: 60 seconds per validation step.
- Teardown: always `container.remove(force=True)` in finally.
- No `-v` mounts from host home or `~/.aws`, `~/.kube`, `.env`.

## Scope File Format

```yaml
version: 1
authorized_by: "engagement owner"
targets:
  sandbox_web_app: "http://127.0.0.1:8080"
  sandbox-auth-endpoint: "http://127.0.0.1:9090"
  sandbox-instance-private-ip: "10.0.0.5"
allowed_targets:
  - sandbox_web_app
  - sandbox-auth-endpoint
  - self-hosted-test-api
forbidden_hosts:
  - "*.prod.example.com"
  - "api.stripe.com"
max_requests_per_hypothesis: 10
rate_limit_rps: 1
```

Without a scope file, validator runs in **dry-run** mode: records `unsafe_to_test` for network/token/tamper hypotheses.

## Rate Limiting

- Per hypothesis: min interval `1 / rate_limit_rps` seconds between requests.
- Global: max 10 requests/minute per hypothesis (hard cap).
- Validator tracks timestamps in-memory per run.

## Evidence Collection

- Capture: HTTP status, headers (redact `Authorization`, `Cookie`, `Set-Cookie`), body preview (512 chars max).
- Replace JWT/API key patterns with `[REDACTED]`.
- Include exit code and stderr tail for subprocess/Docker steps.
- UTC ISO timestamps on every evidence block.

## Positive Control Requirement

Every `confirmed` outcome must include `negative_control`: same steps with mitigation applied (e.g., forged JWT rejected after secret rotation mock, IDOR returns 403 with owner check enabled). Document expected failing response.
