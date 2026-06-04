# Crypto Secrets Severity Rubric

Use severity to communicate exploitability and required response. Score the confirmed impact, not the literal pattern alone.

| Level | Name | Criteria | Response |
|---|---|---|---|
| P0 | Critical | Production secret, private key, or signing key is exposed; token forgery or plaintext recovery is realistic; unsafe deserialization can lead to code execution. | Block release. Rotate credentials immediately. Remove from history where practical. |
| P1 | High | Disabled TLS verification, weak token/session randomness, JWT algorithm confusion, hardcoded high-value non-production secret, or broken crypto one precondition away from compromise. | Fix before next release. Owner review required. |
| P2 | Medium | Deprecated crypto under narrower conditions: MD5/SHA1 for integrity, low KDF iterations, missing token claims, unauthenticated CBC/CTR, weak certificate settings. | Track and fix on a security timeline. |
| P3 | Low | Hygiene or defense-in-depth gap with limited exploitability: expiring cert, placeholder secret in sample config, weak pattern isolated to test-only code. | Fix opportunistically or document accepted risk. |
| Informational | Note | Fake/test fixture, documentation mention, migration note, clean-scan caveat, or scanner false positive worth recording. | No security action unless the pattern is likely to be copied into production. |

## Adjacent-Level Guidance

- Promote to **P0** when the exposed value appears production-like, is in a non-test path, controls cloud/payment/source-code access, signs tokens, decrypts user data, or is a private key.
- Promote to **P1** when the flaw affects authentication, sessions, TLS validation, JWT verification, password hashing, encryption of sensitive data, or secrets used by privileged automation.
- Downgrade to **P3/Informational** only when evidence shows the value is synthetic, local-only, test-only, or documentation-only.
- If unsure whether a secret is live, do **not** validate it. Report conservatively and recommend rotation if it could be real.

## Deployment Risk Rating

| Rating | Criteria |
|---|---|
| High | Any P0, or multiple P1 findings in auth, payments, data encryption, or cloud access paths. |
| Medium | One P1 or multiple P2 findings without confirmed production exposure. |
| Low | Only P3/Informational findings, or no confirmed findings against this control set. |

## Effort Scale

| Effort | Meaning |
|---|---|
| Quick Fix | Local code/config rewrite, such as replacing `verify=False` or moving a sample placeholder out of production config. |
| Moderate | Callsite refactor, API migration, new secret-loading path, KDF parameter migration, or test updates. |
| Complex | Credential rotation, git history cleanup, key migration, token-signing rollout, data re-encryption, or coordinated infra/application deployment. |

## Reporting Requirements

Every confirmed finding should include:

- Severity, category, stable rule id, and `file:line`.
- Redacted evidence for secrets and verbatim snippets for non-secret code.
- Why it is exploitable in this codebase.
- Concrete fixed code or a concrete remediation sequence.
- Whether credential/key rotation is required.
- Any assumptions, especially production vs. test context.
