# Severity Rubric

How to score an IaC finding. The scale is P0–P3 for confirmed misconfigurations, plus a non-graded **Informational** tier. Severity is not read off the pattern — it is derived from **exposure × blast radius** (see the rule below).

| Level | Name | Criteria | Example |
|-------|------|----------|---------|
| P0 | Critical | Internet-reachable **and** high blast radius: unauthenticated data exposure or infrastructure takeover, exploitable as-is | `0.0.0.0/0` → SSH on a public instance; S3 bucket `public-read-write` holding PII; `Principal: "*"` on a KMS key |
| P1 | High | Privilege escalation, lateral movement, or significant data exposure — often one precondition away from P0 | Wildcard IAM policy on a workload role; container `privileged: true`; plaintext DB password in a committed variable |
| P2 | Medium | Defense-in-depth gap; exploitable only under specific conditions or after another foothold | Encryption-at-rest disabled on an internal datastore; HTTP listener with no HTTPS redirect; CloudTrail absent |
| P3 | Low | Best-practice deviation or compliance gap with no direct exploit path | Unrestricted egress; `:latest` image tag; missing log retention; no resource limits |
| Informational | — | Architectural recommendation or documentation note; no security impact on its own | "Consider a customer-managed KMS key here"; "module would benefit from a README of its security assumptions" |

## The exposure × blast radius rule

This is the single most important rule. The **same literal pattern lands at different severities** depending on two questions:

1. **Exposure — can an attacker reach it?**
   - Internet-facing (`0.0.0.0/0`, public ACL, public subnet, public endpoint) → top of the funnel.
   - Internal-only (private subnet, behind an authn proxy, restricted SG) → much lower.
2. **Blast radius — if reached, what falls?**
   - Broad (a role every workload assumes, a bucket of PII, a key that wraps everything) → escalate.
   - Narrow (a scratch resource, a single low-value object, an isolated role) → de-escalate.

Worked examples:

- `Action: "*"` IAM policy → **P1** by default. Attached to a role assumed by every Lambda in the account → **P0**. On a role nothing assumes yet (defined but unattached) → **P2**.
- `encrypted = false` → **P2** by default. On the volume holding the production database → **P1**. On an ephemeral CI scratch volume → **P3**.
- `0.0.0.0/0` to port 443 → often fine (that's a public web service). `0.0.0.0/0` to port 22 or 5432 → **P0**.

When you cannot determine blast radius from the IaC alone, rate **conservatively and state the assumption** ("rated P1 assuming this role is attached to the public API instance; downgrade to P2 if it is not").

## Choosing between adjacent levels

- **P0 vs P1:** P0 needs *no* attacker foothold and a *broad* impact — reachable from the internet (or by any anonymous principal) and yielding data exposure or takeover. The moment it requires an existing foothold, a specific precondition, or impact is bounded to one resource, it's P1.
- **P1 vs P2:** P1 crosses a trust boundary or enables escalation/lateral movement on its own (wildcard role, privileged container, plaintext credential). P2 is a hardening gap that bites only after another bug, or only under a specific condition (encryption off, missing audit trail).
- **P2 vs P3:** P2 has a plausible exploitation path given a precondition. P3 is a best-practice deviation or compliance gap with no demonstrated path (open egress, `:latest`, missing retention).
- **P3 vs Informational:** P3 is a real (if low) deviation tied to a control. Informational is advisory — an architectural suggestion with no control violation.

## Deployment risk rating

Summarize the audit with a single gate, driven by the **highest-severity counts**:

| Rating | Condition | Meaning |
|--------|-----------|---------|
| **High** | One or more P0, **or** three or more P1 | Do not deploy. P0s block; a cluster of P1s is an aggregate critical. |
| **Medium** | One or two P1, or any number of P2 | Deploy only with owner sign-off and tracked remediation. |
| **Low** | P3 / Informational only | Safe to deploy; fix in the normal cycle. |

This maps to the scanner's exit code: **exit 1 when any P0 or P1 is present** (so it gates CI), exit 0 otherwise.

## Effort classification

Tag each finding so the remediation roadmap can group by cost:

- **Quick Fix** — a one-line or single-attribute change. `encrypted = true`, swap a CIDR, add `USER 10001`, pin a tag. Land it in the same PR.
- **Moderate** — a new resource or a non-trivial refactor in the same module. Add an `aws_s3_bucket_public_access_block`, introduce a least-privilege policy, add a CloudTrail.
- **Complex** — an architectural change touching multiple resources or teams. Move a database into a private subnet, re-platform off the Docker socket, introduce a secrets manager and rewire every consumer.

## Default severity is an input, not the answer

The level in `controls.md` is the typical rating for the pattern *in isolation*. Treat it the way a triager treats a reporter's claimed CVSS: a starting point. Record it, then adjust with exposure × blast radius and state why. A control's default P1 can be your P0 (broad blast radius) or your P3 (no exposure) — and the written justification is what makes the rating defensible in review.
