# Check catalog

The catalog of what to inspect, where it lives in the `collect.py` inventory, why an attacker cares, and what the remediation todo should say. Organized by the six report categories. Walk each check against the inventory; a check that can't be observed becomes a "Could not verify" item, not a silent pass.

Severity guide: **Critical** = enables a single-actor compromise or live exfiltration path. **High** = removes a key barrier or broad blast-radius limiter. **Medium** = meaningful hardening, defense in depth. **Low** = hygiene.

---

## 1. Publish & release integrity

The registry is downstream of the repo. A clean repo still ships poison if the publish path is weak. This is the @mastra / dotenvx / TeamPCP class.

- **Long-lived publish tokens.** Inventory: workflow files referencing publish-token secrets such as `NPM_TOKEN`, `PYPI_TOKEN`, or `secrets.NODE_AUTH_TOKEN`; if `files.npmrc` is true, ask the maintainer to confirm it does not contain a registry auth token. A stolen automation/classic token publishes from anywhere, bypassing every repo control. *Todo (Critical):* migrate publishing to OIDC trusted publishing (npm trusted publishers, PyPI trusted publishing) so the registry trusts a short-lived, workflow-scoped identity instead of a static secret; then revoke the long-lived tokens. Names the **registry supply-chain** scenario.
- **No provenance / attestation.** Inventory: publish step lacks `--provenance` (npm) or `actions/attest-build-provenance`; releases have no Sigstore attestation. Without provenance, consumers can't tell a legitimate build from an attacker's hand-published version. *Todo (High):* publish with provenance and add a consumer/CI check that rejects releases lacking a valid provenance attestation.
- **No human gate on publish.** Inventory: publish job runs automatically on tag/merge with no `environment:` protection. *Todo (High):* put the publish job behind a GitHub **Environment** with required reviewers and a 30–60 minute wait timer, restricted to the protected branch. A compromised contributor's auto-publish then needs a second human and a cooling-off window — the control in the @mastra post-mortem.
- **Registry 2FA / scope hygiene.** Can't be read from the repo. *Todo (Medium, unverified):* enforce 2FA on every maintainer's registry account, delete unused granular/automation tokens, and scope any remaining token to the single package. Flag as manual.
- **Publish not restricted to protected branch.** Inventory: publish workflow triggers from any branch or `workflow_dispatch` without branch restriction. *Todo (Medium):* restrict the release environment/workflow to the default branch only.

## 2. Branch & merge protection

This is the wall against a **compromised contributor** merging alone, and it caps what an attacker with write access can do to `main`.

- **No required pull-request review.** Inventory: `branch_protection.required_pull_request_reviews` absent/zero, or no ruleset enforcing it. *Todo (Critical):* require at least one approving review (two for release-bearing repos) before merge to the default branch. Stops a lone compromised account from merging.
- **Self-approval / self-merge allowed.** Inventory: protection lacks `require_code_owner_reviews` or allows the author to satisfy their own review. *Todo (High):* require code-owner review and disallow the PR author from approving their own change.
- **Stale approvals not dismissed.** Inventory: `dismiss_stale_reviews` false. An attacker pushes a clean commit, gets approval, then force-adds a malicious one. *Todo (High):* dismiss stale approvals when new commits land.
- **Admins / bypass exempt.** Inventory: `enforce_admins` false, or ruleset has bypass actors. The control is theater if admins skip it. *Todo (High):* apply protection to admins; remove bypass actors except a break-glass account.
- **Force-push / deletion allowed.** Inventory: `allow_force_pushes` true, `allow_deletions` true. Lets an attacker rewrite history or erase the branch. *Todo (Medium):* block force-push and deletion on protected branches.
- **No required status checks.** Inventory: `required_status_checks` empty. Malicious code merges without CI/security gates running. *Todo (Medium):* require the security and test checks to pass before merge; require branches up to date.
- **Unsigned commits accepted.** Inventory: `required_signatures` false. *Todo (Low–Medium):* require signed commits so a compromised account can't forge authorship of trusted maintainers.
- **No linear history.** Inventory: `required_linear_history` false. *Todo (Low):* require linear history to keep the audit trail clean and reviewable.

## 3. Sensitive-path ownership (CODEOWNERS)

Branch protection is uniform; CODEOWNERS lets you demand *specific* reviewers for the files an attacker targets first. Mirrors the example's "lock down workflow changes."

- **No CODEOWNERS, or it misses high-value paths.** Inventory: `files.codeowners` null, or present but without rules for `.github/workflows/`, `.github/actions/`, `package.json`/manifests, lockfiles (`*-lock.*`, `pnpm-workspace.yaml`), `Dockerfile`, release/publish config, and `CODEOWNERS` itself. These files convert a normal PR into code execution or a supply-chain change. *Todo (High):* add CODEOWNERS rules covering every CI, action, dependency-manifest, lockfile, and release-config path, and require code-owner review for them.
- **Single owner / no redundancy on critical paths.** Inventory: critical paths owned by one individual, not a team. *Todo (Medium):* assign a team (≥2 people) so one compromised account can't both author and approve a sensitive change.
- **CODEOWNERS not enforced.** CODEOWNERS without `require_code_owner_reviews` in branch protection is advisory only. *Todo (High):* enable code-owner review enforcement (cross-reference §2).

## 4. CI/CD workflow hardening

GitHub Actions is the dominant repo-takeover surface. Read every workflow in `files.workflows` — these are **CI/CD compromise** findings and several are Critical.

- **`pull_request_target` (or `workflow_run`) checking out untrusted code.** Inventory: a workflow with `on: pull_request_target` that runs `actions/checkout` against `github.event.pull_request.head` and then builds/tests/installs. This runs attacker-controlled code *with the base repo's secrets*. *Todo (Critical):* never check out and execute PR head under `pull_request_target`; split into a privileged-but-no-checkout workflow and an unprivileged `pull_request` one, or gate on label + maintainer.
- **Script injection from event data.** Inventory: `run:` steps interpolating `${{ github.event.* }}` (PR title, body, branch name, commit message, issue comment) directly into shell. An attacker puts `$(...)` in a PR title and it executes. *Todo (Critical):* pass untrusted values via `env:` and reference as `"$VAR"`; never inline `${{ github.event... }}` into a shell command.
- **Unpinned third-party actions.** Inventory: `uses:` referencing a tag or branch (`@v4`, `@main`) for non-GitHub-owned actions instead of a full commit SHA. A compromised or retagged action runs in your pipeline. *Todo (High):* pin third-party actions to a full-length commit SHA; let Dependabot bump them. (First-party `actions/*` by SHA is ideal but tag is lower-risk.)
- **Over-broad `GITHUB_TOKEN` permissions.** Inventory: no top-level `permissions:` block (defaults can be broad), or `permissions: write-all`, or `contents: write` where read suffices. *Todo (High):* set `permissions: {}` at the top and grant the minimum per job. Caps what a poisoned step can do.
- **Secrets exposed to fork PRs.** Inventory: secrets referenced in workflows triggered by `pull_request` from forks, or `id-token: write` granted where not needed. *Todo (High):* don't expose secrets or OIDC to fork-triggered runs; require manual approval for first-time/fork contributors (repo setting).
- **Self-hosted runners on a public repo.** Inventory: `runs-on:` self-hosted in a public repo. A fork PR can execute on your infrastructure and persist. *Todo (Critical for public):* use ephemeral, isolated runners and never run untrusted PRs on persistent self-hosted runners.
- **Workflow / action files writable without extra review.** Inventory: cross-reference §3 — `.github/workflows` and `.github/actions` not in CODEOWNERS. A contributor edits the pipeline to exfiltrate secrets. *Todo (High):* gate all workflow and composite-action changes behind code-owner review and 2 approvals.
- **Cache poisoning / artifact trust.** Inventory: workflows restoring caches keyed on untrusted input, or downloading artifacts from less-trusted workflows. *Todo (Medium):* scope cache keys to trusted refs; validate artifacts crossing trust boundaries.
- **Actions runtime not restricted.** Inventory (settings): `actions_permissions` allows all actions, or default workflow token is read-write. *Todo (Medium):* restrict to selected/verified actions and set the default token to read-only org/repo-wide.

## 5. Account & access control

Limits who has power and how fast you recover. Covers **compromised contributor** and **attacker with repo access**.

- **2FA not enforced.** Inventory: org-level; usually `not_verified`. *Todo (High, often unverified):* enforce 2FA org-wide (prefer WebAuthn/passkeys over SMS). The cheapest barrier to account takeover.
- **Over-broad collaborator access.** Inventory: `collaborators` with `admin`/`maintain`/`write` beyond who needs it; outside collaborators on a sensitive repo. *Todo (High):* apply least privilege — most contributors need `read` and PRs, not `write`; remove stale and outside collaborators.
- **Unaudited GitHub Apps / PATs.** Inventory: installed apps and their scopes (often `not_verified`). A forgotten app or broad PAT is a quiet backdoor. *Todo (Medium):* review installed apps and personal access tokens, revoke unused, and scope the rest to least privilege.
- **Deploy keys with write access.** Inventory: `deploy_keys` where `read_only` is false. *Todo (Medium):* prefer read-only deploy keys; remove unused; rotate any that may be exposed.
- **Webhooks leaking to untrusted endpoints.** Inventory: `webhooks` pointing at unexpected URLs or without secrets. *Todo (Medium):* audit webhook targets, ensure secrets are set, remove unknown ones.
- **Secret scanning & push protection off.** Inventory: `security_features.secret_scanning` / `push_protection` disabled or `not_verified`. *Todo (High):* enable secret scanning and push protection so a leaked key is caught before it lands — and so an attacker can't quietly commit one.
- **No secret-rotation runbook.** Not directly observable. *Todo (Medium):* document and rehearse rotating every CI secret and registry/publish token, so an "attacker has write access" incident has a known recovery path. Pairs with OIDC migration (§1), which shrinks the secret surface to rotate.

## 6. Dependency & supply-chain review

Stops a poisoned or typosquatted dependency from entering. The **registry supply-chain** scenario, inbound.

- **No Dependabot / security alerts.** Inventory: `files.dependabot` null and `security_features.vulnerability_alerts` off/`not_verified`. *Todo (High):* enable Dependabot alerts + security updates and a `dependabot.yml` covering every ecosystem in the repo (npm, pip, actions, docker — not just one).
- **New dependencies merge without review.** Inventory: no dependency-review gate in CI (`actions/dependency-review-action`) and manifests not in CODEOWNERS. *Todo (High):* gate PRs that add or bump dependencies — fail on known-vulnerable or license-violating additions, and route manifest changes to code owners. (Note where the maintainer's own tooling, e.g. Superagent, can sit.)
- **Typosquat / install-script risk unchecked.** Inventory: presence of many deps; `package.json` with `postinstall`/`preinstall` scripts; no Socket/origin-trust check. New or low-trust packages and install scripts are the classic injection vector. *Todo (Medium):* add typosquat/origin-trust screening on new dependencies and review any pre/postinstall scripts before merge. If a Socket-style tool is configured but not catching issues (e.g. silently failing on large dep counts), call that out as a finding to fix.
- **Lockfile not enforced.** Inventory: lockfile present but CI installs without `--frozen-lockfile`/`npm ci`, or no lockfile at all. Lets an unpinned transitive dep drift. *Todo (Medium):* commit a lockfile and install with frozen/`ci` mode in CI so builds are reproducible and pinned.
- **No SECURITY.md.** Inventory: `files.security_md` false. Researchers have nowhere to report, so findings go public or unreported. *Todo (Low):* add a `SECURITY.md` with a disclosure contact and policy.

---

## Reading workflow files

When inspecting `files.workflows`, scan each for the trigger (`on:`), the `permissions:` block (or its absence), every `uses:` (pinned to SHA?), every `run:` that interpolates `${{ github.event.* }}`, secret references, `id-token`, and `runs-on`. The combination of an untrusted trigger (`pull_request_target`, `workflow_run`, `issue_comment`) with code execution and secret access is the highest-signal pattern — surface it first.
