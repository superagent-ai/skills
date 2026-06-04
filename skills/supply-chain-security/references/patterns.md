# Safe Dependency Patterns

When a pass flags a risk, the user wants the safe way to add or manage the dependency, not just the diagnosis. This file is the cookbook: each entry pairs a common goal with the right way to accomplish it. Examples lean npm because that is where most attacks land; the reasoning ports to every ecosystem in `references/ecosystems.md`.

## "I want to add a new dependency safely"

A new dependency is the highest-risk moment. Walk it:

1. **Confirm identity.** Is the name exactly the real package (not a typo, not an AI-hallucinated near-match)? Is it scoped to the org you expect? `npm view <pkg>` — does it exist, who maintains it, how old is it?
2. **Read the install scripts — and `binding.gyp`.** `npm view <pkg> scripts` (or open `package.json` in the tarball). A `preinstall`/`postinstall` is a yellow flag; one doing network/secret/obfuscated work is a stop. Also check for **`binding.gyp`**: a package with no legitimate native code should not have one, and any `sources` entry with shell expansion is a stop.
3. **Wait out a cooldown.** Don't install a version published hours ago. Most malware is caught within 24–48h, so a delay filters the smash-and-grab campaigns for free (next entry).
4. **Pin and lock.** Add it at an exact version, commit the lockfile, install with the frozen command.
5. **Scan.** `osv-scanner` / `npm audit signatures` against the lockfile, and a behavioral check (Socket/Snyk) if available.

The point is sequencing: confirm *who* and *what* before the install runs code, not after.

## "I want to avoid freshly-published malware (cooldown)"

Most compromised versions are discovered and yanked within a day or two. Refusing to install anything newer than a cooldown window turns the community's detection speed into your defense — at the cost of not getting the newest version immediately.

```ini
# npm (.npmrc), npm >= 11.10 — value in days
min-release-age=3
```
```yaml
# pnpm-workspace.yaml — value in minutes; on by default in pnpm 11
minimumReleaseAge: 4320   # 3 days
```

Set it on the **update bot too**, or it opens PRs you can't install: Dependabot `cooldown`, Renovate `minimumReleaseAge` (covers npm, PyPI, Maven, Go, Cargo, NuGet, RubyGems, and more). The cooldown applies to **transitive** dependencies as well, which is where most attacks actually enter. `min-release-age` is mutually exclusive with npm's `before`.

## "I want to stop a dependency from running code when I install it"

The install hook is the crown jewel. Take it away by default, grant it back by exception.

```ini
# .npmrc — no lifecycle scripts run on install
ignore-scripts=true
```

Then allowlist only the packages that genuinely need to build a native binary:

```jsonc
// pnpm: only these may run install scripts
"pnpm": { "onlyBuiltDependencies": ["esbuild", "sharp", "node-gyp"] }
```

This is the single highest-leverage control for npm: it neutralizes the **`preinstall`/`postinstall` worm class** (Shai-Hulud, s1ngularity) on dev machines and in CI. **It does not block the binding.gyp worm** — that path runs via `node-gyp`, not lifecycle scripts — so pair `ignore-scripts` with diff review for unexpected `binding.gyp` files and multi-megabyte root `index.js`. The cost is maintaining a short allowlist of packages with legitimate build steps. Equivalents elsewhere: review `setup.py`/`build.rs`/Composer `scripts` before first install; prefer wheels over sdists on PyPI so nothing runs at install time.

## "I want internal package names that can't be hijacked (dependency confusion)"

An unscoped internal name (`acme-auth-utils`) can be claimed by anyone on the public registry at a higher version and will win resolution. Close the door with **scope + a pinned, committed registry config**.

```ini
# .npmrc committed to the repo (not ~), so a fresh clone + npm ci can't fall back
@acme:registry=https://npm.internal.acme.com
registry=https://registry.npmjs.org/
```

- Use `@acme/...` for **every** internal package; the scope binds to exactly one registry, so the public registry is never consulted for it.
- Register the `@acme` scope/org on the public registry as a placeholder so no one else can.
- Set `publishConfig.registry` so an internal package can't accidentally publish to the public registry.

For ecosystems without scopes (PyPI, RubyGems, Cargo): proxy **all** resolution through one internal index (Artifactory/Nexus/devpi) that checks internal names first and only falls through to public for an explicit allowlist — never `--extra-index-url` fallthrough, which still queries the public index.

## "I want deterministic, verifiable installs"

A lockfile is the only thing standing between "I reviewed version X" and "CI installed version Y."

- **Commit the lockfile** (`package-lock.json`, `poetry.lock`, `Cargo.lock`, `go.sum`, `Gemfile.lock`, `composer.lock`).
- **Install frozen**: `npm ci`, `pnpm i --frozen-lockfile`, `yarn --immutable`, `pip install --require-hashes`, `bundle install --frozen`, `composer install` (never `update` in CI).
- **Require integrity hashes.** Audit lockfile entries for a `resolved`/tarball URL with an **empty or missing `integrity`** — that entry is unverifiable and effectively floating. On pip, `--require-hashes` makes every package carry a `--hash=`.

Determinism doesn't make a malicious version safe — it makes the version you reviewed the version you ship, and turns "what changed?" into a readable diff.

## "I want exact versions, not ranges"

```jsonc
// Wrong — installs whatever the registry serves next, including a bad patch
"dependencies": { "left-pad": "^1.3.0" }

// Right — exact pin; changes are explicit, reviewable lockfile diffs
"dependencies": { "left-pad": "1.3.0" }
```

Ranges (`^`, `~`, `*`, `latest`) and `git`/URL dependencies mean "trust the future." Pin exact, let the update bot propose bumps as reviewable PRs (with a cooldown), and never depend on a mutable git branch or a `latest`/`dist-tag` for anything you ship.

## "I want to verify a package came from its real source"

```bash
npm audit signatures        # checks registry signatures + provenance attestations
gh attestation verify       # for GitHub-attested artifacts
```

Provenance (npm/SLSA via OIDC, PyPI PEP 740, Sigstore) cryptographically links an artifact to the build that produced it. Prefer dependencies that publish it. **Caveat that matters:** provenance proves *which workflow built it*, not that the publisher was *authorized* — an OIDC token stolen from a CI run produces genuinely valid attestations (the "Mini Shai-Hulud" `@tanstack` compromise did exactly this). Provenance raises the bar; it is not proof of safety. Combine with cooldown and behavioral scanning.

## "I want my own published package not to become the next link in a worm"

If you publish, you are a target — Shai-Hulud spreads by republishing maintainers' own packages with a stolen token.

- **Drop long-lived publish tokens.** Use **Trusted Publishers (OIDC)** so there is no `NPM_TOKEN` to steal; delete the classic token.
- **Gate publishes** behind a manual approval / staged-publishing step so one compromised CI run can't silently push.
- **Isolate secrets from untrusted code.** A fork PR workflow must never see your publish credentials; keep the publish job in a protected environment. (See the sibling `ci-cd-security` skill — stolen-token-via-CI-injection is how nx, PostHog, and `asyncapi/cli` were breached.)
- **Enforce phishing-resistant MFA** on the registry account; the `chalk`/`debug` compromise was a single phished TOTP.

## "I want to keep dependencies safe over time, not just at add-time"

- **Update bot with a cooldown** (Dependabot/Renovate) so bumps are reviewable PRs that have aged past the malware window.
- **PR dependency review**: `actions/dependency-review-action` flags newly added deps and known-vulnerable versions on every PR.
- **Continuous SCA** against OSV/advisories (`osv-scanner` in CI, Socket, Snyk) so a dependency found malicious *after* you adopted it raises an alert.
- **An SBOM** (CycloneDX/Syft) per release, so when the next advisory drops you can answer "were we shipping the bad version?" in seconds instead of days.

None of these is sufficient alone. Together — exact pins, committed lockfile, `ignore-scripts`, cooldown, scoped internal names, provenance, and continuous scanning — they raise the cost of a supply-chain attack from "publish a package" to "defeat every layer," which is the whole game.
