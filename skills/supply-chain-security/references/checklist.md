# Supply-Chain Review Checklist

A flat checklist for vetting a dependency, reviewing a PR that changes dependencies, or auditing a repo. Walk it top to bottom. Anything that fails needs resolution before the dependency lands. "Registry check" means a command the user runs against public data — the review itself is an offline read.

## Per dependency (added or changed)

### Identity

- [ ] The name is **exactly** the intended package — not a typo (`crossenv`/`cross-env`), not a near-match of a popular one
- [ ] If suggested by an AI, the package **actually exists** under that exact name and is the real one (not a slopsquat)
- [ ] Internal packages are **scoped** (`@org/...`) and pinned to the private registry; no unscoped internal-looking name resolvable from a public registry
- [ ] The maintainer/scope is who you expect; the version isn't a sudden odd jump on a long-stable package; the diff doesn't add an install script the package never had

### Install-time behavior

- [ ] Lifecycle hooks reviewed: npm `preinstall`/`install`/`postinstall`/`prepare`, PyPI `setup.py`/build hooks, Cargo `build.rs`, RubyGems native ext, Composer `scripts`
- [ ] **`binding.gyp` reviewed** when present: legitimate native addon only; no shell expansion in `sources` (`$()`, backticks, redirection); no `type: "none"` target whose only job is to run a command; no unexpected multi-megabyte root `index.js` alongside it
- [ ] Any install script does **only** a legitimate platform build into its own directory — no network to non-registry hosts, no env/secret reads, no writes outside the package, no shell spawn, no AI-CLI invocation, no alternate-runtime (Bun) install
- [ ] No campaign-marker files present (see appendix): `setup_bun.js`, `bun_environment.js`, `bun_installer.js`, `environment_source.js`, `telemetry.js`, malicious **`binding.gyp`** + root **`index.js`**

### Payload (when source is available)

- [ ] No obfuscation without reason — no large hex/base64/XOR blob, no `eval`/`new Function`/`atob`+exec in a package whose job is small
- [ ] No fetch-then-execute / decode-then-execute (remote/staged payload)
- [ ] No credential access: `process.env` exfiltration, `~/.npmrc`/`~/.aws`/SSH/`.env` reads, cloud IMDS `169.254.169.254`, container/Vault creds, secret managers, TruffleHog download
- [ ] No exfiltration/C2: POST to a hardcoded host/IP, DNS tunneling, Discord/Telegram/Slack webhook, GitHub repo as dead-drop
- [ ] No self-propagation (reads itself, validates an npm token, enumerates maintainer packages, `npm publish`)
- [ ] No persistence (shell rc edits, self-hosted runner + rogue workflow, cron/systemd) and no destructive/protestware payload (`rm -rf $HOME`, `shred`, shutdown, geo/date-gated sabotage)

### Hygiene

- [ ] Pinned to an exact version, not a range/`latest`/git-URL
- [ ] Present in a committed lockfile with an `integrity` hash (no tarball URL lacking a hash)
- [ ] Not freshly published — passes the cooldown window, or the recency was consciously accepted (`npm view <pkg> time`)
- [ ] Provenance verified where supported (`npm audit signatures`), understanding it proves build origin, not publisher authorization
- [ ] Clean against advisories/malicious-package feeds (`osv-scanner`, `pip-audit`, `cargo audit`, etc.)

## Per PR diff

- [ ] Every **newly added** package (direct and transitive) walked through the per-dependency list above — new transitive entries in the lockfile are reviewed, not just `package.json`
- [ ] Every **version bump** examined: does the diff add an install script, new files, or obfuscated content that wasn't there before?
- [ ] The lockfile change matches the manifest change (no unexplained `resolved` URL pointing off-registry, no integrity downgrade)
- [ ] No new registry/source/`repositories` entry pointing somewhere you don't control
- [ ] `actions/dependency-review-action` (or equivalent) ran and is green

## Per repository

- [ ] Lockfile committed; CI installs frozen (`npm ci` / `--frozen-lockfile` / `--require-hashes` / `bundle --frozen`)
- [ ] `ignore-scripts=true` (or `onlyBuiltDependencies` allowlist) so install hooks don't run unreviewed
- [ ] Committed `.npmrc`/index config scopes internal names to the private registry; no public fallthrough for internal scopes
- [ ] Cooldown configured at install (`min-release-age`/`minimumReleaseAge`) **and** on the update bot (Dependabot/Renovate)
- [ ] Continuous SCA against OSV/advisories; security alerts on
- [ ] If the repo publishes packages: Trusted Publisher (OIDC) not a long-lived token, gated/staged publishing, publish secrets isolated from fork-PR workflows, phishing-resistant MFA
- [ ] An SBOM is produced per release

## Per organization

- [ ] All resolution proxied through one internal registry that applies allowlisting/typosquat detection where possible
- [ ] Internal scope/namespace reserved (and placeholder-published) on public registries
- [ ] Policy on minimum cooldown, pinning, and lockfile enforcement; exceptions are written down
- [ ] Build/dev machines and CI runners have least-privilege credentials and restricted egress, so an install-time payload has little to steal and nowhere to send it

## What a static review can't confirm — verify separately

- [ ] The **published artifact matches the source repo** (the registry tarball is the trust boundary, not GitHub) — install in a sandbox and inspect, or rely on provenance
- [ ] **Transitive dependencies** you didn't open
- [ ] **Runtime-only** behavior (lazy/remote payloads, time/geo bombs) — needs sandboxed execution with network and filesystem monitoring
- [ ] The registry's **current** version still matches what you reviewed

## Triage priorities when scanning at scale

When you have many findings across a project or org, work in this order:

1. **Confirmed malicious install/runtime behavior** — harvest-and-exfiltrate, worm self-propagation, fetch-then-execute, destructive payload, or a campaign-IOC match. P0. Rip out, rotate exposed credentials, clear caches.
2. **Unexplained install scripts** doing network/secret/obfuscated work. P0–P1 by what they touch.
3. **Identity attacks on a real dependency** — typosquat / slopsquat / dependency-confusion candidate of something you actually use. P1; trivially exploited.
4. **Unscoped internal names** resolvable from a public registry. P1.
5. **Floating versions / missing or unenforced lockfile / missing integrity hashes.** P2; mostly mechanical, fix in bulk.
6. **No cooldown, no provenance verification, install scripts not disabled in CI.** P2.
7. **No SBOM / Scorecard / dependency-review automation.** P3.

Don't file a P0–P2 finding without a fix proposal. A ticket that says "this package is sketchy" rots; a PR that removes it, pins the rest, and adds `ignore-scripts` gets merged. For each finding, name the package and version, the pass that fired, and where the install or runtime context exposes secrets.

---

## Appendix: known-campaign markers

These are concrete indicators from real campaigns. They are the **perishable layer** — useful for fast matching, but secondary to the durable behavioral rules above, which catch the *next* campaign before it has a name. Match these, but never rely on them as the whole review: a clean IOC check does not mean a clean dependency.

**Shai-Hulud (npm worm, Sept 2025) and Shai-Hulud 2.0 "The Second Coming" (Nov 2025), 3.0:**
- Install hooks: `postinstall` (v1) → **`preinstall`** (v2/v3), running `node setup_bun.js` / `bun_installer.js`
- Dropped files: `setup_bun.js`, `bun_environment.js`, `bun_installer.js`, `environment_source.js` — installs the **Bun** runtime to run an obfuscated (>10 MB) payload outside Node's monitored process
- Behavior: harvests env/cloud creds (AWS/GCP/Azure IMDS + secret managers), runs **TruffleHog**, exfiltrates to a public GitHub repo described `Sha1-Hulud: The Second Coming.`; staged credential files `cloud.json`, `environment.json`, `contents.json`, `truffleSecrets.json`, `actionsSecrets.json`
- Persistence/C2: self-hosted GitHub Actions runner named **`SHA1HULUD`**, rogue workflow `discussion.yaml`
- Failsafe: wipes `$HOME` (`shred`/`rm`) if it can neither exfiltrate nor self-propagate — so **rotate credentials and remove persistence carefully**, and assume removal of the package alone is not cleanup
- Self-propagation: validates an npm token, enumerates the maintainer's packages, republishes up to 100 backdoored versions

**nx `s1ngularity` (npm, Aug 2025):**
- `postinstall` script `telemetry.js`; steals GitHub (`gh auth token`)/npm/SSH/env
- **Weaponized local AI CLIs** (`claude`, `gemini`, `q`) with `--dangerously-skip-permissions` / `--yolo` / `--trust-all-tools` to inventory secrets
- Exfiltrates triple-base64 `results.b64` to a public repo named `s1ngularity-repository-*`; appended a shutdown to `~/.bashrc`/`~/.zshrc`
- Root cause: a GitHub Actions injection that stole the npm publish token

**binding.gyp worm (npm, June 2026):**
- Vector: a tiny **`binding.gyp`** (~100 bytes) that triggers **`node-gyp`** during `npm install` — **no `preinstall`/`postinstall` in `package.json`**, so script-focused scanners and `ignore-scripts=true` miss it
- Shell expansion in `sources`: `"< $(node index.js >/dev/null) >/dev/null 2>&1 && echo stub.c)"` with `target_name: "Setup"`, `type: "none"` — runs root **`index.js`** (4.5–4.9 MB obfuscated) silently
- Staged payload: ROT-N Caesar decode → AES-128-GCM encrypted blobs → downloads **Bun v1.3.13** from GitHub → ~720 KB worm via Bun (outside Node's process tree)
- Behavior: harvests npm/GitHub/AWS/GCP/Azure/HashiCorp Vault/Kubernetes/RubyGems tokens, 1Password CLI/gopass/pass, and **masked GitHub Actions runner secrets from process memory**; **injects `setup-bun` + payload steps into GitHub Actions workflows**; republishes poisoned versions of the victim's npm/RubyGems packages (self-propagating worm); exfiltrates via **dangling GitHub commits** (RSA-encrypted, not reachable from any branch)
- Families hit (June 3–4, 2026 — list still growing): `@vapi-ai/server-sdk`, `ai-sdk-ollama`, `autotel*` / `awaitly*` / `executable-stories*` / `node-env-resolver*`, `@jagreehal/workflow`, `@evolvconsulting/evolv-coder-lite`, `wrangler-deploy`, and dozens more — see [StepSecurity's post](https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm) for the full IOC table
- Lesson: review **`binding.gyp`** and unexpected root **`index.js`** on every dependency diff, not just `package.json` scripts; `ignore-scripts` alone is not enough

**`chalk` / `debug` "Qix" compromise (npm, Sept 2025):**
- 18 packages (`chalk`, `debug`, `ansi-styles`, `strip-ansi`, `supports-color`, `color-convert`, …), ~2B weekly downloads, live ~2.5h
- Vector: maintainer **phished** via `npmjs.help` (fake 2FA reset); no install script — a browser-side crypto-wallet **clipper** that hooks `fetch`/`window.ethereum` and rewrites transaction addresses
- Lesson the durable rules encode: the most-downloaded packages are exactly the targets; a cooldown plus `npm audit signatures` (the malicious versions lacked provenance) would have caught it

**Older landmarks (same patterns):** `event-stream` (2018, malicious transitive dep targeting a wallet), `ua-parser-js`/`coa`/`rc` (2021, account-takeover cryptominers/stealers), `crossenv` (2017, typosquat of `cross-env`), `node-ipc` (2022, protestware data-wiper), `colors`/`faker` (2022, maintainer sabotage), `xz-utils` (2024, a multi-year social-engineering backdoor of an upstream maintainer — the case static manifest review can't catch, and why provenance + behavioral analysis matter).
