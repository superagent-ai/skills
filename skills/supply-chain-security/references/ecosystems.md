# Supply Chain by Ecosystem

To judge whether a dependency is safe, you have to know how *this* package manager behaves: where it runs install-time code, how it pins and verifies, whether names can be hijacked, and how to confirm provenance. This file is that reference. The recurring tells, in any ecosystem:

- An **install/build hook** that runs on `install` and does more than compile a platform binary into its own directory.
- A **floating version** (a range, `latest`, a git/URL dependency) instead of an exact pin plus a committed, integrity-bearing lockfile.
- A **name an attacker can claim** — unscoped and internal-looking (dependency confusion), or a near-miss of a popular one (typosquat).

Commands marked "registry" reach the public registry/OSV with package data only — the user runs them; the skill itself stays offline.

---

## npm / pnpm / yarn (JavaScript)

**Install hooks:** `preinstall`, `install`, `postinstall`, `prepare` in `package.json` `scripts`. `preinstall` runs before tooling can intervene (Shai-Hulud 2.0's choice). Transitive dependencies' hooks run too. Also **`binding.gyp`**: when present, npm invokes **`node-gyp`** to build a native addon — this runs **outside** lifecycle scripts and is **not** blocked by `ignore-scripts=true`. The June 2026 binding.gyp worm hides execution in shell expansion inside `sources` instead of `package.json` scripts.

**Pinning & lock:** ranges (`^1.2.3`, `~1.2.3`, `*`, `latest`) resolve to whatever the registry serves; pin exact (`1.2.3`). The lockfile (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) pins the full tree with `integrity` (`sha512:`). Enforce it: `npm ci`, `pnpm i --frozen-lockfile`, `yarn install --immutable`. A lockfile entry with a `resolved` URL but no `integrity` is functionally `latest`.

**Namespace / confusion:** scopes (`@org/pkg`) bind to one registry via `.npmrc` (`@org:registry=https://...`). **Unscoped** internal names are the dependency-confusion target. The `.npmrc` must be committed to the repo, not left in `~`, so a fresh clone can't fall back to the public registry.

**Disable hooks:** `ignore-scripts=true` in `.npmrc`, allowlist the few that need building (pnpm: `onlyBuiltDependencies`). **Caveat:** this does **not** stop a malicious **`binding.gyp`** from invoking `node-gyp` — inspect every new/changed `binding.gyp` and unexpected root `index.js` in the diff.

**Cooldown:** `min-release-age` (npm ≥ 11.10), `minimumReleaseAge` (pnpm, minutes; default on in pnpm 11), `npmMinimalAgeGate` (Yarn). Dependabot/Renovate have their own `cooldown` / `minimumReleaseAge`.

**Provenance:** npm provenance (SLSA via OIDC). Verify: `npm audit signatures`. Caveat: provenance proves *which build* produced the artifact, not that the publisher was *authorized* — an OIDC token stolen from CI yields valid attestations (the "Mini Shai-Hulud" `@tanstack` case).

**Registry checks:** `npm view <pkg> time` (recency), `npm view <pkg> maintainers dist.integrity`, `osv-scanner --lockfile=package-lock.json`, `cve-lite-cli` (OWASP; scans the npm/pnpm/yarn/bun lockfile against OSV with direct-vs-transitive visibility and `--fix` remediation, plus an `--offline` advisory DB for restricted networks). These are advisory/OSV matches — pair them with the behavioral review for malware that isn't in an advisory feed yet.

**Bug to flag:** a `preinstall`/`postinstall` doing network/secret/obfuscated work; a **`binding.gyp`** with shell expansion in `sources` or a `type: "none"` fake native target; `setup_bun.js` + `bun_environment.js`, `telemetry.js`, or a malicious `binding.gyp` + root `index.js`; a range or missing lockfile; an unscoped internal name; a lockfile entry with no `integrity`.

---

## PyPI (Python — pip, Poetry, uv, Pipenv)

**Install hooks:** legacy `setup.py` runs **arbitrary code at install** (`cmdclass`, custom `install`/`build` commands). PEP 517 builds (`pyproject.toml`) run the build backend. Wheels (`.whl`) don't execute on install but ship code that runs on first `import`.

**Pinning & lock:** `requirements.txt` should pin `==` and use `--require-hashes` (every package needs a `--hash=sha256:...`). Poetry's `poetry.lock` and uv's `uv.lock` carry hashes and a content hash; install with `poetry install`/`uv sync` (not a loose `pip install`).

**Namespace / confusion:** PyPI has **no namespaces** — a flat global namespace, so dependency confusion is trivial. Defenses are external: pin `--index-url` to an internal index (committed `pip.conf`), proxy through Artifactory/Nexus/devpi, and never rely on `--extra-index-url` fallthrough (it queries PyPI too).

**Cooldown / provenance:** Renovate `minimumReleaseAge` covers PyPI. PyPI supports Trusted Publishing (OIDC) and PEP 740 attestations; `pip install --require-hashes` is the integrity floor.

**Registry checks:** `pip index versions <pkg>`, `osv-scanner --lockfile=poetry.lock`, `pip-audit`.

**Bug to flag:** a `setup.py` with network calls or `os.system`/`subprocess` in the install path; `requirements.txt` without hashes; reliance on `--extra-index-url`; a name one typo from `requests`/`numpy`/`urllib3`, or a slop name (`requests-helper`, `py-utils-pro`).

---

## Go modules

**Install hooks:** none at `go get` / `go build` time — Go has no install scripts (a structural advantage). Risk is in the code that runs when imported/built, and in `//go:generate` (only on explicit `go generate`) and cgo.

**Pinning & lock:** `go.mod` pins versions; `go.sum` records cryptographic hashes of every module and is verified on every build. The checksum database (`sum.golang.org`, `GONOSUMCHECK`/`GONOSUMDB` to scope) provides transparency-log-backed integrity.

**Namespace / confusion:** module paths are domain-based (`github.com/org/mod`), so the namespace is owned by whoever controls the host — confusion is harder, but a typosquatted GitHub org or a mutable branch ref still bites.

**Registry checks:** `go list -m -versions <mod>`, `govulncheck ./...`, `osv-scanner --lockfile=go.mod`.

**Bug to flag:** a `replace` directive pointing at an unexpected fork/host; a dependency on a pseudo-version from an untrusted branch; a missing/edited `go.sum` entry.

---

## Cargo (Rust)

**Install hooks:** `build.rs` runs **arbitrary code at build time** — the primary install-time vector. cgo-style native builds too.

**Pinning & lock:** `Cargo.toml` ranges, `Cargo.lock` pins exact versions with checksums (built-in integrity). Commit the lockfile for binaries; libraries historically don't, so a consumer's resolution still floats.

**Namespace / confusion:** crates.io is a **flat namespace, no scopes** — typosquatting and confusion apply. Crate names are first-come.

**Registry checks:** `cargo search`, `cargo audit` (RustSec), `osv-scanner --lockfile=Cargo.lock`.

**Bug to flag:** a `build.rs` doing network/secret work; a `[dependencies]` git/path source pointing off crates.io; a name near-miss of `serde`/`tokio`/`rand`.

---

## RubyGems (Ruby / Bundler)

**Install hooks:** native extensions (`extconf.rb` / `Rakefile` `ext`) run on install; a gem's code runs on `require`. `gem install` executes the gemspec.

**Pinning & lock:** `Gemfile` ranges (`~>`), `Gemfile.lock` pins exact with no per-gem hash by default — enable `bundle config set --local verify_files true` and source checksums (Bundler ≥ 2.6 `checksums` in the lock). `bundle install --frozen` refuses lockfile drift.

**Namespace / confusion:** flat namespace, **no scopes** — confusion and typosquatting apply.

**Registry checks:** `gem list -r -a <name>`, `bundler-audit`, `osv-scanner --lockfile=Gemfile.lock`.

**Bug to flag:** an `extconf.rb`/post-install with network or shell; a gem from a non-rubygems `source`; a name near-miss of a popular gem.

---

## Maven / Gradle (Java / Kotlin)

**Install hooks:** no install-time scripts, but a build plugin (Maven plugin, Gradle plugin or `build.gradle` script) runs **arbitrary code at build**, and dependencies execute when the app runs.

**Pinning & lock:** coordinates are `groupId:artifactId:version`; pin exact versions (no version ranges, no `latest.release`/`+`). Integrity: Maven `--strict-checksums`; Gradle dependency verification (`gradle/verification-metadata.xml` with SHA-256 + signatures). Use a single proxy repo (Nexus/Artifactory).

**Namespace / confusion:** `groupId` is namespaced and (on Maven Central) ownership-verified by domain, which blunts confusion — but a `repositories` block adding an untrusted repo, or a `groupId` typosquat, reopens it.

**Registry checks:** OSS Index / `dependency-check`, `osv-scanner` on the lockfile/verification metadata.

**Bug to flag:** a version range or dynamic version; an extra `repositories`/`pluginRepositories` entry pointing off your proxy; a build plugin from an unknown coordinate.

---

## NuGet (.NET)

**Install hooks:** modern SDK-style packages don't run `install.ps1` (that was `packages.config` era), but MSBuild `.targets`/`.props` shipped in a package execute at build, and the library runs at app runtime.

**Pinning & lock:** `PackageReference` with `<PackageVersion>` (use Central Package Management); enable a lock file (`packages.lock.json`, `RestorePackagesWithLockFile`) and `--locked-mode`. Verify signatures (`dotnet nuget verify`); NuGet supports **prefix reservation** (`Microsoft.*`), so a reserved-prefix impostor is a strong signal.

**Namespace / confusion:** IDs are flat but prefix reservation + signed packages help. Confusion still applies to unreserved internal IDs across a public+private feed.

**Registry checks:** `dotnet list package --vulnerable`, `osv-scanner`.

**Bug to flag:** floating version; a feed added in `nuget.config` you don't control; an unsigned package or one impersonating a reserved prefix; a build `.targets` with suspicious commands.

---

## Composer (PHP)

**Install hooks:** `scripts` events (`post-install-cmd`, `post-update-cmd`, `post-autoload-dump`) run on install/update — arbitrary code.

**Pinning & lock:** `vendor/package` coordinates; `composer.lock` pins exact with `dist.shasum`. `composer install` (not `update`) honors the lock; commit it.

**Namespace / confusion:** `vendor/package` is namespaced on Packagist (vendor is claimed), which helps — but VCS `repositories` entries and `minimum-stability: dev` reopen risk.

**Registry checks:** `composer audit`, `osv-scanner --lockfile=composer.lock`.

**Bug to flag:** a `scripts` hook running shell/network; a custom `repositories` VCS source; `minimum-stability` loosened to `dev`; a missing or stale `composer.lock`.

---

## Cross-ecosystem summary

| Ecosystem | Install-time code | Lock + integrity | Namespace (confusion exposure) |
|---|---|---|---|
| npm/pnpm/yarn | `pre/post/install`, `prepare` | lockfile + `sha512` `integrity`; `npm ci` | scopes `@org/` — **unscoped is exposed** |
| PyPI | `setup.py`, PEP 517 builds | `--require-hashes`, `poetry.lock`/`uv.lock` | **none — fully exposed** |
| Go | none (`go generate` only) | `go.sum` + checksum DB | domain-based — low |
| Cargo | `build.rs` | `Cargo.lock` checksums | **flat — exposed** |
| RubyGems | native ext, gemspec | `Gemfile.lock` (+ `verify_files`) | **flat — exposed** |
| Maven/Gradle | build plugins/scripts | strict checksums / verification-metadata | `groupId` (domain-verified) — low |
| NuGet | MSBuild `.targets` | `packages.lock.json` + signatures | flat + prefix reservation — medium |
| Composer | `scripts` events | `composer.lock` `shasum` | `vendor/` — medium |

The two ecosystems with both **arbitrary install-time code** and **no namespace protection** — npm (unscoped) and PyPI — are where the overwhelming majority of real-world supply-chain malware lands. Weight your review accordingly.
