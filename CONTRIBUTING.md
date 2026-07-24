# Contributing to OxiBelt

Thanks for helping improve OxiBelt. This project is a public-facing reverse
proxy and WAF, so changes to proxying, routing, TLS, QUIC, headers, request
bodies, OxiRule evaluation, rate limiting, and configuration validation must be
reviewed as security-sensitive unless there is a clear reason they are not.

Use root-relative paths in root-level documentation, scripts, issues, and pull
request notes. For example, prefer `source/config/oxibelt.toml` over
`config/oxibelt.toml` unless the text explicitly says the command is being run
from `source/`.

## Repository Layout

Generated and local-only directories such as `target/`, `source/target/`,
`node_modules/`, and `tests/.tmp/` are not source contributions and should not
be committed.

| Path | Purpose | Change here when |
| --- | --- | --- |
| `Cargo.toml` | Rust workspace, committed package-version sentinel, shared dependency policy, and default members. | Package ownership, shared dependency, committed package metadata, or default members change. |
| `source/` | Integrated data-plane and Admin runtime crate. | You are changing runtime, proxy, TLS, WAF, routing, config, Admin, or Person Proof behavior. |
| `source/apps/` | Independently packaged controller, CLI, keysigner, and netport binaries. | External orchestration, operator tooling, or role-specific helper behavior changes. |
| `source/crates/` | Shared external-control protocol and HTTP client crates. | Stable cross-package models or controller transport behavior changes. |
| `source/assets/` | Canonical build-validated assets embedded in the runtime. | Person Proof or Admin OpenAPI embedding contracts change. |
| `source/src/proxy/` | HTTP, HTTP/3, streaming, WebSocket, WebTransport, and forwarding behavior. | You are changing request or response proxy semantics. |
| `source/src/waf/` | OxiRule, CRS compatibility, body scanning, Person proof, and WAF evaluation. | You are changing request, response, or stream filtering behavior. |
| `source/src/config/` and `source/src/config.rs` | Configuration loading, validation, and typed config modules. | You are adding or changing TOML syntax, defaults, validation, or compatibility. |
| `source/src/tls.rs` and TLS-related modules | Downstream and upstream TLS behavior. | You are changing certificate, client root, remote signer, OCSP, ECH, or TLS policy behavior. |
| `source/config/oxibelt.toml` | Example or default configuration. | User-visible configuration examples need to stay valid. |
| `source/ops/Dockerfile.alpine` | Release Docker image. | Runtime image, package, build, or container layout changes. |
| `deploy/` | Deployable Helm charts and observability assets. | Kubernetes deployment assets, Helm chart templates, dashboards, Prometheus, or collector starter assets change. |
| `tests/rust/` | Rust integration tests and repository-level checks. | Behavior changes need regression coverage. |
| `tests/docker/` | Docker-only mock upstreams, probes, PostgreSQL, DNS, and performance services. | Docker integration, protocol, or performance scenarios need fixtures. |
| `tests/scripts/` | Build, integration, performance, WebDriver, and cleanup orchestration. | Local or CI test flows change. |
| `docs/` | Technical specifications, configuration guides, OxiRule docs, and performance docs. | User-visible behavior, syntax, compatibility, or operations guidance changes. |
| `ui/person-proof/` | Person proof challenge UI workspace. | Browser-visible Person proof assets or build behavior changes. |
| `kernel-extension/` | Host tuning templates and verification helpers. | Linux edge deployment limits, sysctl, or systemd tuning changes. |
| `devops/` | TypeScript-based DevOps and CI support code. | DevOps automation is added or changed. |
| `.github/workflows/` | GitHub Actions workflows. | CI job structure, matrices, or required checks change. |

## Contribution Workflow

1. Identify the affected area before editing: Rust proxy implementation, TLS,
   route/config behavior, Docker test environment, Rust integration tests,
   TypeScript DevOps tooling, GitHub Actions CI, UI assets, kernel extension
   templates, or documentation.
2. Make the smallest reasonable change for the behavior being changed.
3. Add or update tests when proxy, TLS, routing, WAF, configuration, runtime,
   Docker, WebDriver, or CI behavior changes.
4. Update documentation when behavior, configuration syntax, commands,
   technical specifications, operations guidance, or CI workflows change.
5. Run the relevant checks and mention any checks that could not be run.
6. Verify that generated test data and Docker resources are cleaned up.

When changing Rust code, prefer workspace-level commands from the repository
root:

```sh
cargo fmt --check
tests/scripts/check-tests-rustfmt.sh
tests/scripts/check-rust-module-size.sh --warn
cargo audit
cargo deny check
cargo vet --locked
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

Run Docker and integration checks when the change affects containers,
protocol-level behavior, browser-visible behavior, or release images:

```sh
tests/scripts/build-targets.sh
tests/scripts/run-proxy-integration.sh
```

Performance-related changes may also need:

```sh
tests/scripts/run-proxy-performance.sh --profile smoke --comparators oxibelt,nginx,caddy
```

If a command must be run from `source/`, say so explicitly in the command block
or pull request notes.

## Release Changelog and Upgrade Contract

`CHANGELOG.md` is the stable-release ledger. `CHANGELOG-beta.md` is the
beta-release ledger. Do not put beta entries in the stable ledger, and do not
create `CHANGELOG-build.md`: development tags of the form
`X.Y.Z-build.<sha8>` have no changelog entry or GitHub Release.

Add stable and beta entries in strict descending SemVer order. A governed entry
uses the heading `## [VERSION] - YYYY-MM-DD`, followed by these metadata lines:

```md
- Changes since: `PREVIOUS_VERSION`
- Supported upgrade sources: `PREVIOUS_VERSION`
- Upgrade guide: [Upgrade from PREVIOUS_VERSION](docs/Upgrading.md#exact-anchor)
```

The comparison base for a stable release and for `beta.1` is the immediately
preceding stable release. The comparison base for `beta.N`, where `N > 1`, is
the preceding beta for the same target; that entry must list both the
preceding beta and preceding stable release as supported upgrade sources.

Every governed entry must contain these level-three sections in this order:
`Configuration`, `Schema epochs`, `Deprecations and removals`, `Admin API`,
`Feature lifecycle`, `Rulepack compatibility`, `Executables and images`,
`Storage and state`, `Upgrade validation`,
`Rollback and irreversible steps`, `Known issues`, and `Security`. Use
`- No changes for this release.` only for an inapplicable section, and
`- None known at release cut.` when there are no known issues. The complete
entry cannot be placeholder-only. Upgrade validation must include an exact
`sh` or `bash` command block, and rollback guidance must state how to recover
or which step is irreversible.

Update `docs/Upgrading.md` whenever a change affects configuration or schema
compatibility, the Admin API, feature lifecycle, rulepack compatibility,
executable/image roles, or persisted state. Validate the ledger and changed
compatibility surfaces with:

```sh
pnpm run release-contract:check
```

When a stable or beta tag is pushed, the tag workflow binds the entry to the
exact tag commit and prepares a draft GitHub Release. It never publishes the
draft and never overwrites a differing draft or published release. A person
must review and publish the draft; the image-publication workflow then
revalidates the published body against the same exact-revision contract before
publishing artifacts.

## Commit Messages

Use Conventional Commits for commit messages:

```text
<type>(<scope>): <subject>
```

- `type` must be one of `feat`, `fix`, `chore`, `docs`, `ci`, `refactor`,
  `security`, `tests`, or `perf`.
- `scope` is the field, area, or responsibility touched by the code, such as
  `http3`, `static_files`, `tls`, `waf`, `config`, `workflows`, or `docs`.
- `subject` is a short imperative summary. Use a present-tense verb. Do not use
  past tense or past-perfect wording.
- In the commit title and detailed description, wrap code keywords, paths,
  commands, configuration keys, header names, function names, variable names,
  type names, module names, and literal values in Markdown inline code spans
  with backticks.

Valid examples:

```text
feat(http3): add `WebTransportSessionIndex` drain coverage
fix(static_files): reject `..` traversal attempts
security(headers): block ambiguous `Transfer-Encoding` framing
ci(workflows): run docker integration matrix
```

Avoid examples like `fixed route matching`, `added TLS tests`, or
`has updated docs` because the subject is not imperative present tense. Also
avoid leaving identifiers unformatted, such as `update validate_static_root`;
write ``update `validate_static_root``` instead.

## Rust Module Organization

Do not force unrelated functionality into an existing Rust source file just
because the file already exists.

If new code belongs to a different responsibility or feature category, add a
new Rust module or source file under the most appropriate directory and wire it
through `mod.rs`, `lib.rs`, or `main.rs` as needed.

Treat 750 lines as an advisory review threshold for Rust source files under
`source/src/`, not as the definition of a sound module boundary. A file above
that threshold should prompt a responsibility and dependency review, but it
does not fail CI solely because of its length. Run
`tests/scripts/check-rust-module-size.sh --warn` for the advisory report; use
`--enforce` only when a deliberately hard line-count check is required.
Enforced dependency direction, package feature isolation, and public API
ownership are documented in
[Dependency Boundaries](docs/DependencyBoundaries.md).

Keep module boundaries explicit:

- Load balancing logic should not be placed in TLS-specific files such as
  `source/src/tls.rs`.
- WAF or request filtering logic should not be placed in TLS-specific files.
- TLS handshake, certificate, and client root behavior should remain in
  TLS-focused modules.
- HTTP forwarding behavior should remain in proxy-focused modules.
- Configuration parsing should remain in configuration-focused modules.

Keep dependencies directed toward side-effect-free policy and representation
code:

- Parsers and normalizers may build typed representations, but must not perform
  filesystem, network, database, runtime-state, or Admin-routing operations.
- WAF evaluators may consume compiled plans, but must not load configuration or
  external files.
- Configuration modules must not depend on proxy request handling or runtime
  snapshot ownership.
- Data-plane request paths must not depend on Admin HTTP routing, CLI packages,
  or Kubernetes controller packages.
- Storage adapters must expose narrow mechanics and must not own cache, rate,
  or failure policy.
- Observability must consume bounded, redacted projections instead of reaching
  into credentials, raw request headers, URIs, or bodies.

Responsibility modules on HTTP, WAF, cache, and other request hot paths should
use concrete stack-owned orchestration. A decomposition must not introduce
trait-object dispatch, boxed futures, locks, channels, tasks, or unconditional
request cloning merely to cross a new module boundary.

When adding a new Rust file or module, choose a responsibility-focused name,
add tests for new behavior, update technical documentation when behavior is
user-visible, and avoid generic utility modules unless the shared
responsibility is clear.

## Area Guidelines

Be especially careful when modifying:

- `source/src/proxy/http.rs`
- `source/src/tls.rs`
- `source/src/routes.rs`
- `source/src/server.rs`
- `source/src/runtime.rs`
- `source/src/state.rs`
- `source/src/config.rs`

Do not silently change HTTP or TLS behavior. Reverse proxy changes should
explicitly consider request and response header forwarding, `Host` handling,
`Forwarded` and `X-Forwarded-*` headers, timeout behavior, upstream connection
behavior, TLS configuration, route matching, configuration compatibility, error
handling, and logging behavior.

Configuration changes must update `source/src/config.rs` or the relevant
module under `source/src/config/`, update route-related logic when needed,
update `docs/OxiRule.md` or `docs/Configuration.md` when syntax or semantics
change, add or update tests in `tests/rust/config_and_routes.rs`, and keep
`source/config/oxibelt.toml` valid.

Detailed technical specifications belong under `docs/`, not only in
`README.md`. Update `README.md` for setup, usage, high-level project
information, or discoverability changes. Update the relevant `docs/` file for
technical behavior, configuration rules, routing semantics, TLS behavior,
proxy behavior, compatibility, or migration notes.

## Tests and Temporary Data

Rust tests live under `tests/rust/`. Docker-based test utilities live under
`tests/docker/`. Test scripts live under `tests/scripts/`.

When modifying proxy, TLS, routing, WAF, configuration, runtime, or Docker
behavior, update or add tests in the relevant area. Do not remove tests just to
make CI pass, and do not disable TLS, proxy, route, configuration, Chromium, or
Firefox WebDriver tests without documenting the reason.

Tests may need short-lived generated files, such as self-signed TLS
certificates, private keys, temporary configuration files, generated CA roots,
mock upstream fixtures, or probe output files. Treat these as disposable test
data:

- Generate temporary data at test startup or test-suite setup time.
- Use each generated data set only for the relevant test run.
- Delete generated files when the test or test suite finishes.
- Prefer temporary directories over fixed paths inside the repository.
- Avoid committing generated certificates, private keys, runtime configs, logs,
  or probe output files.
- Ensure cleanup also runs when tests fail, where practical.
- Do not reuse stale TLS certificates, keys, or generated configs across
  independent test runs unless the reuse is explicit, safe, and documented.

For TLS tests, self-signed certificates and private keys should be generated
automatically and removed after the tests complete.

## Docker and Integration Tests

Docker-based tests should be reproducible locally and in GitHub Actions.

When changing Docker behavior:

- Avoid depending on host-installed services.
- Keep Docker builds reproducible.
- Prefer explicit package versions when practical.
- Make Docker-based tests work in CI.
- Do not assume local-only paths outside the repository.
- Clean up Docker resources created by tests.

Docker-based virtual environment tests must remove related test containers,
test networks, test-only images, and temporary volumes. Prefer explicit
container, image, network, volume, or label names so cleanup does not remove
unrelated developer resources.

Some developers work inside a Dev Container while Docker is exposed through
Docker outside of Docker. In that environment, bind mounts and host paths can
behave differently from a normal local shell. Prefer `docker cp` or named
Docker volumes instead of relying on fragile host-specific bind mounts when
practical.

Keep `tests/scripts/run-proxy-integration.sh` usable from a clean checkout.
Failures should be easy to diagnose, mock upstream behavior should be
deterministic, and test ports, hostnames, and container names should be
explicit.

## Browser and DevOps Changes

If browser-based tests are added, they must run with both Chromium WebDriver
and Firefox WebDriver. Browser tests should run headless, run locally through
Docker, run in GitHub Actions, avoid browser-specific timing assumptions, and
use explicit waits instead of fixed sleeps where possible.

Deployable Helm charts and observability assets live under `deploy/`. The
`devops/` directory is reserved for TypeScript-based DevOps and CI support
code when such tooling is present. Keep scripts deterministic, avoid hidden
local dependencies, prefer explicit configuration, validate generated or
modified GitHub Actions workflow files, and keep CI behavior compatible with
Linux GitHub-hosted runners unless otherwise documented.

Use GitHub Actions `parallel` only for independent same-job steps whose child
steps do not consume each other's `steps.<id>.outputs` or
`steps['<id>'].outputs` values. Keep
long-running service lifecycles out of CI workflows unless the matching
workflow integrity tests validate the required `background`, `wait`,
`wait-all`, or `cancel` behavior. Current local `actionlint` releases may lag
behind newly documented GitHub Actions syntax, so pair workflow linting with
`cargo test --test ci_workflow_integrity --locked` for `parallel` changes.

If package manager files are added under `devops/`, document the expected
commands. For example:

```sh
cd devops
npm ci
npm run typecheck
npm run lint
npm test
```

Adjust those commands if the directory uses `pnpm`, `yarn`, or `bun`.

GitHub Actions should run at least:

```sh
cargo fmt --check
tests/scripts/check-tests-rustfmt.sh
tests/scripts/check-rust-module-size.sh --warn
cargo audit
cargo deny check
cargo vet --locked
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

CI should also run Docker-based integration checks, such as:

```sh
tests/scripts/build-targets.sh
tests/scripts/run-proxy-integration.sh
```

Every ordinary non-Dependabot pull request runs the complete non-benchmark
validation graph without path-based skipping. The stable
`PR non-benchmark summary` check observes every required Rust, security,
container, Kubernetes, integration, signer, and browser job and fails when a
dependency fails, is cancelled, or is unexpectedly skipped. Comparative
performance, profiling, baseline, and long-load jobs remain scheduled or
manually dispatched and start only after the same workflow run passes the
non-benchmark summary. Pull-request image scans may generate and upload local
dependency snapshot artifacts, but only a trusted default-branch push,
schedule, or explicitly opted-in manual run may submit them to GitHub.

Release-like tags are governed by the tracked
`devops/config/github-release-tag-ruleset.json` policy. Tag creation requires
the GitHub Actions `Non-benchmark validation summary` status, and matching tags
cannot be updated or deleted; the active policy has no bypass actors. Wait for
the canonical default-branch push at the intended commit to pass before
creating the tag, and retry tag creation after that check succeeds if an
earlier attempt was rejected.

Release publication resolves the full tag ref and revision, then independently
queries the newest attempt of the canonical default-branch `Check OxiBelt`
push for that exact commit. It accepts only the single successful terminal
summary and its GitHub Actions check identity; failed, cancelled, skipped,
missing, duplicate, stale, or mismatched evidence blocks release metadata,
image publication, attestations, manifests, and alias promotion. Benchmark
jobs and dependency-snapshot submission remain outside the release
prerequisite.

If TypeScript DevOps tooling is added, CI should run its typecheck, lint, and
tests. If browser WebDriver tests are added, CI must run them with both
Chromium and Firefox.

OxiBelt uses the root pnpm workspace for TypeScript DevOps tooling under
`devops/`. When changing release versioning, GHCR image publishing, or other
DevOps TypeScript automation, run:

```sh
corepack enable
corepack install
pnpm install --frozen-lockfile
pnpm run dependency-admission
pnpm run lint
pnpm run typecheck
pnpm run test
pnpm run image-vulnerability-policy:check
pnpm run versioning:check
```

Changes to `supply-chain/image-vulnerability-policy.json`, the release image
scanner, or its evaluator are security-sensitive release-boundary changes.
Keep stable and beta releases fail-closed for every `CRITICAL` finding and
every `HIGH` finding with a nonempty fixed version; development build releases
remain fail-closed for every `CRITICAL` finding. Do not suppress findings in
Trivy or substitute Cargo or Node admission for the image gate.

A vulnerability exception must identify one exact vulnerability, package
identity and version, image role, release channel, and architecture. It also
requires a named `@owner`, rationale, impact analysis, an OxiBelt issue or pull
request approval reference, review date, and bounded expiry. Wildcard,
open-ended, malformed, expired, stale, partially matching, or otherwise
overbroad exceptions must fail admission. Keep raw scan reports available when
the gate fails, and record the policy change, approval, affected release
subjects, and focused policy-test evidence in the pull request.

### Repository Version Policy

The committed development version is the `0.0.0` sentinel. The root Cargo
workspace owns that value; production Cargo packages inherit it, first-party
fuzz, test, and probe packages declare it explicitly, and their generated lock
entries must agree. Private npm workspace packages and both Helm charts'
`version` and `appVersion` fields also remain `0.0.0`; the private root npm
orchestration package remains versionless, and `package.json` and
`pnpm-workspace.yaml` must name the same policy-covered workspaces.

The sentinel is package metadata, not OxiBelt's runtime or product identity. A
direct source-archive build uses the complete development identity tuple
`0.0.0-dev.archive`, unknown revision, ref, and dirty state, and
`source_archive` build kind. The canonical build-identity layer supplies
validated Git development or official release identities to binaries, runtime
metadata, and OCI labels; its source-archive fallback remains bound to the same
archive version.

`pnpm run versioning:check` is the authoritative committed-state gate. It must
validate every policy-bearing Cargo, lockfile, Docker/archive, npm, Helm, and
release-helper default and report all mismatches together, naming each file or
package, its expected value, and its actual value.

Release tooling may rewrite only the root Cargo workspace version and the
production package entries in `Cargo.lock`, and only inside a disposable
release checkout or worktree. Sentinel-only Cargo packages, npm packages, Helm
charts, and direct-build archive defaults remain unchanged. Never commit files
rewritten for a release build.

## Security Requirements

Do not hard-code:

- secrets
- tokens
- credentials
- private URLs
- cookies
- certificates or private keys

Be careful with:

- `Authorization`
- `Cookie`
- `Set-Cookie`
- `Host`
- `Forwarded`
- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

Do not weaken TLS behavior, certificate validation, proxy isolation, or
security-sensitive defaults without tests and documentation.

OxiBelt is a public-facing reverse proxy and WAF. Treat all client-controlled
HTTP, TLS, QUIC, header, body, path, routing, and OxiRule inputs as untrusted.

When modifying HTTP proxy behavior, explicitly consider:

- conflicting `Content-Length` headers
- `Transfer-Encoding` and `Content-Length` ambiguity
- hop-by-hop header removal
- `Connection` header token handling
- `Upgrade` and WebSocket forwarding
- `Host` and authority handling
- absolute-form request targets
- path normalization and percent-decoding
- duplicate header behavior
- request body size limits
- response body size or streaming behavior
- timeout and backpressure behavior
- upstream connection reuse isolation

Do not normalize, drop, merge, or forward security-sensitive headers without
tests that describe the intended behavior.

For security-related changes:

1. Identify the affected trust boundary.
2. Identify attacker-controlled inputs.
3. Describe the vulnerability class or suspected vulnerability class.
4. Add or update regression tests whenever practical.
5. Prefer fail-closed behavior for security-sensitive decisions.
6. Avoid introducing `unwrap`, `expect`, `panic!`, `todo!`, or `unreachable!`
   on externally reachable input paths.
7. Avoid silently ignoring errors in proxying, TLS handling, routing, WAF
   evaluation, Person proof validation, rate limiting, configuration
   validation, or upstream forwarding.
8. Run the relevant tests or clearly state why they could not be run.
9. Summarize remaining risks and compatibility concerns.

First-party Rust denies unsafe code by default. Follow
[`docs/UnsafeCode.md`](docs/UnsafeCode.md) for the exact allowlist, required
safety documentation, focused validation, and review process. A change to an
allowlisted module or the allowlist requires approval from a named reviewer
other than the author, with the safety model and Miri, sanitizer, syscall-test,
and fuzz evidence recorded in the pull request.

Dependency admission is security-sensitive. Changes to Cargo or pnpm
manifests, lockfiles, `deny.toml`, `supply-chain/`, lifecycle-script approvals,
or dependency exceptions must run the repository admission checks. A new
direct dependency, a new security-critical major version, a source or feature
change to a critical dependency, a new Rust build script or pnpm lifecycle
script, or a new exception requires a named owner and tracking issue. Record
the source and unsafe-code review, license and maintenance review, alternatives
considered, and any fuzzing or wrapper boundary in the pull request. Cargo-vet
evidence must use `safe-to-deploy` for runtime dependencies and `safe-to-run`
for development or build-only dependencies. Exceptions must match the shared
policy ledger exactly and may not be open-ended.

Security-sensitive decisions include WAF and OxiRule evaluation, route matching
and route authorization, Person proof validation, bot, agent, and person
classification, rate limiting, TLS policy decisions, upstream selection,
request filtering, header normalization, body size enforcement, and timeout
enforcement.

If a security-sensitive operation fails, the default should be deny, block,
challenge, or return a safe error unless there is a documented and tested
reason to allow the request.

## Do Not

- Do not remove tests just to make CI pass.
- Do not disable TLS, proxy, route, configuration, Chromium, or Firefox
  WebDriver tests without a documented reason.
- Do not commit `target/`, `node_modules/`, generated build artifacts,
  generated certificates, private keys, temporary configs, logs, or probe
  output files unless explicitly required.
- Do not make CI depend on local-only files or absolute host paths.
- Do not silently change public proxy behavior.
- Do not change configuration syntax without updating docs and tests.
- Do not put detailed technical specifications only in `README.md` when they
  belong under `docs/`.
- Do not leave Docker test containers, networks, images, or temporary volumes
  behind after Docker-based tests finish.
- Do not rely on Dev Container bind-mount paths being visible to the Docker
  daemon in the same way as inside the container.

## Pull Request Checklist

Before opening or marking a pull request ready:

- The commit messages use the documented Conventional Commits format.
- The affected area is clear in the pull request description.
- User-visible behavior changes are covered in `README.md` or `docs/` as
  appropriate.
- Compatibility-surface changes update `docs/Upgrading.md` or the appropriate
  stable/beta changelog entry and pass `pnpm run release-contract:check`.
- Configuration changes update tests, docs, and example configuration when
  needed.
- Proxy, TLS, routing, WAF, runtime, or security-sensitive changes include
  regression tests whenever practical.
- Relevant local checks were run, or any skipped checks are explained.
- Temporary test data was removed.
- Docker-based tests clean up containers, networks, test-only images, and
  temporary volumes.
- Security-sensitive changes describe trust boundaries, attacker-controlled
  inputs, failure behavior, remaining risks, and compatibility concerns.
- Unsafe-code allowlist or allowlisted-module changes name a non-author
  security reviewer and include the evidence required by `docs/UnsafeCode.md`.
