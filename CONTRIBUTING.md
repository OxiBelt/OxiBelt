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
| `source/` | Main Rust reverse proxy crate. | You are changing runtime, proxy, TLS, WAF, routing, config, admin, or binary behavior. |
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
tests/scripts/check-rust-module-size.sh
cargo audit
cargo deny check advisories
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

Treat 750 lines as the review threshold for Rust source files under
`source/src/`. Files above that threshold should be split into smaller
responsibility-focused modules unless there is a documented reason to keep the
implementation together. Existing oversized files are tracked by
`tests/scripts/check-rust-module-size.sh` and should shrink over time rather
than grow.

Keep module boundaries explicit:

- Load balancing logic should not be placed in TLS-specific files such as
  `source/src/tls.rs`.
- WAF or request filtering logic should not be placed in TLS-specific files.
- TLS handshake, certificate, and client root behavior should remain in
  TLS-focused modules.
- HTTP forwarding behavior should remain in proxy-focused modules.
- Configuration parsing should remain in configuration-focused modules.

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
steps do not consume each other's `steps.<id>.outputs` values. Keep
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
tests/scripts/check-rust-module-size.sh
cargo audit
cargo deny check advisories
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

CI should also run Docker-based integration checks, such as:

```sh
tests/scripts/build-targets.sh
tests/scripts/run-proxy-integration.sh
```

If TypeScript DevOps tooling is added, CI should run its typecheck, lint, and
tests. If browser WebDriver tests are added, CI must run them with both
Chromium and Firefox.

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
