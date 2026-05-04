# AGENTS.md

## Project Overview

OxiBelt is a Rust-based reverse proxy project.

This repository is organized as a monorepo. The main reverse proxy implementation lives under `source/`. Tests live under `tests/`. Technical specifications and configuration documentation live under `docs/`. DevOps and CI-related automation should live under `devops/`.

The project should be testable locally and in CI using Docker-based environments.

## Repository Structure

- `source/`
  - Main Rust reverse proxy crate.
- `source/src/`
  - Core application source code.
- `source/src/proxy/`
  - HTTP proxy implementation.
- `source/src/proxy/http.rs`
  - HTTP reverse proxy behavior.
- `source/src/tls.rs`
  - TLS-related behavior.
- `source/src/config.rs`
  - Configuration loading and validation.
- `source/src/routes.rs`
  - Route matching and route configuration logic.
- `source/config/oxibelt.toml`
  - Example or default OxiBelt configuration.
- `source/ops/Dockerfile.alpine`
  - Alpine-based Docker image for OxiBelt.
- `tests/rust/`
  - Rust integration tests.
- `tests/rust/common/`
  - Shared Rust test helpers.
- `tests/docker/mock_upstream/`
  - Mock upstream service used for proxy integration tests.
- `tests/docker/pq_probe/`
  - Rust-based probe container for post-quantum or TLS-related testing.
- `tests/scripts/`
  - Test orchestration scripts.
- `docs/`
  - Technical specifications, configuration guides, rule documentation, and behavior references.
- `docs/OxiRule.md`
  - OxiBelt rule specification and configuration documentation.
- `devops/`
  - TypeScript-based DevOps and GitHub Actions support code.
- `.github/workflows/`
  - GitHub Actions workflows, if present.

## Path and Working Directory Guidelines

Commands may be run either from the repository root or from `source/`.

If a command assumes `source/` as the working directory, document that explicitly.

Root-level documentation should use root-relative paths, for example:

- `source/config/oxibelt.toml`
- `source/ops/Dockerfile.alpine`
- `tests/scripts/run-proxy-integration.sh`
- `tests/docker/mock_upstream/Dockerfile`

Avoid ambiguous paths such as `config/oxibelt.toml` or `ops/Dockerfile.alpine` in root-level documentation unless the text clearly says that the command is being run from `source/`.

## Rust Workspace Guidelines

This repository has a root `Cargo.toml` and a Rust crate under `source/`.

When changing Rust code:

- Prefer workspace-level commands from the repository root when possible.
- Use `cargo fmt` before committing.
- Use `cargo clippy` and fix warnings where practical.
- Add or update tests under `tests/rust/` when behavior changes.
- Avoid changing proxy, TLS, route, or configuration behavior without corresponding tests.

Recommended checks:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

If a command must be run from `source/`, document that clearly.


## Rust Module Organization Guidelines

Do not force unrelated functionality into an existing Rust source file just because the file already exists.

If new code belongs to a different responsibility or feature category, add a new Rust module or source file under the most appropriate directory and wire it through `mod.rs`, `lib.rs`, or `main.rs` as needed.

Examples:

- Load balancing logic should not be placed in TLS-specific files such as `source/src/tls.rs`. Prefer a dedicated module such as `source/src/load_balancing.rs` or `source/src/proxy/load_balancing.rs`, depending on its scope.
- WAF or request filtering logic should not be placed in TLS-specific files. Prefer a dedicated module such as `source/src/waf.rs`, `source/src/security/waf.rs`, or `source/src/proxy/filter.rs`, depending on the design.
- TLS handshake, certificate, and client root behavior should remain in TLS-focused modules.
- HTTP forwarding behavior should remain in proxy-focused modules.
- Configuration parsing should remain in configuration-focused modules.

When adding a new Rust file or module:

- Choose a name that clearly reflects the feature responsibility.
- Keep module boundaries explicit and easy to review.
- Add tests for the new behavior.
- Update technical documentation under `docs/` when the behavior is user-visible or configuration-related.
- Avoid creating overly generic utility modules unless the shared responsibility is clear.

## Reverse Proxy Guidelines

Be especially careful when modifying:

- `source/src/proxy/http.rs`
- `source/src/tls.rs`
- `source/src/routes.rs`
- `source/src/server.rs`
- `source/src/runtime.rs`
- `source/src/state.rs`
- `source/src/config.rs`

Do not silently change HTTP or TLS behavior.

Changes to the reverse proxy should consider:

- request header forwarding
- response header forwarding
- `Host` handling
- `Forwarded` and `X-Forwarded-*` headers
- timeout behavior
- upstream connection behavior
- TLS configuration
- route matching
- configuration compatibility
- error handling
- logging behavior

## Configuration Guidelines

The main example configuration is:

```sh
source/config/oxibelt.toml
```

When changing configuration behavior:

- Update `source/src/config.rs`.
- Update route-related logic if needed.
- Update `docs/OxiRule.md` when rule syntax or semantics change.
- Add or update tests in `tests/rust/config_and_routes.rs`.
- Keep example configuration valid.

Configuration-related changes should not be treated as code-only changes. They must be reflected in tests and technical documentation when they affect user-visible behavior.

## Documentation Guidelines

The `docs/` directory is responsible for technical specifications and configuration-focused documentation.

Use `docs/` for:

- OxiBelt rule specifications
- configuration syntax and semantics
- routing behavior
- TLS behavior documentation
- proxy behavior references
- technical design notes
- compatibility or migration notes

When changing user-visible technical behavior:

- Update `README.md` if setup, usage, or high-level project information changes.
- Update the relevant Markdown files under `docs/` if technical behavior, configuration rules, routing semantics, TLS behavior, or proxy behavior changes.
- Update `docs/OxiRule.md` if OxiRule syntax, matching behavior, route configuration, or configuration semantics change.
- Keep examples synchronized with `source/config/oxibelt.toml`.

Do not place detailed technical specifications only in `README.md`. Prefer `docs/` for detailed specs and configuration guides, and keep `README.md` focused on overview, setup, and basic usage.

## Test Structure

Rust tests are under:

```sh
tests/rust/
```

Docker-based test utilities are under:

```sh
tests/docker/
```

Test scripts are under:

```sh
tests/scripts/
```

Important test-related files:

- `tests/rust/config_and_routes.rs`
- `tests/rust/pq_negotiation_support.rs`
- `tests/rust/tls_client_roots.rs`
- `tests/scripts/build-targets.sh`
- `tests/scripts/run-proxy-integration.sh`
- `tests/docker/mock_upstream/server.py`
- `tests/docker/mock_upstream/client.py`
- `tests/docker/pq_probe/src/main.rs`

When modifying proxy, TLS, routing, or configuration behavior, update or add tests in the relevant area.

## Test Temporary Data Guidelines

Tests may need short-lived generated files, such as self-signed TLS certificates, private keys, temporary configuration files, generated CA roots, mock upstream fixtures, or probe output files.

These files must be treated as disposable test data.

When adding or modifying tests:

- Generate temporary data at test startup or test-suite setup time.
- Use each generated temporary data set for only the relevant test run.
- Delete generated files when the test or test suite finishes.
- Prefer temporary directories over fixed paths inside the repository.
- Avoid committing generated certificates, private keys, runtime configs, logs, or probe output files.
- Ensure cleanup also runs when tests fail, where practical.
- Do not reuse stale TLS certificates, keys, or generated configs across independent test runs unless the reuse is explicit, safe, and documented.

For TLS tests, self-signed certificates and private keys should be generated automatically and removed after the tests complete.


## Docker Guidelines

Docker-based tests should be reproducible locally and in GitHub Actions.

Current Docker-related files include:

```sh
source/ops/Dockerfile.alpine
tests/docker/mock_upstream/Dockerfile
tests/docker/pq_probe/Dockerfile
```

When changing Docker behavior:

- Avoid depending on host-installed services.
- Keep Docker builds reproducible.
- Prefer explicit package versions when practical.
- Make sure Docker-based tests work in CI.
- Do not assume local-only paths outside the repository.
- Clean up Docker resources created by tests after the test run finishes.

Docker-based virtual environment tests must remove related resources after completion, including:

- test containers
- test networks
- test images built only for the test run
- temporary volumes, if they are created by the test

Prefer deterministic cleanup commands in test scripts. For example, use explicit container, image, network, and volume names or labels so cleanup does not accidentally remove unrelated developer resources.

Some developers may work inside a Dev Container while Docker is exposed through Docker outside of Docker. In that environment, bind mounts and host paths can behave differently from a normal local shell. When practical, prefer copying test inputs or outputs with `docker cp` or using named Docker volumes instead of relying on fragile host-specific bind mounts.

Do not assume that the path visible inside the Dev Container is identical to the path visible to the Docker daemon.

## Integration Test Guidelines

The integration test script is:

```sh
tests/scripts/run-proxy-integration.sh
```

When changing integration behavior:

- Keep the script usable from a clean checkout.
- Avoid requiring manual setup beyond documented dependencies.
- Make failures easy to diagnose.
- Ensure mock upstream behavior is deterministic.
- Keep test ports, hostnames, and container names explicit.

## Browser / WebDriver Testing

If browser-based tests are added, they must run with both:

- Chromium WebDriver
- Firefox WebDriver

Browser tests should:

- run in headless mode
- run locally through Docker
- run in GitHub Actions
- avoid Chromium-only assumptions
- avoid browser-specific timing assumptions
- use explicit waits instead of fixed sleeps where possible

Do not disable either Chromium or Firefox tests without documenting the reason.

## TypeScript / DevOps Guidelines

The `devops/` directory is reserved for TypeScript-based DevOps and CI support code.

When adding TypeScript DevOps code:

- Keep scripts deterministic.
- Avoid hidden dependencies on the local machine.
- Prefer explicit configuration.
- Validate generated or modified GitHub Actions workflow files.
- Keep CI behavior compatible with Linux GitHub-hosted runners unless otherwise documented.

If package manager files are added under `devops/`, document the expected commands here.

Example with npm:

```sh
cd devops
npm ci
npm run typecheck
npm run lint
npm test
```

Adjust these commands if the repository uses `pnpm`, `yarn`, or `bun`.

## GitHub Actions Requirements

GitHub Actions should run at least:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

It should also run Docker-based integration tests, for example:

```sh
tests/scripts/build-targets.sh
tests/scripts/run-proxy-integration.sh
```

If TypeScript DevOps tooling is added, CI should also run its typecheck, lint, and tests.

If browser WebDriver tests are added, CI must run them with both Chromium and Firefox.

## Security Guidelines

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

Do not weaken TLS behavior, certificate validation, proxy isolation, or security-sensitive defaults without tests and documentation.

## Do Not

- Do not remove tests just to make CI pass.
- Do not disable TLS, proxy, route, or configuration tests without a documented reason.
- Do not disable Chromium or Firefox WebDriver tests if browser tests exist.
- Do not commit `target/`, `node_modules/`, or generated build artifacts unless explicitly required.
- Do not make CI depend on local-only files or absolute host paths.
- Do not silently change public proxy behavior.
- Do not change configuration syntax without updating docs and tests.
- Do not put detailed technical specifications only in `README.md` when they belong under `docs/`.
- Do not leave generated test certificates, keys, temporary configs, logs, or probe outputs in the repository after tests finish.
- Do not leave Docker test containers, networks, images, or temporary volumes behind after Docker-based tests finish.
- Do not rely on Dev Container bind-mount paths being visible to the Docker daemon in the same way as inside the container.

## Recommended Workflow

When modifying this repository:

1. Identify the affected area:
   - Rust proxy implementation
   - TLS behavior
   - route/config behavior
   - Docker test environment
   - Rust integration tests
   - TypeScript DevOps tooling
   - GitHub Actions CI
   - documentation under `docs/`

2. Make the smallest reasonable change.

3. Add or update tests.

4. Run relevant checks:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

5. Run Docker/integration checks when relevant:

```sh
tests/scripts/build-targets.sh
tests/scripts/run-proxy-integration.sh
```

6. Verify that temporary test data was removed after the test run.

7. Verify that Docker-based tests cleaned up their containers, networks, test-only images, and temporary volumes.

8. Update documentation when behavior, configuration, commands, technical specifications, or CI workflows change.

9. Ensure changes to configuration or technical behavior are reflected in the relevant Markdown files under `docs/`.
