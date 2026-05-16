# AGENTS.md

## Project Overview

OxiBelt is a Rust-based reverse proxy and WAF project.

This repository is organized as a monorepo. The main reverse proxy
implementation lives under `source/`. Tests live under `tests/`. Technical
specifications and configuration documentation live under `docs/`. DevOps and
CI-related automation should live under `devops/`.

The project should be testable locally and in CI using Docker-based
environments.

## Repository Structure

- `source/`
  - Main Rust reverse proxy crate.
- `source/src/`
  - Core application source code.
- `source/src/proxy/`
  - HTTP, HTTP/3, stream, WebSocket, and WebTransport proxy behavior.
- `source/src/waf/`
  - OxiRule, CRS compatibility, body scanning, Person proof, and WAF behavior.
- `source/src/config/`
  - Configuration validation modules.
- `source/config/oxibelt.toml`
  - Example or default OxiBelt configuration.
- `source/ops/Dockerfile.alpine`
  - Alpine-based Docker image for OxiBelt.
- `tests/rust/`
  - Rust integration tests and repository-level checks.
- `tests/docker/`
  - Docker test services, protocol probes, database fixtures, and performance probes.
- `tests/scripts/`
  - Test, build, integration, performance, and WebDriver orchestration scripts.
- `docs/`
  - Technical specifications, configuration guides, rule documentation, and behavior references.
- `ui/person-proof/`
  - Person proof challenge UI assets and build scripts.
- `kernel-extension/`
  - Linux edge deployment tuning templates and verification helpers.
- `devops/`
  - TypeScript-based DevOps and GitHub Actions support code.
- `.github/workflows/`
  - GitHub Actions workflows.

## Contributor Guidance

`CONTRIBUTING.md` is the source of truth for contributor workflow, security
requirements, pull request checks, and commit-message format. Use these
sections before making or reviewing changes:

- [Contribution Workflow](CONTRIBUTING.md#contribution-workflow)
- [Commit Messages](CONTRIBUTING.md#commit-messages)
- [Security Requirements](CONTRIBUTING.md#security-requirements)
- [Pull Request Checklist](CONTRIBUTING.md#pull-request-checklist)

If this file and `CONTRIBUTING.md` diverge on workflow, security, testing,
documentation, or Conventional Commits requirements, follow `CONTRIBUTING.md`
and update this pointer file only when agent-specific orientation changes.
