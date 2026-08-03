# AGENTS.md

## Project Overview

OxiBelt is a Rust-based reverse proxy and WAF project.

This repository is organized as a monorepo. The main reverse proxy
implementation lives under `source/`. Tests live under `tests/`. Technical
specifications and configuration documentation live under `docs/`. Deployable
Helm and observability assets live under `deploy/`. TypeScript-based DevOps and
CI support code should live under `devops/` when present.

The project should be testable locally and in CI using Docker-based
environments.

## Repository Structure

- `Cargo.toml`
  - Rust workspace, shared package metadata, and dependency policy.
- `source/`
  - Integrated data-plane, Admin, WAF, and Person Proof runtime crate.
- `source/apps/`
  - Independently packaged Gateway Controller, CLI, keysigner, and netport binaries.
- `source/crates/`
  - Shared external-control protocol, HTTP, and deployment-diagnostics crates.
- `source/assets/`
  - Canonical build-validated assets embedded in the runtime.
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
- `deploy/`
  - Deployable Helm charts and observability bundle assets.
- `devops/`
  - TypeScript-based DevOps and GitHub Actions support code when present.
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

## Agent Commit Message Guidance

Commit messages must contain portable, repository-relevant context. Do not
include session-specific command aliases, absolute host paths, or local-only
environment data and artifacts. For example, do not record the availability or
use of `docker-rootful` or cite files under `.agents/temp`; describe the
portable result instead, such as whether performance benchmarks were run.

When additional context is useful, prefer stable sources that readers can
access publicly, such as tracked repository files, public GitHub projects,
issues, pull requests, commits, published security advisories, and official
documentation. If no suitable public source exists, explain the necessary
context inline without citing inaccessible local material. Sanitize the
description and do not expose secrets, personal data, or undisclosed
vulnerability details.

## Codex Security Advisory Guidance

Follow the [Security Policy](SECURITY.md) for every validated, high-confidence,
report-worthy finding from Codex Security Cloud or a local Codex Security scan.
Use one GitHub repository Security Advisory per finding and keep the disclosure
state fail-closed:

- If a supported fix or actionable mitigation is not yet available, submit
  only a private vulnerability report to the repository advisory inbox and
  keep it in `triage` or `draft`. Do not substitute a public issue, discussion,
  pull request, or revealing commit message.
- Once the supported fix or actionable mitigation is verified and disclosure
  is permitted by the Security Policy, publish the repository Security
  Advisory.
- Preview the exact advisory payload and obtain explicit approval for each
  submission or publication. Before writing, verify the canonical repository,
  immutable source revision and finding locations, duplicate status,
  authenticated identity, permissions, and intended visibility. Read the
  advisory back before reporting success.
- Do not request a CVE identification number unless the user explicitly asks
  for one.
- If the available credentials or tooling cannot preserve the required private
  or published state, stop and report the blocker without changing disclosure
  channels.
