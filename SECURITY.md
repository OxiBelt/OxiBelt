# Security Policy

## Scope

This policy covers OxiBelt source code, supported releases, release workflow
artifacts, and official container images. Report a vulnerability when OxiBelt's
code, configuration defaults, documentation, release process, or official
artifact can be exploited or causes an unsafe security outcome.

Forks, local modifications, third-party registries, and systems that are not
operated by the OxiBelt project are not separate supported products. A
vulnerability in an upstream dependency is still in scope when OxiBelt's use of
it is affected.

## Product Threat Model

The [product threat model](docs/ThreatModel.md) is the canonical description of
OxiBelt's security assets, actors, trust boundaries, attacker-controlled inputs,
deployment assumptions, failure semantics, and severity context. Use it with
the feature lifecycle matrix below; this file remains authoritative for
supported releases, private reporting, patching, and disclosure policy.

## Supported Versions and Branches

| Branch or release | Security support |
| --- | --- |
| `main` | Supported development branch. Security fixes are merged here, but it is not a stable release. |
| [Latest stable GitHub release](https://github.com/OxiBelt/OxiBelt/releases/latest) | Supported stable release. |
| Older stable releases, the legacy `0.0.1` branch, beta/build releases, and other branches | Unsupported unless OxiBelt explicitly announces otherwise. |

## Security Patch and End-of-Support Policy

OxiBelt handles accepted reports privately when practical. A fix for the
latest stable release is applied to that release line and to `main`. If `main`
has diverged, maintainers may create a short-lived maintenance branch from the
latest stable tag to prepare the patch release.

Maintainers prefer a compatible patch release. If a safe remediation requires
an incompatible change, they will release the next stable version and document
the required migration. OxiBelt does not guarantee backports to unsupported
releases.

A stable release reaches end of support when its successor is published. End of
support ends patch and backport commitments; later advisories may still identify
an end-of-support release as affected, and users must upgrade to a supported
release.

## Reporting a Vulnerability

Use [GitHub private vulnerability reporting](https://github.com/OxiBelt/OxiBelt/security/advisories/new)
for all undisclosed security reports. Do not open a public issue, discussion,
pull request, or commit that reveals an unpatched vulnerability.

Include, when available:

- affected release, commit, package tag, and image digest;
- relevant configuration, protocol, provider, backend, and deployment context;
- attacker prerequisites, security impact, and a minimal reproduction or proof
  of concept;
- sanitized logs, traces, and a mitigation or workaround if known; and
- related CVE, GHSA, dependency, or cryptographic-provider information.

Do not include real credentials, private keys, tokens, personal data, or more
data than is needed to reproduce the issue.

## Response Process

The following are response targets, not a service-level agreement:

- acknowledge a report within 3 business days;
- complete initial validation and triage within 7 calendar days of receipt; and
- provide a status update at least weekly while remediation is active.

Triage identifies the affected support line, exploitability, impact, and
required coordination. OxiBelt will explain a declined or out-of-scope report
when practical.

## Disclosure Policy

Please keep reports private while OxiBelt validates the issue, prepares a fix
or mitigation, and coordinates disclosure. After a supported fix or actionable
mitigation is available, maintainers may publish a GitHub Security Advisory and
request a CVE when appropriate.

There is no fixed embargo period. OxiBelt may accelerate disclosure when an
issue is actively exploited or already public, and may adjust timing for
upstream dependency or cryptographic-provider coordination. Reporters may be
credited with their consent.

This policy does not authorize testing systems that you do not own or operate.

## Dependency Vulnerabilities

Report an OxiBelt-relevant dependency vulnerability through the private channel,
including those in Cargo, Node.js/DevOps tooling, GitHub Actions, container
base images, operating-system packages, or transitive libraries.

Maintainers assess reachability, configuration, exploitability, and impact in
OxiBelt before choosing an upgrade, pin, mitigation, feature disablement, or
other remediation. When a supported release is affected, the resulting fix or
mitigation follows the patch and disclosure policy above. Upstream-only issues
that do not affect OxiBelt's use may be tracked with the upstream project
without an OxiBelt advisory.

## Cryptographic Issues

Treat cryptographic reports as high priority. Report protocol use, defaults,
provider or backend selection, primitive implementation, certificate handling,
and key-management issues privately. Include the relevant provider/backend and
the smallest safe reproduction; never send production secret material.

Maintainers coordinate with affected cryptographic providers or upstream
projects before public disclosure when appropriate. Operators who suspect that
keys, certificates, tokens, or other secret material are exposed should rotate
or revoke them promptly. This policy does not claim formal cryptographic
certification.

## Official Container Images

The only official OxiBelt container images are artifacts published by OxiBelt
release workflows in these exact repositories:

- `ghcr.io/oxibelt/oxibelt`
- `ghcr.io/oxibelt/oxibelt-dataplane`
- `ghcr.io/oxibelt/oxibelt-dataplane-strict`
- `ghcr.io/oxibelt/oxibelt-gateway-controller`
- `ghcr.io/oxibelt/oxibelt-tools`
- `ghcr.io/oxibelt/oxibelt-keysigner`

This scope does not trust the broader `ghcr.io/oxibelt/*` namespace. It includes
versioned, architecture-specific, and multi-architecture variants. Security
support follows the underlying release, not a mutable tag alias. `latest`,
major, Alpine musl, beta, and build tags are official artifacts but do not
create additional supported release lines.

Use an image digest when deploying or reporting an image vulnerability so the
artifact is unambiguous. Unqualified `oxibelt:latest`, forks, mirrors, local
builds, test helper images, and third-party base images are not official OxiBelt
images.

The release workflow creates and verifies GitHub API-hosted keyless SLSA
provenance and CycloneDX SBOM attestations for every canonical platform and
multi-architecture index digest. These bundles are not Cosign signatures or
GHCR OCI referrers. Use [Release Image Trust and
Attestations](docs/SupplyChain.md) to resolve and verify an approved immutable
digest with the exact repository, workflow, source ref, source revision,
subject, predicate, and trusted-timestamp policy. Historical OCI referrers can
remain attached to older digests, but their presence does not establish current
API attestation coverage. OxiBelt does not ship a Kubernetes admission policy
for these API-only records; do not weaken a fail-closed operator policy merely
to unblock deployment.

## Experimental Features

The [feature lifecycle matrix](docs/FeatureStatus.md) is the canonical source
for supported, experimental, reserved, and removed features. Security reports
for experimental features are welcome and will be assessed, but a remediation
may disable, remove, or incompatibly change the feature. Experimental features
have no compatibility or backport guarantee beyond the supported-release policy
above.
