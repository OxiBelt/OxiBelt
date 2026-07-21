# Release Image Trust and Attestations

OxiBelt publishes six role-specific container images. The release workflow
creates GitHub artifact attestations for every canonical platform image digest
and every canonical multi-architecture index digest. Each digest receives:

- SLSA provenance with predicate type `https://slsa.dev/provenance/v1`;
- a CycloneDX SBOM with predicate type `https://cyclonedx.org/bom`; and
- a deterministic rebuild recipe with predicate type
  `https://oxibelt.dev/attestations/rebuild/v1`.

These are keyless GitHub Attestations API records signed from the release's
GitHub Actions identity. The workflow deliberately sets
`push-to-registry: false`: the bundles are not GHCR OCI referrers, Cosign
signatures, `.sig` artifacts, or registry-resident SBOMs. Verification normally
retrieves bundles from GitHub's API and separately reads the image from GHCR.

An OCI digest identifies exact registry content. A successfully verified
attestation additionally authenticates the GitHub Actions signer identity and
binds a statement to that digest. It does not prove that the source was
reviewed or approved, that dependencies or the image are vulnerability-free,
or that the digest is the newest acceptable release. The rebuild recipe makes
the stated source tree, build inputs, base images, role/architecture contract,
binary inventory, SBOM, and build environment independently checkable; it is
still a workflow assertion until a separate rebuild verifies it. Operators
must enforce approval, freshness, rollback, vulnerability, and
deployment-admission policy separately.

## Official image repositories

Only the following repositories are official OxiBelt image sources:

| Role | OCI repository | Expected executable inventory |
| --- | --- | --- |
| `standalone` | `ghcr.io/oxibelt/oxibelt` | `oxibelt`, `oxibeltctl`, `oxibelt-keysigner`, `oxibelt-netport-switcher` |
| `dataplane` | `ghcr.io/oxibelt/oxibelt-dataplane` | `oxibelt` |
| `dataplane-strict` | `ghcr.io/oxibelt/oxibelt-dataplane-strict` | `oxibelt-dataplane-strict` |
| `controller` | `ghcr.io/oxibelt/oxibelt-gateway-controller` | `oxibelt-gateway-controller` |
| `tools` | `ghcr.io/oxibelt/oxibelt-tools` | `oxibeltctl` |
| `keysigner` | `ghcr.io/oxibelt/oxibelt-keysigner` | `oxibelt-keysigner` |

Do not treat the broader `ghcr.io/oxibelt/*` namespace, a similarly named
repository, a fork, or a mirror as an official source. The standalone and
compatibility `dataplane` images use the same integrated `oxibelt` runtime,
including Admin and Person Proof. The `dataplane-strict` package retains Person
Proof but removes the Admin runtime and Admin OpenAPI asset at compile time; it
is not merely a different entrypoint or an Admin-disabled configuration. The
controller, tools, and keysigner images remain separate single-purpose roles.

Releases may include these platform and CPU-policy variants:

| Release artifact | OCI platform | CPU policy |
| --- | --- | --- |
| `amd64v2` | `linux/amd64` | `x86-64-v2` |
| `amd64` | `linux/amd64` | `x86-64-v3` |
| `amd64v4` | `linux/amd64` | `x86-64-v4` |
| `arm64` | `linux/arm64` | architecture default |
| `riscv64` | `linux/riscv64` | architecture default |

The versioned multi-architecture index is composed from the canonical
`amd64` (`x86-64-v3`), `arm64`, and `riscv64` platform digests. Explicit
architecture tags also expose the platform variants. Resolve the exact tag
intended for the target platform instead of assuming that two tags name the
same digest.

## Select and record an immutable digest

Start from an exact official repository and an approved version tag. Resolve
the registry digest before verification or deployment:

```sh
image=ghcr.io/oxibelt/oxibelt-dataplane
version=15.2.0
digest="$(docker buildx imagetools inspect \
  --format '{{json .Manifest}}' \
  "${image}:${version}" | jq -r '.digest')"
printf '%s\n' "${digest}" | grep -Eq '^sha256:[0-9a-f]{64}$'
printf '%s@%s\n' "${image}" "${digest}"
```

Record the repository, release version, digest, target platform, source Git
revision and ref, approval source, and approval time in deployment evidence.
Re-resolve the digest immediately before verification and deployment. Never use
a mutable alias as the recorded deployment identity.

Both OxiBelt Helm charts accept `image.digest`. A lowercase
`sha256:<64-hex-characters>` digest takes precedence over `image.tag` and
renders `repository@sha256:...`:

```yaml
image:
  role: dataplane
  repository: ghcr.io/oxibelt/oxibelt-dataplane
  digest: sha256:FULL_64_CHARACTER_LOWERCASE_DIGEST
```

Use the controller repository with the same `image.digest` shape in the
Gateway Controller chart. Pin and verify each role independently; a data-plane
attestation is not evidence for a strict data plane, controller, tools,
keysigner, or standalone image. The Helm chart validates official
repository/role combinations so selecting `dataplane-strict` cannot silently
run the compatibility `oxibelt` executable.

## Verify GitHub attestations

Use a current GitHub CLI, authenticate it for the OxiBelt repository, and
authenticate Docker to GHCR when the package is not anonymously readable. The
following example verifies the cryptographic bundles for a platform digest
from the reusable platform release workflow:

```sh
image=ghcr.io/oxibelt/oxibelt-dataplane
digest=sha256:FULL_64_CHARACTER_LOWERCASE_DIGEST
version=15.2.0
revision=FULL_40_CHARACTER_GIT_COMMIT
subject="oci://${image}@${digest}"
signer=OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml

gh attestation verify "${subject}" \
  --repo OxiBelt/OxiBelt \
  --signer-workflow "${signer}" \
  --signer-digest "${revision}" \
  --source-digest "${revision}" \
  --source-ref "refs/tags/${version}" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners \
  --predicate-type https://slsa.dev/provenance/v1 \
  --limit 100 \
  --format json > provenance.json

gh attestation verify "${subject}" \
  --repo OxiBelt/OxiBelt \
  --signer-workflow "${signer}" \
  --signer-digest "${revision}" \
  --source-digest "${revision}" \
  --source-ref "refs/tags/${version}" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners \
  --predicate-type https://cyclonedx.org/bom \
  --limit 100 \
  --format json > sbom.json

gh attestation verify "${subject}" \
  --repo OxiBelt/OxiBelt \
  --signer-workflow "${signer}" \
  --signer-digest "${revision}" \
  --source-digest "${revision}" \
  --source-ref "refs/tags/${version}" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners \
  --predicate-type https://oxibelt.dev/attestations/rebuild/v1 \
  --limit 100 \
  --format json > rebuild.json
```

For a multi-architecture index digest, use the same commands with
`signer=OxiBelt/OxiBelt/.github/workflows/release.yml`. The release itself also
verifies both versioned canonical index tags resolve to the same index digest
before promotion.

`--signer-workflow` constrains a workflow path prefix. A complete consumer
policy must inspect every returned verification result, not just the first,
and require all of the following for at least one provenance, CycloneDX, and
rebuild-recipe result:

- the statement subject name is exactly the tagless image repository and its
  SHA-256 digest is exactly the independently resolved digest;
- the certificate subject alternative name is exactly the expected workflow
  identity, rather than merely sharing its prefix; for this example that is
  `https://github.com/OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml@refs/tags/15.2.0`,
  while an index uses
  `https://github.com/OxiBelt/OxiBelt/.github/workflows/release.yml@refs/tags/15.2.0`;
- `verifiedTimestamps` is nonempty;
- provenance names the `OxiBelt/OxiBelt` source repository, the expected tag
  ref and revision, and the expected builder and caller workflow identities;
  for platform images, the signer/builder is `release-image-arch.yml` while the
  provenance caller path is `.github/workflows/release.yml`; and
- the CycloneDX predicate exactly matches the SBOM expected for that digest;
  and
- the rebuild predicate is the expected `platform` or `index` recipe, has one
  exact subject, source ref and revision, and binds the expected role,
  architecture, source tree, build contract, binary inventory, and SBOM.

Attestation generation is safely repeatable, so the API can return duplicate
valid records as well as historical records. Verification must examine all
results and select an exact match. A trusted timestamp proves when a particular
bundle was witnessed; it is not a release-freshness or anti-rollback policy.

## Independent rebuild verification

`.github/workflows/verify-release-rebuild.yml` is a separate read-only
consumer of published evidence. After a successful stable or beta release it
rebuilds all six roles and five architecture variants. A manual dispatch can
target one stable, beta, or build artifact. The job checks out the exact tag in
a fresh tree, starts an isolated rootless Docker daemon, verifies the
provenance, SBOM, and rebuild-recipe records through GitHub's API, resolves the
canonical GHCR digest, and rebuilds without downloading artifacts from the
producer workflow.

The verifier writes a machine-readable receipt with one of four outcomes:

- `exact` means the rebuilt archive digest and bound evidence match exactly;
- `normalized_equivalent` means the semantic image contract matches after
  ignoring only documented archive ordering, compression, filesystem mtime,
  and OCI created/history timestamp fields;
- `mismatch` is a verification failure; and
- `unverifiable` means evidence was missing, malformed, unsafe to compare, or
  outside the comparator's resource bounds, and also fails the job.

Normalization preserves filesystem content and types, modes, ownership,
links, extended attributes and capabilities, OCI configuration, executable
hashes, and the SBOM graph. A normalized result is evidence of semantic
equivalence, not a claim of byte-for-byte reproducibility.

## Dependency admission

Rust admission is defined by `deny.toml`, `supply-chain/config.toml`, and the
owned exception and bootstrap ledger in
`supply-chain/dependency-policy.json`. CI runs the complete `cargo deny check`
policy and locked `cargo vet` review evidence. Duplicate compatibility lines,
critical dependencies, allowed registries/licenses, and every temporary
exception are statically checked; exceptions require an owner, rationale,
review reference, and bounded expiry.

Node admission requires exact manifest and lockfile specifiers, the
hash-pinned root `packageManager`, the public npm registry, lockfile integrity,
a minimum release age, denied exotic sources, and an exact allowlist for
lifecycle scripts. CI installs with `--ignore-scripts`, then separately checks
the approved script tuple, license inventory, an unfiltered audit report, and
registry signatures. Vulnerability exceptions must exactly match GHSA,
package, affected range, owner, issue, review date, and expiry; stale or
unreported exceptions fail admission.

## Download bundles for retained verification

Download the API-hosted bundles while GitHub and GHCR are available, then use
the downloaded JSON Lines bundle with the same identity and predicate checks:

```sh
gh attestation download "${subject}" \
  --repo OxiBelt/OxiBelt \
  --limit 100

bundle="${digest}.jsonl"
gh attestation verify "${subject}" \
  --repo OxiBelt/OxiBelt \
  --bundle "${bundle}" \
  --signer-workflow "${signer}" \
  --signer-digest "${revision}" \
  --source-digest "${revision}" \
  --source-ref "refs/tags/${version}" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners \
  --predicate-type https://slsa.dev/provenance/v1 \
  --limit 100 \
  --format json
```

Repeat the bundle verification with
`--predicate-type https://cyclonedx.org/bom` and
`--predicate-type https://oxibelt.dev/attestations/rebuild/v1`. Retain the
immutable image digest, bundle, expected source/signer identity, expected SBOM
and rebuild recipe, GitHub CLI version, and required trust material together.
OxiBelt does not publish these bundles as OCI referrers, so
`--bundle-from-oci` is not the supported path. Downloaded bundles enable
file-based verification, but the release contract does not provide a complete
registry-only or air-gapped verification system; operators must provision the
image and verifier trust material for those environments.

## RISC-V build trust boundary

The `linux/riscv64` images are built on `linux/amd64` without QEMU or `binfmt`
runtime emulation. The Rust builder copies only `/x-tools` from a
manifest-digest-pinned `cross-rs` toolchain image. Before Cargo runs, the build
fails closed unless the toolchain has the expected compiler digest and version,
target triple, and linker version. The immutable image digest is recorded with
its exact `cross-rs` source revision in the Dockerfile and integrity tests. The
build does not invoke the `cross` CLI, inherit its QEMU runner, mount a Docker
socket, or run a nested container.

The Alpine runtime remains a signed Alpine/musl filesystem rather than a
host-built approximation. A build-platform Alpine stage copies an unexecuted
RISC-V seed and uses its target repositories and signing keys with
`apk --root --arch riscv64 --no-scripts`. Untrusted packages are not allowed.
The target package database, CA bundle, fixed users, directories, ownership,
and modes are validated before a copy-only final image is created, so no
RISC-V executable runs during rootfs construction.

CI validates RISC-V compilation, static ELF linkage, image architecture,
executable and package inventories, image metadata, SBOMs, and attestations. It
does not start a RISC-V container or claim emulated runtime coverage. A valid
RISC-V attestation therefore authenticates the released artifact and build
workflow under the documented policy; it is not evidence that every runtime
path was exercised on RISC-V hardware. Updating the pinned cross-toolchain
image or its expected identity is a supply-chain boundary change that requires
review and synchronized integrity-test updates.

## SBOM coverage

Each platform attestation carries the CycloneDX document produced from that
exact local image and validated before publication. It preserves Trivy's
operating-system and library inventory and dependency graph, identifies the
exact container component, and adds validated OxiBelt release properties for
role, version, revision, ref, artifact architecture, OCI platform, CPU policy,
repository, and digest. Fixed role-specific executable components and their
SHA-256 hashes are attached to the root dependency.

Each multi-architecture index attestation carries a CycloneDX 1.7 composition
document. It identifies the index digest and the ordered `amd64`, `arm64`, and
`riscv64` child container digests. Before composition, release CI compares each
child against the corresponding platform SBOM. The index document deliberately
does not merge the three operating-system, library, or executable inventories;
its `io.oxibelt.sbom.inventory` value is
`separate-platform-attestation`. Verify the matching platform attestations when
component-level inventory is required.

An SBOM is an inventory statement at build time. It is not a vulnerability
scan result, a promise that every component is detectable, or evidence that a
component remains safe. Apply current vulnerability intelligence and policy to
the verified digest and SBOM separately.

## Trust boundary and residual risk

The release process retains role-specific builds, explicit executable
inventories, image labels, vulnerability scanning, versioned tags, separate
multi-architecture indexes, immutable action pins, and separated package-write
jobs. GitHub verifies the keyless signature, certificate identity, and trusted
timestamp in each attestation bundle. The predicate contents are assertions by
the trusted workflow.

Consequently:

- A compromised release workflow, caller inputs within its authority, runner,
  dependency, maintainer, pinned action commit, release credential, GitHub
  Actions identity, or registry authority can still produce or publish
  malicious content and plausible predicates.
- Attestations bind a digest to a trusted workflow and stated source; the
  rebuild predicate records base-image pins and reproducibility inputs, but an
  attestation alone does not prove code review, branch protection, human
  approval, or an independently successful rebuild.
- Image labels and executable inventories remain publisher-supplied metadata.
- Vulnerability reports and dependency snapshots do not prove that a deployed
  digest is vulnerability-free.
- Digest pinning and trusted timestamps do not provide freshness or rollback
  prevention. Operators must enforce those policies separately.
- A valid attestation for one role, platform, digest, ref, or revision cannot
  be substituted for another.

## Historical OCI referrers and admission

Some existing GHCR digests may retain signatures, provenance statements,
SBOMs, or other OCI referrers produced by earlier release designs. Registry
referrers attached to a historical digest are independent of the current
GitHub API-hosted attestation contract. Their discovery does not prove that a
newer digest is attested, that every role or platform has equivalent evidence,
that the release completed promotion, or that the evidence satisfies current
policy.

OxiBelt does not ship a Sigstore Policy Controller policy or another
OxiBelt-managed Kubernetes admission rule for the GitHub API bundles. A policy
that searches GHCR referrers, requires a Cosign signature, or verifies with
`--bundle-from-oci` will not find the current API-only records. Do not switch a
validating webhook to `failurePolicy: Ignore`, broaden an allowlist to
`ghcr.io/oxibelt/*`, or remove a fail-closed policy merely to make deployment
proceed. Any replacement admission policy is an operator-owned security-boundary
change and must be separately approved, staged, tested for every role, and
given a rollback plan.

## Release and rollback records

Treat a release as deployable only after its release workflow, in-workflow
attestation verification, and repository publication complete successfully and
the exact intended digest is approved and recorded. A version-specific tag,
API attestation, or historical OCI referrer can remain visible after an
interrupted attempt, so none alone proves release completion.

For rollback, retain the previous repository and digest for each deployed role.
Rollback should change the pinned digest, not repoint a mutable tag. The
standalone and compatibility data-plane images keep their integrated Admin and
Person Proof behavior; the strict image retains Person Proof but has no Admin
runtime. Switching between any of these repositories changes the artifact role,
executable, and capability boundary and is not an equivalent digest rollback.
