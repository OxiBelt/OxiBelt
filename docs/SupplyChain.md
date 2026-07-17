# Release Image Trust and Attestations

OxiBelt publishes five role-specific container images. The release workflow
creates GitHub artifact attestations for every canonical platform image digest
and every canonical multi-architecture index digest. Each digest receives:

- SLSA provenance with predicate type `https://slsa.dev/provenance/v1`; and
- a CycloneDX SBOM with predicate type `https://cyclonedx.org/bom`.

These are keyless GitHub Attestations API records signed from the release's
GitHub Actions identity. The workflow deliberately sets
`push-to-registry: false`: the bundles are not GHCR OCI referrers, Cosign
signatures, `.sig` artifacts, or registry-resident SBOMs. Verification normally
retrieves bundles from GitHub's API and separately reads the image from GHCR.

An OCI digest identifies exact registry content. A successfully verified
attestation additionally authenticates the GitHub Actions signer identity and
binds a statement to that digest. It does not prove that the source was
reviewed or approved, that the build is reproducible, that dependencies or the
image are vulnerability-free, or that the digest is the newest acceptable
release. Operators must enforce approval, freshness, rollback, vulnerability,
and deployment-admission policy separately.

## Official image repositories

Only the following repositories are official OxiBelt image sources:

| Role | OCI repository | Expected executable inventory |
| --- | --- | --- |
| `standalone` | `ghcr.io/oxibelt/oxibelt` | `oxibelt`, `oxibeltctl`, `oxibelt-keysigner`, `oxibelt-netport-switcher` |
| `dataplane` | `ghcr.io/oxibelt/oxibelt-dataplane` | `oxibelt` |
| `controller` | `ghcr.io/oxibelt/oxibelt-gateway-controller` | `oxibelt-gateway-controller` |
| `tools` | `ghcr.io/oxibelt/oxibelt-tools` | `oxibeltctl` |
| `keysigner` | `ghcr.io/oxibelt/oxibelt-keysigner` | `oxibelt-keysigner` |

Do not treat the broader `ghcr.io/oxibelt/*` namespace, a similarly named
repository, a fork, or a mirror as an official source. The standalone and
minimal data-plane images use the same integrated `oxibelt` runtime, including
Admin and Person Proof. The minimal image removes operator, controller, and
helper executables; it does not remove those runtime security capabilities.

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
  repository: ghcr.io/oxibelt/oxibelt-dataplane
  digest: sha256:FULL_64_CHARACTER_LOWERCASE_DIGEST
```

Use the controller repository with the same `image.digest` shape in the
Gateway Controller chart. Pin and verify each role independently; a data-plane
attestation is not evidence for a controller, tools, keysigner, or standalone
image.

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
```

For a multi-architecture index digest, use the same commands with
`signer=OxiBelt/OxiBelt/.github/workflows/release.yml`. The release itself also
verifies both versioned canonical index tags resolve to the same index digest
before promotion.

`--signer-workflow` constrains a workflow path prefix. A complete consumer
policy must inspect every returned verification result, not just the first,
and require all of the following for at least one provenance result and at
least one CycloneDX result:

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
- the CycloneDX predicate exactly matches the SBOM expected for that digest.

Attestation generation is safely repeatable, so the API can return duplicate
valid records as well as historical records. Verification must examine all
results and select an exact match. A trusted timestamp proves when a particular
bundle was witnessed; it is not a release-freshness or anti-rollback policy.

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
`--predicate-type https://cyclonedx.org/bom`. Retain the immutable image digest,
bundle, expected source/signer identity, expected SBOM, GitHub CLI version, and
required trust material together. OxiBelt does not publish these bundles as
OCI referrers, so `--bundle-from-oci` is not the supported path. Downloaded
bundles enable file-based verification, but the release contract does not
provide a complete registry-only or air-gapped verification system; operators
must provision the image and verifier trust material for those environments.

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
- Attestations bind a digest to a trusted workflow and stated source; they do
  not prove code review, branch protection, human approval, reproducibility, or
  base-image digest pinning.
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
standalone compatibility image keeps its existing entrypoint and integrated
Admin and Person Proof behavior; switching between standalone and minimal
data-plane repositories is an artifact-role change, not an equivalent digest
rollback.
