# Release Supply-Chain Verification

OxiBelt release workflows publish a keyless Cosign signature, SLSA provenance
v1, and a CycloneDX 1.6 software bill of materials (SBOM) for every official
role/platform image and role-specific multi-architecture index. Each artifact
names the immutable digest of its exact OCI repository and role as its subject.
Consumers can verify
the GitHub Actions OIDC issuer, repository, workflow, release tag, source
commit, hosted builder, and digest independently of a workflow artifact or
mutable registry tag.

## Published subjects

Each release publishes the following independently attributable image roles:

| Role | OCI repository | Expected executable inventory |
| --- | --- | --- |
| `standalone` | `ghcr.io/oxibelt/oxibelt` | `oxibelt`, `oxibeltctl`, `oxibelt-keysigner`, `oxibelt-netport-switcher` |
| `dataplane` | `ghcr.io/oxibelt/oxibelt-dataplane` | `oxibelt` |
| `controller` | `ghcr.io/oxibelt/oxibelt-gateway-controller` | `oxibelt-gateway-controller` |
| `tools` | `ghcr.io/oxibelt/oxibelt-tools` | `oxibeltctl` |
| `keysigner` | `ghcr.io/oxibelt/oxibelt-keysigner` | `oxibelt-keysigner` |

Every role is built for five platform/CPU-policy variants from the same
release version and source commit:

| Release artifact | OCI platform | CPU policy |
| --- | --- | --- |
| `amd64v2` | `linux/amd64` | `x86-64-v2` |
| `amd64` | `linux/amd64` | `x86-64-v3` |
| `amd64v4` | `linux/amd64` | `x86-64-v4` |
| `arm64` | `linux/arm64` | architecture default |
| `riscv64` | `linux/riscv64` | architecture default |

The reusable `.github/workflows/release-image-arch.yml` workflow signs and
attests each role/platform digest. The top-level `.github/workflows/release.yml`
workflow also signs and attests each role's digest shared by the versioned
`:<version>` and `:<version>-alpine-musl` multi-architecture indexes. Each index
SBOM retains the
three included platform inventories (`amd64`, `arm64`, and `riscv64`) as
separate components rather than flattening architecture-specific metadata.
The `amd64v2` and `amd64v4` images remain architecture-specific variants and
are not children of the multi-architecture index.

Role/platform SBOMs include the image role, source commit, the actual BuildKit start and finish
timestamps (normalized to UTC), builder workflow identity, target platform and
CPU policy, Rust toolchain version, resolved base-image digests, and the paths,
versions, and SHA-256 checksums of exactly the executables declared for that
role in the table above. Build metadata also records the Docker target,
entrypoint, runtime UID, exposed ports, embedded-asset digests when applicable,
and the `io.oxibelt.image.role` label. Validation rejects an extra or missing
binary rather than merging all role inventories.

They also include the operating-system and library inventory discovered by
Trivy. The index SBOM identifies its child image digests and preserves the
corresponding per-platform component and dependency graphs. Its build window
records the actual canonical-index composition/validation step. CycloneDX
`metadata.timestamp` records when each BOM was generated; the separate OCI
`org.opencontainers.image.created` property remains the stable tagged-commit
timestamp used for reproducible image metadata.

The provenance predicate uses `https://slsa.dev/provenance/v1` and the GitHub
Actions workflow build type. Release verification requires the exact source
repository, release workflow, tag ref, commit SHA, GitHub-hosted runner, and
builder identity. This is the repository's minimum SLSA Build Level 2 policy;
it is not a reproducible-build claim or a SLSA certification.

## Verify a keyless signature and provenance

Install Cosign 3.1.1, a recent GitHub CLI with artifact-attestation support,
Docker Buildx, and `jq`. Resolve the immutable digest first. For example, for
the standard `amd64` platform image from release `15.2.0`:

OxiBelt keeps Cosign's legacy registry bundle format for compatibility with
the existing release admission contract, so retain `--new-bundle-format=false`
when verifying an official release signature.

```sh
image=ghcr.io/oxibelt/oxibelt-dataplane
version=15.2.0
source_commit=FULL_40_CHARACTER_RELEASE_COMMIT_SHA
release_ref="refs/tags/${version}"
workflow=OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml
identity="https://github.com/${workflow}@${release_ref}"
platform_digest="$(docker buildx imagetools inspect \
  --format '{{json .Manifest}}' \
  "${image}:${version}-alpine-musl-amd64" | jq -r '.digest')"

cosign verify --new-bundle-format=false \
  --certificate-identity "${identity}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository OxiBelt/OxiBelt \
  --certificate-github-workflow-ref "${release_ref}" \
  --certificate-github-workflow-sha "${source_commit}" \
  "${image}@${platform_digest}"

gh attestation verify \
  "oci://${image}@${platform_digest}" \
  --repo OxiBelt/OxiBelt \
  --bundle-from-oci \
  --predicate-type https://slsa.dev/provenance/v1 \
  --signer-workflow "${workflow}" \
  --source-digest "${source_commit}" \
  --source-ref "${release_ref}" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners
```

GitHub CLI treats `--signer-workflow` and `--cert-identity` as mutually
exclusive identity selectors. The signer workflow, source ref, source commit,
and OIDC issuer together retain the exact release identity constraints, while
the separate Cosign command above continues to verify the full certificate
identity.

The release gate additionally parses the verified provenance and requires the
GitHub Actions workflow build type, `OxiBelt/OxiBelt` source URL, exact
workflow path and tag ref, a resolved Git dependency with the exact commit,
the `github-hosted` runner environment, and the exact builder identity.

For another role, change `image` to its exact repository from the role table.
For a multi-architecture index, resolve `:${version}`, set `workflow` to
`OxiBelt/OxiBelt/.github/workflows/release.yml`, rebuild `identity`, and run
the same two verification commands against the index digest.

## Verify a platform SBOM

Resolve the immutable digest before verification. For example, to verify the
standard `amd64` image for release `15.2.0`:

```sh
image=ghcr.io/oxibelt/oxibelt-dataplane
version=15.2.0
source_commit=FULL_40_CHARACTER_RELEASE_COMMIT_SHA
platform_digest="$(docker buildx imagetools inspect \
  --format '{{json .Manifest}}' \
  "${image}:${version}-alpine-musl-amd64" | jq -r '.digest')"

gh attestation verify \
  "oci://${image}@${platform_digest}" \
  --repo OxiBelt/OxiBelt \
  --bundle-from-oci \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml \
  --source-digest "${source_commit}" \
  --source-ref "refs/tags/${version}" \
  --deny-self-hosted-runners
```

To inspect the SBOM only after the same verification succeeds, request JSON
output and extract the verified predicate:

```sh
gh attestation verify \
  "oci://${image}@${platform_digest}" \
  --repo OxiBelt/OxiBelt \
  --bundle-from-oci \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml \
  --source-digest "${source_commit}" \
  --source-ref "refs/tags/${version}" \
  --deny-self-hosted-runners \
  --format json \
  --jq '.[].verificationResult.statement.predicate'
```

Use the architecture-specific version tag that matches the artifact being
checked. A mutable major alias can help discover an image, but it must not
replace the resolved digest in the verification subject.

## Verify a multi-architecture index SBOM

Resolve and verify the index independently. The versioned `:<version>` and
`:<version>-alpine-musl` tags are required to resolve to the same digest:

```sh
image=ghcr.io/oxibelt/oxibelt-dataplane
version=15.2.0
source_commit=FULL_40_CHARACTER_RELEASE_COMMIT_SHA
index_digest="$(docker buildx imagetools inspect \
  --format '{{json .Manifest}}' "${image}:${version}" | jq -r '.digest')"
alpine_index_digest="$(docker buildx imagetools inspect \
  --format '{{json .Manifest}}' \
  "${image}:${version}-alpine-musl" | jq -r '.digest')"
test "${index_digest}" = "${alpine_index_digest}"

gh attestation verify \
  "oci://${image}@${index_digest}" \
  --repo OxiBelt/OxiBelt \
  --bundle-from-oci \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow OxiBelt/OxiBelt/.github/workflows/release.yml \
  --source-digest "${source_commit}" \
  --source-ref "refs/tags/${version}" \
  --deny-self-hosted-runners
```

Use the JSON output and predicate selector shown in the platform example to
extract the verified index SBOM. Consumers that deploy one platform can also
inspect the index, select its platform manifest digest, and verify that digest
with the platform workflow command above.

Authenticate to GHCR first if the local client cannot
read the image and OCI attestation; a token used only for verification should
have no more than `read:packages` access. For the GitHub CLI verification model
and additional policy flags, see
[`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify).

For a manual release, dispatch the workflow from the release tag itself so the
GitHub OIDC source ref and source digest match the requested subject:

```sh
gh workflow run release.yml --ref "${version}" -f "release_tag=${version}"
```

A default-branch dispatch that merely names a tag is rejected intentionally;
checking out a tag does not change the workflow's signed `GITHUB_REF` and
`GITHUB_SHA` identity.

## Trust model and limitations

Successful verification establishes that Sigstore or GitHub's
artifact-attestation service accepted a signature, provenance predicate, or
CycloneDX predicate from the named OxiBelt workflow for the specified source
repository, source commit, source tag, and immutable OCI subject. The trusted
timestamp and workflow identity come from the signed envelope; descriptive
provenance and SBOM fields remain workflow-produced claims.

The SBOM lets consumers audit the recorded contents and build inputs, but it
does not prove that the inventory is complete, that a component is safe, or
that the build is reproducible. A compromised dependency, runner, maintainer,
pinned action, or repository workflow can still produce a malicious image and
a corresponding valid attestation.

BuildKit records the base-image digests actually resolved during the build.
The release build still begins from configured base-image references;
recording the resolved digest does not itself pin that reference before
resolution or guarantee that a later rebuild resolves identically. Base-image
digest pinning is the separate P2-2 control.

The checked-in Sigstore Policy Controller example allowlists the five exact
official repositories above; it does not use a broad `ghcr.io/oxibelt/*`
pattern. It requires an immutable OxiBelt digest, a valid release-workflow
keyless signature, and provenance
that satisfies the minimum build policy. See
[`deploy/admission/sigstore/README.md`](../deploy/admission/sigstore/README.md)
for installation and test instructions. The example does not enforce image
freshness, rollback prevention, or a vulnerability threshold. Operators should
continue to apply their own registry, freshness, rollback, and optional
vulnerability policies.

## Failure and retry behavior

The release workflow fails closed at each stage:

- A role/platform SBOM generation or validation failure prevents that exact
  role image and its multi-architecture index from being published.
- A platform canonical version tag is pushed before its signature and
  attestations can be attached. If signing, attestation, or independent OCI
  verification fails, the workflow stops before promoting mutable aliases or
  building the multi-architecture index.
- Canonical indexes are assembled from verified platform digests before the
  aggregate SBOM is composed, allowing the index SBOM itself to embed the
  immutable index digest. Index signing, provenance, SBOM, OCI verification,
  or live Kubernetes admission failure can leave canonical version tags
  present, but stops mutable index-alias promotion.
- A retry accepts an existing canonical tag only when it resolves to the same
  expected digest. It fails instead of overwriting a canonical release tag
  that names different content.

The OCI image creation time is derived from the tagged commit timestamp, so a
fresh run for the same tag rebuilds the same image configuration instead of
changing the digest merely because wall-clock time advanced. Actual BuildKit
start and finish times remain recorded separately in each platform SBOM.
Retries may legitimately attach another timestamp-varying predicate to the
same immutable image. Verification therefore requires that OCI contain the
exact SBOM generated by the current run; unrelated historical predicates do
not satisfy that check and do not make the current matching predicate
ambiguous.

An interrupted release can therefore leave a version-specific platform or
index tag in GHCR without completing alias promotion. Treat a release as
complete only after its release workflow succeeds and its OCI-linked
signature and attestations pass the verification commands above.
