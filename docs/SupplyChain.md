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
still a workflow assertion until a separate rebuild verifies it. The
publication-time vulnerability gate described below applies repository policy
to the release scan, but operators must still enforce approval, current
vulnerability intelligence, freshness, rollback, and deployment approval.
OxiBelt's experimental admission-bundle flow supplies exact-evidence and
freshness enforcement for the documented Kubernetes path; it does not replace
those operator decisions.

## Official image repositories

Official builds bind one atomic identity tuple: release version, full source
revision, `refs/tags/<version>`, `clean`, and `official_release`. Release CI
requires that tuple to agree across the embedded executable marker and
`--version` output, authenticated runtime metadata, OCI version/revision and
OxiBelt source-ref/dirty/kind labels, the image plan, and the artifact
contract. The `official_release` field is not self-authenticating; trust still
requires the verified release workflow identity, tag and commit, subject
digest, and provenance described below. A local clean exact-tag build is
`tagged_development`, while a direct archive Docker build is
`0.0.0-dev.archive`; neither is an official artifact.

Release-like tags are covered by the active, bypass-free desired state in
`devops/config/github-release-tag-ruleset.json`. Creation requires the
GitHub Actions `Non-benchmark validation summary` status, while updates and
deletions are blocked. Operators must wait for the canonical default-branch
push at the intended commit to pass before creating a tag; a rejected tag
creation can be retried after that check succeeds.

Before release preparation or publication, the release workflow resolves the
tag to one full lowercase commit and uses read-only Actions, Checks, and
Contents access to inspect the newest canonical default-branch
`.github/workflows/check-oxibelt.yml` push run for that exact revision. It
requires the latest attempt to contain exactly one completed, successful
`Non-benchmark validation summary` job and verifies the corresponding check
name, revision, details URL, and GitHub Actions application identity. Failure,
cancellation, skip, missing or duplicate evidence, a stale older success, or
any repository, workflow, branch, event, ref, revision, check, or application
mismatch blocks release metadata, GHCR writes, attestations, manifests,
verification, and alias promotion. The 39-job terminal summary covers Rust,
dependency, TypeScript, fuzzing, sanitizer, cross-build, image, vulnerability,
database, Kubernetes, integration, signer, and browser validation. Benchmark
jobs and dependency-snapshot submission remain outside the release
prerequisite.

Source-validation artifacts are evidence for the gate, not official release
inputs. After the gate, release CI checks out the same immutable revision,
revalidates its tag identity, applies the disposable release-version rewrite,
and independently rebuilds every image. Actions transport names include the
release run and attempt so validation and release artifacts cannot collide;
the image plan, tar filenames, OCI repositories, and public tags are unchanged.
The runtime verifier and tag ruleset are complementary: the ruleset prevents
creation without the canonical status and makes matching tags immutable, while
the release workflow independently verifies exact-run provenance before any
publication permission is reached.

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

For AMD64 artifacts, the selected CPU policy applies to both Rust code through
`-Ctarget-cpu` and bundled native C or C++ code through target-qualified
`-march` flags. Thus `amd64v2`, `amd64`, and `amd64v4` consistently build at
`x86-64-v2`, `x86-64-v3`, and `x86-64-v4`, respectively. Bindgen parsing keeps
only its target and sysroot inputs; it does not inherit the code-generation
ISA flag. Direct Docker builds should set `OXIBELT_AMD64_TARGET_CPU`.
`OXIBELT_RUST_TARGET_CPU` remains a compatibility alias, and conflicting
values are rejected.

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

`edge-secure-medium` v2 is intentionally stricter than the general chart: it
admits only `ghcr.io/oxibelt/oxibelt-dataplane-strict` at an immutable digest
and requires the experimental signed admission bundle described below. The
Secret-free profile report records the exact image reference, bundle payload
digest, signing-key ID, and that admission is required. The ConfigMap is only
transport for an independently signed bundle; its Kubernetes checksum is not
provenance evidence.

## Verify Helm OCI release evidence

The Helm OCI receipt and deterministic-rebuild helper uses schema v3 and the
`https://oxibelt.dev/attestations/helm-chart-rebuild/v3` predicate type. Each
chart receipt embeds the exact registry descriptor, manifest, and config byte
sequences as canonical padded base64. Validation decodes and rechecks those
bytes to prove that the descriptor identifies the exact manifest, the manifest
identifies the exact config, and its single chart-content layer matches the
recorded package digest and size. Each embedded document remains limited to
256 KiB, and the canonical receipt or predicate envelope is limited to 4 MiB.

Schema-v2 receipts and `/v2` predicates are not valid release evidence and are
rejected rather than parsed as a legacy compatibility form. Matching published
and independently rebuilt archive bytes does not compensate for missing or
substituted registry evidence.

The release workflow uses this helper to publish exactly the two versioned
chart tags, build the bounded receipt, reproduce both packages with Helm
v4.2.4, and attest the schema-v3 predicate through GitHub's attestation API.
The `github-workflow-authentication-required` receipt value remains a policy
marker rather than proof by itself. Consumers must verify the exact GitHub
repository, signer workflow, source ref and revision, subject digest,
predicate type, and trusted timestamp through the GitHub attestation API.
Charts remain experimental and never receive a mutable `latest` or major
alias.

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

## Generate a deployment admission bundle

`oxibeltctl supply-chain admission-bundle` verifies a canonical
multi-architecture index, not a mutable tag. By default it calls `gh
attestation verify` separately for SLSA provenance, CycloneDX, and the OxiBelt
index rebuild recipe with the exact repository, digest, source ref, full
source revision, hosted-runner requirement, workflow identity, and predicate
type. There is no local-evidence bypass: all three attestation classes must
pass the GitHub CLI's cryptographic verification during bundle generation.

The index recipe must contain the exact producer contract: schema-v2 index
metadata for the requested role, repository, and digest; canonical Linux
`amd64`, `arm64`, and `riscv64` descriptor children; the canonical metadata
hash; the same ordered children and platform-recipe hashes; and the hash of
the selected CycloneDX predicate. Unknown or malformed fields fail closed.
Supply the ID of one successful automatic
`.github/workflows/verify-release-rebuild.yml` run. The command fetches its
three exact role/architecture artifacts through the GitHub API, verifies each
artifact archive against GitHub's immutable SHA-256 digest, safely extracts
one bounded receipt, and checks the receipt's repository, release ref, source
revision, role, architecture, exact platform-recipe hash, workflow path, run
ID, positive run attempt, and approved verifier commit. The fixed receipt shape
also binds both image and archive digests, the exact normalization allowlist,
an empty security-relevant difference set, and an outcome-specific guarantee.
`exact` requires both bound digests to match; any accepted digest inequality
must be `normalized_equivalent` and satisfy the fixed normalization comparison.
Unknown, partial, or
internally inconsistent receipts fail closed. Newly generated signed v2 bundles
expose run ID, run attempt, and each platform-recipe hash so a reviewer can
identify the exact GitHub execution and recipe whose bounded receipt hash was
accepted. Earlier unexpired v2 bundles without these explicit extension fields
remain readable; their signed receipt object hashes remain unchanged. The v2
schema accepts these extensions only as an all-absent legacy set or as a
complete positive run attempt plus all three platform-recipe hashes; partial
forms fail closed.
The workflow must be the approved revision on `main`; after all downloads, the
command rereads the run and requires its complete trusted identity and state to
be unchanged. `exact` and `normalized_equivalent` are accepted; a manual,
failed, stale, expired, missing, duplicate, mismatched, rerun, or unbound
receipt fails closed.

New bundles use schema v2. An optional bounded workload-policy file lets the
deployment signer approve third-party auxiliary images without claiming that
they received OxiBelt provenance, SBOM, or independent-rebuild verification:

```json
{
  "schemaVersion": 1,
  "auxiliaryContainers": [
    {
      "class": "native-sidecar",
      "name": "mesh-proxy",
      "imageReference": "ghcr.io/example/mesh-proxy@sha256:FULL_64_CHARACTER_LOWERCASE_DIGEST"
    }
  ]
}
```

The fixed classes are `regular`, `init`, `native-sidecar`, and `ephemeral`.
Native sidecars are entries in `spec.initContainers` with
`restartPolicy: Always`; ordinary init containers omit that field. Names are
globally unique lowercase Kubernetes DNS labels, `oxibelt` is reserved for the
primary regular container, and image references must be a fully qualified,
tagless `repository@sha256:<64 lowercase hex>` identity. Entries are optional
permissions: the admitted Pod may contain any subset, but every executable
that is present must match one exact signed class, name, and image.

```sh
umask 077
head -c 32 /dev/urandom > admission-bundle.ed25519

oxibeltctl supply-chain admission-bundle \
  --repository ghcr.io/oxibelt/oxibelt-dataplane-strict \
  --role dataplane-strict \
  --digest sha256:FULL_64_CHARACTER_LOWERCASE_DIGEST \
  --source-ref refs/tags/15.2.0 \
  --source-revision FULL_40_CHARACTER_GIT_COMMIT \
  --release-channel stable \
  --independent-rebuild-run-id SUCCESSFUL_AUTOMATIC_WORKFLOW_RUN_ID \
  --independent-rebuild-workflow-sha APPROVED_FULL_40_CHARACTER_VERIFIER_COMMIT \
  --revocations deploy/supply-chain/revocations.example.json \
  --workload-policy deployment-workload-policy.json \
  --signing-key-file admission-bundle.ed25519 \
  --public-key-output admission-bundle.ed25519.pub \
  --key-id deployment-admission-2026 \
  --output bundle.json
```

The signing key is a raw 32-byte Ed25519 seed in an owner-only regular file.
`--public-key-output` derives its raw 32-byte public key; distribute only that
file to the admission component. The command prints `payloadDigest`; this is
the identity placed in Helm values and on admitted Pods. Bundle payload
serialization and Ed25519 signing are
deterministic for identical evidence, policy inputs, and the explicitly
modeled verification time. `--workload-policy` is optional; omitting it emits a
v2 primary-only bundle with an empty auxiliary list. Entries are sorted by a
fixed class/name/image order before signing, and noncanonical signed policy
claims fail verification.

The verifier applies these hard bounds:

- 100 results and 16 MiB for each GitHub verification response;
- 1 MiB for workflow metadata, 4 MiB for at most 100 artifact records, 2 MiB
  for each ZIP archive, and 1 MiB for each of exactly three rebuild receipts;
- a 60-second deadline and 64 KiB diagnostic limit for every GitHub CLI call;
- 1,024 entries and 1 MiB for the revocation policy;
- 64 KiB and at most 63 entries for the auxiliary workload policy, leaving
  one executable slot for the required primary container;
- 256 KiB for the final bundle and each admission request;
- evidence freshness of at most one year, bundle lifetime of at most 30 days,
  and at most five minutes of future clock skew. Generation rejects a requested
  expiry after the earliest provenance, SBOM, rebuild-recipe, or independent-
  rebuild timestamp plus the configured evidence age. Admission independently
  recomputes that horizon, so a longer nominal expiry in an older signed bundle
  cannot keep stale evidence deployable.

The legacy v1 bundle schema remains
`deploy/supply-chain/admission-bundle.schema.json`. New bundles use
`deploy/supply-chain/admission-bundle-v2.schema.json`, and workload-policy
input uses `deploy/supply-chain/admission-workload-policy-v1.schema.json`.
Revocations use `deploy/supply-chain/revocations.schema.json`. Unknown fields, mutable refs,
role/repository confusion, conflicting duplicate predicates, unparseable
trusted timestamps, stale evidence, malformed CycloneDX properties, incomplete
rebuild coverage, workflow-attempt drift, and an effective revocation all fail
closed. Equivalent duplicate attestations are selected deterministically by
trusted timestamp and canonical object digest, independent of GitHub response
order.

## Kubernetes validating admission

Set `supplyChainAdmission.enabled=true` and provide the exact generated bundle,
payload digest, public key, revocation policy, TLS Secret, CA bundle, and a
digest-pinned official tools image. Also configure one to sixteen exact
`webhook.apiServerSourceCidrs` observed for the cluster's API-server webhook
connections; do not substitute the whole Pod or node CIDR. `edge-secure-medium`
v2 requires this configuration and rejects a bundle whose embedded repository,
role, image digest, payload digest, decision, or key ID differs from Helm
values.

The chart runs `oxibeltctl supply-chain admission-server` with no ambient
ServiceAccount token, no GitHub credential, no egress, a read-only root
filesystem, fixed CPU/memory limits, and a maximum of 128 concurrent TLS
connections. The `ValidatingWebhookConfiguration` uses `failurePolicy: Fail`,
matches only this release's OxiBelt Pods, and requires the exact bundle
annotation, role annotation, and digest-pinned `oxibelt` container image. A
second exact `UPDATE` rule covers `pods/ephemeralcontainers`; the chart never
uses `pods/*`. The server validates the final `spec.containers`,
`spec.initContainers`, and `spec.ephemeralContainers` shape as one globally
unique set of at most 64 executables. The primary is always required, and every
other regular, init, native-sidecar, or ephemeral image must match a signed v2
approval. A valid v1 bundle is accepted only as a primary-only policy, so
upgrading the server closes the legacy bypass without first rotating the
bundle. Missing, unreachable, malformed, expired, mismatched, unapproved, or
revoked evidence therefore blocks creation or update; existing running Pods
are not terminated.

The immutable ConfigMap is content-addressed by the bundle payload digest. The
admission Deployment and Service endpoint revision binds both that digest and
the exact webhook image repository/digest, so an image rotation cannot mix old
and new admission binaries behind one Service. On rotation, generate a new
bundle rather than editing one in place, install it with the new image identity,
and wait for the new admission endpoints before judging the data-plane rollout.
The Service may temporarily have no endpoints and fail closed during cutover;
Kubernetes controllers retry temporarily denied Pod creation. Operate at least
two replicas, retain the prior still-authorized bundle for rollback, monitor
readiness, and test certificate renewal before expiry.

Validating admission observes the final object after mutating admission. For a
workload that retains this release's chart selector labels, an injector
therefore succeeds only when its final container name, semantic class, and
exact digest are already signer-approved; name, class, or digest drift denies
the Pod. Kubernetes `objectSelector` labels are scoping, not an authorization
boundary: a mutating admission component that can remove those labels is a
trusted cluster-admission authority. The auxiliary policy intentionally does
not authenticate commands, arguments, environment, mounts, capabilities, or
security context. Pod Security and other admission controls remain
authoritative for those properties. Remove a compromised auxiliary approval by
rotating the bounded, expiring bundle; the schema-v1 revocation list remains
scoped to the primary OxiBelt artifact.

Key rotation requires a new key ID, public key, bundle, and content-addressed
admission Deployment. Revocation-policy changes also require a new bundle
because the payload signs the canonical policy hash. To withdraw the currently
deployed digest, publish the revocation and replacement bundle together; the
old webhook then becomes unready/fail-closed until a non-revoked bundle is
installed. Rollback is permitted only to an older digest that has fresh exact
evidence, accepted rebuild receipts, and no effective revocation.

This component authenticates the signed decision produced by the bundle
operator. Compromise of the bundle signing key, admission TLS key, Helm release
authority, webhook tools image, Kubernetes API/admission chain, or node remains
a deployment trust-boundary compromise. Keep the signing key outside the
cluster and do not place GitHub credentials in data-plane or admission Pods.

## Independent rebuild verification

`.github/workflows/verify-release-rebuild.yml` is a separate read-only
consumer of published evidence. After a successful stable or beta release it
rebuilds all six roles and five architecture variants plus both Helm charts.
A manual dispatch can target one stable, beta, or build image artifact. The
automatic job checks out the exact tag in a fresh tree, starts an isolated
rootless Docker daemon, verifies image and schema-v3 chart attestations through
GitHub's API, resolves canonical GHCR digests, and rebuilds without consuming
producer build outputs.

Every automatic beta or stable verification seals one schema-3 release
qualification containing exactly 30 image receipts, two byte-identical chart
receipts, 12 immutable index identities with exact independently verified
`amd64`, `arm64`, and `riscv64` child descriptor bindings, and the exact
producer and verifier run identities. Both canonical tags for each role must
resolve to the same index digest and child set. Beta qualifications contain no
mutable aliases. For a stable
qualification, the producer's exact release-contract receipt must name the
sole latest same-target beta; that beta's exact aggregate bytes, tag, release,
automatic verifier run, artifact identity, and SHA-256 are bound into the
stable qualification. Stable publication must occur at least 24 hours after
both beta publication and completion of the beta qualification. The verifier
derives every plan field and the complete stable alias inventory with its
approved release-planning code; producer image-plan metadata is not a
qualification input.

The release producer writes only immutable versioned image and chart tags.
`.github/workflows/promote-stable-aliases.yml` is the sole mutable-alias writer.
It accepts only the newest published stable release and a complete automatic
qualification, re-reads every immutable digest and both chart attestations in
a read-only job, rechecks every index child against the sealed independent
platform receipts, and requires the exact 30 platform plus 18 index alias,
source-tag, digest, and kind mappings before snapshotting. The final
`packages: write` job derives and checks the same mapping and validation-run
identity again before registry authentication, then performs sequential
idempotent promotion from qualified immutable digests. It also repeats the
index-child readback immediately before mutation. Manual, beta, build, stale,
replayed, pre-schema-3, incomplete, duplicated, cross-role, or drifted
qualifications fail closed; chart aliases are never created.

Manual dispatch remains a diagnostic facility and is never accepted as
release-admission evidence. Admission bundles accept only a successful
automatic `workflow_run` for a stable or beta release.

GitHub-hosted verification requests Docker's `cgroupfs` driver so the rootless
daemon does not require an interactively authorized systemd scope. Docker
reports no host cgroup resource controller in this configuration, so
per-container CPU and memory limits are not enforced. The verifier does not
depend on those limits: rootless user isolation, seccomp, and a cgroup
namespace remain required, while the ephemeral runner, job timeout, and
`max-parallel` bound resource exhaustion.

The verifier writes a machine-readable receipt with one of four outcomes:

- `exact` means both the rebuilt OCI manifest digest and complete image archive
  SHA-256 match the published values exactly;
- `normalized_equivalent` means the semantic image contract matches after
  ignoring only documented archive ordering, compression, filesystem mtime,
  and OCI created/history timestamp fields. This includes a matching manifest
  packaged into a different archive; archive inequality can never be `exact`;
- `mismatch` is a verification failure; and
- `unverifiable` means evidence was missing, malformed, unsafe to compare, or
  outside the comparator's resource bounds, and also fails the job.

Successful receipts also carry the exact source repository, tag ref, full
revision, image role, architecture, verifier workflow path and approved commit,
run ID, and run attempt. The verifier workflow commit is checked out separately
from the release source tree; all planning, comparison, and receipt-binding code
runs from that approved verifier tree while the release tree is only a build
input. These fields make a downloaded artifact reviewable and prevent a
receipt from another successful run or release from being substituted during
admission-bundle generation.

Normalization preserves filesystem content and types, modes, ownership,
links, extended attributes and capabilities, OCI configuration, executable
hashes, and the SBOM graph. A normalized result is evidence of semantic
equivalence, not a claim of byte-for-byte reproducibility. CycloneDX ordering
is normalized only for schema-validated component, dependency, `dependsOn`,
property, and hash collections from CycloneDX `1.6` or `1.7`; every component
requires string `type` and `name`, and custom arrays retain their order. Its generated
serial number and timestamp are ignored. The root image subject hash/property
are ignored only when each is an exact-shaped, unique binding to that SBOM's
declared OCI subject; duplicate, malformed, or missing bindings fail closed.
All other fields remain comparison-significant. A failed comparison emits at
most eight sorted filesystem path fingerprints and at most eight component or
dependency fingerprints per collection, with total and truncation counts. The
receipt never copies image content or archive paths into diagnostics, and
rejects SBOMs outside its fixed depth, node, and collection-item bounds.

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

## Release image vulnerability admission

Official image release scanning is a publication gate, not only a report. The
repository-owned policy is
`supply-chain/image-vulnerability-policy.json`; contributors validate its
schema, thresholds, and exceptions with:

```sh
pnpm run image-vulnerability-policy:check
```

Release CI builds and scans all 30 final platform images: each of the six roles
at `amd64v2`, `amd64`, `amd64v4`, `arm64`, and `riscv64`. Trivy receives the
loaded image's full immutable SHA-256 image ID rather than a mutable local or
GHCR tag. A scan contract binds that ID, the raw Trivy report, release run and
attempt, source revision, role, architecture, policy hash, and expected OCI
manifest digest. Publication must later resolve to that exact manifest digest.
Raw scan artifacts remain immutable and attempt-qualified. On a failed-job
rerun, the global gate selects each subject's highest available evidence
attempt from the same release run that is no newer than the current attempt.
The selected artifact name, contract attempt, and subject must agree exactly;
a malformed or incomplete newest artifact fails closed without falling back
to older evidence. Missing, duplicate, future-attempt, wrong-run,
wrong-revision, or hash-mismatched evidence also fails closed.

The channel thresholds are:

| Release channel | Blocking findings | Report-only findings |
| --- | --- | --- |
| `stable`, `beta` | Every `CRITICAL`; every `HIGH` with a nonempty Trivy `FixedVersion` | `HIGH` without a fix, `UNKNOWN`, `MEDIUM`, and `LOW` |
| `build` | Every `CRITICAL` | Every `HIGH`, `UNKNOWN`, `MEDIUM`, and `LOW` |

Scanner failures, unsupported severities, and malformed finding fields are gate
errors, not report-only results. Trivy's raw JSON remains unfiltered: the
workflow does not hide findings with `.trivyignore`, `ignore-unfixed`, or a
filtered report. Release CI uploads the available raw reports, scan contracts,
and global decision before enforcing the result and retains them for seven
days, including on failed gates. Pull-request, scheduled, and other nonrelease
image scans remain report-only and do not gain package-publication authority.

An exception can admit only an otherwise-blocking finding. Its exact identity
fields are `exceptionId`, `vulnerabilityId`, `packageName`, `packagePurl`,
`packageType`, `installedVersion`, `fixedVersion`, and `severity`; an empty
`fixedVersion` means that Trivy reports no known fix. Its exact scope fields
are nonempty `roles`, `channels`, and `architectures`. It also requires
`rationale`, `impactAnalysis`, an `owner` in `@username` form, an `approvalUrl`
under `https://github.com/OxiBelt/OxiBelt/issues/<number>` or
`https://github.com/OxiBelt/OxiBelt/pull/<number>`, and `reviewedOn` and
`expiresOn` UTC dates.

Wildcards, unknown fields, overlapping or duplicate exceptions, empty scopes,
future review dates, and an interval longer than 90 days from review through
expiry are invalid; `expiresOn` remains valid through that UTC date. Every
declared role and architecture combination in the current channel must contain
the exact finding. Partial matches are overbroad and fail, and an applicable
exception that no longer matches the scan is stale and also fails. Excepted
findings remain visible in the raw report.

One read-only global gate evaluates the complete 30-subject matrix before any
job with `packages: write` can start. The `schemaVersion: 2` decision remains
bound to the gate producer attempt and records `evidenceAttempt` for every
subject. The gate exports its canonical artifact name and producer attempt to
each publisher. A rerun may reuse that decision only from the same release run,
with a nonempty canonical `release-vulnerability-decision-RUN_ID-ATTEMPT` name
and a positive producer attempt no newer than the consumer; malformed,
cross-run, missing, or future-attempt references fail before the artifact is
downloaded. The current build-and-scan matrix must still succeed; prior
evidence cannot admit a currently failed row. Each publisher revalidates that
its role, architecture, gate producer attempt, revision, policy hash, evidence
provenance, and manifest digest appear in the allowed decision before registry
login or push. This prevents a clean matrix leg from publishing while another
subject is missing or blocked.

The versioned multi-architecture index is not redundantly vulnerability-scanned
because it contains no package inventory beyond its platform children. Its
existing descriptor and SBOM checks remain mandatory, and every canonical
`amd64`, `arm64`, and `riscv64` child digest must appear in the admitted global
decision before index assembly. Explicit architecture tags likewise refer only
to platform images that passed the gate.

The decision reflects the pinned Trivy version and vulnerability database
available during the release run. A passing gate is not a promise that an
image is vulnerability-free, does not account for vulnerabilities disclosed
later, and cannot eliminate false positives or component-detection gaps.
Operators must rescan approved immutable digests with current intelligence and
apply their own deployment admission, freshness, remediation, and rollback
policy.

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
executable and package inventories, image metadata, SBOMs, and attestations.
The release-only `riscv64` scan workflow then performs a bounded functional
smoke under QEMU user-mode emulation before the corresponding platform image
can reach the package-write publication job. Emulation remains outside the
build boundary: the smoke job downloads the already-built image tar plus its
release plan and artifact contract, verifies every digest and the official
build identity, and loads only the validated config digest. Its QEMU setup
action and `binfmt` image are immutable-pinned, scoped to `riscv64`, and cannot
alter an image that will later be published.

The smoke runs all six role images. It requires exact `/usr/local/bin`
inventories and successful `--version` identity output; checks configuration
validation, server startup, health endpoints, and an HTTP/1 redirect for the
data-plane roles; proves the strict role refuses an Admin-enabled
configuration; exercises controller rendering, authenticated Kubernetes
watching, leader contention, and health/readiness separation; and verifies a
real keysigner process creates its Unix socket and readiness event. Runtime
containers are non-root, read-only, capability-free, protected by
`no-new-privileges`, and given explicit process, memory, CPU, and timeout
ceilings. The job records a bounded JSON receipt and failure diagnostics,
removes only resources it created, and has read-only repository permissions
with no secrets or package write capability.

This is a deterministic functional admission check, not a benchmark, soak
test, full protocol matrix, or native-hardware qualification. QEMU cannot prove
RISC-V hardware performance, kernel/device behavior, or every production path.
A valid RISC-V attestation therefore authenticates the released artifact and
build workflow under the documented policy; the pre-publication smoke adds
bounded emulated-runtime evidence but does not replace a future native RISC-V
hardware lane. Updating the pinned cross-toolchain or QEMU images, their
expected identities, the role inventory, or the smoke boundary is a
supply-chain change that requires review and synchronized integrity-test
updates.

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
  attestation alone does not prove code review, branch protection, approval by
  a person, or an independently successful rebuild.
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

The OxiBelt admission-bundle verifier consumes the GitHub API verification
model above; it does not search OCI referrers or require Cosign sibling
artifacts. A policy that searches GHCR referrers, requires a Cosign signature,
or verifies with `--bundle-from-oci` will not find the current API-only
records. Do not switch the validating webhook to `failurePolicy: Ignore`,
broaden an allowlist to `ghcr.io/oxibelt/*`, or remove a fail-closed policy
merely to make deployment proceed. Bundle v2 permits only signer-approved
exact class/name/digest entries; it does not permit repository prefixes or
wildcards. Any replacement admission policy is an
operator-owned security-boundary change and must be separately approved,
staged, tested for every role, and given a rollback plan.

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
