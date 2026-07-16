# Release Image Trust and Migration

OxiBelt publishes five role-specific container images. The current release
contract identifies those images by exact GHCR repository, release version,
role, and immutable digest. It does not publish or require a supported keyless
signature, build-provenance attestation, or release SBOM attestation for each
image digest.

An OCI digest identifies exact registry content, but it does not authenticate
who built or published that content. Operators must protect the registry and
release-management boundary, approve the intended release through their own
change process, and record the digest they approved.

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

The versioned multi-architecture index contains the supported index platforms;
architecture-specific variants can also be published under explicit tags.
Always resolve the exact tag intended for the target platform instead of
assuming that two tags name the same digest.

## Select and record an immutable digest

Start from an exact official repository and an approved version tag. Resolve
the registry digest before deployment:

```sh
image=ghcr.io/oxibelt/oxibelt-dataplane
version=15.2.0
digest="$(docker buildx imagetools inspect \
  --format '{{json .Manifest}}' \
  "${image}:${version}" | jq -r '.digest')"
printf '%s\n' "${digest}" | grep -Eq '^sha256:[0-9a-f]{64}$'
printf '%s@%s\n' "${image}" "${digest}"
```

Record the repository, release version, digest, target platform, approval
source, and approval time in deployment evidence. Re-resolve the digest before
an upgrade if a mutable alias such as `latest`, a major-version alias, or an
architecture alias was used for discovery. Never use a mutable alias as the
recorded deployment identity.

Both OxiBelt Helm charts accept `image.digest`. A lowercase
`sha256:<64-hex-characters>` digest takes precedence over `image.tag` and
renders `repository@sha256:...`:

```yaml
image:
  repository: ghcr.io/oxibelt/oxibelt-dataplane
  digest: sha256:FULL_64_CHARACTER_LOWERCASE_DIGEST
```

Use the controller repository with the same `image.digest` shape in the
Gateway Controller chart. Pin each role independently; a data-plane digest is
not evidence for a controller, tools, keysigner, or standalone image.

## Current trust boundary

The current release process retains role-specific builds, explicit executable
inventories, image labels, vulnerability scanning, versioned tags, and separate
multi-architecture indexes. These controls can catch packaging mistakes and
known vulnerabilities within their configured coverage, but they do not give a
consumer a cryptographically verifiable source-workflow binding.

In particular:

- A digest proves content identity after it is resolved, not publisher or
  source identity.
- Registry access control, protected release refs, workflow permissions, and
  maintainer review remain trusted authorities.
- Image labels and executable inventories are publisher-supplied metadata.
- CI vulnerability reports and dependency snapshots are not release SBOM
  attestations and do not prove that a deployed digest is vulnerability-free.
- Digest pinning does not provide freshness or rollback prevention. Operators
  must enforce those policies separately.
- Reproducible-build proof and base-image digest pinning are separate controls.

## Historical OCI referrers

Some existing GHCR digests may retain signatures, provenance statements, SBOMs,
or other OCI referrers produced before this release-contract rollback. Registry
referrers are content attached to one historical digest; they are not an
indication that current or future OxiBelt releases publish equivalent evidence.

Do not infer any of the following from referrer discovery alone:

- that the referenced release is currently supported;
- that every role or platform in that release has matching evidence;
- that a newer digest has been signed or attested;
- that historical evidence satisfies a current organizational policy; or
- that an interrupted release completed alias promotion.

An operator may continue to verify historical evidence under the policy that
was in effect when it was produced, but that verification is outside the
current OxiBelt release contract. Preserve the exact historical digest and the
old verification policy together when that evidence is needed for an audit.

## Migrating fail-closed admission policies

> **Warning:** A fail-closed admission policy that requires the former OxiBelt
> signature or provenance predicates will reject newly published images that do
> not carry those referrers. This is expected enforcement, not a transient
> registry failure.

Before upgrading a cluster that installed an earlier Sigstore Policy Controller
or equivalent OxiBelt policy, inventory every policy and namespace that selects
OxiBelt images. Choose one of these explicit migration paths:

1. Keep the policy and continue running the last approved historical digest
   that satisfies it.
2. Replace it with an organization-owned policy that enforces the controls
   still available, such as an exact repository allowlist and approved immutable
   digests, then test the replacement against every OxiBelt role before rollout.
3. Pause the upgrade until the organization has an alternative publisher and
   build-identity verification mechanism.

Do not switch a validating webhook to `failurePolicy: Ignore`, broaden an
allowlist to `ghcr.io/oxibelt/*`, or remove a fail-closed policy merely to make a
deployment proceed. Such a change weakens a cluster security boundary and must
be separately approved, staged, observed, and provided with a rollback plan.
Keep the last known-good digest available until the replacement policy and new
image have both passed admission in a non-production namespace.

## Release and rollback records

Treat a release as deployable only after its release workflow and repository
publication complete successfully and the exact intended digest is recorded by
the operator. A version-specific tag or historical OCI referrer can remain
visible after an interrupted attempt, so neither is sufficient evidence of
release completion by itself.

For rollback, retain the previous repository and digest for each deployed role.
Rollback should change the pinned digest, not repoint a mutable tag. The
standalone compatibility image keeps its existing entrypoint and integrated
Admin and Person Proof behavior; switching between standalone and minimal
data-plane repositories is an artifact-role change, not an equivalent digest
rollback.
