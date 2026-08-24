# OxiBelt Stable Changelog

This file records stable OxiBelt releases only. Beta releases are recorded in
[CHANGELOG-beta.md](CHANGELOG-beta.md). Development build tags such as
`0.7.0-build.46d6ea54` do not receive changelog entries or GitHub Releases.

OxiBelt follows [Semantic Versioning](https://semver.org/). Starting with the
release after `0.6.5`, every stable entry is a person-reviewed, cumulative
description of changes since the immediately preceding stable release. Release
automation rejects missing, cross-channel, misordered, or placeholder-only
entries. See the
[contributor release contract](CONTRIBUTING.md#release-changelog-and-upgrade-contract)
for the governed entry format.

## [0.8.1] - 2026-08-24

> Stable carry-forward of the person-reviewed `0.8.1-beta.9` source after its
> complete exact-revision automatic qualification. The beta-to-stable delta is
> one documentation-only commit and changes no runtime, configuration, schema,
> dependency, image, chart, or deployment behavior.

- Changes since: `0.6.6`
- Supported upgrade sources: `0.6.6`, `0.8.1-beta.9`
- Upgrade guide: [Upgrade from 0.6.6 to the 0.8.1 line](docs/Upgrading.md#upgrade-from-066-to-the-081-line)

### Configuration

- Advance the native configuration surface to epoch `1` with activation
  planning, typed secret references, manifest-bound filesystem confinement,
  strict seccomp expectations, resolved-topology diagnostics, and the
  `edge-secure-medium` v2 deployment profile. Selected but unavailable or
  unqualified capabilities fail closed.
- Add bounded persistent direct-H1, pooled direct-H2, adaptive HTTP/3, QUIC
  Initial reassembly, and Happy Eyeballs v3 upstream dialing. Use
  `[proxy.upstream_resolution]` as the canonical resolver policy and retain
  `[quic.upstream.resolution]` only as the epoch-1 compatibility input.
- Preserve `access_log.system.enabled` as the canonical system access-log
  switch and the `0.6.6` `access_log.enable_system` compatibility input.

### Schema epochs

- Advance native configuration from epoch `0` to epoch `1`. Migrate with
  `oxibeltctl config migrate --from 0 --to 1`; there is no automatic
  down-migration.
- Add versioned deployment, confinement, feature-evidence, supply-chain
  admission, workload-policy, revocation, and Helm OCI evidence schemas.
  Consumers must reject unknown schema versions.

### Deprecations and removals

- Keep `access_log.enable_system` and `[quic.upstream.resolution]` as
  compatibility inputs. New configurations must use
  `access_log.system.enabled` and `[proxy.upstream_resolution]`; configuring
  the same effective resolver leaf in both tables remains invalid.
- Replace partial image-admission assumptions with digest-bound attestation,
  SBOM, provenance, vulnerability, independent-rebuild, and signed
  workload-policy evidence. Partial or mismatched evidence cannot qualify a
  release.

### Admin API

- Add durable long-running operations, external audit-chain anchoring, atomic
  secret-reference activation, staged fixed-member membership, and version-2
  membership epochs while retaining compatible version-1 learners.
- Add explicit owned and embedded runtime APIs plus activation-plan and
  resolved-topology diagnostics. Mutation decoding, signing, idempotency,
  authorization, audit classification, and rollback remain fail closed.

### Feature lifecycle

- Keep every tracked general and Kubernetes feature `experimental` and
  `unvalidated`. Stable versioning does not graduate a feature or substitute
  for its exact native or cluster evidence.
- Bind graduation evidence to the canonical repository, exact ref and
  revision, target version, complete registry inventory, phase, and required
  platform. Missing, stale, duplicate, or partial evidence is ineligible.
- Permit mutable stable aliases only after the stable release, all exact
  stable-version artifacts, independent rebuilds, aggregate qualification,
  and final registry readback pass their stable-only authorization gates.

### Rulepack compatibility

- Retain the existing OxiRule and CRS compatibility contract without a
  rulepack format, syntax, matching, normalization, precedence, or production
  response change.
- Use the directly executed same-project `online-dsl-forge` parser at `0.3.1`
  with its crates.io checksum and Cargo-vet delta audit bound to the release.
- Refresh the directly admitted `syn` parser line to `3.0.4` with its
  Cargo-vet delta audit and lockfile checksum bound to the release.

### Executables and images

- Deliver the role-separated `oxibelt`, `oxibeltctl`, `oxibelt-keysigner`,
  `oxibelt-netport-switcher`, `oxibelt-gateway-controller`, and
  `oxibelt-dataplane-strict` surfaces as six image roles with five platform
  subjects per role.
- Build the workspace and standalone probes with Rust `1.98.0`; keep the
  admitted Cargo graph, Node 24 policy, pnpm `11.23.0`, immutable action and
  container pins, BuildKit `0.32.2`, Trivy `0.74.0`, Helm `4.2.4`, and the
  supported Kubernetes image set exact.
- Run the sustained fuzz lanes with the dated `nightly-2026-08-24` toolchain;
  the production workspace and release images remain on Rust `1.98.0`.
- Publish all 30 exact `0.8.1` image subjects and both exact-version Helm chart
  packages only through the governed release workflow. Require vulnerability,
  SBOM, provenance, attestation, independent-rebuild, and registry-readback
  verification before mutable stable image aliases may advance; charts receive
  no mutable aliases.

### Storage and state

- Serialize PostgreSQL shared-state initialization, retain durable Admin
  operation and membership records, and preserve append-only audit anchoring.
  Stop new-version writers before rollback and restore a compatible database
  backup with the older binaries.
- Retain durable UDP ownership and rollout state with explicit
  mixed-generation admission and cleanup boundaries. Resolver,
  connection-pool, and runtime-planning state remain bounded in memory and are
  discarded on drain or restart.

### Upgrade validation

- Create and inspect an epoch-1 sibling tree, validate it with the `0.8.1`
  binaries, and inspect the canonical Helm client before staged rollout:

```sh
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1 --dry-run
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1
oxibeltctl config validate \
  /etc/oxibelt/config/oxibelt.toml.migrated-v1/oxibelt.toml \
  --local-only
helm version --short
```

- Render both charts, inspect immutable admission references, and perform a
  staged rollout while observing readiness, drain, audit anchors, shared
  state, Gateway Controller Lease ownership, resolver provenance, and
  connection-capacity rejection metrics before increasing traffic.

### Rollback and irreversible steps

- Retain the `0.6.6` and qualified beta.9 image digests, complete epoch-0 and
  epoch-1 configuration trees, referenced assets, compatible PostgreSQL
  backups, admission bundles, audit evidence, controller rollback ConfigMaps,
  Gateway API CRDs and Lease, and shared UDP identity material through rollout.
- Stop new-version Admin, membership, shared-state, and UDP writers; drain the
  data plane before the controller; restore the selected older binaries,
  configuration, and database together; and remove unknown epoch-1 tables
  before validating with `0.6.6`. There is no automatic epoch-1
  down-migration.
- External audit checkpoints, exported telemetry, terminated connections,
  sessions, datagrams, endpoint selection, and client-visible effects cannot
  be recreated by rollback.

### Known issues

- Native `linux/riscv64` cluster-runner graduation evidence remains unmet;
  every tracked general and Kubernetes feature remains experimental and
  unvalidated.
- Keep `generic-array` `0.14.7` while `crypto-common` selects that
  compatibility line, `x509-cert` `0.2.5` for `x509-ocsp`'s public type
  family, and `@types/node` on the Node 24 policy line. These are reviewed
  compatibility holds rather than stale lockfile resolution.
- Keep the standalone protocol probe's direct `h2` dependency aligned at the
  already-admitted `0.4.18` for its bounded fragmented-body WAF oracle. This
  test-only edge does not change runtime behavior and remains tracked in
  [#153](https://github.com/OxiBelt/OxiBelt/issues/153) until the Hyper path can
  prove complete request-body submission itself.
- Whole-crate `safe-to-deploy` certification remains withheld for
  `kube-client` `4.2.0` and `web-transport-trait` `0.4.0`. Their exact,
  expiring Cargo-vet exceptions and selected-path mitigations are tracked in
  [#120](https://github.com/OxiBelt/OxiBelt/issues/120) and
  [#121](https://github.com/OxiBelt/OxiBelt/issues/121); proxy transport and
  raw generic receive-buffer paths remain outside the admitted runtime surface.
- Preserve every earlier failed, incomplete, or superseded `0.8.0` and
  `0.8.1` beta cut as immutable history. Do not relabel or reuse their artifacts,
  attestations, receipts, or workflow evidence.

### Security

- Block every `CRITICAL` finding and every fixable `HIGH` finding for each
  exact image subject; no global allowance may rescue a failed role or
  platform.
- Preserve fail-closed nested-path decoding, HTTP framing and WAF decisions,
  TLS and CRLite policy, QUIC Initial admission, WebTransport isolation,
  effective-owner HTTPS/SVCB binding, per-candidate connection admission,
  shared-state mutation, Kubernetes confinement, secret redaction, and audit
  boundaries.
- Require approved registries, immutable lockfile checksums, no unreviewed
  lifecycle scripts, complete license and advisory gates, exact Cargo-vet
  audits or exemptions, digest-bound SBOM and provenance, signed admission
  evidence, independent rebuild receipts, and one exact aggregate
  qualification result before stable aliases may advance.

## [0.6.6] - 2026-08-14

> Published maintenance release. The immutable release was cut from a
> maintenance branch before this governed entry existed. This entry records
> the published change without moving the tag, reconstructing release
> evidence, or retroactively qualifying that cut under the current contract.

- Changes since: `0.6.5`
- Supported upgrade sources: `0.6.5`
- Upgrade guide: [Upgrade from 0.6.5 to 0.6.6](docs/Upgrading.md#upgrade-from-065-to-066)

### Configuration

- Restore the legacy `access_log.enable_system` switch as an accepted runtime
  source of system access-log enablement while retaining
  `access_log.system.enabled` as the canonical configuration path. When either
  switch enables system records, configured stdout and OTLP sinks receive the
  same records.

### Schema epochs

- No changes for this release.

### Deprecations and removals

- Keep `access_log.enable_system` as a legacy compatibility input. New
  configurations should use `access_log.system.enabled`; neither field is
  removed by this maintenance release.

### Admin API

- No changes for this release.

### Feature lifecycle

- No changes for this release.

### Rulepack compatibility

- No changes for this release.

### Executables and images

- Rebuild the selected `0.6.6` executable or image from the immutable signed
  `0.6.6` source revision. Do not substitute an artifact from the divergent
  development branch merely because it contains the corresponding fix.

### Storage and state

- No changes for this release.

### Upgrade validation

- Validate the complete configuration and referenced files with the `0.6.6`
  `oxibeltctl` before rollout, then confirm the intended system access-log sink
  receives a probe record:

```sh
oxibeltctl config validate /etc/oxibelt/config/oxibelt.toml --local-only
```

### Rollback and irreversible steps

- The change introduces no schema or durable-state migration. Retain the
  prior image digest and configuration, drain the `0.6.6` instance, and
  restore both together if legacy system records cause an unexpected logging
  volume. Records already exported to stdout or OTLP are not retractable.

### Known issues

- The governed entry and lineage reconciliation were added after the signed
  tag and published release. They preserve attributable history but cannot
  manufacture missing exact-tag contract evidence or alter the immutable
  `0.6.6` release commit.

### Security

- Treat access-log destinations as sensitive telemetry sinks. Keep existing
  redaction, transport authentication, retention, and least-privilege controls
  in place when legacy enablement restores delivery.

## [0.6.5] - 2026-07-16

> Historical baseline. This release predates the versioned changelog and
> upgrade contract. No compatibility or migration claims are reconstructed
> retrospectively.

- Source revision:
  [`46b30e90c40530196aa8024b67b4bfaec82d33d3`](https://github.com/OxiBelt/OxiBelt/commit/46b30e90c40530196aa8024b67b4bfaec82d33d3)
- GitHub release:
  [`0.6.5`](https://github.com/OxiBelt/OxiBelt/releases/tag/0.6.5)
- Earlier releases:
  [GitHub Releases](https://github.com/OxiBelt/OxiBelt/releases)
