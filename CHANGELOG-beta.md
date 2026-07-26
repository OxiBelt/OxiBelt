# OxiBelt Beta Changelog

This file records beta releases with tags of the form `X.Y.Z-beta.N` only.
Stable releases are recorded in [CHANGELOG.md](CHANGELOG.md). Development
build tags such as `0.7.0-build.46d6ea54` do not receive changelog entries or
GitHub Releases.

Each `beta.1` entry describes changes since the immediately preceding stable
release. Each later beta describes changes since the preceding beta for the
same target version. Exact beta entries are required only for beta tags created
after this contract is introduced; OxiBelt has no pre-contract beta tags to
backfill.

See the
[contributor release contract](CONTRIBUTING.md#release-changelog-and-upgrade-contract)
for the governed entry format.

## [0.7.0-beta.2] - 2026-07-26

> First publishable beta for the `0.7.0` line. Relative to the immutable
> `0.7.0-beta.1` source revision, this cut changes release qualification and
> metadata only; it does not change OxiBelt runtime behavior.

- Changes since: `0.7.0-beta.1`
- Supported upgrade sources: `0.7.0-beta.1`, `0.6.5`
- Upgrade guide: [Upgrade from 0.6.5 to the 0.7.0 line](docs/Upgrading.md#upgrade-from-065-to-the-070-line)

### Configuration

- No changes for this release.

### Schema epochs

- No changes for this release.

### Deprecations and removals

- No changes for this release.

### Admin API

- No changes for this release.

### Feature lifecycle

- No changes for this release.

### Rulepack compatibility

- No changes for this release.

### Executables and images

- Correct release-only `linux/riscv64` runtime-smoke socket preparation so the
  helper sets the directory mode before transferring ownership. The helper
  retains `--cap-drop ALL` with only `CAP_CHOWN`; no OxiBelt executable, image
  filesystem, runtime user, or runtime capability contract changes.
- Record the failed `0.7.0-beta.1` cut in the governed beta ledger so the
  immutable tag remains attributable without creating or rewriting a release
  for that tag.

### Storage and state

- No changes for this release.

### Upgrade validation

- When upgrading directly from `0.6.5`, create and inspect the epoch-1 review
  tree with the target `oxibeltctl`, then validate the complete migrated
  configuration and all referenced files before activation:

```sh
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1 --dry-run
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1
oxibeltctl config validate \
  /etc/oxibelt/config/oxibelt.toml.migrated-v1/oxibelt.toml \
  --local-only
```

- For a source build made from `0.7.0-beta.1`, the same epoch-1 configuration
  remains valid, but deploy only person-reviewed `0.7.0-beta.2` release
  artifacts after verifying their exact repositories, digests, build identity,
  GitHub attestations, and independent-rebuild result.

### Rollback and irreversible steps

- Retain the exact prior role-specific image digests, configuration tree,
  referenced assets, PostgreSQL backup, controller rollback ConfigMaps, and
  Gateway API Lease before rollout. Stop all new-version Admin writers before
  restoring the prior images and data; epoch-1 migration has no automatic
  down-migration, so restore the epoch-0 configuration and pre-upgrade
  PostgreSQL backup or roll forward.
- Roll back the data plane before the Gateway Controller. Before returning to a
  controller without Lease fencing, run one controller replica and wait for
  replacement; never downgrade or delete operator-owned Gateway API CRDs as an
  implicit Helm rollback. Externally witnessed audit checkpoints are
  append-only and must not be rewritten during recovery.

### Known issues

- The Kubernetes Gateway Controller, its Helm integration, and its Gateway API
  features remain `experimental`; their native `linux/riscv64` cluster-runner
  graduation evidence is still unmet.
- UDP stream-listener and generated `UDPRoute` flow state is process-local and
  does not survive a process restart or Pod replacement.
- Existing admission policies that require the retired OxiBelt-managed Cosign
  signature or OCI-referrer contract reject the GitHub API-attested images
  until an operator installs and validates a replacement admission policy.

### Security

- Preserve the fail-closed stable/beta image gate for every `CRITICAL`
  vulnerability and every fixable `HIGH` vulnerability, and preserve
  exact-revision SLSA provenance, CycloneDX SBOM, and independent-rebuild
  evidence for each role and architecture.
- The RISC-V release-smoke repair keeps the helper least-privileged: socket
  ownership setup uses only `CAP_CHOWN`, and the helper does not gain
  `CAP_FOWNER` or a broader container capability set.

## [0.7.0-beta.1] - 2026-07-26

> Immutable unpublished failed cut. The tag workflow rejected this tag before
> draft creation because the exact tagged revision had no governed beta entry.
> No GitHub Release or official release artifacts were produced, and this tag
> is not a published beta.

- Changes since: `0.6.5`
- Supported upgrade sources: `0.6.5`
- Upgrade guide: [Upgrade from 0.6.5 to the 0.7.0 line](docs/Upgrading.md#upgrade-from-065-to-the-070-line)

### Configuration

- Add opt-in PostgreSQL-backed Admin operation persistence, fixed-member
  `admin_cluster` rollout, atomic typed secret-reference activation, and
  external audit anchoring. Activation validates prerequisites and fails
  closed rather than silently falling back.
- Add raw TCP/UDP stream pools and Gateway API `TCPRoute`, `UDPRoute`, and
  `BackendTLSPolicy` inputs, including bounded UDP flow controls and explicit
  upstream TLS trust policy. Helm values add the strict data-plane role,
  controller high availability, additional L4 ports, and their least-privilege
  policy controls.

### Schema epochs

- Establish native configuration schema epoch `1`, publish its JSON Schema,
  and add local `oxibeltctl config schema`, `validate`, `explain`, and
  deterministic epoch-0-to-1 sibling-tree migration commands. Rust semantic
  validation remains authoritative.

### Deprecations and removals

- Migrate legacy `tls.key_exchange_groups` to
  `tls.1_3.key_exchange_groups`, `tls.session_tickets` to
  `tls.resumption.mode`, and `tls.session_ticket_rotation_seconds` to
  `tls.resumption.rotation_seconds`. The epoch-1 validator accepts the
  documented compatibility aliases only where they do not conflict with the
  canonical fields.
- Migrate `upstream_pools[].health_check.rise` to `healthy_threshold` and
  `upstream_pools[].health_check.fall` to `unhealthy_threshold`; configuring
  an alias with its canonical field is invalid.
- Remove OxiBelt's bundled Sigstore Policy Controller and Cosign/OCI-referrer
  admission assets. Official image evidence uses GitHub API-hosted attestations
  and requires an operator-owned admission policy where cluster admission is
  needed.

### Admin API

- Add durable long-running operation journals, recovery classes, progress,
  bounded encrypted artifacts, terminal receipts, cancellation, and
  restart-safe fencing; process-local WebTransport snapshot/drain work remains
  explicitly ephemeral.
- Add redacted configuration schema, validation, and explanation surfaces;
  fixed-member rollout diagnostics and all-member acknowledgement; atomic
  secret-reference activation; external audit-anchor status; and canonical
  build identity metadata.

### Feature lifecycle

- Mark native schema tooling, role-specific OCI artifacts, dependency
  admission, the strict data-plane artifact, durable Admin operation control,
  fixed-member Admin rollout, atomic secret activation, and external audit
  anchoring as `supported`.
- Keep the Gateway Controller, its Helm charts, Gateway API route translation,
  and `BackendTLSPolicy` integration `experimental`; their objective graduation
  gates remain authoritative.

### Rulepack compatibility

- Require catalog `min_oxibelt_version` values to use strict SemVer. A gated
  rulepack is compatible only when `oxibeltctl` has an official clean exact-tag
  identity at or above the requested version; untagged, dirty, and source
  archive identities fail closed. Catalog entries without this field retain
  their existing compatibility.

### Executables and images

- Add the `oxibelt-dataplane-strict` package, executable, OCI repository, and
  Helm role. It retains the public proxy, WAF, Person Proof, health, metrics,
  reload, and lifecycle surfaces while compiling out Admin listeners,
  mutations, operations, cluster runtime, and the Admin OpenAPI asset.
- Expand `oxibeltctl` with local configuration schema/migration/validation/
  explanation and external audit verification commands. Bind binaries, Admin
  metadata, OCI labels, attestations, and release subjects to one validated
  build identity while retaining Cargo's committed `0.0.0` sentinel.
- Define separate standalone, compatibility data-plane, strict data-plane,
  Gateway Controller, tools, and keysigner release-image roles for
  `linux/amd64`, `linux/arm64`, and `linux/riscv64`, each with exact
  executable-inventory and role-confusion checks.

### Storage and state

- Add additive PostgreSQL state for durable Admin operations, fixed-member
  rollout, encrypted commands/checkpoints, external audit-anchor outbox and
  authority records, and bounded retention. Old binaries do not understand
  these new rows, so rollback requires stopping new writers and restoring
  compatible data.
- Secret activation retains bounded rollback grace and redacted reference-set
  fingerprints. Raw UDP stream and generated `UDPRoute` flow state remains
  bounded and process-local.

### Upgrade validation

- Create and inspect the epoch-1 review tree with the target `oxibeltctl`, then
  validate the complete migrated configuration and every referenced
  certificate, key, rule, and other external file before activation:

```sh
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1 --dry-run
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1
oxibeltctl config validate \
  /etc/oxibelt/config/oxibelt.toml.migrated-v1/oxibelt.toml \
  --local-only
```

- Before enabling fixed-member rollout, durable operations, secret activation,
  or external anchoring, validate matching build/capability identity,
  membership and deployment epochs, PostgreSQL authority, signer keys,
  expected audit streams, and rollback witnesses on every member.

### Rollback and irreversible steps

- Retain the exact `0.6.5` role image digests, epoch-0 configuration and
  referenced assets, and PostgreSQL backup. Stop all `0.7.0` Admin writers
  before restoring prior images and data. There is no automatic epoch-1
  down-migration; restore the epoch-0 tree and pre-upgrade database backup or
  roll forward.
- Roll back the data plane before the Gateway Controller. Before downgrading
  past Lease fencing, run one controller replica and wait for replacement.
  Retain controller-generated rollback ConfigMaps and the Lease, and never
  downgrade or delete operator-owned Gateway API CRDs as part of Helm rollback.
- External audit checkpoints and independently retained witnesses are
  append-only evidence. Do not rewrite or delete them; start a new deployment
  epoch when recovery changes the witnessed stream lineage.

### Known issues

- This tag cannot be repaired or republished: release-tag policy prohibits
  update and deletion, and its exact revision cannot satisfy the governed-entry
  contract. No draft, GitHub Release, or official image set exists for
  `0.7.0-beta.1`; use the first subsequent person-reviewed beta instead.
- The release-only `linux/riscv64` keysigner smoke cannot prepare its Unix
  socket directory with the helper's least-privilege capability set at this
  revision, so the release image matrix is not publishable.
- Kubernetes, Helm, and Gateway API integrations remain `experimental`, with
  native `linux/riscv64` cluster evidence still unmet. UDP flow state is
  process-local and resets on Pod replacement.
- OxiBelt no longer ships its former Cosign/OCI-referrer admission policy;
  deployments enforcing that old contract must install and validate an
  operator-approved GitHub-attestation policy before adopting later images.

### Security

- Reject ambiguous or malformed HTTP/1 `Content-Length` and
  `Transfer-Encoding` framing before public, Admin, or operations service
  dispatch while preserving valid fixed-length, chunked, upgrade, and tunnel
  behavior.
- Add secret-reference preflight and redaction, database-time rollout fencing
  with all-member acknowledgement, external append-only audit anchoring,
  fail-closed Cargo/pnpm dependency admission, exact-revision release identity,
  independent rebuilds, and a six-role/five-architecture Trivy release gate.
- Update security-sensitive dependencies including `aws-lc-rs` `1.17.3`,
  Hyper `1.11.0`, and `web-transport-trait` `0.3.7`.
