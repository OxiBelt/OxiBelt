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

## [0.7.0-beta.4] - 2026-07-28

> Qualification beta for the `0.7.0` stable candidate. The published
> `0.7.0-beta.3` release completed its image-publication workflow, but its
> automatic independent rebuild stopped during hosted rootless Buildx setup
> before the complete role/architecture evidence matrix was produced. This
> cut supersedes that incomplete qualification with the durable UDP and
> release-validation changes made afterward.

- Changes since: `0.7.0-beta.3`
- Supported upgrade sources: `0.7.0-beta.3`, `0.6.5`
- Upgrade guide: [Upgrade from 0.6.5 to the 0.7.0 line](docs/Upgrading.md#upgrade-from-065-to-the-070-line)

### Configuration

- Add opt-in `udp_flow_state = "shared_required"` for native UDP stream
  listeners while retaining `local` as the compatibility default. Shared mode
  requires enabled shared state, an explicit `udp_flows_backend` naming a
  Redis-compatible or PostgreSQL backend, and one deployment-wide 32-byte
  base64 identity key named by `udp_flow_identity_key_env`.
- Fix the UDP shared-state failure policy at `reject_new_only`, require the
  effective shared connection-limit backend to match `udp_flows_backend`, and
  validate the backend connection budget, idle/operation timing, flow
  capacity, and token-rate bounds before activation.
- Require a Redis-compatible `udp_flows_backend` to expose `INFO memory` and
  prove either `maxmemory = 0` or `maxmemory_policy = noeviction` at activation
  and every configuration reload. An unsafe or unverifiable eviction policy
  fails activation; PostgreSQL and Redis backends not selected for durable UDP
  are unchanged.
- Default generated `UDPRoute` flow state to `disabled`. The Gateway
  Controller refuses to publish generated UDP listeners until
  `l4.udp.flowState` or `--udp-flow-state` is explicitly set to
  `shared_required`; it never generates process-local UDP flow state.

### Schema epochs

- Keep native configuration schema epoch `1`. Add optional epoch-1 metadata
  for `stream_listeners[].udp_flow_state`,
  `shared_state.udp_flows_backend`,
  `shared_state.udp_flow_identity_key_env`, and
  `shared_state.failure_policies.udp_flows`; existing beta.3 epoch-1
  configurations require no schema migration and retain local/disabled
  defaults.

### Deprecations and removals

- No changes for this release.

### Admin API

- No changes for this release.

### Feature lifecycle

- Keep the Kubernetes Gateway Controller, Helm integration, and generated
  `UDPRoute` support `experimental`. Generated UDP now fails closed until the
  operator explicitly selects required shared flow state and supplies matching
  shared-state configuration to every selected data-plane Pod.

### Rulepack compatibility

- No changes for this release.

### Executables and images

- Add the Gateway Controller's `--udp-flow-state` argument and corresponding
  Helm `l4.udp.flowState` value. Render controller integer arguments as
  canonical decimal digits so Helm cannot emit scientific notation into the
  container argument vector.
- Repair the independent release rebuild on hosted rootless Docker by using
  the `cgroupfs` driver without a host cgroup resource controller while still
  requiring rootless isolation, a cgroup namespace, and the built-in seccomp
  profile.
- Restore strict all-numeric build-tag parsing and the release build's pinned
  Rust `1.97.1` compatibility checks without changing committed `0.0.0`
  package-version sentinels.
- Strengthen the Kubernetes qualification harness with a reviewed Valkey
  manifest, isolated controller Lease recovery, live-controller recovery
  baselines, and deterministic UDP rollout checks.

### Storage and state

- Add one atomic, fenced UDP flow-record contract across the memory,
  Redis-compatible, and PostgreSQL adapters. The memory adapter exercises the
  same contract but remains process-local; only Redis-compatible and
  PostgreSQL backends provide records that another process or replacement Pod
  can recover.
- Persist opaque keyed listener, peer, route, target, owner, and routing-
  generation identities with bounded capacity, new-flow and per-flow token
  state, server-time expiry, ownership leases, and monotonic fencing. Recovery
  reauthorizes the stored route and target against the active configuration
  and rejects stale owners, missing targets, generation drift, or uncertain
  admission decisions.
- Preserve one listener-wide capacity, new-flow-token, and monotonic-fence
  scope while routing generations overlap. Existing client tuples remain
  pinned to their stored generation and target, while distinct new tuples may
  enter through the active generation without bypassing the shared admission
  bounds.
- Reject Redis scope, expiry-index, and target-flow partial state, including an
  expiry-index cardinality that disagrees with the stored active-flow count,
  before garbage collection, counter initialization, or new-flow admission.
  This prevents partial backend state loss from resetting shared capacity,
  rate, or fence counters.

### Upgrade validation

- A beta.3 configuration that does not opt into shared UDP remains valid with
  process-local native listeners and disabled generated `UDPRoute`. Validate
  the complete configuration before replacing an image:

```sh
oxibeltctl config validate /etc/oxibelt/config/oxibelt.toml --local-only
```

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

- Before enabling shared UDP, stop new admission, drain existing process-local
  flows, configure one common namespace, backend mapping, and identity key on
  every selected Pod, then roll all selected data-plane Pods and verify
  readiness before enabling controller `shared_required`.
- For a Redis-compatible UDP backend, grant the configured account permission
  to run `INFO memory`, configure unlimited Redis memory or `noeviction`, and
  verify every selected Pod activates successfully. Stop UDP admission before
  changing either setting and require every replica to reload and revalidate
  the safe policy before resuming.
- Deploy `0.7.0-beta.4` only after its person-reviewed release, all 30
  role/architecture image subjects, vulnerability admission, attestations,
  and independent-rebuild receipts succeed. Do not reuse beta.3's incomplete
  independent-rebuild evidence.

### Rollback and irreversible steps

- Before returning to beta.3 or `0.6.5`, disable generated UDP, stop new UDP
  admission, and drain beta.4 owners. Restore the prior data-plane
  configuration and immutable image digests before the prior controller, and
  retain the beta.4 identity key and shared backend until the rollback
  decision is complete.
- Older binaries do not consume beta.4 UDP flow records. Leave them to expire
  or remove them only after every beta.4 owner has drained; rollback does not
  recreate a prior socket, upstream source port, NAT/conntrack entry, exact
  Kubernetes Service endpoint, in-flight datagram, or application session.
- For a direct `0.6.5` rollback, also restore the epoch-0 configuration tree
  and pre-upgrade PostgreSQL backup or roll forward. Externally witnessed
  audit checkpoints remain append-only, and operator-owned Gateway API CRDs
  must not be deleted as an implicit Helm rollback.

### Known issues

- The Kubernetes Gateway Controller, its Helm integration, and its Gateway API
  features remain `experimental`; their native `linux/riscv64` cluster-runner
  graduation evidence is still unmet.
- Durable UDP preserves logical flow ownership, route/target affinity, and
  bounded admission only. It does not preserve the connected socket, upstream
  source port, NAT or conntrack state, exact endpoint selected behind a
  Kubernetes Service, upstream-initiated or in-flight datagrams, or
  application/session protocol state across restart.
- Existing admission policies that require the retired OxiBelt-managed Cosign
  signature or OCI-referrer contract reject the GitHub API-attested images
  until an operator installs and validates a replacement admission policy.

### Security

- Escape existing backslashes before Markdown table delimiters when rendering
  vulnerability findings into the GitHub Actions step summary. The
  machine-readable image decision and its fail-closed admission semantics are
  unchanged.
- Require TLS 1.2 or newer and disable TLS compression in the local
  Kubernetes Lease mock used by the RISC-V release-image smoke; its generated
  CA, certificate, bearer token, and Docker-only trust boundary remain
  test-scoped.
- Derive opaque shared-store identities with the deployment key instead of
  storing raw peers, route names, origins, or resolved endpoints as record
  authority. A missing or inconsistent key, backend mapping, routing
  generation, target, lease, fence, capacity decision, or token decision fails
  activation or rejects the affected new/recovered flow.
- Fail Redis-backed durable UDP activation when memory retention cannot be
  verified as non-evicting, and reject detectable scope/index/flow divergence
  before it can reset cluster-wide capacity, token, or fencing state.
- Bind each `shared_required` UDP listener generation to the exact selected
  shared-state runtime. A full reload that replaces same-path Redis
  credentials, trust roots, or client identity now drains and replaces the
  affected durable UDP listeners instead of retaining tasks backed by the
  retired pool; unchanged TCP and `local` UDP tasks retain their sockets, and
  local-only listener sets do not react to runtime identity alone.
- Preserve the fail-closed stable/beta image gate for every `CRITICAL`
  vulnerability and every fixable `HIGH` vulnerability, with exact-revision
  SLSA provenance, CycloneDX SBOMs, and independent-rebuild evidence for each
  role and architecture.
- Keep the independent verifier rootless and seccomp-confined. Its hosted
  `cgroupfs` configuration deliberately exposes no host cgroup resource
  controller; the ephemeral runner, job timeout, and bounded parallelism
  remain its resource-exhaustion controls.

## [0.7.0-beta.3] - 2026-07-27

> Recovery beta for the `0.7.0` line. The immutable published
> `0.7.0-beta.2` cut stopped during `linux/riscv64` keysigner runtime
> qualification before official release assets, manifests, attestations, or
> images were published.

- Changes since: `0.7.0-beta.2`
- Supported upgrade sources: `0.7.0-beta.2`, `0.6.5`
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

- Preserve the keysigner image's writable Unix-socket directory as
  `/run/oxibelt-keysigner`, owned by `10002:10002` with mode `0770`, when the
  directory is copied into the role-specific scratch image.
- Initialize the existing shared tracing subscriber in `oxibelt-keysigner` so
  its readiness event and compatibility-mode peer-allowlist warning reach
  container logs without changing CLI flags, token handling, key material, or
  signer protocol behavior.
- Prevent Docker empty-volume copy-up from replacing the release smoke's
  preinitialized socket-volume metadata, and validate the packaged directory
  owner and mode from the exported image root filesystem before target
  execution.

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

- Treat `0.7.0-beta.1` and `0.7.0-beta.2` only as source-build recovery
  identities. Deploy `0.7.0-beta.3` only after its person-reviewed release,
  complete role/architecture image qualification, vulnerability admission,
  attestations, and independent-rebuild evidence succeed.

### Rollback and irreversible steps

- Retain the exact prior role-specific image digests, configuration tree,
  referenced assets, PostgreSQL backup, controller rollback ConfigMaps, and
  Gateway API Lease before rollout. Stop all new-version Admin writers before
  restoring prior images and data; epoch-1 migration has no automatic
  down-migration, so restore the epoch-0 configuration and pre-upgrade
  PostgreSQL backup or roll forward.
- Roll back the data plane before the Gateway Controller. Before returning to a
  controller without Lease fencing, run one controller replica and wait for
  replacement; never downgrade or delete operator-owned Gateway API CRDs as an
  implicit Helm rollback. Externally witnessed audit checkpoints remain
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
  vulnerability and every fixable `HIGH` vulnerability, with exact-revision
  SLSA provenance, CycloneDX SBOMs, and independent-rebuild evidence for each
  role and architecture.
- Keep the RISC-V keysigner helper rootless and read-only with
  `--cap-drop ALL`, `no-new-privileges`, and `CAP_CHOWN` as its sole added
  capability. The repair does not add `CAP_FOWNER`, privileged mode, network
  access, or another writable mount.

## [0.7.0-beta.2] - 2026-07-26

> Immutable published failed cut. The GitHub prerelease exists, but its
> release-image workflow failed during `linux/riscv64` keysigner runtime smoke
> before official assets, manifests, attestations, or images were published.
> This cut has no deployable official release artifacts.

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

- Attempt to correct release-only `linux/riscv64` runtime-smoke socket
  preparation by setting the directory mode before transferring ownership.
  Docker subsequently replaced the empty volume's initialized metadata from
  the role image, so the keysigner could not bind its Unix socket and the
  release stopped before official artifact publication.
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

- For source builds made from `0.7.0-beta.1` or `0.7.0-beta.2`, the same
  epoch-1 configuration remains valid, but neither failed cut has official
  release artifacts to deploy. Advance to a later person-reviewed beta whose
  complete role/architecture image and evidence gates succeed.

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

- The `linux/riscv64` keysigner role cannot bind its Unix socket in the release
  runtime smoke because Docker replaces the preinitialized empty socket-volume
  metadata with the role image's `root:root` `0755` directory metadata. The
  release therefore produced no official assets, manifests, attestations, or
  images.
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
