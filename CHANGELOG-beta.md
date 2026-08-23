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

## [0.8.1-beta.8] - 2026-08-23

> Fresh qualification candidate after repairing sustained-fuzz artifact
> consumption and deterministic HTTP/2 WAF smoke framing, admitting
> `online-dsl-forge` `0.3.0`, refreshing the remaining admissible Rust, CI,
> and benchmark dependencies, and restoring the bounded hosted mutation
> campaign. Beta.7 remains an immutable published
> prerelease; do not reuse its artifacts, attestations, rebuild receipts, or
> qualification evidence for beta.8.

- Changes since: `0.8.1-beta.7`
- Supported upgrade sources: `0.8.1-beta.7`, `0.6.6`
- Upgrade guide: [Upgrade from 0.6.6 to the 0.8.1 line](docs/Upgrading.md#upgrade-from-066-to-the-081-line)

### Configuration

- Preserve every beta.7 epoch-1 key, default, validation rule, reload class,
  compatibility alias, resolver policy, and route behavior. The dependency
  refresh changes no runtime configuration or request-processing policy.

### Schema epochs

- Keep native configuration at epoch `1` and retain every beta.7 deployment,
  evidence, admission, workload-policy, revocation, and Helm OCI schema
  version. JSON Schema `0.51.0` validates and regenerates the existing native
  and admission schemas without drift.

### Deprecations and removals

- Add no deprecation or removal. The refresh changes dependency and benchmark
  tool versions without removing a command, option, compatibility alias,
  image role, or published contract.

### Admin API

- Preserve beta.7 Admin request, response, authentication, authorization,
  idempotency, audit, membership, operation, and embedded-runtime contracts.
  No Admin endpoint or wire representation changes in this cut.

### Feature lifecycle

- Keep the general and Kubernetes graduation targets on `0.8.1`. Every
  tracked feature remains `experimental` and `unvalidated` until its complete
  exact-revision evidence succeeds; beta.7 evidence cannot qualify beta.8.
- Preserve stable-alias eligibility classification and every stable-only
  mutation gate. A beta.8 qualification envelope remains read-only and cannot
  publish or promote stable aliases.

### Rulepack compatibility

- Retain the beta.7 OxiRule and CRS compatibility contract without syntax,
  matching, normalization, precedence, or production response changes.
- Admit the signed `online-dsl-forge` `0.3.0` package after verifying that its
  packaged production source and README are byte-identical to `0.2.0`. Its
  raised MSRV and dependency floors are already selected by OxiBelt, and its
  new development dependencies do not propagate into the runtime graph.

### Executables and images

- Preserve the six image roles, five platform subjects per role, executable
  names, entrypoints, users, ports, and OCI identity contracts from beta.7.
- Build the workspace and standalone probes with Rust `1.98.0`. Advance
  AES-GCM to `0.11.1`, CRC32 to `1.5.1`, JSON Schema and its companion crates
  to `0.51.0`, `log` to `0.4.34`, and WebPKI to `0.103.15`; keep the three
  independent probe lockfiles synchronized.
- Pin CodeQL `4.37.8` to its immutable release commit, NGINX comparator
  `1.31.4` to its verified source checksum, OHA `1.16.0`, and pnpm `11.23.0`
  to its registry integrity. Preserve the Node 24 type policy, BuildKit
  `0.32.2`, Trivy `0.74.0`, Helm
  `4.2.4`, and the supported Kubernetes image set.
- Load sustained Docker security-fuzz artifacts from the nested paths emitted
  by artifact download. Keep artifact identities, checksums, and the rootless
  execution boundary unchanged.
- Bound the `waf_bypass` HTTP/2 eager-body smoke case to the catalogued frame
  budget by excluding benign non-body entropy. Preserve one-byte request-body
  fragmentation, WAF semantics, and all other fuzz inputs.
- Raise the explicit mewt per-mutant ceiling to 602 seconds so a cold hosted
  baseline can complete while retaining the 120-minute job cap, complete
  30-mutant inventory, and fail-closed no-skip/no-timeout result checks.
- Bind unused HTTPS listeners directly to kernel-assigned ports in stream
  reload tests so released ephemeral reservations cannot be reclaimed by
  concurrent work on hosted ARM runners.
- Require all 30 fresh beta.8 image subjects and both Helm `4.2.4` chart
  packages to complete vulnerability, SBOM, provenance, attestation,
  independent-rebuild, and registry readback verification. Do not promote or
  republish beta.7 subjects under beta.8 tags.

### Storage and state

- Change no persistent schema, serialization, shared-state, membership, audit,
  UDP ownership, resolver cache, connection-admission, or rollout-state
  format. Beta.7 source state remains directly compatible.

### Upgrade validation

- Validate and inspect the epoch-1 sibling tree with the beta.8 binaries and
  canonical Helm client before staged rollout:

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

- Deploy only newly qualified beta.8 digests after person-reviewed
  publication, canonical non-benchmark validation, all image and chart
  receipts, independent rebuilds, and the aggregate automatic qualification
  receipt succeed.

### Rollback and irreversible steps

- Retain the `0.6.6` and beta.7 image digests, complete epoch-0 and epoch-1
  configuration trees, referenced assets, compatible PostgreSQL backups,
  admission bundles, audit evidence, controller rollback ConfigMaps, Gateway
  API CRDs and Lease, and shared UDP identity material until beta.8
  qualification completes.
- Stop new-version writers and drain the data plane before restoring beta.7 or
  stable binaries, configuration, and database together. External audit,
  telemetry, network, and client-visible effects cannot be undone.

### Known issues

- Beta.7 is an immutable published prerelease with its own exact-version
  images, charts, attestations, and workflow evidence. Preserve that history,
  but do not relabel or reuse any beta.7 subject or receipt as beta.8 evidence.
- Keep `generic-array` `0.14.7` while `crypto-common` selects that compatibility
  line, and keep the `x509-cert` `0.2.5` alias required by `x509-ocsp`'s public
  type family. Keep `@types/node` on the Node 24 line until the repository's
  runtime policy advances; these are reviewed compatibility holds, not stale
  lockfile resolution.
- Native `linux/riscv64` cluster-runner graduation evidence remains unmet; all
  tracked general and Kubernetes features remain experimental and unvalidated.

### Security

- Bind every new Rust archive to its crates.io checksum and record
  safe-to-deploy Cargo-vet delta audits. The AES-GCM tag comparison remains
  constant-time, WebPKI signature verification and OxiBelt's explicit TLS and
  OCSP algorithm sets are unchanged, CRC SIMD paths stay CPU-gated and
  bounds-checked, and JSON Schema retrieval features remain disabled.
- Keep Rust and Node dependency admission exact: approved registries only,
  immutable lockfile checksums, no new lifecycle script, complete license and
  advisory gates, and exact-version Cargo-vet exemptions whose inventory hash
  and count require review. Do not introduce wildcard exemptions or broaden
  deployment criteria.
- Require a fresh exact beta.8 aggregate qualification result before starting
  the 24-hour stable soak. Beta.7 publication, artifacts, receipts, and
  workflow completion times do not start or shorten that soak.

## [0.8.1-beta.7] - 2026-08-22

> Fresh qualification candidate after the Rust, pnpm, workflow, container,
> Kubernetes, Helm, and supply-chain dependency refresh, stable-alias
> eligibility classification, validation-matrix scheduling repair, and
> release-tag governance repair. Beta.6 remains an immutable published
> prerelease; do not reuse its artifacts, attestations, rebuild receipts, or
> qualification evidence for beta.7.

- Changes since: `0.8.1-beta.6`
- Supported upgrade sources: `0.8.1-beta.6`, `0.6.6`
- Upgrade guide: [Upgrade from 0.6.6 to the 0.8.1 line](docs/Upgrading.md#upgrade-from-066-to-the-081-line)

### Configuration

- Preserve every beta.6 epoch-1 key, default, validation rule, reload class,
  compatibility alias, resolver policy, and route behavior. The dependency
  refresh changes no runtime configuration or request-processing policy.

### Schema epochs

- Keep native configuration at epoch `1` and retain every beta.6 deployment,
  evidence, admission, workload-policy, revocation, and Helm OCI schema
  version. No schema field or migration changes in this cut.

### Deprecations and removals

- Add no deprecation or removal. The refresh changes supported toolchain and
  dependency versions without removing a command, option, compatibility
  alias, image role, or published contract.

### Admin API

- Preserve beta.6 Admin request, response, authentication, authorization,
  idempotency, audit, membership, operation, and embedded-runtime contracts.
  Updated parser, transport, and transitive dependencies do not change an
  Admin endpoint or wire representation.

### Feature lifecycle

- Keep the general and Kubernetes graduation targets on `0.8.1`. Every
  tracked feature remains `experimental` and `unvalidated` until its complete
  exact-revision evidence succeeds; beta.6 evidence cannot qualify beta.7.
- Classify a valid beta qualification envelope as ineligible for stable alias
  promotion before stable-only fields are required. Keep that path read-only,
  skip every registry mutation job, and retain strict validation and mutation
  gates for stable qualification envelopes.

### Rulepack compatibility

- Retain the beta.6 OxiRule and CRS compatibility contract without syntax,
  matching, normalization, precedence, or production response changes.

### Executables and images

- Preserve the six image roles, five platform subjects per role, executable
  names, entrypoints, users, ports, and OCI identity contracts from beta.6.
- Build the workspace and standalone probes with Rust `1.98.0`, refresh the
  compatible Cargo graph, and advance the direct JSON Schema, YAML, HTTP/2,
  and WebTransport dependencies. Preserve CLI, service, protocol, and image
  role behavior.
- Use pnpm `11.22.0`, Oxlint `1.79.0`, BuildKit `0.32.2` by immutable digest,
  Trivy `0.74.0`, CodeQL `4.37.7`, Buildx `4.3.0`, and the supported
  Kubernetes patch releases. Keep action commits, container digests, package
  integrity hashes, and workflow assertions exact.
- Remove workflow-level concurrency caps from validation matrices so GitHub
  can schedule independent rows according to runner availability. Preserve
  fail-fast settings, per-job timeouts, rootless container isolation, and the
  complete terminal summary gate.
- Require all 30 fresh beta.7 image subjects and both Helm `4.2.4` chart
  packages to complete vulnerability, SBOM, provenance, attestation,
  independent-rebuild, and registry readback verification. Do not promote or
  republish beta.6 subjects under beta.7 tags.

### Storage and state

- Change no persistent schema, serialization, shared-state, membership, audit,
  UDP ownership, resolver cache, connection-admission, or rollout-state
  format. Beta.6 source state remains directly compatible.

### Upgrade validation

- Validate and inspect the epoch-1 sibling tree with the beta.7 binaries and
  canonical Helm client before staged rollout:

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

- Deploy only newly qualified beta.7 digests after person-reviewed
  publication, canonical non-benchmark validation, all image and chart
  receipts, independent rebuilds, and the aggregate automatic qualification
  receipt succeed.

### Rollback and irreversible steps

- Retain the `0.6.6` and beta.6 image digests, complete epoch-0 and epoch-1
  configuration trees, referenced assets, compatible PostgreSQL backups,
  admission bundles, audit evidence, controller rollback ConfigMaps, Gateway
  API CRDs and Lease, and shared UDP identity material until beta.7
  qualification completes.
- Stop new-version writers and drain the data plane before restoring beta.6 or
  stable binaries, configuration, and database together. External audit,
  telemetry, network, and client-visible effects cannot be undone.

### Known issues

- Beta.6 is an immutable published prerelease with its own exact-version
  images, charts, attestations, and workflow evidence. Preserve that history,
  but do not relabel or reuse any beta.6 subject or receipt as beta.7 evidence.
- The beta.1 tag remains local-only, beta.2 remains an immutable unpublished
  failed cut, beta.3 remains a published failed cut without canonical images,
  and beta.4 and beta.5 remain published without complete independent image
  receipts. The `0.8.0` beta cuts remain invalid, unqualified, or unpublished
  history and cannot supply beta.7 qualification evidence.
- Native `linux/riscv64` cluster-runner graduation evidence remains unmet; all
  tracked general and Kubernetes features remain experimental and unvalidated.

### Security

- Bind the hosted release-tag ruleset to its existing repository ruleset ID,
  restore `Non-benchmark validation summary` as the required GitHub Actions
  check, and keep update, deletion, and bypass protections exact. Canonical
  default-branch CI checks every publicly visible field, while an authenticated
  operator preflight verifies the hidden bypass list before one explicit tag
  ref is pushed; bulk `git push --tags` is not a release operation.
- Advance `h2` to `0.4.18` throughout the root and independently resolved
  probe graphs, retain the existing direct-HTTP/2 regression coverage, and
  keep the TLS, QUIC, WebTransport, URI, framing, admission, and timeout
  boundaries fail closed.
- Keep Rust and Node dependency admission exact: approved registries only,
  immutable lockfile checksums, no new lifecycle script, complete license and
  advisory gates, and exact-version cargo-vet exemptions whose inventory hash
  and count require review. Do not introduce wildcard exemptions or broaden
  deployment criteria.
- Require a fresh exact beta.7 aggregate qualification result before starting
  the 24-hour stable soak. Beta.6 publication, artifacts, receipts, and
  workflow completion times do not start or shorten that soak.

## [0.8.1-beta.6] - 2026-08-21

> Fresh qualification candidate after beta.5 published its complete image and
> chart set but independent image rebuilds exposed build-time APK log content
> and scanner serialization metadata. Do not reuse beta.5 artifacts,
> attestations, rebuild receipts, or qualification evidence.

- Changes since: `0.8.1-beta.5`
- Supported upgrade sources: `0.8.1-beta.5`, `0.6.6`
- Upgrade guide: [Upgrade from 0.6.6 to the 0.8.1 line](docs/Upgrading.md#upgrade-from-066-to-the-081-line)

### Configuration

- Preserve every beta.5 epoch-1 key, default, validation rule, reload class,
  compatibility alias, resolver policy, and route behavior. This recovery cut
  changes no runtime configuration or request-processing policy.

### Schema epochs

- Keep native configuration at epoch `1` and retain every beta.5 deployment,
  evidence, admission, workload-policy, revocation, and Helm OCI schema
  version. No schema field or migration changes in this cut.

### Deprecations and removals

- Add no deprecation or removal. Removing build-time-only rootfs and scanner
  serialization variance corrects release evidence without weakening an
  identity, digest, policy, semantic SBOM field, or publication gate.

### Admin API

- Preserve beta.5 Admin request, response, authentication, authorization,
  idempotency, audit, membership, operation, and embedded-runtime contracts.
  No Admin endpoint or wire representation changes in this cut.

### Feature lifecycle

- Keep the general and Kubernetes graduation targets on `0.8.1`. Every
  tracked feature remains `experimental` and `unvalidated` until its complete
  exact-revision evidence succeeds; beta.5 contributes no qualification.

### Rulepack compatibility

- Retain the beta.5 OxiRule and CRS compatibility contract without syntax,
  matching, normalization, precedence, or production response changes.

### Executables and images

- Preserve the six image roles, five platform subjects per role, executable
  names, entrypoints, users, ports, and OCI identity contracts from beta.5.
- Remove `/var/log/apk.log` from the prepared Alpine rootfs after package and
  CA validation, with fail-closed directory and absence postconditions, so APK
  wall-clock diagnostics cannot become released filesystem content.
- Derive BuildKit `SOURCE_DATE_EPOCH` from the canonical second-resolution UTC
  release creation time and request exporter timestamp rewriting. Reject an
  invalid or pre-epoch creation time instead of silently choosing a local
  clock.
- Canonicalize only validated Trivy serialization metadata: the local subject
  digest purl, layer digest properties, layer diff-ID properties, and the
  scanner-generated operating-system reference plus its dependency edges.
  Preserve package identities, hashes, semantic properties, and dependencies,
  and reject malformed, duplicate, conflicting, or ambiguous metadata.
- Give the path-security target a 15-second case budget for its serial H1/H2/H3
  probe-container and upstream-observer checks. Keep every other target on the
  global five-second default, reject target overrides outside `5..=30`
  seconds, and preserve the 120-second PR campaign deadline.
- Require all 30 fresh beta.6 image subjects and both Helm `4.2.4` chart
  packages to complete vulnerability, SBOM, provenance, attestation,
  independent-rebuild, and registry readback verification. Do not promote or
  republish beta.5 subjects under beta.6 tags.

### Storage and state

- Change no persistent schema, serialization, shared-state, membership, audit,
  UDP ownership, resolver cache, connection-admission, or rollout-state
  format. Beta.5 source state remains directly compatible for recovery.

### Upgrade validation

- Validate and inspect the epoch-1 sibling tree with the beta.6 binaries and
  canonical Helm client before staged rollout:

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

- Deploy only newly qualified beta.6 digests after person-reviewed
  publication, canonical non-benchmark validation, all image and chart
  receipts, independent rebuilds, and the aggregate automatic qualification
  receipt succeed.

### Rollback and irreversible steps

- Retain the `0.6.6` image digests, complete epoch-0 configuration tree,
  referenced assets, compatible PostgreSQL backup, admission bundle, audit
  evidence, controller rollback ConfigMaps, Gateway API CRDs and Lease, and
  shared UDP identity material until beta.6 qualification completes.
- A beta.5 source deployment may be retained as a directly compatible rollback
  source, but beta.5 has no qualified official image or evidence to promote or
  relabel. Stop new-version writers and drain the data plane before restoring
  older binaries, configuration, and database together.

### Known issues

- The immutable beta.5 prerelease and its exact-version images and charts
  exist. Release workflow `32450530430` completed successfully, and automatic
  verifier workflow `32453049844` independently reproduced both charts, but
  its first image rebuilds found normalized filesystem and SBOM differences.
  The failed verifier cannot produce the complete 30-image receipt set or
  aggregate qualification receipt. Preserve those artifacts as attributable
  failed-cut history and reuse none of any partial receipts or incomplete
  evidence.
- Exact pre-tag Check workflow `32457898102` correctly withheld beta.6 after
  its path-security job exhausted the former five-second case budget. The
  captured recovery request succeeded, both unsafe paths were rejected, and no
  upstream leak was observed before the timeout. The tag remained local and
  was discarded; that failed preflight supplies no release evidence.
- Exact pre-tag Check workflow `32470310304` then stopped at the mandatory
  Rust lint gate because the new timeout validation used a collapsible nested
  condition. Keep that source-only lint failure as attributable preflight
  history; it produced no tag, release artifact, or qualification evidence.
- The beta.1 tag remains local-only, beta.2 remains an immutable unpublished
  failed cut, beta.3 remains a published failed cut without canonical images,
  and beta.4 remains published without independent receipts. The `0.8.0` beta
  cuts remain invalid, unqualified, or unpublished history and cannot supply
  beta.6 qualification evidence.
- Native `linux/riscv64` cluster-runner graduation evidence remains unmet; all
  tracked general and Kubernetes features remain experimental and unvalidated.

### Security

- Preserve beta.5 nested-path rejection, external-auth trailer sanitization,
  malformed TURN containment, effective-owner SVCB binding, per-candidate
  connection admission, and all existing fail-closed release controls.
- Keep the independent verifier globally read-only and rootless. Bind every
  rebuilt subject and receipt to the exact producer run, tag, revision, digest,
  attestation, role, and platform; treat normalization as a narrow removal of
  validated non-semantic scanner or layer-serialization identity only.
- Preserve the security-fuzz case timeout as a fail-closed absolute bound.
  Apply the larger allowance only to the path-security oracle whose serial
  container probes cannot reliably complete within five hosted seconds; do
  not relax recovery, campaign, concurrency, payload, or artifact limits.
- Require a fresh exact beta.6 aggregate qualification result before starting
  the 24-hour stable soak. Beta.5 publication, producer completion, chart
  receipts, image failures, and workflow completion times do not start or
  shorten that soak.

## [0.8.1-beta.5] - 2026-08-21

> Fresh qualification candidate after beta.4 published its complete image and
> chart set but the automatic independent verifier failed before producing any
> rebuild receipt. Do not reuse beta.4 artifacts, attestations, rebuild inputs,
> or qualification evidence.

- Changes since: `0.8.1-beta.4`
- Supported upgrade sources: `0.8.1-beta.4`, `0.6.6`
- Upgrade guide: [Upgrade from 0.6.6 to the 0.8.1 line](docs/Upgrading.md#upgrade-from-066-to-the-081-line)

### Configuration

- Preserve every beta.4 epoch-1 key, default, validation rule, reload class,
  compatibility alias, resolver policy, and route behavior. This recovery cut
  changes no runtime configuration or request-processing policy.

### Schema epochs

- Keep native configuration at epoch `1` and retain every beta.4 deployment,
  evidence, admission, workload-policy, revocation, and Helm OCI schema
  version. No schema field or migration changes in this cut.

### Deprecations and removals

- Add no deprecation or removal. Resolving package-manager and TypeScript
  tooling from the approved verifier checkout corrects release qualification
  execution without relaxing an identity, digest, policy, or publication gate.

### Admin API

- Preserve beta.4 Admin request, response, authentication, authorization,
  idempotency, audit, membership, operation, and embedded-runtime contracts.
  No Admin endpoint or wire representation changes in this cut.

### Feature lifecycle

- Keep the general and Kubernetes graduation targets on `0.8.1`. Every
  tracked feature remains `experimental` and `unvalidated` until its complete
  exact-revision evidence succeeds; beta.4 contributes no qualification.

### Rulepack compatibility

- Retain the beta.4 OxiRule and CRS compatibility contract without syntax,
  matching, normalization, precedence, or production response changes.

### Executables and images

- Preserve the six image roles, five platform subjects per role, executable
  names, entrypoints, users, ports, and OCI identity contracts from beta.4.
- Resolve Corepack, pnpm, TypeScript modules, and chart-verification scripts
  from the immutable approved verifier checkout. Keep the tagged release
  checkout isolated as build input and address it through one explicit,
  non-parent-traversing sibling workspace path.
- Keep Docker security-fuzz machine observations as stdout-only structured
  JSON while retaining probe diagnostics in bounded executor logs. Preserve
  every nonzero probe status as a failed case so asynchronous HTTP/2
  diagnostics cannot corrupt or mask a qualification oracle.
- Require all 30 fresh beta.5 image subjects and both Helm `4.2.4` chart
  packages to complete vulnerability, SBOM, provenance, attestation,
  independent-rebuild, and registry readback verification. Do not promote or
  republish beta.4 subjects under beta.5 tags.

### Storage and state

- Change no persistent schema, serialization, shared-state, membership, audit,
  UDP ownership, resolver cache, connection-admission, or rollout-state
  format. Beta.4 source state remains directly compatible for recovery.

### Upgrade validation

- Validate and inspect the epoch-1 sibling tree with the beta.5 binaries and
  canonical Helm client before staged rollout:

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

- Deploy only newly qualified beta.5 digests after person-reviewed
  publication, canonical non-benchmark validation, all image and chart
  receipts, independent rebuilds, and the aggregate automatic qualification
  receipt succeed.

### Rollback and irreversible steps

- Retain the `0.6.6` image digests, complete epoch-0 configuration tree,
  referenced assets, compatible PostgreSQL backup, admission bundle, audit
  evidence, controller rollback ConfigMaps, Gateway API CRDs and Lease, and
  shared UDP identity material until beta.5 qualification completes.
- A beta.4 source deployment may be retained as a directly compatible rollback
  source, but beta.4 has no qualified official artifact or evidence to promote
  or relabel. Stop new-version writers and drain the data plane before
  restoring older binaries, configuration, and database together.

### Known issues

- The immutable beta.4 prerelease and its exact-version images and charts
  exist. Release workflow `32430526861` completed successfully, but automatic
  verifier workflow `32433121789` ran `corepack install` outside both sibling
  checkouts and failed before resolving its rebuild matrix. Preserve those
  artifacts as attributable failed-cut history and reuse none of their
  incomplete evidence.
- The beta.1 tag remains local-only, beta.2 remains an immutable unpublished
  failed cut, and beta.3 remains a published failed cut without canonical
  images. The `0.8.0` beta cuts remain invalid, unqualified, or unpublished
  history and cannot supply beta.5 qualification evidence.
- Native `linux/riscv64` cluster-runner graduation evidence remains unmet; all
  tracked general and Kubernetes features remain experimental and unvalidated.

### Security

- Preserve beta.4 nested-path rejection, external-auth trailer sanitization,
  malformed TURN containment, effective-owner SVCB binding, per-candidate
  connection admission, and all existing fail-closed release controls.
- Keep the independent verifier globally read-only and rootless. Execute
  package and verification tooling only from its approved immutable checkout;
  treat the tagged release checkout only as source input, and retain exact
  producer-run, tag, revision, digest, attestation, and receipt binding.
- Require a fresh exact beta.5 aggregate qualification result before starting
  the 24-hour stable soak. Beta.4 publication, artifact, or workflow completion
  times do not start or shorten that soak.

## [0.8.1-beta.4] - 2026-08-20

> Fresh qualification candidate after beta.3 published but its release-image
> workflow failed before any canonical image could be published. Do not reuse
> beta.3 artifacts, attestations, rebuilds, or qualification evidence.

- Changes since: `0.8.1-beta.3`
- Supported upgrade sources: `0.8.1-beta.3`, `0.6.6`
- Upgrade guide: [Upgrade from 0.6.6 to the 0.8.1 line](docs/Upgrading.md#upgrade-from-066-to-the-081-line)

### Configuration

- Preserve every beta.3 epoch-1 key, default, validation rule, reload class,
  compatibility alias, resolver policy, and route behavior. This recovery cut
  changes no runtime configuration or request-processing policy.

### Schema epochs

- Keep native configuration at epoch `1` and retain every beta.3 deployment,
  evidence, admission, workload-policy, revocation, and Helm OCI schema
  version. No schema field or migration changes in this cut.

### Deprecations and removals

- Add no deprecation or removal. Invoking a staged release helper through its
  declared shell interpreter only makes artifact consumption portable; it
  does not relax an identity, digest, policy, or publication requirement.

### Admin API

- Preserve beta.3 Admin request, response, authentication, authorization,
  idempotency, audit, membership, operation, and embedded-runtime contracts.
  No Admin endpoint or wire representation changes in this cut.

### Feature lifecycle

- Keep the general and Kubernetes graduation targets on `0.8.1`. Every
  tracked feature remains `experimental` and `unvalidated` until its complete
  exact-revision evidence succeeds; beta.3 contributes no qualification.

### Rulepack compatibility

- Retain the beta.3 OxiRule and CRS compatibility contract without syntax,
  matching, normalization, precedence, or production response changes.

### Executables and images

- Preserve the six image roles, five platform subjects per role, executable
  names, entrypoints, users, ports, and OCI identity contracts from beta.3.
- Stage the bounded BuildKit pull helper as artifact data and invoke it through
  an explicitly quoted `bash` interpreter after download. Keep the immutable
  BuildKit digest and every same-run artifact and vulnerability-decision
  binding unchanged.
- Require all 30 fresh beta.4 image subjects and both Helm `4.2.4` chart
  packages to complete vulnerability, SBOM, provenance, attestation,
  independent-rebuild, and registry readback verification.

### Storage and state

- Change no persistent schema, serialization, shared-state, membership, audit,
  UDP ownership, resolver cache, connection-admission, or rollout-state
  format. Beta.3 source state remains directly compatible for recovery.

### Upgrade validation

- Validate and inspect the epoch-1 sibling tree with the beta.4 binaries and
  canonical Helm client before staged rollout:

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

- Deploy only newly qualified beta.4 digests after person-reviewed
  publication, canonical non-benchmark validation, all image and chart
  receipts, independent rebuilds, and the aggregate automatic qualification
  receipt succeed.

### Rollback and irreversible steps

- Retain the `0.6.6` image digests, complete epoch-0 configuration tree,
  referenced assets, compatible PostgreSQL backup, admission bundle, audit
  evidence, controller rollback ConfigMaps, Gateway API CRDs and Lease, and
  shared UDP identity material until beta.4 qualification completes.
- A beta.3 source deployment may be retained as a directly compatible rollback
  source, but beta.3 has no qualified official image to promote or reuse.
  Stop new-version writers and drain the data plane before restoring older
  binaries, configuration, and database together.

### Known issues

- The immutable beta.3 GitHub prerelease exists, but release workflow
  `32413789905` failed closed when all 30 image publication jobs attempted to
  execute a downloaded helper whose executable mode was not preserved. The
  failure occurred before those jobs could mutate GHCR. Preserve the tag and
  release as failed-cut history and reuse none of its incomplete evidence.
- The beta.1 tag remains local-only, and beta.2 remains an immutable
  unpublished failed cut. The `0.8.0` beta cuts remain invalid, unqualified,
  or unpublished history and cannot supply beta.4 qualification evidence.
- Native `linux/riscv64` cluster-runner graduation evidence remains unmet; all
  tracked general and Kubernetes features remain experimental and unvalidated.

### Security

- Preserve beta.3 nested-path rejection, external-auth trailer sanitization,
  malformed TURN containment, effective-owner SVCB binding, per-candidate
  connection admission, and all existing fail-closed release controls.
- Consume the exact same-run release metadata helper through `bash` without
  adding `eval`, unquoted input, mutable dependencies, broader permissions, or
  a publication fallback. Artifact, vulnerability-decision, digest, and source
  revision checks remain mandatory before any registry mutation.
- Require a fresh exact beta.4 aggregate qualification result before starting
  the 24-hour stable soak. Beta.3 publication time or workflow results do not
  start or shorten that soak.

## [0.8.1-beta.3] - 2026-08-20

> Fresh qualification candidate after beta.2 failed before draft creation.
> Do not reuse beta.2 workflow results or any artifact, attestation, rebuild,
> or qualification evidence from an earlier cut.

- Changes since: `0.8.1-beta.2`
- Supported upgrade sources: `0.8.1-beta.2`, `0.6.6`
- Upgrade guide: [Upgrade from 0.6.6 to the 0.8.1 line](docs/Upgrading.md#upgrade-from-066-to-the-081-line)

### Configuration

- Preserve every supported epoch-1 configuration key, default, validation
  rule, reload class, and compatibility alias from beta.2. This cut changes no
  runtime configuration or request-routing policy.
- Continue to use `[proxy.upstream_resolution]` as the canonical resolver
  policy while retaining `[quic.upstream.resolution]` only as the documented
  compatibility input.

### Schema epochs

- Keep native configuration at epoch `1` and retain every beta.2 deployment,
  evidence, admission, workload-policy, revocation, and Helm OCI schema
  version. This cut adds no schema field or migration.
- Continue to migrate from epoch `0` with
  `oxibeltctl config migrate --from 0 --to 1`; automatic down-migration remains
  unsupported.

### Deprecations and removals

- Add no deprecation or removal. Preserve the legacy system access-log and
  QUIC resolver compatibility inputs with the same conflict and precedence
  checks as beta.2.
- Keep partial or mismatched supply-chain evidence ineligible. Candidate
  metadata is now read from the exact tagged Git tree rather than mutable
  checkout files, without relaxing any receipt or publication requirement.

### Admin API

- Preserve beta.2 Admin request, response, authentication, authorization,
  idempotency, audit, membership, operation, and embedded-runtime contracts.
  No Admin endpoint or wire representation changes in this cut.
- Continue to fail closed on malformed mutation, identity, signature,
  membership, secret-reference, and rollback evidence.

### Feature lifecycle

- Keep the general and Kubernetes graduation targets on `0.8.1`; every tracked
  feature remains `experimental` and `unvalidated` until its complete
  exact-revision evidence succeeds.
- Add no lifecycle state or evidence exception. Beta.3 requires one fresh
  canonical 39-job non-benchmark validation summary.

### Rulepack compatibility

- Retain the beta.2 OxiRule and CRS compatibility contract. The strengthened
  nested-path rejection and test oracle do not alter rule syntax, matching,
  precedence, or production WAF responses.

### Executables and images

- Preserve the beta.2 executable names, six image roles, five platform
  subjects per role, entrypoints, users, ports, and OCI identity contracts.
- Require all 30 fresh exact-revision image subjects and both Helm `4.2.4`
  chart packages to complete vulnerability, SBOM, provenance, attestation,
  independent-rebuild, and readback verification. Beta publication writes no
  stable aliases, and charts receive no mutable aliases.

### Storage and state

- Change no persistent schema, serialization, shared-state, membership, audit,
  UDP ownership, or rollout-state format. Resolver metadata now stays bound to
  the effective DNS owner, and connection admission now accounts for each
  physical racing transport under both global and configured-pool capacity.
- Continue to stop new-version writers and drain the data plane before any
  rollback that restores an older compatible database and configuration tree.

### Upgrade validation

- Validate and inspect the epoch-1 sibling tree with the candidate binaries and
  canonical Helm client before staged rollout:

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

- Exercise shallow, boundary-depth, over-depth, malformed, and benign encoded
  paths over raw HTTP/1.1, HTTP/2, and HTTP/3. Dangerous paths must receive the
  exact rejection and never reach the protected upstream; benign controls must
  reach it exactly once.
- Deploy only newly qualified beta.3 digests after the canonical 39-job
  summary, person-reviewed release, all image and chart receipts, and the
  aggregate automatic qualification receipt succeed.

### Rollback and irreversible steps

- Retain the `0.6.6` image digests, complete epoch-0 configuration tree,
  referenced assets, compatible PostgreSQL backup, admission bundle, audit
  evidence, controller rollback ConfigMaps, Gateway API CRDs and Lease, and
  shared UDP identity material until qualification completes.
- If upgrading from a source build at the beta.2 revision, retain its binaries
  and matching state only as a rollback source; beta.2 has no published
  official artifacts or qualification evidence to promote into beta.3.
- Stop new-version writers, drain the data plane before the controller, and
  restore the selected older binaries, configuration, and database together.
  External audit, telemetry, connection, session, datagram, and client-visible
  effects cannot be recreated by rollback.

### Known issues

- The signed `0.8.1-beta.1` tag remains only at its original local revision and
  is absent from GitHub. The signed remote `0.8.1-beta.2` tag is immutable, but
  draft preparation failed and no GitHub Release or official artifact exists.
  Preserve both cuts without moving or deleting their tags and use no evidence
  from either to qualify beta.3.
- `0.8.0-beta.0`, `0.8.0-beta.1`, and `0.8.0-beta.2` remain invalid,
  unqualified, or unpublished failed-cut history and cannot supply evidence or
  a stable-promotion source.
- Native `linux/riscv64` cluster-runner graduation evidence remains unmet; all
  tracked general and Kubernetes features remain experimental and unvalidated.

### Security

- Reject a request path when a dangerous encoded token appears at any layer up
  to the supported nesting limit or when another valid percent-decoding layer
  remains after that limit. Validation stays bounded and occurs before routing
  or upstream forwarding.
- Bind the beta changelog, stable changelog, upgrade guide, and forbidden-build
  ledger used for release-candidate metadata to bounded regular blobs in the
  exact tagged Git tree. Dirty or later checkout files cannot qualify an older
  candidate or alter its canonical release body.
- Treat malformed TURN REST expiry fields as invalid credentials without
  allowing one bad packet to terminate the listener task.
- Query and admit HTTPS/SVCB metadata only for the canonical DNS owner that
  supplied the usable base addresses. Conflicting, missing, hosts-file, or
  mismatched response provenance remains ineligible for metadata expansion.
- Acquire global and configured-pool connection capacity before each racing
  HTTP transport attempt, retain the winning lease for the physical
  connection lifetime, and release failed, losing, canceled, or stale attempts
  by ownership. A candidate rejected only by a racing peer is retried after
  that peer fails without relaxing the shared absolute deadline.
- Preserve every beta.2 fail-closed request-framing, TLS, CRLite, QUIC,
  resolver-provenance, confinement, secret, shared-state, admission, and
  supply-chain boundary. Require one fresh exact aggregate qualification
  result before the 24-hour stable soak begins.

## [0.8.1-beta.2] - 2026-08-20

> Fresh qualification candidate after beta.1's canonical validation exposed
> release-harness flakes. Do not reuse beta.1 workflow results or any artifact,
> attestation, rebuild, or qualification evidence from an earlier cut.

- Changes since: `0.8.1-beta.1`
- Supported upgrade sources: `0.8.1-beta.1`, `0.6.6`
- Upgrade guide: [Upgrade from 0.6.6 to the 0.8.1 line](docs/Upgrading.md#upgrade-from-066-to-the-081-line)

### Configuration

- Preserve every supported epoch-1 configuration key, default, validation
  rule, reload class, and compatibility alias from beta.1. The pool and WAF
  changes are deterministic test-harness repairs and do not alter runtime
  configuration or request policy.
- Continue to use `[proxy.upstream_resolution]` as the canonical resolver
  policy while retaining `[quic.upstream.resolution]` only as the documented
  compatibility input.

### Schema epochs

- Keep native configuration at epoch `1` and retain every beta.1 deployment,
  evidence, admission, workload-policy, revocation, and Helm OCI schema
  version. This cut adds no schema field or migration.
- Continue to migrate from epoch `0` with
  `oxibeltctl config migrate --from 0 --to 1`; automatic down-migration remains
  unsupported.

### Deprecations and removals

- Add no deprecation or removal. Preserve the legacy system access-log and
  QUIC resolver compatibility inputs with the same conflict and precedence
  checks as beta.1.
- Keep partial or mismatched supply-chain evidence ineligible; the bounded
  BuildKit bootstrap retry does not relax an exact digest or qualification
  requirement.

### Admin API

- Preserve beta.1 Admin request, response, authentication, authorization,
  idempotency, audit, membership, operation, and embedded-runtime contracts.
  No Admin endpoint or wire representation changes in this cut.
- Continue to fail closed on malformed mutation, identity, signature,
  membership, secret-reference, and rollback evidence.

### Feature lifecycle

- Keep the general and Kubernetes graduation targets on `0.8.1`; every tracked
  feature remains `experimental` and `unvalidated` until its complete
  exact-revision evidence succeeds.
- Correct the documented non-benchmark validation inventory to the existing 39
  required aggregate jobs without changing lifecycle state or accepting
  partial evidence.

### Rulepack compatibility

- Retain the beta.1 OxiRule and CRS compatibility contract. A unique test-only
  WAF rejection sentinel strengthens the Docker fuzz oracle but does not alter
  rule syntax, matching, normalization, precedence, or production responses.

### Executables and images

- Preserve the beta.1 executable names, six image roles, five platform
  subjects per role, entrypoints, users, ports, and OCI identity contracts.
- Pre-pull the same immutable BuildKit digest with bounded retry before release
  Buildx setup. A failed pull still stops the job; no mutable tag, mirror,
  image-build retry, or publication bypass is introduced.
- Require all 30 fresh exact-revision image subjects and both Helm `4.2.4`
  chart packages to complete vulnerability, SBOM, provenance, attestation,
  independent-rebuild, and readback verification. Beta publication writes no
  stable aliases, and charts receive no mutable aliases.

### Storage and state

- Change no persistent schema, serialization, shared-state, membership, audit,
  resolver, pool, UDP ownership, or rollout-state behavior. The pool edit only
  removes wall-clock dependence from an expiry unit test.
- Continue to stop new-version writers and drain the data plane before any
  rollback that restores an older compatible database and configuration tree.

### Upgrade validation

- Validate and inspect the epoch-1 sibling tree with the candidate binaries and
  canonical Helm client before staged rollout:

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

- Accept the fragmented HTTP/2 WAF body case only after the probe proves that
  every bounded DATA fragment and END_STREAM were submitted, the response is
  the exact WAF 403 sentinel, and the protected upstream count is unchanged.
- Deploy only newly qualified beta.2 digests after the canonical 39-job
  summary, person-reviewed release, all image and chart receipts, and the
  aggregate automatic qualification receipt succeed.

### Rollback and irreversible steps

- Retain the `0.6.6` image digests, complete epoch-0 configuration tree,
  referenced assets, compatible PostgreSQL backup, admission bundle, audit
  evidence, controller rollback ConfigMaps, Gateway API CRDs and Lease, and
  shared UDP identity material until qualification completes.
- If upgrading from a locally built beta.1 revision, retain its binaries and
  matching state only as a rollback source; beta.1 has no published official
  artifacts or qualification evidence to promote into beta.2.
- Stop new-version writers, drain the data plane before the controller, and
  restore the selected older binaries, configuration, and database together.
  External audit, telemetry, connection, session, datagram, and client-visible
  effects cannot be recreated by rollback.

### Known issues

- The signed `0.8.1-beta.1` tag exists locally at its original commit but is
  absent from GitHub, and that exact commit did not obtain trustworthy
  canonical qualification. Preserve it without moving or deleting it; remote
  beta.2 publication remains blocked until the predecessor lineage is resolved
  under the immutable release contract.
- `0.8.0-beta.0`, `0.8.0-beta.1`, and `0.8.0-beta.2` remain invalid,
  unqualified, or unpublished failed-cut history and cannot supply evidence or
  a stable-promotion source.
- Native `linux/riscv64` cluster-runner graduation evidence remains unmet; all
  tracked general and Kubernetes features remain experimental and unvalidated.

### Security

- Treat an HTTP/2 send failure, reset, incomplete body, missing completion
  proof, unexpected status or response body, or protected-upstream reach as a
  failed WAF fuzz case. Do not turn transport failure into a non-bypass result.
- Keep the direct `h2` probe dependency on the already-audited locked 0.4.16
  source and confine it to explicit bounded test bodies; it adds no runtime
  dependency, feature, build script, or unsafe-code capability.
- Preserve every beta.1 fail-closed request-framing, TLS, CRLite, QUIC,
  resolver-provenance, confinement, secret, shared-state, admission, and
  supply-chain boundary. Require one fresh exact aggregate qualification
  result before any stable soak begins.

## [0.8.1-beta.1] - 2026-08-19

> Fresh qualification candidate after the abandoned `0.8.0` line. Do not
> reuse any draft, image, chart, attestation, rebuild, or workflow evidence
> from that line.

- Changes since: `0.6.6`
- Supported upgrade sources: `0.6.6`
- Upgrade guide: [Upgrade from 0.6.6 to the 0.8.1 line](docs/Upgrading.md#upgrade-from-066-to-the-081-line)

### Configuration

- Advance the epoch-1 configuration surface with activation planning, typed
  secret references, manifest-bound filesystem confinement, strict seccomp
  expectations, resolved-topology diagnostics, and the `edge-secure-medium`
  v2 deployment profile. Selected but unavailable or unqualified capabilities
  fail closed.
- Add bounded persistent direct-H1, pooled direct-H2, adaptive HTTP/3, QUIC
  Initial reassembly, and Happy Eyeballs v3 upstream dialing. The canonical
  resolver policy is `[proxy.upstream_resolution]`; the epoch-1
  `[quic.upstream.resolution]` input remains a deprecated compatibility alias.
  Do not configure the same effective leaf in both locations.
- Preserve the canonical `access_log.system.enabled` setting and the `0.6.6`
  `access_log.enable_system` compatibility input.

### Schema epochs

- Advance native configuration from epoch `0` to epoch `1`. Use
  `oxibeltctl config migrate --from 0 --to 1`; there is no automatic
  down-migration.
- Add versioned deployment, confinement, feature-evidence, supply-chain
  admission, workload-policy, revocation, and Helm OCI evidence schemas.
  Consumers must reject unknown schema versions.

### Deprecations and removals

- Keep legacy system access-log enablement and the epoch-1 QUIC resolver table
  as compatibility inputs. New configurations must use
  `access_log.system.enabled` and `[proxy.upstream_resolution]`.
- Retire partial image-admission assumptions in favor of digest-bound GitHub
  attestation, SBOM, provenance, vulnerability, independent-rebuild, and
  signed workload-policy evidence. Partial evidence cannot qualify this cut.

### Admin API

- Add durable long-running Admin operations, external audit-chain anchoring,
  atomic secret-reference activation, staged fixed-member membership, and
  version-2 membership epochs while retaining compatible version-1 learners.
- Add explicit owned and embedded runtime APIs plus activation-plan and
  resolved-topology diagnostics. Mutation decoding, signing, idempotency,
  audit classification, and rollback remain fail closed.

### Feature lifecycle

- Retarget the general and Kubernetes graduation registries and official-beta
  validation to `0.8.1`; all tracked features remain `experimental` and
  `unvalidated`.
- Keep graduation evidence bound to the canonical repository, exact ref and
  revision, target version, complete registry inventory, phase, and required
  native or cluster platform. Missing, stale, duplicate, or partial evidence
  is ineligible.

### Rulepack compatibility

- Retain the existing OxiRule and rulepack compatibility contract. Fuzzing and
  normalization coverage do not introduce a rulepack format or undocumented
  rule-behavior change.

### Executables and images

- Deliver the documented role-separated `oxibelt`, `oxibeltctl`,
  `oxibelt-keysigner`, `oxibelt-netport-switcher`,
  `oxibelt-gateway-controller`, and `oxibelt-dataplane-strict` surfaces.
- Require fresh exact-revision runtime checks, immutable digests, SBOMs,
  provenance, attestations, vulnerability decisions, and independent rebuild
  receipts for all 30 image subjects.
- Package both official Helm charts with Helm `4.2.4`, publish exact
  `0.8.1-beta.1` OCI versions, and verify descriptor, manifest, config, layer,
  attestation, and byte-identical rebuild evidence. Helm `3.21.3` remains a
  supported consumer.
- Do not write stable image aliases during beta publication. Charts never
  receive mutable aliases.

### Storage and state

- Serialize PostgreSQL shared-state initialization, retain durable Admin
  operation and membership records, and preserve append-only audit anchoring.
  Stop new-version writers before rollback and restore a compatible database
  backup with the older binaries.
- Retain durable UDP ownership and rollout state. Mixed-generation flows have
  explicit admission and cleanup boundaries; rollback cannot recreate sockets,
  source ports, NAT or conntrack entries, endpoint selection, or in-flight
  datagrams.
- Resolver, connection-pool, and runtime-planning state remain bounded in
  memory and are discarded on drain or restart.

### Upgrade validation

- Create and inspect an epoch-1 sibling tree, validate it with the candidate
  binary, and inspect the selected Helm client before staged rollout:

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
  staged rollout with readiness, drain, audit-anchor, shared-state, and Gateway
  Controller Lease observations before increasing traffic.
- Deploy only after person review, exact-revision release publication, the
  vulnerability decision, all 30 image receipts, both chart receipts, and the
  aggregate qualification receipt succeed. Begin the 24-hour stable soak only
  from that fresh evidence set.

### Rollback and irreversible steps

- Retain `0.6.6` image digests, the complete epoch-0 configuration tree,
  referenced assets, PostgreSQL backup, signed admission bundle, audit
  evidence, controller rollback ConfigMaps, Gateway API CRDs and Lease, and
  shared UDP identity material until qualification completes.
- Stop new-version Admin, membership, shared-state, and UDP writers; drain the
  data plane before the controller; restore the epoch-0 tree and compatible
  database with `0.6.6`; and remove unknown epoch-1 tables before validation.
  There is no automatic epoch-1 down-migration.
- External audit checkpoints, exported telemetry, terminated connections,
  sessions, datagrams, endpoint selection, and external side effects cannot be
  recreated by rollback.

### Known issues

- `0.8.0-beta.0` is forbidden failed-cut history. `0.8.0-beta.1` was
  published, but its release-image workflow failed and independent rebuilds
  were skipped. `0.8.0-beta.2` was an unpublished failed cut without a
  governed entry. None may supply artifacts, evidence, or a stable-promotion
  source.
- Native `linux/riscv64` cluster-runner graduation evidence remains unmet; all
  tracked general and Kubernetes features remain experimental and unvalidated.
- Performance comparison is optional and hosted-only. If skipped, record it
  as unrun; it does not substitute for release qualification.

### Security

- Block every `CRITICAL` finding and every fixable `HIGH` finding for every
  exact image subject. A global allowance cannot rescue a failed role or
  architecture.
- Preserve fail-closed HTTP framing, TLS and CRLite decisions, QUIC Initial
  admission, WebTransport isolation, Happy Eyeballs address provenance,
  shared-state mutation, Kubernetes admission, confinement, secret redaction,
  and audit boundaries.
- Require digest-bound SBOM, provenance, GitHub attestation, Helm OCI
  schema-v3 evidence, signed admission evidence, independent rebuild receipts,
  and one exact aggregate qualification result. Do not promote aliases when
  any identity, digest, receipt, release, workflow, or readback binding is
  missing or inconsistent.

## [0.8.0-beta.1] - 2026-08-14

> Fresh qualification candidate for the `0.8.0` line. The immutable
> `0.8.0-beta.0` tag is an invalid failed cut because beta numbering starts at
> beta.1. Do not move, recreate, publish, or attach artifacts to beta.0, and do
> not reuse any result associated with it.

- Changes since: `0.6.6`
- Supported upgrade sources: `0.6.6`
- Upgrade guide: [Upgrade from 0.6.6 to the 0.8.0 line](docs/Upgrading.md#upgrade-from-066-to-the-080-line)

### Configuration

- Add epoch-1 configuration activation planning, native schema and migration
  tooling, resolved runtime-topology diagnostics, manifest-bound filesystem
  confinement, strict seccomp expectations, typed secret-reference activation,
  and the `edge-secure-medium` v2 deployment profile. Selected but unavailable
  or unqualified capabilities continue to fail closed.
- Add bounded persistent direct-H1, pooled direct-H2, adaptive multi-address
  HTTP/3, and cross-datagram QUIC Initial reassembly controls. New tables are
  optional and defaulted, but an operator must enable experimental engines
  deliberately and validate the complete file tree before rollout.
- Preserve both the canonical `access_log.system.enabled` setting and the
  `0.6.6` legacy `access_log.enable_system` compatibility input.

### Schema epochs

- Advance the native configuration from epoch `0` at `0.6.6` to epoch `1`.
  Use `oxibeltctl config migrate --from 0 --to 1`; there is no automatic
  down-migration.
- Add versioned deployment, confinement, feature-evidence, supply-chain
  admission, workload-policy, and revocation schemas. Consumers must reject
  unknown schema versions instead of interpreting a newer payload as an older
  contract.

### Deprecations and removals

- Retain legacy system access-log enablement for compatibility, but keep
  `access_log.system.enabled` as the canonical setting for new configuration.
- Retire the earlier image-signature admission assumptions in favor of the
  current digest-bound GitHub attestation, provenance, SBOM, vulnerability,
  rebuild, and signed workload-policy evidence contracts. Old partial evidence
  cannot qualify this cut.

### Admin API

- Add durable long-running Admin operations, external audit-chain anchoring,
  atomic secret-reference activation, staged fixed-member cluster membership,
  and version-2 membership epochs while preserving compatible version-1
  learners.
- Add explicit owned and embedded runtime APIs plus activation-plan and
  resolved-topology diagnostics. Mutation decoding, signing, idempotency,
  audit classification, and rollback remain bound to the shared fail-closed
  control-plane contracts.

### Feature lifecycle

- Replace ESLint-only suppression directives with their Oxlint equivalents in
  release tooling. This tooling-only migration does not change the lifecycle
  registries, evidence schemas, promotion eligibility, or runtime behavior.
- Keep every general and Kubernetes feature in the tracked graduation
  registries `experimental` and `unvalidated` for `0.8.0`. The expanded test
  and attestation inventory is qualification machinery, not evidence of a
  lifecycle promotion.
- Bind future graduation evidence to the canonical repository, exact ref and
  revision, target version, complete registry inventory, phase, and native
  architecture or cluster requirements. Missing, stale, duplicate, or partial
  evidence remains ineligible.

### Rulepack compatibility

- Retain the existing OxiRule and rulepack compatibility contract. The new
  fuzz targets exercise parsing and normalization boundaries but do not
  promote a new rulepack format or make an undocumented rule behavior change.

### Executables and images

- Add the Gateway Controller and strict data-plane delivery surfaces while
  preserving the documented executable names and role separation for
  `oxibelt`, `oxibeltctl`, `oxibelt-keysigner`, `oxibelt-netport-switcher`,
  `oxibelt-gateway-controller`, and `oxibelt-dataplane-strict`.
- Build and independently verify all 30 role and architecture image subjects
  from this exact revision. Each subject requires its own runtime check,
  immutable digest, SBOM, provenance, attestation, vulnerability decision,
  and reproducible-build receipt.
- Copy the canonical fuzz-regression fixtures only into the
  `riscv64-musl-check` validation stage so RISC-V
  `cargo check --all-targets --locked` compiles fixture-backed tests. This does
  not alter delivered executables, image roles, runtime contents, or upgrade
  procedures.
- Package both official Helm charts from tracked regular files with Helm
  `4.2.4`, publish exact `0.8.0-beta.1` OCI versions, and verify their
  descriptor, manifest, config, layer, attestation, and byte-identical rebuild
  evidence. Helm `3.21.3` remains a supported consumer only.
- Do not write stable image aliases during publication. Alias promotion is a
  separate fail-closed operation after the automatic independent verifier has
  accepted the exact 30-image and two-chart qualification set. Charts never
  receive mutable aliases.

### Storage and state

- Serialize PostgreSQL shared-state initialization, add durable Admin
  operation and membership records, and preserve append-only audit anchoring.
  Stop new-version writers before rollback and restore a compatible database
  backup with the old binaries.
- Add shared durable UDP ownership and rollout state. Mixed-generation flows
  have explicit admission and cleanup boundaries; rollback cannot recreate
  sockets, source ports, NAT or conntrack entries, endpoint selection, or
  in-flight datagrams.
- QUIC Initial reassembly, HTTP pooling, resolver selection, and runtime
  planning state remain bounded and in memory and are discarded on drain or
  restart.

### Upgrade validation

- Create and inspect the epoch-1 sibling tree, then validate every referenced
  file with the beta.1 binary before activation:

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

- Render both charts with the selected supported client, inspect the complete
  manifests and admission references, and perform a staged rollout with
  readiness, drain, audit-anchor, shared-state, and Gateway Controller Lease
  observations before increasing traffic.
- Deploy beta.1 only after person review and the fresh exact-revision release
  workflow, vulnerability policy, 30 image receipts, two chart receipts, and
  aggregate qualification receipt all succeed. Start the 24-hour stable soak
  only from that complete automatic evidence set.

### Rollback and irreversible steps

- Retain the `0.6.6` image digests, epoch-0 configuration tree, referenced
  assets, PostgreSQL backup, signed admission bundle, audit evidence,
  controller rollback ConfigMaps, Gateway API CRDs and Lease, and shared UDP
  identity material until the beta.1 decision is complete.
- Stop new-version Admin, membership, shared-state, and UDP writers; drain the
  data plane before the controller; restore the epoch-0 tree and compatible
  database with `0.6.6`; and remove whole unknown epoch-1 tables before
  validating with the older strict parser. There is no automatic epoch-1
  down-migration.
- Externally witnessed audit checkpoints and already exported telemetry remain
  append-only. Rollback cannot reproduce terminated connections, sessions,
  datagrams, exact Service endpoints, or external side effects.

### Known issues

- The signed `0.8.0-beta.0` tag is forbidden release history and has no GitHub
  Release. It cannot be repaired or used as the preceding beta; beta.1 starts
  a fresh chain from stable `0.6.6`.
- No beta.1 qualification exists until its exact hosted workflows produce and
  verify all required artifacts and receipts. Local checks, development-build
  tags, manual verifier runs, and evidence from earlier release lines do not
  satisfy this gate.
- The Gateway Controller, Gateway API, Helm integration, and every other
  tracked feature remain experimental and unvalidated. Native
  `linux/riscv64` cluster-runner graduation evidence remains unmet.
- Performance comparison is optional and hosted-only for this cut. If it is
  skipped, record it as unrun; it does not block the non-benchmark release
  summary or stable qualification.

### Security

- Require the stable/beta vulnerability policy for every exact image subject:
  block every `CRITICAL` finding and every fixable `HIGH` finding. A global
  vulnerability allowance cannot rescue a failed role or architecture check.
- Preserve fail-closed HTTP framing, TLS and CRLite decisions, QUIC Initial
  fragment and replay admission, WebTransport isolation, shared-state
  mutation, Kubernetes admission, confinement, secret-redaction, and audit
  boundaries introduced since `0.6.6`.
- Require digest-bound SBOM, provenance, GitHub attestation, Helm OCI schema-v3
  raw evidence, signed admission evidence, independent rebuild receipts, and
  one exact aggregate qualification result. Do not promote aliases when any
  source, identity, digest, receipt, release, workflow, or readback binding is
  missing or inconsistent.

## [0.7.1-beta.4] - 2026-08-11

> Recovery candidate for the `0.7.1` line. This cut advances from the
> immutable unpublished `0.7.1-beta.3` tag at a new exact revision. It does
> not move or repair beta.3 and must rebuild and qualify every official
> artifact independently.

- Changes since: `0.7.1-beta.3`
- Supported upgrade sources: `0.7.1-beta.3`, `0.7.1-beta.2`, `0.6.5`
- Upgrade guide: [Upgrade from 0.6.5 to the 0.7.1 line](docs/Upgrading.md#upgrade-from-065-to-the-071-line)

### Configuration

- Add the optional defaulted `[sni_forward.quic_initial_reassembly]` table for
  bounded cross-datagram QUIC Initial CRYPTO reconstruction. It has no effect
  on existing configurations that omit it and uses the epoch-1 defaults:
  64 pending sessions, fragments, and datagrams per session; 131072 retained
  datagram bytes per session; 4194304 total buffered bytes; and a 10000 ms
  deadline capped by `limits.tls_handshake_timeout_ms`.

### Schema epochs

- Retain native configuration schema epoch `1`. The nested QUIC Initial
  reassembly table is additive and defaulted, so beta.2 and beta.3
  configurations remain valid without migration.

### Deprecations and removals

- No changes for this release.

### Admin API

- No changes for this release.

### Feature lifecycle

- No changes for this release.

### Rulepack compatibility

- No changes for this release.

### Executables and images

- Require the shared RISC-V release-image smoke configuration to declare
  `runtime.hardening.seccomp.expectation = "required"`, matching the existing
  `oxibelt-dataplane-strict` artifact contract. A repository regression loads
  that exact tracked fixture, supplies test TLS material, validates it under
  the strict artifact role, and confirms that enabling Admin still fails for
  the Admin capability fields.
- Rebuild every role and architecture at the exact beta.4 revision. Do not
  promote a beta.2 image, synthesize a beta.3 asset, or reuse an earlier build,
  manifest, SBOM, provenance statement, attestation, vulnerability result, or
  independent-rebuild receipt.

### Storage and state

- QUIC Initial reassembly state is bounded, in-memory, and shared per logical
  UDP bind only. No database, shared-state backend, durable record, or schema
  migration is introduced.

### Upgrade validation

- Beta.2 and beta.3 configurations remain at native schema epoch `1`. Validate
  the complete configuration and every referenced file with the beta.4
  `oxibeltctl` before rollout:

```sh
oxibeltctl config validate /etc/oxibelt/config/oxibelt.toml --local-only
```

- When enabling split QUIC Initial ClientHello support, validate the new table
  with the beta.4 binary before rollout. Its total budget covers retained raw
  datagrams plus unique decrypted CRYPTO bytes; `client_hello_max_bytes`
  remains the ClientHello bound.

- When upgrading directly from `0.6.5`, create and inspect the epoch-1 sibling
  tree, then validate the migrated configuration before activation:

```sh
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1 --dry-run
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1
oxibeltctl config validate \
  /etc/oxibelt/config/oxibelt.toml.migrated-v1/oxibelt.toml \
  --local-only
```

- Deploy beta.4 only after its person-reviewed release, all 30
  role/architecture runtime checks, vulnerability admission, immutable
  manifests, SBOMs, attestations, provenance, and independent-rebuild receipts
  succeed for its exact revision. Begin the stable qualification soak only
  from that complete evidence set.

### Rollback and irreversible steps

- Retain the last operator-approved image digests, epoch-1 configuration tree,
  referenced assets, PostgreSQL backup, signed admission bundle, audit
  evidence, controller rollback ConfigMaps, Gateway API Lease, and shared UDP
  identity key and backend until the beta.4 rollback decision is complete.
- Stop new-version Admin and staged-membership writers and new UDP admission
  before restoring prior images and compatible data. Roll back the data plane
  before the Gateway Controller, drain durable UDP owners, and restore the
  epoch-0 configuration and pre-upgrade PostgreSQL backup when returning to
  `0.6.5`; there is no automatic epoch-1 down-migration.
- Externally witnessed audit checkpoints remain append-only, and
  operator-owned Gateway API CRDs must not be deleted as an implicit rollback.
  Rollback cannot recreate prior sockets, source ports, NAT or conntrack
  entries, exact Service endpoints, in-flight datagrams, or sessions.
- Before returning to an older strict-unknown-field binary, remove the whole
  `[sni_forward.quic_initial_reassembly]` table and validate the resulting
  configuration with that binary. The reassembly state is not persisted and is
  discarded on drain/restart; an older binary does not provide its
  cross-datagram replay behavior.

### Known issues

- The immutable `0.7.1-beta.3` tag has no GitHub Release or official artifact
  and cannot be repaired. A source build from its revision is recovery input,
  not an image or evidence source for beta.4.
- The published `0.7.1-beta.2` prerelease did not complete its independent
  rebuild evidence. Direct beta.2-to-beta.4 configuration recovery is
  supported, but beta.2 evidence cannot qualify beta.4.
- No beta.4 release qualification exists until the new signed tag's hosted
  workflows produce and verify the complete exact-revision evidence set. A
  local release-contract receipt or source check is not publication or stable
  readiness.
- The Kubernetes Gateway Controller and its Gateway API features remain
  `experimental`; native `linux/riscv64` cluster-runner graduation evidence is
  still unmet.

### Security

- Keep QUIC Initial reconstruction fail closed: conflicting overlaps, expiry,
  capacity admission, fragment/datagram/byte limits, and replay-admission
  failures reject the pending input without displacing established sessions.
  DEBUG and TRACE diagnostics are sampled and redacted, and the fixed-outcome
  reassembly metric has no peer, connection-ID, SNI, or error-text labels.
- Keep the strict runtime contract unchanged and fail closed: the repaired
  fixture supplies the required seccomp expectation instead of weakening the
  validator, role capabilities, runtime hardening, or vulnerability policy.
- Require all 30 exact-revision subjects to pass their runtime matrix and the
  stable/beta vulnerability policy, which blocks every `CRITICAL` finding and
  every fixable `HIGH` finding. A global vulnerability `allow` cannot rescue a
  failed role/architecture runtime check.
- Require fresh digest-bound SBOM, provenance, GitHub attestation, Helm OCI
  evidence, signed admission evidence, and independent-rebuild receipts for
  beta.4. Earlier beta or build-tag results must not be copied, promoted, or
  interpreted as evidence for this revision.

## [0.7.1-beta.3] - 2026-08-10

> Immutable unpublished failed cut. The tag workflow rejected this exact
> revision before draft creation because it had no governed beta entry. No
> GitHub Release or official `0.7.1-beta.3` artifact was produced. This entry
> records the cut as attributable history; it does not repair, move, recreate,
> or republish the signed tag.

- Changes since: `0.7.1-beta.2`
- Supported upgrade sources: `0.7.1-beta.2`, `0.6.5`
- Upgrade guide: [Upgrade from 0.6.5 to the 0.7.1 line](docs/Upgrading.md#upgrade-from-065-to-the-071-line)

### Configuration

- Add configuration activation planning and resolved runtime-topology
  reporting for the bounded Compio direct-H1 engine, persistent direct-H1
  services, stateful direct-H2 pooling, and adaptive HTTP/3 address selection.
  Capability and file-root checks remain fail closed when a selected runtime
  surface is unavailable or unqualified.
- Add manifest-based filesystem confinement verification, installed-manifest
  binding across reloads, and explicit strict-artifact seccomp expectations.
  The `edge-secure-medium` v2 profile renders and validates these hardening
  inputs as one deployment contract, including redacted manifest diagnostics.

### Schema epochs

- Keep the native OxiBelt configuration at schema epoch `1`; no epoch
  migration is required between beta.2 and this cut.
- Add supply-chain admission bundle schema v2 and digest-bound immutable
  evidence schemas. Version 2 signs a bounded workload-image policy for
  regular, init, native-sidecar, and ephemeral containers; an older fixed
  admission server must not receive a v2 bundle.

### Deprecations and removals

- No changes for this release.

### Admin API

- Add staged fixed-member cluster membership with isolated mutation keys,
  audit classification, shared mutation decoding, and version-2 membership
  epochs. Keyless version-1 learners remain live while a staged transition is
  recoverable, and invalid or incomplete epochs fail closed.
- Preserve the existing Admin audit wire contract while adding membership
  mutation compatibility and the resolved activation/runtime diagnostics used
  to review a configuration before it becomes active.

### Feature lifecycle

- Add exact-revision feature-graduation evidence, detached qualification
  attestations, and complete graduation-summary inventory checks. Evidence is
  bound to the repository, ref, phase, and full checked-out revision rather
  than being inferred from a mutable branch.
- Keep the Kubernetes Gateway Controller, Gateway API translation, and Helm
  integration `experimental`. Expanded Gateway capabilities and their
  admission/hardening qualification do not promote those surfaces without all
  required native architecture and cluster evidence.

### Rulepack compatibility

- No changes for this release.

### Executables and images

- Add explicit owned and embedded OxiBelt runtime APIs and validate their
  lifecycle and unsafe-code boundaries. Keep `netport-switcher` a standalone
  artifact and preserve the existing public executable names and role split.
- Expand Gateway API handling and Helm hardening, produce reproducible Helm
  archives, and bind Helm OCI descriptors, manifests, configuration, chart
  layers, and rebuild predicates with the self-verifying schema-v3 evidence
  contract. Older or internally inconsistent evidence is rejected.
- Align independent image rebuild inputs, bound mismatch diagnostics, and
  prefetch the complete locked Cargo graph for offline fixture checks. Every
  release role and architecture still requires its own exact-revision image,
  SBOM, provenance, vulnerability, and rebuild evidence.

### Storage and state

- Serialize PostgreSQL shared-state schema initialization with one
  transaction-scoped advisory lock. Base shared-state and durable UDP table
  and index creation now commit atomically, so concurrent initializers wait
  instead of racing catalog objects; stored records and schema layouts do not
  change.
- Persist staged Admin membership epochs through the existing durable Admin
  operation and audit boundaries. Stop new-version membership writers before
  restoring an older binary that does not understand a staged epoch.

### Upgrade validation

- A beta.2 configuration remains at epoch `1`, but validate the complete
  configuration and referenced files with the target source build before any
  recovery exercise:

```sh
oxibeltctl config validate /etc/oxibelt/config/oxibelt.toml --local-only
```

- When starting from `0.6.5`, create and inspect the epoch-1 sibling tree with
  the target `oxibeltctl`, then validate the migrated configuration before
  activation:

```sh
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1 --dry-run
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1
oxibeltctl config validate \
  /etc/oxibelt/config/oxibelt.toml.migrated-v1/oxibelt.toml \
  --local-only
```

- Do not deploy or promote `0.7.1-beta.3`: the immutable cut has no official
  image or release asset. A source build may be used only to inspect or recover
  configuration and state, and has neither beta.3 release identity nor release
  qualification.

### Rollback and irreversible steps

- Because beta.3 produced no official artifacts, retain the last
  operator-approved image digests instead of treating the beta.3 tag or a
  source build as a rollback target. Preserve the prior configuration tree,
  referenced assets, PostgreSQL backup, admission bundle, audit evidence, and
  controller rollback state until recovery is complete.
- Stop staged-membership, Admin, shared-state, and UDP writers before restoring
  older images and compatible data. Restore the data plane before the Gateway
  Controller, drain durable UDP owners, and restore epoch-0 configuration and
  the pre-upgrade database when returning to `0.6.5`; no automatic epoch-1
  down-migration exists.
- Externally witnessed audit checkpoints remain append-only. Rollback cannot
  recreate prior sockets, upstream source ports, NAT or conntrack entries,
  exact Kubernetes Service endpoints, in-flight datagrams, or application
  sessions.

### Known issues

- The signed `0.7.1-beta.3` tag is immutable and its tree lacks this governed
  entry, so its failed draft workflow cannot be repaired. It has no draft,
  GitHub Release, official asset, manifest, attestation, or image.
- The same-revision `0.7.1-build.bcfd6140` release-image run failed the first
  `dataplane-strict` `linux/riscv64` runtime check because the shared smoke
  fixture omitted the required seccomp expectation. Its global vulnerability
  evaluator admitted all 30 subjects with zero findings, but that decision
  cannot override the failed runtime matrix or qualify beta.3.
- The published `0.7.1-beta.2` prerelease did not complete its independent
  30-subject rebuild evidence and is not qualified evidence for beta.3 or a
  stable release.
- The Kubernetes Gateway Controller and its Gateway API features remain
  `experimental`; native `linux/riscv64` cluster-runner graduation evidence is
  still unmet.

### Security

- Bind installed filesystem-confinement manifests to activation and reload,
  distinguish handled filesystem access from granted paths, stabilize atomic
  manifest digests, and require the strict data-plane artifact to observe its
  declared seccomp contract. Missing or mismatched hardening evidence blocks
  startup or reload.
- Require signed workload-image policies and digest-bound admission evidence,
  including exact executable coverage for auxiliary and ephemeral containers.
  Namespace, serving-target, image-digest, bundle-revision, and webhook-rule
  mismatches fail closed.
- Preserve CRLite certificate rejection across TLS decisions, contain
  WebTransport receive operations, honor Gateway ExternalAuth response-header
  allowlists, and admit dependency updates only with matching lockfile,
  Cargo-vet, and supply-chain evidence.
- A vulnerability `allow` decision is necessary but not sufficient: every
  role/architecture runtime smoke, immutable manifest, provenance,
  attestation, and independent rebuild gate must also succeed for the exact
  release revision.

## [0.7.1-beta.2] - 2026-07-29

> Recovery candidate for the `0.7.1` line. The immutable
> `0.7.1-beta.1` tag was rejected before draft creation because its exact
> revision had no governed beta entry. This cut preserves that failed tag as
> attributable history and advances the release contract without moving,
> deleting, recreating, or hand-publishing it.

- Changes since: `0.7.1-beta.1`
- Supported upgrade sources: `0.7.1-beta.1`, `0.6.5`
- Upgrade guide: [Upgrade from 0.6.5 to the 0.7.1 line](docs/Upgrading.md#upgrade-from-065-to-the-071-line)

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

- Carry forward the `0.7.1-beta.1` same-run vulnerability-evidence repair
  without changing runtime source behavior, image roles, configuration, or
  packaging layout. Build every official artifact again with the exact
  `0.7.1-beta.2` identity. A later gate attempt may select the newest available
  scan bundle at or below the current attempt independently for each subject,
  while the current scan matrix and current-attempt publication decision
  remain mandatory.
- Record the failed `0.7.1-beta.1` cut in the governed beta ledger so its
  signed immutable tag remains attributable without creating or rewriting a
  GitHub Release for that tag.

### Storage and state

- No changes for this release.

### Upgrade validation

- A source build from `0.7.1-beta.1` has the same runtime, configuration,
  schema, and persisted-state behavior as this recovery candidate, but it has
  a different build identity and is not an official beta.2 artifact. Validate
  the complete configuration before replacing it:

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

- Deploy `0.7.1-beta.2` only after its person-reviewed release, all 30
  role/architecture image subjects, vulnerability admission, attestations,
  provenance, and independent-rebuild receipts succeed. Produce a new
  evidence set for this exact revision; do not reuse `0.7.0-beta.4` or
  `0.7.1-beta.1` release evidence.

### Rollback and irreversible steps

- The failed `0.7.1-beta.1` cut has no official image or release asset to
  restore. Retain the exact prior deployable image digests, configuration
  tree, referenced assets, PostgreSQL backup, controller rollback ConfigMaps,
  Gateway API Lease, and shared UDP identity key and backend until the
  `0.7.1-beta.2` rollback decision is complete.
- Stop all new-version Admin writers and new UDP admission before restoring
  prior images and data. Roll back the data plane before the Gateway
  Controller, drain durable UDP owners, and restore the epoch-0 configuration
  and pre-upgrade PostgreSQL backup when returning to `0.6.5`; there is no
  automatic epoch-1 down-migration.
- Externally witnessed audit checkpoints remain append-only, and
  operator-owned Gateway API CRDs must not be deleted as an implicit rollback.
  Rollback does not recreate a prior UDP socket, upstream source port,
  NAT/conntrack entry, exact Kubernetes Service endpoint, in-flight datagram,
  or application session.

### Known issues

- The immutable `0.7.1-beta.1` tag cannot be repaired or republished. It has
  no draft, GitHub Release, official asset, manifest, attestation, or image;
  retain it only as source-build recovery history.
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

- Preserve attempt-qualified raw Trivy artifacts and select the highest
  same-run evidence attempt not greater than the current attempt for each
  expected image subject. Artifact name, run, subject, revision, channel,
  policy, report hash, immutable image identity, and manifest digest must all
  agree; a malformed newest bundle fails closed without falling back.
- Keep the current scan matrix successful, emit only a current-attempt
  schema-2 decision with per-subject `evidenceAttempt`, and require publishers
  to recheck that provenance and the complete 30-subject manifest set before
  registry login.
- Preserve the stable/beta block on every `CRITICAL` vulnerability and every
  fixable `HIGH` vulnerability, with exact-revision SLSA provenance,
  CycloneDX SBOMs, GitHub attestations, and independent-rebuild evidence for
  each role and architecture.

## [0.7.1-beta.1] - 2026-07-29

> Immutable unpublished failed cut. The tag workflow rejected this tag before
> draft creation because the exact tagged revision had no governed beta entry.
> No GitHub Release or official release artifact was produced, and this tag is
> not a published beta.

- Changes since: `0.6.5`
- Supported upgrade sources: `0.6.5`
- Upgrade guide: [Upgrade from 0.6.5 to the 0.7.1 line](docs/Upgrading.md#upgrade-from-065-to-the-071-line)

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
- Add opt-in `udp_flow_state = "shared_required"` for native UDP listeners,
  backed by an explicitly selected Redis-compatible or PostgreSQL
  `udp_flows_backend` and one deployment-wide identity key. Keep `local` as
  the native compatibility default and generated `UDPRoute` flow state
  disabled until the operator explicitly selects `shared_required`.
- Require Redis-compatible durable UDP backends to prove unlimited memory or
  `maxmemory_policy = noeviction` at activation and reload. An unsafe or
  unverifiable eviction policy, backend mismatch, identity-key mismatch, or
  invalid capacity/timing bound fails activation.

### Schema epochs

- Establish native configuration schema epoch `1`, publish its JSON Schema,
  and add local `oxibeltctl config schema`, `validate`, `explain`, and
  deterministic epoch-0-to-1 sibling-tree migration commands. Rust semantic
  validation remains authoritative.
- Add optional epoch-1 metadata for durable UDP listener policy, backend
  selection, identity-key lookup, and fixed `reject_new_only` failure policy.
  Existing configurations retain local native UDP and disabled generated
  `UDPRoute` defaults unless they opt in.

### Deprecations and removals

- Migrate legacy `tls.key_exchange_groups` to
  `tls.1_3.key_exchange_groups`, `tls.session_tickets` to
  `tls.resumption.mode`, and `tls.session_ticket_rotation_seconds` to
  `tls.resumption.rotation_seconds`. The epoch-1 validator accepts documented
  compatibility aliases only where they do not conflict with canonical
  fields.
- Migrate `upstream_pools[].health_check.rise` to `healthy_threshold` and
  `upstream_pools[].health_check.fall` to `unhealthy_threshold`; configuring
  an alias with its canonical field is invalid.
- Remove OxiBelt's bundled Sigstore Policy Controller and Cosign/OCI-referrer
  admission assets. Official image evidence uses GitHub API-hosted
  attestations and requires an operator-owned admission policy where cluster
  admission is needed.

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
  generated `UDPRoute`, and `BackendTLSPolicy` integration `experimental`.
  Generated UDP fails closed until every selected data-plane Pod has matching
  required shared-flow state.

### Rulepack compatibility

- Require catalog `min_oxibelt_version` values to use strict SemVer. A gated
  rulepack is compatible only when `oxibeltctl` has an official clean
  exact-tag identity at or above the requested version; untagged, dirty, and
  source-archive identities fail closed. Catalog entries without this field
  retain their existing compatibility.

### Executables and images

- Add the `oxibelt-dataplane-strict` package, executable, OCI repository, and
  Helm role. It retains public proxy, WAF, Person Proof, health, metrics,
  reload, and lifecycle behavior while compiling out Admin listeners,
  mutations, operations, cluster runtime, and the Admin OpenAPI asset.
- Expand `oxibeltctl` with local configuration schema, migration, validation,
  explanation, and external audit verification commands. Bind binaries, Admin
  metadata, OCI labels, attestations, and release subjects to one validated
  build identity while retaining Cargo's committed `0.0.0` sentinel.
- Define standalone, compatibility data-plane, strict data-plane, Gateway
  Controller, tools, and keysigner release roles across the five supported
  architecture subjects, with exact executable inventory, role-confusion,
  native `linux/riscv64`, and immutable manifest checks.
- Package `/run/oxibelt-keysigner` with owner `10002:10002` and mode `0770`,
  initialize keysigner tracing, and keep the release smoke rootless,
  read-only, and limited to `CAP_CHOWN` for its socket-volume helper.
- Add the Gateway Controller's `--udp-flow-state` and Helm
  `l4.udp.flowState` controls, render integer arguments as canonical decimal
  digits, and strengthen Kubernetes qualification with reviewed Valkey,
  Lease-recovery, rollout, and UDP probes.
- Repair hosted rootless independent rebuild setup without exposing a host
  cgroup controller, retain strict all-numeric build-tag parsing and Rust
  `1.97.1` release compatibility, and keep release package metadata at the
  committed `0.0.0` sentinel.
- Preserve immutable attempt-qualified Trivy reports while allowing a later
  gate attempt to reevaluate the newest available same-run evidence per
  subject. The gate emits a current-attempt `schemaVersion: 2` decision with
  per-subject `evidenceAttempt` and never uses prior evidence to rescue a
  failed current matrix.

### Storage and state

- Add additive PostgreSQL state for durable Admin operations, fixed-member
  rollout, encrypted commands/checkpoints, external audit-anchor outbox and
  authority records, and bounded retention. Old binaries do not understand
  these rows, so rollback requires stopping new writers and restoring
  compatible data. Atomic secret activation retains bounded rollback grace and
  redacted reference-set fingerprints.
- Persist opaque keyed durable UDP listener, peer, route, target, owner, and
  routing-generation identities with bounded capacity, token state,
  server-time expiry, ownership leases, and monotonic fencing across memory,
  Redis-compatible, and PostgreSQL adapters. Only shared backends allow
  another process or replacement Pod to recover a record.
- Preserve one listener-wide capacity, new-flow-token, and monotonic-fence
  scope across overlapping routing generations. Recovery reauthorizes the
  stored route and target and rejects stale owners, missing targets,
  generation drift, partial backend state, or uncertain admission.

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
- Before enabling shared UDP, stop new admission, drain existing process-local
  flows, configure one namespace, backend mapping, identity key, and safe
  Redis eviction policy on every selected Pod, then roll the Pods and verify
  readiness before enabling controller `shared_required`.
- Do not deploy this failed cut. Use only a subsequent person-reviewed beta
  whose exact-tag draft, complete 30-subject artifact matrix, vulnerability
  decision, attestations, provenance, and independent rebuild all succeed.

### Rollback and irreversible steps

- Retain the exact `0.6.5` image digests, epoch-0 configuration and referenced
  assets, PostgreSQL backup, controller rollback ConfigMaps, Gateway API
  Lease, and any durable UDP identity key and backend until rollback is
  complete. Stop new-version Admin writers and UDP admission before restoring
  prior images and data.
- Roll back the data plane before the Gateway Controller and drain durable UDP
  owners before returning to an older binary. There is no automatic epoch-1
  down-migration; restore the epoch-0 tree and pre-upgrade PostgreSQL backup or
  roll forward.
- External audit checkpoints and independently retained witnesses are
  append-only. Do not rewrite or delete them, do not delete operator-owned
  Gateway API CRDs as an implicit Helm rollback, and do not expect rollback to
  recreate sockets, NAT/conntrack state, endpoints, datagrams, or sessions.

### Known issues

- This tag cannot be repaired or republished: release-tag policy prohibits
  update and deletion, and its exact revision cannot satisfy the governed
  entry contract. No draft, GitHub Release, or official artifact exists for
  `0.7.1-beta.1`; use `0.7.1-beta.2` or a later person-reviewed release.
- The Kubernetes Gateway Controller, its Helm integration, and its Gateway API
  features remain `experimental`; native `linux/riscv64` cluster-runner
  graduation evidence is still unmet.
- Durable UDP preserves logical ownership, route/target affinity, and bounded
  admission only. It does not preserve the socket, upstream source port,
  NAT/conntrack state, exact Kubernetes Service endpoint, upstream-initiated
  or in-flight datagrams, or application/session protocol state across
  restart.
- OxiBelt no longer ships its former Cosign/OCI-referrer admission policy.
  Deployments enforcing that contract must install and validate an
  operator-approved GitHub-attestation policy before adopting later images.

### Security

- Reject ambiguous or malformed HTTP/1 `Content-Length` and
  `Transfer-Encoding` framing before public, Admin, or operations dispatch
  while preserving valid fixed-length, chunked, upgrade, and tunnel behavior.
- Add secret-reference preflight and redaction, database-time rollout fencing,
  all-member acknowledgement, external append-only audit anchoring,
  fail-closed dependency admission, exact-revision release identity, SLSA
  provenance, CycloneDX SBOMs, GitHub attestations, and independent rebuilds.
- Derive durable UDP identities with the deployment key, require safe
  non-evicting Redis retention, reject partial state, and reauthorize every
  recovered route and target under the active routing generation. Missing or
  inconsistent identity, backend, target, lease, fence, capacity, or token
  state fails activation or rejects the affected flow.
- Keep stable and beta releases fail closed for every `CRITICAL`
  vulnerability and every fixable `HIGH` vulnerability. Same-run evidence
  reuse remains subject-specific, exact-name and exact-content bound,
  current-policy reevaluated, and unable to override a failed current matrix
  or malformed newest bundle.
- Update security-sensitive dependencies including `aws-lc-rs` `1.17.3`,
  Hyper `1.11.0`, and `web-transport-trait` `0.3.7`.

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
