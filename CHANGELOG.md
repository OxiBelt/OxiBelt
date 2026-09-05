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

## [0.9.1] - 2026-09-05

> Stable candidate for the cumulative `0.9.0` to `0.9.1` development
> lineage, based on the published and independently qualified
> `0.9.1-beta.2` source. This entry is prepared for the required one-commit
> documentation-only transition and does
> not claim stable publication, stable qualification, mutable-alias promotion,
> or stable artifact availability. Stable draft preparation may occur during
> the beta.2 soak after terminal exact-revision beta qualification and exact
> stable-source CI succeed. The 24-hour eligibility interval and person review
> gate stable publication; the stable release's own 30-image and two-chart
> qualification gates mutable-alias promotion.

- Changes since: `0.9.0`
- Supported upgrade sources: `0.9.0`, `0.9.1-beta.2`
- Upgrade guide: [Upgrade from 0.9.0 to the 0.9.1 line](docs/Upgrading.md#upgrade-from-090-to-the-091-line)

### Configuration

- Add optional per-route `[routes.bandwidth]` upload and download
  byte-per-second limits. Omitting the table preserves unlimited traffic, each
  direction is independent, and budgets are shared only within one process.
  Accounting is payload-only across HTTP, CONNECT, WebSocket, and WebTransport;
  protocol framing and control frames are not charged. WebSockets without
  stream WAF retain their prior frame-size and extension behavior through the
  constant-memory wire-frame adapter, and live policy is rechecked in bounded
  16 KiB payload chunks, including for sessions that began unlimited.
- Add optional HTTPS upstream client identities for direct upstreams, pool
  members, and discovery templates. Each identity requires a certificate-root-
  relative chain and a matching unencrypted private key; ordinary upstream
  server authentication remains mandatory. Client-identity connections disable
  outbound TLS resumption and the persistent client-configuration cache, while
  established long-lived connections may retain the previous identity until
  drain.
- Add bounded empty-body `[routes.actions.direct_response]` error targets with
  status codes from `400` through `599`. A direct response is terminal and
  cannot be combined with another route target or request-processing action.
  The Gateway controller uses match-equivalent `503` targets when an HTTP or
  gRPC route can be deprogrammed safely.
- Add opt-in Helm upstream client-identity Secret projections through
  `upstreamTls.clientIdentitySecretProjections` and the Gateway-controller
  `upstreamClientTls.sourceSecretAllowlist`. Omitted values grant no Secret
  access and preserve existing Pod and controller behavior. A bounded valid
  chain/key pair is required before a content-addressed target-namespace Secret
  is created.
- Complete the native WebRTC fallback configuration with RFC 8489 SHA-256 and
  compatible MD5 authentication, source-bound current and previous nonce
  secrets, bounded secret-file sources, RFC 6062 TCP relay limits, and
  independent per-server `turns://` TLS policies including optional client
  identity.
- Add default-off Helm `turn` values for generated proxy or singleton edge
  relay configuration, explicit UDP/TCP/TLS control and relay exposure,
  projected Secret files, and matching network-policy rules. Omission preserves
  prior chart rendering. Generated proxy mode may use multiple replicas;
  generated edge-relay mode requires one Deployment replica,
  `service.externalTrafficPolicy = "Local"`, explicit public and relay
  addresses, and bounded UDP/TCP relay ranges. Preserve native syntax,
  defaults, validation, reload behavior, schema epoch `1`, effective-TOML
  output, and secret redaction. Omission of the new optional route, upstream,
  direct-response, and TURN fields preserves the corresponding prior behavior
  and requires no native migration. Production CT storage and Kubernetes doctor
  admission remain subject to the tightened checks documented below. Effective
  configuration redacts `tls.client_identity.private_key` paths in direct HTTP,
  pool-member, discovery, and TURN upstream shapes.

### Schema epochs

- Keep the native configuration schema at epoch `1` while adding the optional
  bandwidth, upstream-client-identity, direct-response, and TURN fields.
  Existing epoch-1 configurations remain valid and retain their behavior
  without a migration. The beta.1 dependency and qualification changes add no
  native or durable schema epoch.
- Extend the two Helm values schemas and Kubernetes feature-graduation policy
  for opt-in Secret projections and refreshed immutable matrix inputs. These
  are deployment-contract additions, not native, database, or on-disk schema
  migrations.

### Deprecations and removals

- No configuration key, API, executable, image role, rule syntax, or supported
  upgrade source is deprecated or removed.

### Admin API

- No Admin API endpoint, authentication, authorization, request, response, or
  persisted Admin contract changes. Existing bounded diagnostics may report
  effective upstream client-identity state without exposing certificates,
  private keys, Secret contents, or sensitive paths.
- `oxibeltctl doctor --kubernetes` requires a direct, certificate-verified
  HTTPS API-server transport. It rejects kubeconfig `proxy-url`,
  `HTTPS_PROXY`/`https_proxy`, `insecure-skip-tls-verify`, and `exec` or
  `auth-provider` credentials before constructing its client.

### Feature lifecycle

- Preserve every existing feature lifecycle and release-policy gate. The
  qualification verifier applies bounded retries to registry descriptor
  inspection failures and malformed responses before sealing a result, while
  valid descriptor or child-manifest mismatches fail immediately. The runtime
  graph replaces yanked `chacha20 0.10.1` with compatible `0.10.2` without
  changing enabled features.
- Extend the repository-only PascalCase declaration policy to class accessors
  and methods, abstract methods, and interface methods. Constructors and
  computed members remain exempt; this contributor-tooling policy changes no
  shipped runtime, configuration, API, rulepack, image, chart, or storage
  behavior.
- Add supported native route bandwidth shaping and native upstream mTLS client
  authentication. Gateway and Helm delivery of client identities retain their
  existing experimental and unvalidated lifecycle state.
- Complete supported TURN edge relay over UDP and RFC 6062 TCP,
  transport-matched TURN proxying over UDP/TCP/TLS, dual-stack relay
  allocation, and coturn/client interoperability coverage. Generic raw UDP
  forwarding remains available through existing `[[stream_listeners]]`.
- Add bounded direct-response routing and fail-closed Gateway behavior.
  Proven-safe HTTPRoute and GRPCRoute withdrawal publishes exact
  match-equivalent empty-body `503` tombstones; proven-safe TCPRoute and
  UDPRoute withdrawal removes only the affected listener. Backend pools are
  all-or-nothing. Ambiguous translation failures and TLSRoute failures preserve
  the last good revision because omission could expose another route or SNI
  rule.
- Extend the Kubernetes `1.34`-`1.37` representatives with `v1.37.0` while
  retaining `v1.34.11`, `v1.35.8`, and `v1.36.4`, Kind `v0.33.0`, and Helm
  `3.21.4`/`4.2.4`. These are fresh graduation-evidence inputs and do not
  themselves promote a Kubernetes feature. Native Certificate Transparency and
  its `oxibelt-ct` chart remain disabled by default, experimental, and
  unvalidated.

### Rulepack compatibility

- Change no OxiRule, CRS, rulepack schema, phase, action, matching, or
  normalization syntax. Strict Brotli decoding changes only how encoded bodies
  reach the existing WAF inspection pipeline: incomplete, trailing,
  no-progress, and Large Window streams are rejected rather than accepted or
  decoded with an unbounded memory requirement.

### Executables and images

- Preserve executable names, package ownership, image roles, chart names, and
  the 30-image and two-chart release inventory. The Gateway controller and data
  plane must be deployed from the same exact candidate revision for the
  client-identity and fail-closed rollout contracts.
- Preserve the compatible `chacha20 0.10.2` patch in official binaries and
  images. Valid registry descriptor or child-manifest mismatches fail closed;
  malformed or unavailable descriptor reads may retry only within the bounded
  qualification budget and must report expected-versus-actual inventories.
- Refresh compatible Rust dependency graphs, standalone probe lockfiles,
  cargo-vet and dependency-policy evidence, CI actions, builder/runtime image
  digests, Kubernetes node images, Kind, Helm 3, Helm 4, and the pinned fuzz
  nightly. The digest-pinned coturn image is a reusable CI helper only, not an
  OxiBelt release image or runtime dependency. Stable artifacts must be rebuilt
  from the exact stable candidate. Do not relabel beta artifacts or substitute
  beta receipts for stable evidence; bind the successful beta.2 aggregate
  separately as the required predecessor qualification.

### Storage and state

- No durable database, object-store, shared-state, or on-disk migration is
  required for the 0.9.1 changes. Bandwidth credits and queues are process-local
  and reconstructed from configuration.
- Production CT startup rejects local or plaintext object storage and requires
  HTTPS S3-compatible versioned storage whose capability probe proves create-only
  writes, conditional replacement, version reporting, and checksum-stable
  readback. Credentials and provider errors remain redacted; this adds no
  migration, and CT remains default-off, experimental, and unvalidated.
- TURN allocations, relay sockets, and pending RFC 6062 data connections remain
  process-local. Compatible full reloads preserve unchanged listeners and
  stable pool runtime; process or Pod replacement starts with empty TURN state.
  Client allocation state is released before stream failures propagate.
- Helm-projected source Secrets, controller-derived target Secrets, immutable
  controller ConfigMaps, mounts, and rollout references are Kubernetes
  deployment state. Remove them only after the corresponding old data-plane
  revision has drained; they do not introduce a native or database schema
  epoch.

### Upgrade validation

- Validate the exact candidate revision with fresh Rust, TypeScript,
  configuration/schema, rootless image, Helm, Gateway-controller, and
  Kubernetes `1.34`-`1.37` evidence. Qualify raw UDP and TURN edge/proxy UDP,
  TCP, TLS, IPv4, IPv6 relay, and RFC 6062 behavior with OxiBelt probes and
  the pinned coturn client, and run relay-only Chromium and Firefox data-channel
  coverage. Keep CT disabled until its separate production-support evidence is
  complete.
- Before preparing the stable draft during the beta.2 soak, require terminal
  beta.2 exact-revision qualification and exact stable-source CI, including the
  release-contract, ancestry, documentation-only-delta, source, configuration,
  schema, Helm, Gateway-controller, and Kubernetes checks. Stable artifact
  production and its receipts are not draft prerequisites. The beta.2 24-hour
  eligibility interval and person review gate stable publication; the stable
  release's own 30-image and two-chart qualification is the later mutable-alias
  gate.
- Validate the exact stable source and both compatibility ranges with full
  immutable revisions:

```sh
stable_revision="$(git rev-parse HEAD)"
beta_2_revision="cc33b2a08d988bd3f3ad65c60a0c9a0961968627"
stable_base_revision="b1ca5aab407e8398792a2b11c8436b6ff78ed193"
git merge-base --is-ancestor "${stable_base_revision}" "${stable_revision}"
git merge-base --is-ancestor "${beta_2_revision}" "${stable_revision}"
pnpm run release-contract:check
pnpm run release-contract:check --change-base "${beta_2_revision}" --change-head "${stable_revision}"
pnpm run release-contract:check --change-base "${stable_base_revision}" --change-head "${stable_revision}"
oxibeltctl config validate /etc/oxibelt/oxibelt.toml --local-only
```

### Rollback and irreversible steps

- Rolling back `0.9.1` to the same-source `0.9.1-beta.2` requires no field
  removal or state conversion. Drain affected long-lived connections as needed,
  then restore the retained beta.2 controller and data-plane images together by
  immutable digest; keep their matching configuration and release records.
- Rolling back to `0.9.0` requires removing every beta.2-only
  `[routes.bandwidth]`, `tls.client_identity`, and
  `actions.direct_response` field, new TURN TLS/auth/limit or file-secret
  field, generated Helm `turn` value, Secret projection, and Gateway
  `clientCertificateRef` that the older binary cannot consume. Drain TURN
  allocations and RFC 6062 data connections as well as other long-lived
  connections, then restore the retained `0.9.0` controller and data-plane
  images together by immutable digest. Remove projected or controller-derived
  Secrets only after no active or retained rollout references them.
- No durable state conversion is required. Drain ephemeral TURN allocations and
  RFC 6062 data connections before rollback, and revoke a compromised old
  client identity at the upstream.

### Known issues

- Stable publication, stable artifact qualification, and mutable-alias
  promotion remain separate pending steps. The beta.2 qualification interval
  and person review must precede publication; stable then requires its own
  exact-version artifacts and qualification before mutable aliases move.
- Native Certificate Transparency remains disabled by default,
  experimental, and unvalidated. Versioning and release qualification do not
  constitute CT production support; the experimental chart is not part of the
  official release chart inventory.
- Route bandwidth is process-local, so replicas enforce independent budgets.
  Ambiguous Gateway translation errors and TLSRoute failures deliberately keep
  the last good revision; operators must resolve the reported condition rather
  than treating status rejection alone as proof that an old TLS route stopped
  serving.
- Registry inspection failures and descriptor-malformation faults can still
  prevent qualification after bounded retries. Valid inventory mismatches
  remain fail-closed by design, and no failed or partial beta.2 evidence is
  reusable for stable publication.

### Security

- Keep qualification sealing fail closed: descriptor inspection failures and
  malformed responses may retry only within the bounded budget, while valid
  digest and child-manifest mismatches fail immediately with actionable exact-
  inventory diagnostics. Retain approved registries, lockfile checksums,
  cargo-vet evidence, vulnerability policy, SBOM, provenance, and attestation
  gates for every exact image subject.
- Reject Brotli Large Window, incomplete, trailing, and no-progress encodings;
  enforce segment-boundary route-prefix matching; require an exclusively
  `websocket` Upgrade offer and response; and preserve `413 Payload Too Large`
  classification through shaped HTTP/2 and HTTP/3 request bodies.
- Validate upstream client certificate chains and matching keys before
  activation, keep upstream server authentication mandatory, disable
  client-auth resumption, redact private-key paths from every supported HTTP
  and TURN upstream shape, and restrict Gateway Secret reads to exact
  operator-allowlisted names with any required cross-namespace `ReferenceGrant`.
- Require direct HTTPS Kubernetes doctor transport with trusted CA data and
  bounded static credentials; reject proxy, cleartext, insecure TLS, `exec`,
  and `auth-provider` modes before client construction.
- Bind TURN nonces to the observed client tuple, realm, and advertised password
  algorithms; reject ambiguous or unknown required attributes; integrity-sign
  authenticated responses; confine and redact secret sources; bound proxy UDP
  sessions and pending TCP connections; require permissions before peer-to-
  client relay; and deny private and special-use relay peers by default.
- Publish fail-closed Gateway replacements only when translation proves the
  exact affected scope: HTTP/gRPC route withdrawal publishes match-equivalent
  `503` tombstones, and safe L4 failures remove the exact listener. Partial
  backend pools, orphaned authentication or policy artifacts, unrelated
  listener removal, and diagnostic-code-only safety decisions are forbidden;
  ambiguous or mixed failures preserve the last good revision.

## [0.9.0] - 2026-08-27

> Stable carry-forward of the person-reviewed `0.9.0-beta.1` source in exactly
> one documentation-only commit. Certificate Transparency remains disabled by
> default, experimental, and unvalidated; stable versioning, the one-time
> predecessor-gate waiver, and release publication do not grant CT production
> support.

- Changes since: `0.8.1`
- Supported upgrade sources: `0.8.1`, `0.9.0-beta.1`
- Upgrade guide: [Upgrade from 0.8.1 to the 0.9.0 line](docs/Upgrading.md#upgrade-from-081-to-the-090-line)

### Configuration

- Add optional `[tls.ct]` downstream embedded-SCT verification. `audit` reports
  Chrome/Firefox-style policy results and `enforce` fails closed for activation
  and new handshakes; the default remains `disabled`. Managed mode authenticates
  and persistently caches the official Chromium v3 Log list, while static mode
  accepts a signed offline list.
- Add optional `[certificate_transparency]` configuration. It is disabled by
  default and requires explicit protocol, log identity, signer, accepted-root
  bundle, storage, shard, and limit configuration before a `ct_log` route can
  serve CT traffic. Activating or changing CT requires a full reload.
- Limit each writable process to one CT log and keep operator, gateway, signer,
  and independent-monitor responsibilities separated. A CT route passes normal
  route admission but bypasses upstream proxying, static serving, cache, WAF,
  retry, and response rewriting.
- Preserve route-action path-template syntax and validation while accelerating
  the internal delimiter scan. Literal `?` and `#` remain rejected for rewrite
  and redirect paths; keys, defaults, schema epoch, accepted and rejected
  configurations, reload class, and rollback behavior remain unchanged.
- Preserve WAF keys and defaults while forcing policy-authored advanced-regex
  match-time subject, backtrack, and matcher stack failures closed for request,
  response, and stream phases, including when `waf.fail_policy = "open"`.
  Unrelated evaluation failures retain the configured fail policy.

### Schema epochs

- Keep the native configuration schema at epoch `1` while adding optional CT
  fields. A `0.8.1` epoch-1 configuration with CT disabled needs no native
  migration and retains its existing behavior.
- Introduce CT PostgreSQL schema version `3`. Production CT operators must run
  the explicit migration while CT traffic is stopped; OxiBelt never performs a
  live production CT migration. A `0.8.1` binary does not understand the CT
  configuration fields or CT schema.

### Deprecations and removals

- No changes for this release.

### Admin API

- Extend authenticated downstream TLS status and support bundles with bounded
  CT policy, Log-list freshness, and per-certificate count/error state. Add
  fixed-cardinality aggregate CT metrics without exposing SNI, certificate
  identities, SCTs, Log IDs, operators, URLs, or paths.

### Feature lifecycle

- Keep native Certificate Transparency and the `oxibelt-ct` Helm chart
  `experimental` and `unvalidated`. They are not production-supported until
  the exact candidate passes interoperability, failure, fencing, and
  resource-based load gates and an independent monitor observes seven
  continuous days without rollback, fork, invalid proof, or stale STH.
- Require `0.9.0-beta.1` publication before `0.9.0` publication. For this exact
  transition only, stable publication may waive the beta's independent
  qualification and 24-hour eligibility interval. Stable still requires every
  normal exact artifact and release gate and its own automatic 30-image and
  two-chart qualification before mutable aliases move. No other transition
  inherits this waiver.

### Rulepack compatibility

- Change no OxiRule syntax, CRS compatibility, rulepack schema, or successful
  matching semantics. Advanced-regex match-time resource failures use the
  phase's fail-closed decision instead of fail-open. CT endpoints remain
  outside WAF inspection and deliberately bypass proxy, static, cache, WAF,
  retry, and response-rewrite behavior after route admission.
- Accelerate percent-marker, normalization, malicious-input, and compiled
  literal searches without changing OxiRule or CRS syntax, normalization
  results, match precedence, request classification, or enforcement behavior.

### Executables and images

- Add `oxibeltctl ct` commands for accepted-root bundles, shard planning,
  independent monitoring, explicit PostgreSQL migration, and storage checks.
  Extend `oxibelt-keysigner` with a purpose-exclusive CT log key and immutable
  signing profile.
- Preserve the six official image roles and two official release Helm charts.
  Register `deploy/helm/oxibelt-ct/Chart.yaml` only in the development version
  inventory; the experimental CT chart is not packaged, published, rebuilt,
  qualified, or promoted by the official release chart contract.

### Storage and state

- Add crash-consistent local CT schema version `1` for development and
  interoperability use only. Production CT uses PostgreSQL schema version `3`
  for sequencing plus HTTPS S3-compatible versioned object storage with object
  lock, retention, checksum readback, and an operator-supplied deletion-denial
  attestation.
- Require a stopped-traffic PostgreSQL migration and fresh storage checks
  before production activation. There is no automatic live migration or
  down-migration for CT state.

### Upgrade validation

- Validate the target binary, migrate and probe production CT storage before
  enabling routes, and render the experimental chart under person review:

```sh
oxibeltctl config validate /etc/oxibelt/oxibelt.toml --local-only
oxibeltctl ct postgres migrate --database-url-env OXIBELT_CT_DATABASE_URL
oxibeltctl ct postgres storage-check --database-url-env OXIBELT_CT_DATABASE_URL
helm lint --strict deploy/helm/oxibelt-ct
helm template oxibelt-ct deploy/helm/oxibelt-ct \
  --values deploy/helm/oxibelt-ct/values-production.yaml
```

- Keep CT disabled until the accepted-root digest and signature quorum, log
  identity, signer profile, shard interval, route limits, PostgreSQL backup,
  object-lock retention, deletion denial, and independent monitor witness have
  been reviewed against the exact candidate.

### Rollback and irreversible steps

- To return to `0.8.1`, stop new submissions, drain every CT operator and
  gateway, remove `ct_log` and `ct_surface` routes and the CT configuration,
  then validate and restore the `0.8.1` binary and configuration together.
  Preserve PostgreSQL and object-store snapshots, root bundles, log keys, and
  monitor witnesses until rollback is verified.
- Published CT checkpoints, signed tree heads, receipts, and retained or
  object-locked versions are externally visible or immutable and cannot be
  retracted by rolling back OxiBelt. Do not delete or reuse a log identity to
  conceal a failed cut.

### Known issues

- Production CT support remains unqualified until exact-candidate
  interoperability, outage, failover, fencing, load, and seven-day independent
  monitor requirements complete.
- CT remains disabled by default and experimental/unvalidated. Beta or stable
  publication, the one-time predecessor waiver, and stable artifact
  qualification do not constitute CT production support.
- The experimental chart keeps its Service disabled and cannot install a safe
  readiness probe because `log.config` is opaque. Enabling the Service needs an
  explicit no-readiness acknowledgement and does not make the deployment
  production-supported.
- OxiBelt does not inject SCTs into downstream TLS certificates and does not
  provide an ACME service.

### Security

- Keep CT private keys in a purpose-bound `oxibelt-keysigner` process that
  accepts exactly one CT key and immutable profile. Mount signer, operator,
  gateway, storage, and accepted-root secrets only into their owning roles.
- Verify every remote CT signer response against the configured signer key and
  exact transcript before accepting, persisting, publishing, or returning CT
  output; malformed or cryptographically invalid responses fail closed.
- Pin accepted roots by exact SHA-256 bundle digest and require at least two
  independent Ed25519 signatures in production. Require HTTPS object storage,
  object lock and retention, deletion-denial policy, replica fencing, and
  independent monitor evidence.
- Anonymous CT submission remains supported; apply bounded request bodies,
  route rate limits, timeouts, and worker admission before CT dispatch.

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
