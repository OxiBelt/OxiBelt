# OxiBelt Product Threat Model

Status: Living product security contract  
Applies to: The source tree or release that contains this document

## Overview

OxiBelt is a Linux-first reverse proxy and Web Application Firewall intended to
sit between untrusted clients and protected upstream services. The primary
runtime accepts HTTP/1.1, HTTP/2, HTTP/3 over QUIC, WebSocket, WebTransport,
raw TCP/UDP streams, and WebRTC TURN traffic. It can terminate TLS, route or
forward traffic, apply OxiRule and CRS-compatible WAF policy, cache responses,
enforce admission controls, and use Redis-compatible or PostgreSQL shared
state. The repository also ships an Admin API, a Kubernetes Gateway
Controller, Helm charts, release workflows, and official container images.

This document is the repository-wide security model for those product and
deployment surfaces. Exact behavior and configuration syntax remain in the
[technical specification](Specification.md),
[configuration reference](Configuration.md), [Admin API reference](AdminAPI.md),
[Admin OpenAPI document](../source/assets/admin-openapi.json), and
[Gateway API reference](GatewayAPI.md). The
[feature lifecycle matrix](FeatureStatus.md) is authoritative for whether a
feature is supported, experimental, reserved, or removed. The
[security policy](../SECURITY.md) remains authoritative for supported releases,
private reporting, disclosure, and official artifact scope.

The model is versioned by the Git tree or release that contains it. A commit or
container-image digest identifies the exact version under review; this living
document does not embed a commit that would become stale on its next update.

### Security assets and objectives

| Asset | Security objective |
| --- | --- |
| Downstream requests and upstream responses | Preserve message boundaries, authority, routing identity, policy decisions, and confidentiality while proxying. |
| Upstream services | Prevent untrusted clients from bypassing intended routing, WAF, identity, rate, cache, and transport policy. |
| TLS and QUIC state | Protect private keys, remote-signing authority, trust roots, resumption state, and QUIC Retry/token keys from disclosure or unauthorized use. |
| Configuration and policy | Activate only validated TOML, certificates, routes, OxiRule/CRS policy, dynamic policy, and immutable Kubernetes revisions. |
| Administrative authority | Authenticate and authorize every Admin request, constrain mutation scope, reject stale writes where supported, and create an attributable audit record. |
| Admin operation journal and receipts | Preserve authenticated operation identity, monotonic state, exclusive worker ownership, bounded encrypted artifacts, terminal evidence, and retention across restart without turning an ambiguous side effect into success. |
| Shared state | Preserve the integrity, confidentiality, atomicity, expiry, and namespace separation of distributed decisions and durable control-plane records. |
| Availability | Bound connections, streams, requests, bodies, queues, retries, cache fills, WAF work, and backend waiters so one workload cannot exhaust the edge. |
| Release artifacts | Bind official images to reviewed source and prevent stale or malicious artifacts from being silently deployed. |

Security defects should be reported through the private channel in
[`SECURITY.md`](../SECURITY.md). This model describes vulnerability classes and
severity context; it does not disclose or assert a finding in any current diff.

## Threat Model, Trust Boundaries, and Assumptions

### Actors and input ownership

| Actor or component | Inputs it controls | Trust posture |
| --- | --- | --- |
| Untrusted Internet client | TCP/UDP timing, TLS ClientHello and SNI, QUIC packets, HTTP framing, authority, headers, paths, bodies, trailers, WebSocket/WebTransport data, TURN messages, and public cache-purge requests | Fully attacker-controlled. No client-supplied identity, forwarding metadata, priority label, or parser interpretation is trusted without explicit verification. |
| Upstream service or discovery source | Response framing, headers, bodies, cache metadata, redirects, health results, and discovered endpoints | Operator-selected but potentially compromised. Responses remain untrusted protocol and cache input. |
| Admin client | Bearer credential, optional client certificate, requested action/resource, precondition headers, and mutation payload | Authenticated does not imply authorized. Compromised, replayed, or over-privileged credentials are credible threats. |
| Operator | TOML, Helm values, certificates, secrets, rulepacks, trust roots, backend endpoints, listener exposure, and failure policies | Trusted to define deployment intent, but mistakes or compromised automation can defeat product controls. Validation reduces but cannot remove this trust. |
| Redis or PostgreSQL service | Shared values, expiry, transaction results, policy rows, audit rows, and availability | A trusted security dependency once authenticated. TLS and ACLs protect access and transit, not malicious authenticated responses or a compromised server. |
| Gateway Controller and Kubernetes control plane | Gateway objects, desired TOML, ConfigMaps, workload patches, Pod identity, readiness, RBAC, Secrets, and admission decisions | Privileged deployment boundary. Namespace ownership, API authorization, and admission policy are external assumptions. |
| Developer and build system | Source, dependencies, workflow definitions, build inputs, image manifests, tags, and registry writes | Trusted supply-chain boundary. A compromised maintainer, dependency, runner, action, or release credential can affect official artifacts. |
| External integration | Person proof frontend/provider, external auth, external cache handler, discovery service, OCSP/CRLite source, telemetry collector, or signer sidecar | Operator-selected and independently compromisable. Each receives only the data and authority required by its documented protocol. |

### Required trust-boundary flows

```text
Untrusted Internet Client
    -> Public Listener
    -> Protocol Parsing
    -> Routing / WAF / Identity
    -> Upstream Services

Management Network
    -> Admin Listener
    -> Configuration and Secret Mutation

OxiBelt Instances
    <-> Redis or PostgreSQL Shared State

Gateway Controller
    -> Desired Configuration
    -> Data-Plane Rollout

Build System
    -> Standalone / Data-Plane / Controller / Tools / Keysigner Images
    -> Container Registry (exact role repositories)
    -> GitHub Attestations API (provenance and SBOM bundles)
    -> Kubernetes Admission
```

Additional local boundaries are the OxiBelt process to
`oxibelt-keysigner` Unix socket, the unprivileged process to the
`oxibelt-netport-switcher` bind broker, and OxiBelt to mounted configuration,
certificate, OxiRule, cache, and runtime-state directories.

The standalone and minimal data-plane artifacts use the same `oxibelt`
runtime binary, including co-located Admin and Person Proof. The minimal image
removes operator, Kubernetes, and helper executables; it is not a reduced
security-feature variant. Controller, tools, and keysigner images have exact
single-binary inventories. Release validation, role labels, and executable
inventory checks make some cross-role packaging mistakes observable. Release
CI also creates and verifies GitHub API-hosted keyless SLSA provenance and
CycloneDX SBOM attestations for each canonical platform and index digest before
promotion. The bundles authenticate the workflow identity and bind its
statements to an immutable subject; they are not GHCR OCI referrers, proof of
review or reproducibility, or a freshness, rollback, or vulnerability policy.
Operators must verify, approve, select, and record the intended immutable
repository digest.

### Listener and entry-point inventory

| Surface | Trust model and required controls |
| --- | --- |
| Public HTTP data plane | `listeners.http_binds` accepts optional plaintext HTTP over TCP. `listeners.https_binds` accepts TLS HTTP/1.1 and HTTP/2 over TCP and, when enabled, HTTP/3 over UDP. WebSocket, CONNECT, and WebTransport extend connection lifetime and state. All protocol input is hostile; strict framing, authority, header, body, timeout, connection, stream, and admission limits are required. Legacy signed cache-purge requests also arrive on a public listener and require their separate signature, timestamp, nonce, route, and cache-policy checks. |
| SNI forwarding and raw stream proxy | `[sni_forward]` classifies visible TCP TLS or QUIC SNI before local HTTP termination. `[[stream_listeners]]` accepts raw TCP or UDP and may only perform bounded SNI classification. Forwarded payloads do not pass through the HTTP router or HTTP WAF; operators must trust and protect the selected upstream protocol separately. Missing or malformed SNI follows the configured default or fails closed when no default exists. |
| WebRTC TURN | `[[webrtc_turn_listeners]]` can expose UDP, TCP, TLS, and dynamic relay UDP ports. TURN authentication, allocation, permission, channel, peer-address, lifetime, queue, and rate limits form the boundary. TURN media payload is protocol-forwarded and is not OxiRule/CRS-inspected; application signaling and media authorization remain external responsibilities. |
| Admin API | The dedicated TCP listener supports HTTP/1 and optional TLS; opt-in Admin HTTP/3 adds UDP and WebTransport event subscriptions. By default, every request requires bearer authentication. Opt-in `[admin.workload_identity]` binds a verified required-mTLS certificate SAN/SPIFFE identity to exactly one IPM principal and requires any supplied bearer or break-glass credential to resolve to that same principal; optional bearer mode permits the mapped certificate alone. Production exposure requires a private management path, TLS 1.3, required client certificates, IPM default-deny authorization, bounded requests/operations, and enforcing durable audit. |
| Metrics | The Prometheus listener is plaintext and has no application authentication. It is disabled and loopback-bound by default. Only bounded aggregate/detail labels belong here. The Helm NetworkPolicy baseline can restrict its named port to explicit monitoring peers, but enforcement depends on the cluster CNI and correctly maintained namespace/Pod labels. Rule-level WAF data remains on authenticated Admin endpoints. |
| Health | Readiness and liveness are plaintext, unauthenticated operational endpoints, disabled and loopback-bound by default. They reveal bounded process state and must be reachable only by trusted local or orchestration probes. Health capacity is separate from public request capacity. |
| Gateway Controller health | `--health-bind` exposes plaintext `/healthz` and `/readyz`; the Helm chart binds it on the Pod network for probes. It has no application authentication and must not be published as a public service. It reports only bounded reconciliation readiness. |
| Local privileged IPC | The remote signer and netport switcher listen on Unix sockets rather than network ports. Filesystem permissions, distinct UIDs/GIDs, peer allowlists, unguessable rotating tokens, request bounds, and capability minimization are mandatory because compromise grants signing or privileged-bind authority. |

### Mandatory deployment assumptions

- The deployment uses a supported source tree or release and evaluates the
  lifecycle status shipped with that version. Experimental behavior is not a
  stable production guarantee.
- Operators validate configuration before activation, keep strict unknown-field
  handling where practical, and review every explicit fail-open or insecure
  compatibility override.
- Internet-facing deployments configure explicit SNI names, suitable TLS
  versions and certificates, a stable protected QUIC host key, trusted proxy
  CIDRs, finite protocol/body limits, and bounded overload/circuit-breaker
  controls. The `edge-secure-medium` profile provides a baseline but does not
  create external infrastructure or credentials.
- Admin is isolated from public traffic. A production Admin listener uses a
  dedicated management bind, TLS 1.3, required client certificates, bearer/IPM
  authorization, least-privilege policies, credential rotation, and enforcing
  PostgreSQL audit storage.
- Metrics, health, controller health, Redis, PostgreSQL, signer IPC, and
  telemetry endpoints are restricted with host, namespace, firewall, or
  NetworkPolicy controls appropriate to their trust boundary.
- When the Helm NetworkPolicy baseline is enabled, the cluster runs a CNI that
  enforces it and operators declare every intended DNS, upstream, shared-state,
  revocation, Kubernetes API, and external-dependency path before rollout.
- Mutually distrustful tenants use separate OxiBelt instances, credentials,
  configuration roots, state namespaces/backends, cache storage, and management
  authority. Route names, host matching, cache partition keys, and shared-state
  namespaces are logical policy mechanisms, not a process or database sandbox.
- Clustered configuration uses the documented immutable rollout model or an
  equivalently verified external control plane. A successful request to one
  instance or a load-balanced Admin Service does not prove cluster convergence.
- Host root, container runtime, Kubernetes API, DNS, upstreams, external
  providers, and build/release identities are protected outside OxiBelt. A
  compromise of those authorities can exceed the protections in this model.
- Official images are selected from the exact documented repositories by an
  operator-approved immutable digest. GitHub API-hosted provenance and SBOM
  attestations are verified against the exact signer workflow, signer/source
  revision, source ref, subject digest, predicate, and trusted timestamp. The
  registry, release workflow, protected refs, GitHub Actions identity, and
  approval process remain external trusted authorities. Registry freshness,
  rollback prevention, code review, reproducibility, and vulnerability policy
  remain operator controls.

### Conditional guarantees

When the mandatory assumptions and documented supported configuration hold,
OxiBelt is designed to preserve these invariants:

- Ambiguous HTTP framing, forbidden hop-by-hop forwarding, invalid authority,
  unsafe path/file traversal, invalid configuration, and unsupported WAF/CRS
  syntax are rejected at their enforcement boundary rather than silently
  reinterpreted.
- Client-supplied forwarding and priority metadata does not become trusted
  identity or reserved capacity without configured trusted-proxy, IPM, or
  verified client-certificate authority.
- Connection, stream, request, body, decompression, WAF, queue, retry, cache,
  shared-state, Admin operation, and telemetry work has configurable or fixed
  bounds; security-sensitive exhaustion returns a safe error or closes the
  affected flow.
- Invalid hot reloads preserve the active validated snapshot. Kubernetes
  immutable rollout readiness requires the assigned revision and raw content
  digest, and the controller commits only after all owned Ready Pods converge.
- Every Admin request is authenticated, IPM uses explicit-deny then allow with
  default deny when enabled, and protected mutations attempt a structured audit
  record. Enforcing durable audit reserves capacity before handler execution.
- When required Admin mutation protection is configured, a valid signer bound
  to the authenticated principal, an unexpired exact-body digest, the current
  logical revision, PostgreSQL replay admission, and enforcing durable audit
  are all required before a high-risk side effect. Exact request-ID replays do
  not apply the side effect twice.
- Shared-state mutations that require atomicity use one Redis script or one
  PostgreSQL transaction, are deadline-bounded, and are not retried after an
  ambiguous transport result.
- Secret-bearing configuration is redacted from supported effective-config,
  status, metrics, and support-bundle surfaces as documented.

These are design and configuration invariants, not a claim that the
implementation is vulnerability-free or that every deployment enables the
strongest available policy.

### Explicit non-guarantees

- OxiBelt does not guarantee protection from volumetric DDoS that exhausts
  network, host, kernel, cloud, or upstream capacity before process admission
  controls can act.
- WAF and parser controls do not guarantee detection of every malicious payload
  or semantic equivalence with every upstream framework. Raw stream/TURN media
  payloads are outside HTTP WAF inspection, and reserved stream-CRS behavior is
  not implemented.
- Person proof is an anti-automation control, not authentication, identity
  proof, proof of legal personhood, or proof of benign intent.
- OxiBelt does not provide a hard multi-tenant sandbox inside one process,
  configuration, cache, or shared backend.
- Failure policies describe backend unavailability or error handling; they do
  not make data from a compromised authenticated Redis/PostgreSQL service safe.
- Mutation replay protection is limited to the documented protected Admin
  families and only applies when `[admin.mutations]` is enabled. Other Admin
  writes, local process signals, externally managed Kubernetes changes, and
  direct changes by a compromised PostgreSQL authority do not inherit this
  guarantee.
- Fixed-member `admin_cluster` is not a Byzantine consensus system and does not
  remain writable through member loss. It trusts PostgreSQL, every configured
  host, the shared artifact key, and the configured signer/IPM authorities.
  Loss or incompatibility of one required member intentionally denies protected
  writes; membership changes require a quiesced offline rollout.
- Best-effort audit/export does not guarantee durable, queryable, ordered, or
  acknowledged audit-of-record delivery.
- OxiBelt does not issue or renew certificates, rotate external secrets,
  operate Redis/PostgreSQL, or protect a compromised host,
  cluster administrator, registry, upstream, frontend, or provider.
- Release workflows publish role-specific platform images and
  multi-architecture indexes with GitHub API-hosted keyless SLSA provenance and
  CycloneDX SBOM attestations. Platform SBOMs carry detailed inventory; index
  SBOMs identify the three canonical child digests and point to separate
  platform evidence. The bundles are not GHCR OCI referrers, and OxiBelt does
  not ship an admission policy for them. Historical registry referrers do not
  imply current API evidence coverage, and an existing fail-closed admission
  policy must be deliberately evaluated rather than weakened to unblock an
  image.
- Experimental features may be disabled, removed, or incompatibly changed and
  have no compatibility or backport guarantee beyond `SECURITY.md`.

### Failure semantics

Shared-state failure policy applies after a backend snapshot activates. Startup,
authentication, TLS, schema initialization, or required prewarm failure keeps a
replacement snapshot from activating. A malicious backend is a compromise, not
a normal failure-mode transition.

| Feature | Default mode | Security behavior after backend failure |
| --- | --- | --- |
| `rate_limits` | `fail_closed` | Rejects when a distributed token decision cannot be made. Configured local fallback is bounded but process-local; fail open explicitly admits without the distributed decision. |
| `connection_limits` | `reject_new_only` | Preserves existing leases but rejects new distributed leases. A configured local fallback has no cluster-wide count. |
| `person_proof` | `fail_closed` | Replay prevention, clearance revocation, and the Person proof Admin mutation reject; weaker modes are invalid. |
| `upstream_health` | `stale_snapshot` | Uses only the last published non-mutating health/active-count observation until the backend recovers. |
| `sticky_sessions` | `local_fallback` | Retains process-local sticky state. Cross-instance affinity is not guaranteed while degraded. |
| `cache` | `local_fallback` | Treats shared-cache failure as a local miss and continues through local/origin handling. Administrative shared purge fails rather than claiming partial success. |
| `reload` | `fail_open` | Logs/observes the failed cross-instance heartbeat while the already-active local configuration continues. It does not prove cluster convergence. |
| Dynamic policy | `use_last_good` by default | Keeps the last verified snapshot; configured startup or disable-on-error behavior remains authoritative. |
| IPM | Startup policy plus last-good refresh | Startup follows `ipm.fail_closed`; later backend refresh failure retains the last good dynamic snapshot or configured static policy behavior. |
| Admin audit | `best_effort`, `durable_required`, or `durable_required_for_actions` | Best effort records delivery failure but permits work. Durable modes reject required Admin work unless the selected synchronous PostgreSQL or bounded fsynced-spool acknowledgement completes. Legacy `enforcing` aliases `durable_required`. |
| Admin mutation ledger | `fail_closed` | Rejects a new protected mutation when PostgreSQL replay admission, critical audit, or the selected rollout authority cannot be proved. `admin_cluster` additionally requires exact live membership and current fenced authority; NACK, timeout, readiness loss, or mismatch enters rollback. An indeterminate prior request remains blocked until reconciled. |
| Admin operation journal | `fail_closed` in `postgres`; visible bounded fallback in `auto` | Explicit PostgreSQL mode rejects startup or journal-dependent API work when schema, audit, artifact key, or backend authority is unavailable. Automatic mode may retain explicitly reported ephemeral operation status. An expired lease permits one fenced recovery owner; an ambiguous non-resumable operation becomes `indeterminate`. |

`local_fallback` is bounded, observable, and limited to one process. It never
provides a cluster-wide security decision. `fail_open` must be treated as an
explicit availability-over-enforcement choice.

### Externally protected secrets

| Secret or authority | External protection requirement |
| --- | --- |
| TLS private keys, certificate trust roots, session/ticket state, QUIC host key | Restrictive mounts and ownership, rotation/revocation, stable Secret delivery, and separation by certificate/SNI boundary. Prefer the remote signer when private-key isolation is required. |
| Remote-signer token and socket authority | Separate signer UID/GID, restrictive socket directory/mode, peer allowlist, bounded IPC, atomic token rotation, and no private-key mount in the OxiBelt process. |
| Admin bearer, IPM, break-glass, and workload certificate identity | Secret manager or protected environment/file delivery, least privilege, short exposure, rotation/revocation, no logs or TOML literals, and management-network isolation. Default Admin authentication uses bearer/IPM; optional workload binding verifies mTLS SAN/SPIFFE identity and requires a principal match before using bearer or break-glass credentials. |
| Cache-purge, dynamic-policy, Person proof, and provider signing/shared secrets | Independent random keys, protected environment/file delivery, rotation compatible with replay/expiry windows, and isolation between environments or tenants. |
| Redis/PostgreSQL passwords, ACL users, client keys, URLs, and CA roots | Verified TLS for remote services, least-privilege database identities, protected projected files/environment, network isolation, backups, monitoring, and rotation. |
| External-auth, external cache, telemetry, discovery, and third-party-provider credentials | Restrict endpoint egress and data disclosure, validate TLS, bound requests/responses, and rotate credentials in the owning service. |
| Kubernetes ServiceAccount, registry, CI, release, and admission authority | Data-plane Pods receive no ServiceAccount token by default. API-using workloads use explicit short-lived projected tokens, least-privilege namespace-scoped RBAC where possible, protected runners and environments, immutable image selection, branch/tag protection, and independent admission policy. |
| ACME account keys, DNS provider tokens, and renewal state | Keep outside the OxiBelt process/container. OxiBelt consumes provisioned certificate material but does not manage issuance or renewal. |

### Experimental features

The following list is synchronized with rows marked `experimental` in the
[feature lifecycle matrix](FeatureStatus.md). Experimental features are valid
security research scope, but must not be presented as stable production
guarantees.

| Feature ID | Security consequence |
| --- | --- |
| `crlite` | Revocation filter coverage, managed downloads, cache integrity, and degraded-allow behavior require deployment-specific review. |
| `tls-upstream-revocation` | Outbound OCSP/CRLite reachability, freshness, and failure policy can affect upstream availability and trust. |
| `root-netport-switcher` | The privileged bind broker expands the local capability and Unix-socket boundary. |
| `client-identity-asn` | Operator-supplied or managed ASN data is a fallible classifier, not authenticated client identity. |
| `sybil-rate-limit-identities` | Composite and hashed classifiers can reduce abuse but do not prove one human or one device. |
| `gateway-controller` | A UID-and-epoch-fenced Lease limits normal operation to one writer, but Kubernetes API integrity, RBAC, admission, and timely Lease observations remain external trust boundaries. |
| `gateway-api-httproute` | Translation supports a bounded subset and rejects unsupported matching/filter behavior. |
| `gateway-api-grpcroute` | Translation supports only the documented bounded gRPC route subset. |
| `gateway-api-tlsroute` | Passthrough translation relies on visible SNI and does not terminate or WAF-inspect the tunneled protocol. |
| `helm-data-plane` | Chart output depends on operator values and cluster controls and is not a complete security deployment attestation. |
| `helm-gateway-controller` | The controller has a deliberately projected API token, exact-name Lease RBAC, and narrowly scoped default namespace authority, but its Gateway/rollout permissions and any explicit cluster-wide watch choice still require namespace and cluster-policy review. Lease deletion denies writes until Helm recreates the exact object. |

## Attack Surface, Mitigations, and Attacker Stories

The tables below use existing controls as evidence, not as proof that a threat
is impossible. Exact configuration and wire behavior remain in the linked
canonical references.

### Public protocol, routing, WAF, and cache threats

| Threat | Boundary and asset | Existing controls | Attacker story and residual risk |
| --- | --- | --- | --- |
| HTTP request smuggling | Client → parser → upstream; request boundaries and authorization context | Conflicting `Content-Length`, `Transfer-Encoding` ambiguity, hop-by-hop tokens, later trailers, and unsafe forwarding are rejected or sanitized before upstream dispatch. | A client searches for a downstream/upstream parser differential that causes one byte stream to be split into different requests. Any reachable differential crossing route, identity, cache, or upstream connection reuse is high impact. |
| Header ambiguity | Client/upstream headers → routing, WAF, cache, or peer parser | Header count/size limits, duplicate/framing checks, connection-token removal, reserved-header mutation rejection, and trailer validation constrain interpretation. | Duplicate or syntactically unusual fields may still expose library/protocol differences. Security-sensitive headers require end-to-end tests whenever handling changes. |
| H2 and H3 stream abuse | Client → multiplexed connection state and admission capacity | Per-connection/per-stream limits, bounded requests, overload state, circuit breakers, timeouts, drain signaling, and dedicated control-plane capacity limit work. | A client can create/reset/stall many streams or QUIC state. Process bounds do not stop upstream bandwidth or host/kernel exhaustion before admission. |
| Decompression bombs | Encoded body → body transform/WAF memory and CPU | Supported encodings are explicit; encoded/decoded byte caps, expansion ratio, decode timeout, concurrency, and inspection-prefix limits bound work. | Novel codec behavior, repeated requests within allowed bounds, or operator-expanded limits can still create CPU pressure. Unsupported or multiple codings fail closed on transform routes. |
| WAF bypass and parser mismatch | Client bytes → HTTP parser → OxiRule/CRS view → upstream framework | WAF uses normalized request context, bounded body prefixes and transforms, fail-closed compilation, cost/regex limits, and explicit monitor/enforce modes. | OxiBelt does not guarantee semantic parity with every backend. Truncated inspection, monitor mode, raw tunnels, unsupported CRS stream payloads, or upstream normalization can leave bypass opportunities. |
| Cache poisoning | Client/upstream metadata → shared cached representation | Keys include scheme/host by default, credential requests bypass by default, `Vary` is bounded, origin cache-status headers are stripped, partial fills are not committed, and purge is authorized. | Unsafe custom keys, omitted variation dimensions, hostile upstream cache metadata, or a compromised external/shared cache can serve content across users or hosts. Operators must treat partition design as security policy. |
| Host and SNI confusion | TLS SNI/certificate policy → HTTP authority/route/upstream | Strict SNI options, certificate partitioning, normalized host routing, route-TLS policy checks, and `421` rejection constrain cross-host reuse. | Permissive fallback certificates, wildcard routes, proxy absolute-form targets, or inconsistent upstream authority can cross a virtual-host boundary. Strict public SNI and cache host keys are mandatory. |
| Forwarded-header spoofing | Direct peer/client headers → resolved client identity and upstream metadata | Trusted proxy CIDRs gate PROXY/Real-IP input; untrusted `Forwarded` and `X-Forwarded-*` values are removed or overwritten under secure policy. | An overly broad trusted CIDR or alternate unnormalized identity header can let a client impersonate a source, bypass a limit, or poison audit data. Trust configuration is operator-owned. |

### Cryptographic and transport-key threats

| Threat | Boundary and asset | Existing controls | Attacker story and residual risk |
| --- | --- | --- | --- |
| TLS key compromise | Files/remote signer → TLS termination authority | Restrictive file roots, optional remote signer, signer public-key match, token authentication, peer UID/GID controls, bounded IPC, and reload validation reduce exposure. | A stolen local key enables impersonation until revocation. A compromised process with live signer access may request signatures even without reading the key, so isolation and rotation remain external duties. |
| QUIC token-key instability | QUIC host key → Retry/token validation and restart behavior | Public secure profiles require an explicit stable 64-byte host key and reject generated restart-local material. | Ephemeral or shared-across-boundary key handling can invalidate tokens, weaken operational continuity, or expand blast radius. Kubernetes Secret integrity and rotation are operator responsibilities. |

### Management, configuration, and audit threats

| Threat | Boundary and asset | Existing controls | Attacker story and residual risk |
| --- | --- | --- | --- |
| Admin credential replay | Management client → Admin bearer/IPM authority | Dedicated listener, TLS/mTLS options, default bearer authentication, exact mTLS workload binding, IPM checks, token digests, and rotation/revocation reduce credential exposure. Protected mutations additionally require an expiring signer/principal-bound envelope and durable request-ID ledger. | A stolen bearer remains replayable for unprotected reads and writes until revoked. A stolen mutation signing key can authorize its scoped protected actions until removed; signer custody and rotation remain external duties. |
| Configuration rollback attack | Admin/controller/operator → active security policy | Validation, signed previous/new revisions, exact content digests, durable receipts, retained committed artifacts, immutable Kubernetes revisions, and rollout status make revision changes visible. | An authorized signer can intentionally select an older valid policy unless external approval policy forbids it. A compromised artifact key or PostgreSQL authority can corrupt rollback state. |
| Partial cluster rollout | Desired revision → multiple data-plane instances | Kubernetes immutable rollout proves owned Ready Pods. Fixed-member Admin rollout binds exact membership, encrypts artifacts, validates all members, uses deterministic canary observation, fences every worker/coordinator transition, requires all-member revision/digest ACKs, and rolls back every possibly applied target on failure. | A compromised Kubernetes or PostgreSQL authority, signer, artifact key, or member host can forge or subvert its evidence. Member loss denies Admin writes, and an ambiguous external effect becomes blocking `indeterminate` rather than a success claim. |
| Stale Gateway controller leader | Lease holder → ConfigMap/workload/status authority | Every write requires a fresh exact-Lease proof; workload state records Lease UID, transition epoch, and holder; status uses source/workload resource-version and owner-chain proof; followers do not translate or mutate. | Kubernetes Lease election is not a distributed transaction across resources. A compromised or partitioned API server can violate observations, and an already accepted request cannot be recalled. Resource-version conflicts, immutable artifacts, term annotations, short renew bounds, and pre-commit revalidation reduce this residual race; cluster API integrity remains required. |
| Audit sink failure | Admin mutation → audit spool/store/export | Versioned redacted events, explicit acknowledgement, bounded non-evicting spool, synchronous PostgreSQL option, pre-side-effect intent records, and fail-closed durable modes bound loss. | Best-effort mode can lose records and exports are not acknowledgements. A full/lost volume or unavailable acknowledgement denies required mutations. Pod/node/host loss can destroy an ephemeral or colocated spool. |
| Audit history tampering | Local spool/PostgreSQL → forensic evidence | Every v1 event is domain-separated and SHA-256 chained with sequence and previous hash; optional HMAC-SHA256 authenticates the event hash with an externally supplied key. Replay verifies order and content before deletion. | Hash-only chains can be rewritten by an attacker controlling all stored state. HMAC does not protect against a compromised OxiBelt process/host or stolen key, and neither mode independently proves that an unanchored final suffix was not deleted. External retention/anchoring remains required. |

### Shared state and tenant-boundary threats

| Threat | Boundary and asset | Existing controls | Attacker story and residual risk |
| --- | --- | --- | --- |
| Redis compromise | OxiBelt ↔ Redis decisions, secrets, cache, and leases | Verified `rediss://`, hostname checks, optional mTLS/SPKI pins, ACL files, bounded pools, scripts, namespaces, TTLs, and no ambiguous mutation replay protect access and operations. | A compromised authenticated Redis can return or mutate plausible malicious state, bypass distributed controls, poison cache, or disclose Person proof state. TLS does not validate application truth. |
| PostgreSQL compromise | OxiBelt ↔ PostgreSQL shared/control-plane records | Verified TLS, bounded operations, transactions, namespaces, signed dynamic-policy rows, hashed credentials, explicit durable audit acknowledgement, and optional HMAC-authenticated audit chains constrain normal operation. | Database authority can alter or disclose IPM, dynamic policy, audit, mitigation, shared state, or replay data and can deny Admin mutations. Hash-only audit can be rewritten; HMAC detects forgery only while its key and an authentic chain reference remain outside database authority. Database access, backup, anchoring, and recovery are external trust assumptions. |
| Tenant isolation failure | Hosts/routes/cache/state → another logical tenant | Host-aware routing/cache keys, explicit partition keys, namespaces, typed IPM resources, and bounded per-route policy support logical separation. | One process and backend are not a hostile-tenant sandbox. A cache-key omission, broad Admin grant, shared secret, route conflict, or backend compromise can cross tenants; isolate mutually distrustful tenants operationally. |

### Availability and amplification threats

| Threat | Boundary and asset | Existing controls | Attacker story and residual risk |
| --- | --- | --- | --- |
| Retry amplification | Client request/upstream failure → repeated upstream work | Idempotency/method rules, overall deadlines, per-attempt timeouts, jittered backoff, proportional retry budget, circuit state, and disabled hidden client retries bound attempts. | A failing or malicious upstream can still multiply work within configured budgets. Unsafe operator retry policy or many independent instances can amplify load across the cluster. |
| Queue exhaustion | Public/backend work → memory, latency, and control-plane availability | Global and route/pool active/pending bounds, FIFO cancellation-safe queues, queue timeouts, per-priority shares, reserved authenticated capacity, and immediate rejects bound state. | Attackers can keep allowed queues full or exploit expensive admitted work. Bounds protect process state but may produce sustained `503` responses and do not create network capacity. |
| Cache-fill stampede | Many misses → upstream, memory, disk, and shared-state work | Local collapsed forwarding, shared fill locks, follower deadlines, bounded fill concurrency/size, committed-at-EOF entries, admission policy, and overload suppression reduce duplication. | Lock/backend failure falls back to safe misses and can increase origin load. Multiple instances or deliberately varied keys can still create many independent fills. |

### Extension and supply-chain threats

| Threat | Boundary and asset | Existing controls | Attacker story and residual risk |
| --- | --- | --- | --- |
| Plugin or custom frontend compromise | Operator rulepack/frontend/provider/handler → policy, browser, or external data | OxiRule is declarative and bounded with no general scripting/import callback sandbox; rulepack provenance can be pinned. Custom frontend URLs are same-origin routes, provider/handler exchanges are bounded, and failures follow explicit policy. | There is no native plugin security boundary. A hostile rulepack changes policy, a frontend can steal browser-visible proof/clearance data, a provider controls proof verdicts, and an external cache can observe or forge cached objects within its authority. |
| Compromised build pipeline | Source/dependencies/actions/runner → official image | Workflow actions are commit-pinned, release refs/tags and role metadata are validated, build and package-write jobs are separated, images are scanned, and exact-subject GitHub provenance/SBOM attestations are verified before promotion. | A compromised dependency, runner, maintainer, pinned action commit, release credential, trusted workflow, GitHub Actions identity, or registry authority can produce malicious content or plausible workflow-controlled predicate fields. A valid attestation authenticates the workflow identity and subject binding; it does not prove review, benign workflow execution, or reproducibility. |
| Malicious or stale container image, including role confusion | Registry/tag/deployment → running data plane or control plane | Official image scope is an exact five-repository allowlist, OCI role/source/revision labels and executable inventories are checked during release, both Helm charts support immutable digests, and API attestations bind canonical platform/index digests to exact signer/source policy. | Mutable tags can select stale content before digest resolution, labels and predicate contents are publisher-controlled, and API bundles are not an OxiBelt-managed Kubernetes admission gate. Exact digest and role selection, freshness, rollback controls, registry access, vulnerability policy, approval, and operator-owned admission remain operator responsibilities. Historical OCI referrers do not establish current API evidence coverage. |

### Shared-state compromise impact

Normal failure modes do not limit the authority of a compromised backend.
Operators should rotate backend and feature secrets, stop affected mutation
paths, restore verified data, invalidate replay/session state where possible,
and roll every instance to a known revision after compromise.

| Shared-state feature | Backend | Compromise impact |
| --- | --- | --- |
| Distributed rate limits | Redis or PostgreSQL | Modify token counts/expiry to bypass controls or deny clients; enumerate hashed/raw identity-derived keys available to the backend. |
| Connection and upstream-pool leases | Redis or PostgreSQL | Admit beyond configured cluster limits, deny new work, corrupt active counts, or retain stale leases until expiry/reconciliation. |
| Person proof | Redis or PostgreSQL | Expose or replace cluster HMAC state, replay markers, active clearance hashes, and revocation tombstones; enable replay/bypass or denial until secrets and state are rotated. |
| Upstream health and active counts | Redis or PostgreSQL | Steer traffic toward failed/malicious servers or mark healthy capacity unavailable. Stale-snapshot outage behavior does not detect believable malicious values. |
| Sticky sessions | Redis or PostgreSQL | Change shared affinity secrets/state, redirect sessions to different pool members, or force process-local fallback. Sticky affinity is not authentication. |
| Shared cache, tags, fill locks, and purge state | Redis or PostgreSQL | Read cached objects/metadata, serve poisoned representations, suppress or multiply fills, or make purge incomplete. OxiBelt validates record shape but trusts authenticated backend content within that protocol. |
| Reload heartbeat and instance generation | Redis or PostgreSQL | Hide drift, forge instance presence/generation, or create false degraded signals. Heartbeats are observability, not a signed cluster-consensus protocol. |
| Dynamic policy | PostgreSQL | Deny service, replay old signed rows, or modify unsigned/database-owned metadata. HMAC verification protects active signed row content unless the signing key or authorized automation is also compromised. |
| IPM principals, credentials, policies, and bindings | PostgreSQL | Grant or revoke Admin/data-plane authority, expose credential digests/prefixes and audit metadata, or prevent refresh. Static bootstrap collisions fail refresh but do not make the DB untrusted. |
| Admin audit | Local spool and PostgreSQL | Delete, forge, reorder, or disclose the queryable record, exhaust the bounded spool, or block required mutations. SHA chaining detects modification/order breaks; HMAC additionally detects forgery without the key. A database or host attacker can still delete a chain tail, and a host/process/key compromise can forge future records. Independent restricted key custody, retained volumes, export/backup, and external chain anchoring are required for stronger evidence. |
| Admin mutation ledger and rollout | PostgreSQL | Forge request outcomes, logical revisions, member leases, rollout ACKs, retained artifacts, or break-glass activations; suppress a valid mutation or cause divergent policy. Signatures protect request provenance but do not make a compromised coordinator database trustworthy. |
| Admin operation journal | PostgreSQL | Read redacted identities and progress, forge operation state, leases, checkpoints, receipts, or retention, suppress cancellation, or deny operation queries. Encrypted command/checkpoint artifacts limit plaintext disclosure without the external key, while compare-and-set revisions and boot-bound lease epochs prevent normal competing workers from both owning execution; neither protects against a compromised database. |
| Mitigation intents | PostgreSQL | Forge, suppress, or alter aggregate intents consumed by an external mitigation controller. Downstream ISP/cloud actions remain outside OxiBelt and require their own authorization. |

### Admin mutation authorization and audit

All Admin requests require bearer authentication by default. With opt-in workload
binding, a verified Admin mTLS identity maps to exactly one principal and any
bearer or break-glass credential must match it; optional bearer mode permits
the mapped certificate alone. With IPM enabled, explicit deny takes precedence, an allow must match the action/resource/conditions, and
the default is deny. Mutations emit structured audit attempts with the actor,
principal, peer, operation, target, outcome, and safe request summary. The
canonical endpoint and action inventory is the
[Admin OpenAPI document](../source/assets/admin-openapi.json); new mutation
families must define equivalent authorization, concurrency/replay behavior, and
audit semantics.

| Mutation family | Authorization and concurrency requirement | Audit and residual requirement |
| --- | --- | --- |
| Configuration load/rollback, file sync, downstream TLS key reload, secret-reference activation, downstream/upstream TLS refresh | Matching `config:*` action/resource; protected Admin/IPM configuration changes additionally require `admin:UpdateConfig` or `ipm:UpdateConfig`; high-risk mutations require the active ETag and signed mutation envelope in required mode. | Secret-reference providers receive only one typed reference operation; raw values never enter the ledger or audit stream. Activation preflights a complete candidate and swaps it atomically. Single-instance rollback retains old protected material for a bounded drain grace; fixed-member Admin mode additionally requires all-member reference-set-digest and runtime-revision convergence. Kubernetes immutable rollout remains a separate cluster authority. |
| Cache purge/warm and key administration | Matching cache policy and normalized host/tag resources; public signed purge uses its independent signature/nonce policy. | Record actor, policy/host scope, count/outcome, and partial-failure rejection. Shared purge must not report a partial success. |
| Upstream and stream pool server mutations | Matching pool/server resource and action with current pool ETag. | Record old/new target context and outcome. A mutation changes only the current process unless backed by the documented shared/control-plane mechanism. |
| Dynamic policy create/apply/import/update/delete | Authorize stored and proposed source/name/route resources; enforce quotas, signatures, TTL policy, and ETag rules where required. | Record successful and rejected policy changes. Panic-button `apply` remains intentionally repeatable and does not provide general Admin idempotency. |
| IPM principal, credential, policy, and binding changes plus break-glass activation | Matching typed IPM resource/action with current IPM ETag and signed mutation envelope; credential plaintext is returned only at first creation/rotation execution. Fixed-member token-producing forward progress is pinned to a live cancellation-safe response owner on the admission origin. | Commit IPM CAS, replay record, outcome, and audit transactionally without raw tokens. Exact credential replay is redacted and cannot re-emit the token. Owner loss or origin restart must fail before effect or roll back rather than commit an unrecoverable credential. A bad grant or activation can expand Admin authority. |
| OxiRule/rulepack file management and reload | Matching typed WAF file/reload actions and any underlying config/file preconditions. Development analysis endpoints are non-mutating. | Record install/delete/reload outcome and validation error. Provenance pins protect only when operators require and verify them. |
| Lifecycle drain/undrain and runtime session drain | Matching lifecycle/runtime action and scoped resource; operation enqueue rechecks the source action, and creators have only documented ownership rights. | Record enqueue, cancellation, execution, and outcome. Process-local operation state is lost on restart and does not represent cluster consensus. |
| Person proof clearance revocation | Matching hash-scoped WAF/Person proof resource; optional `Idempotency-Key` is stored only as a digest for the tombstone lifetime. | Record hash-only target and outcome. This legacy narrow contract remains separate from signed high-risk mutation envelopes. |
| Async operation cancellation and control | Creator rights or matching Admin operation action/resource; cancellation cannot undo side effects already completed. | Record creator, operation kind/id, cancellation result, and terminal outcome within bounded retention. |

In `best_effort` audit mode, recording failure is observable but does not block
the mutation. `durable_required` covers every Admin event;
`durable_required_for_actions` covers an exact configured set of semantic
mutation actions. Required intent is acknowledged to PostgreSQL or to the
bounded fsynced spool before the side effect, and acknowledgement failure
returns `503`. Spool admission reserves one record and the configured maximum
event bytes for the terminal outcome before the handler runs, so concurrent
events cannot consume that capacity after the side effect is admitted. P1-13
remains stricter: its mutation ledger and critical audit
transactions require the configured PostgreSQL authority even when ordinary
audit acknowledgement uses the local spool. SHA chaining is tamper-evident,
not immutable storage; optional HMAC adds forgery resistance only while the
32-byte key and an authentic chain reference remain uncompromised.

## Severity Calibration

Severity depends on attacker prerequisites, affected deployment, cross-tenant or
cross-boundary impact, persistence, and whether safe defaults are bypassed.
Configuration footguns that require an explicit documented insecure choice are
normally lower than vulnerabilities reachable under recommended defaults, but
an explicit option does not excuse behavior that contradicts its documented
contract.

### Critical

Critical issues provide unauthenticated remote code execution or equivalent
control of the public data plane, compromise broadly reusable signing/release
authority, or bypass the whole management boundary across supported secure
deployments. Examples include:

- memory corruption or command execution reachable from a public HTTP/QUIC/TURN
  listener;
- extraction or unrestricted use of production TLS signing keys across many
  hosts; or
- a compromised official release path that silently publishes attacker code as
  the expected image for supported releases.

### High

High issues cross a major trust boundary with serious confidentiality,
integrity, authorization, or sustained availability impact but lack the breadth
of a critical compromise. Examples include:

- request smuggling, authority confusion, or cache poisoning that crosses users,
  routes, hosts, or upstream authorization boundaries;
- WAF/IPM bypass or replayed Admin authority that permits a protected mutation;
  or
- malicious shared-state influence that bypasses Person proof, distributed
  limits, dynamic policy, or tenant separation in a realistic deployment.

### Medium

Medium issues require a constrained deployment prerequisite, have bounded or
single-instance impact, expose limited sensitive data, or weaken defense in
depth without directly crossing the principal authorization boundary. Examples
include:

- sustained but bounded queue, stream, decompression, or cache-fill exhaustion
  that makes one instance unavailable without escaping configured resource
  limits;
- loss of best-effort audit records without enabling the underlying mutation;
  or
- consistency loss limited to documented process-local fallback during backend
  unavailability.

### Low

Low issues are limited information disclosures or hardening gaps with little
direct security impact and unrealistic or already-trusted prerequisites.
Examples include:

- exposure of aggregate health/metrics state to an adjacent network without
  secrets, identities, or policy contents; or
- a harmless diagnostic/status inconsistency that does not change enforcement,
  authority, artifact integrity, or availability.

Developer-only tests, examples, and local tooling are not primary product
surfaces unless they execute with privileged CI/release credentials or produce
artifacts consumed by production. A weakness there should be raised above Low
only when a concrete path reaches a runtime, deployment, secret, or supply-chain
boundary.
