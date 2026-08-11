# OxiBelt Technical Specification

Status: Draft
Target project: OxiBelt Rust-based reverse proxy

This document is the compact behavior specification for OxiBelt. Configuration
syntax is covered in [Configuration.md](Configuration.md), OxiRule WAF syntax is
covered in [OxiRule.md](OxiRule.md), and canonical feature lifecycle status is
covered in [FeatureStatus.md](FeatureStatus.md).

## Scope

OxiBelt is a Linux-first edge reverse proxy. It accepts downstream HTTP traffic, terminates TLS where configured, applies routing and policy, and forwards to named upstreams or upstream pools.

The implementation is optimized for:

- Non-root container operation.
- Read-only root filesystem deployments.
- TOML configuration with strict validation.
- Bounded process-local state.
- Safe hot reload of selected runtime inputs.
- Docker-based local and CI testing.
- Optional in-process multi-worker accept using Linux `SO_REUSEPORT`.

OxiBelt currently targets Rust 1.97 and uses `rustls` with the `aws-lc-rs` crypto provider. The default downstream TLS 1.3 key exchange group set enables `X25519MLKEM768`, `X25519`, `secp256r1`, and `secp384r1`; downstream TLS 1.3 and TLS 1.2 cipher suites can be restricted with `tls.1_3.ciphers` and `tls.1_2.groups`. Deployments can omit the hybrid group with `tls.1_3.key_exchange_groups` when cold-handshake CPU cost matters more than post-quantum hybrid negotiation.

## Secure Operational Profile

`profile = "edge-secure-medium"` selects the compiled-in v1 public-edge
baseline. The optional `profile_version = 1` is an explicit pin; omitting it
also selects v1 permanently rather than following a future latest version. v1
is a compatibility contract: its defaults and protected boundaries will not be
silently changed. The active redacted effective configuration materializes the
version, and a change to the selected name or version is a full configuration
change rather than an OxiRule-only reload.

Profiles are not dynamically loaded. OxiBelt does not accept local profile
files, profile URLs, remote catalogs, or unreviewed operator-defined profile
definitions. The compiled-in catalog can add separately documented and tested
name/version entries, but `edge-secure-medium` v1 is the only shipped
operational profile. A configuration without `profile` retains its historical
behavior.

Expansion occurs before typed configuration validation. Built-in profile values
are the lowest-precedence layer; explicit TOML, including includes, overrides
them; supported runtime configuration overrides are last. Arrays replace rather
than append. A profile-protected value can be overridden only when it preserves
the v1 boundary. Invalid selectors and unsafe weakening are rejected even when
unknown-field compatibility is enabled.

The v1 boundary requires TLS 1.3, explicit public SNI names (with the literal
`*` rejected) and downstream
certificate/key or remote-signer material, strict SNI rejection, QUIC Retry,
disabled TCP/QUIC early data, a stable explicit QUIC host key when HTTP/3 is
enabled, finite public request/connection/stream/body limits, strict framing
and trailer handling, overwritten forwarding metadata, and explicit trusted
proxy CIDRs before Real-IP or PROXY protocol use. It requires source TOML to
declare `[waf] enabled = true`; it defaults WAF to enforcing mode while allowing
an explicit monitor-mode rollout. It also preserves fail-closed WAF behavior,
exact/provenance-pinned rulepacks, bounded overload and circuit-breaker
controls, detailed metrics and health endpoints, no remote plaintext
Redis/Valkey, and an Admin listener that is disabled by default and tightly
validated if enabled. Lifecycle defaults provide a 10-second shutdown delay,
a 30-second ordinary drain, and a 300-second long-connection close delay.

This baseline intentionally does not invent credentials or infrastructure
policy. Operators supply certificates, key/signer material, trust roots,
server names, trusted proxy CIDRs, QUIC host-key Secret material, IPM policy,
and durable-audit connection details. Its projected QUIC Secret item must be
base64 text representing exactly 64 random bytes (not raw key bytes). The Helm companion preset at
`deploy/helm/oxibelt/examples/edge-secure-medium-v1-values.yaml` selects the
same runtime profile, narrowly projects the QUIC host-key Secret, and enables
the chart's opt-in NetworkPolicy baseline; it does not make the chart default
select a profile. Operators still declare route-specific egress dependencies
and validate enforcement with their cluster CNI.

The profile is a configuration-security baseline, not an attestation that all
medium-scale edge controls are complete. Its Helm companion supplies the P1-10
topology and drain lifecycle contract on Kubernetes 1.31 or later. OxiBelt now
also implements certificate-to-IPM identity binding (P1-12), single-instance
general mutation idempotency (P1-13), and bounded, versioned, tamper-evident
audit acknowledgements (P1-14). Release workflows publish role-specific
platform images and multi-architecture indexes with explicit executable
inventories. They create and verify GitHub API-hosted keyless SLSA provenance
and CycloneDX SBOM attestations for every canonical platform and index digest
before promotion. Platform SBOMs carry detailed component inventory; index
SBOMs identify the three canonical child digests and retain their inventories
as separate platform attestations. The bundles are not GHCR OCI referrers, and
the project does not provide an OxiBelt-managed signature/provenance admission
gate. Before any package write, a repository-owned global vulnerability gate
requires all 30 role/platform images to be scanned by immutable image ID and
bound to their expected OCI manifest digests. Stable and beta releases block
every `CRITICAL` and every fixable `HIGH`; development build releases block
every `CRITICAL`. Only exact, approved, expiring exceptions can admit a
blocking finding. Multi-architecture indexes are assembled only from admitted
child digests rather than redundantly rescanning an inventory-free index.
Operators must still verify, approve, pin, and rescan each role's immutable
digest with current vulnerability intelligence. Base-image digest pinning
(P2-2), deployment freshness, rollback prevention, code-review proof, and
reproducible-build proof remain separate controls.

The optional strict data-plane release is a separate
`oxibelt-dataplane-strict` package, executable, and OCI repository. It retains
Person Proof and the public data-plane behavior but is compiled without the
Admin listener, Admin mutation/operation/cluster runtime, or Admin OpenAPI
asset. The compatibility `oxibelt` package and existing standalone/default
build remain unchanged. A workspace-wide all-features build is not evidence of
strict isolation; release acceptance uses an isolated package graph plus
binary, image-filesystem, listener, Helm-role, SBOM, and provenance checks.

## Effective Build Identity

The workspace Cargo version `0.0.0` is a package-rewrite sentinel, not a
product version. A dependency-free first-party resolver freezes one atomic
build identity at compile time. An explicit release tuple is accepted only
when all of version, full lowercase revision, full tag ref, clean dirty-state,
and build kind are present and mutually consistent. Otherwise a Git checkout
uses the highest valid exact release tag at `HEAD`, or
`0.0.0-dev.g<revision-prefix>` when untagged; tracked index or worktree changes
append `+dirty`. A source archive without Git metadata is
`0.0.0-dev.archive` with unknown revision, ref, and dirty state. If a `.git`
control directory exists but cannot be interrogated, the build fails rather
than falling back to archive identity. Untracked-only files are excluded from
dirty-state calculation so Cargo rebuild inputs remain deterministic.

Only an official release or a clean exact-tag development build has a SemVer
compatibility version. Official status is a build assertion, not an
authentication decision; release tag, commit, workflow identity, artifact
digest, and provenance establish trust. Admin version metadata, capabilities,
runtime introspection, support bundles, cluster build fencing, executable
`--version`, OCI labels, and release artifact contracts consume this canonical
identity. Runtime introspection retains format version `2`; the confinement
contract advances the support-bundle format to version `3` to add bounded,
redacted hardening evidence. Public readiness and liveness responses retain
their existing non-identifying contract.

## Request Pipeline

At a high level, each HTTP transaction follows this order:

1. Accept TCP or QUIC traffic from a downstream client.
2. Apply listener-level checks such as the global connection limit, PROXY protocol intake, configured per-IP connection-limit identity, TLS handshake limits, and optional TCP max-hop policy.
3. When `[sni_forward]` is enabled, inspect visible TCP TLS or QUIC Initial ClientHello SNI before local TLS termination; explicit forwarding rules may tunnel the L4 session to a configured target.
4. Terminate downstream TLS for local sessions and collect transport metadata, including SNI, ALPN, client certificate presence, and QUIC metadata where available.
5. Parse the HTTP request and normalize the client IP used for Real-IP connection-limit modes, rate limits, and WAF evaluation.
6. Match a route by host and path prefix.
7. Evaluate request-phase OxiRule rules and enabled CRS phase 1/2 rules when WAF is enabled.
8. Select the configured upstream or upstream pool, optionally using request-phase routing actions.
9. Apply the effective request buffering policy, normalize forwarded headers, and forward the request upstream.
10. Build a response context from the upstream response or from a synthetic upstream-error response.
11. Evaluate response-phase OxiRule rules and enabled CRS phase 3/4 rules when WAF is enabled.
12. Apply response mutations, the effective response buffering policy, cache behavior, structured access-log actions, and response forwarding back to the downstream client.

If a validation, runtime, or WAF policy failure occurs, the configured fail policy determines whether OxiBelt rejects the transaction or allows it to continue.

HTTP request and response buffering is opt-in and defaults to streaming. `memory` buffers bounded bodies in memory, `spool` spills bytes beyond the memory threshold to explicit temp files and removes partial files if buffering fails, and route-level buffering overrides inherit omitted values from `[proxy.buffering]`. CONNECT tunnels, HTTP Upgrade, and WebTransport sessions remain streaming.

HTTP semantics controls preserve compatibility across common edge cases. OxiBelt accepts `Expect: 100-continue` in automatic mode, rejects unsupported `Expect` values with `417`, can strip or pass RFC 9218 `Priority` headers, and can drop ordinary HTTP trailer frames while preserving native gRPC trailers. `text/event-stream` responses remain streaming by default even when route response buffering is enabled. Native gRPC requests preserve `grpc-status` and `grpc-message` trailers, can honor `grpc-timeout`, and receive gRPC status trailers for proxy-generated upstream failures. A client-requested gRPC deadline that expires before OxiBelt's configured upstream first-byte timeout is treated as a client deadline expiry and does not increment passive upstream-pool health failures.

Runtime topology is explicit. The canonical default `hybrid_compio` owns one Compio bootstrap driver around a Tokio compatibility island; Tokio owns orchestration, TCP accept, general HTTP, HTTP/3 and QUIC, DNS and discovery, timers, background/control tasks, and blocking work, while Compio owns direct-H1 transport only when its Linux-only experimental worker fleet is active. Legacy `compio` aliases this topology with a diagnostic. `[runtime.workers].tokio`, `[runtime.workers].compio_direct_h1`, TCP accept workers, and QUIC socket workers accept explicit positive counts or `"auto"`; auto uses `std::thread::available_parallelism()`, the matching `[runtime.worker_multipliers]` value, round-up, and a one-worker detection fallback. Legacy `runtime.worker_threads` and multiplier `runtime` fill only omitted owner-specific values. A changed main topology or Tokio count requires process restart; a direct-H1 backend/count change may full-reload only after the replacement fleet is staged, while accept and QUIC changes retain listener-rebind behavior. `topology_policy = "require_exact"` rejects a candidate that would fall back. When accept or QUIC resolves above one, the matching `reuse_port` setting is required. Kernel sysctl and file-limit changes remain outside the binary; the optional `kernel-extension/` installer stages Linux 7.0.x+ host tuning separately.

## Protocol Behavior

Downstream protocol support:

- HTTP/1.1 and HTTP/2 are served over TCP.
- HTTP/3 is served over QUIC on every configured `https_binds` UDP address. IPv6 listener sockets are IPv6-only, so dual-stack deployments configure explicit IPv4 and IPv6 binds.
- `[sni_forward]` can inspect visible TLS ClientHello SNI before OxiBelt terminates local traffic. Explicit SNI forwarding rules override local route hosts; otherwise configured route hosts remain local, and unknown SNI forwards only when `sni_forward.default_target` is configured. Missing, malformed, or unparseable SNI fails closed. Route host `"*"` does not count as a defined SNI name. QUIC SNI forwarding bounds pre-classification session state, local datagram queues, and pending Initial reassembly with `[sni_forward]` limits.
- TCP SNI forwarding uses bounded `TcpStream::peek`, preserving the original ClientHello for raw TCP passthrough targets. Local matches continue through the normal rustls HTTP/1.1 and HTTP/2 path. Forwarded TCP sessions keep the accepted connection's global lease and, in Real-IP connection-limit modes, acquire the normal per-IP and named leases for the post-PROXY-protocol peer address before tunneling.
- QUIC SNI forwarding uses the same UDP addresses as downstream HTTP/3. OxiBelt decrypts QUIC Initial payloads, reassembles visible CRYPTO frames across datagrams, parses visible ClientHello SNI, and replays contributing datagrams in arrival order to UDP passthrough or Quinn after the policy decision. Pending reconstruction is shared per logical bind, bounded by `[sni_forward.quic_initial_reassembly]`, and separate from established sessions. Identical retransmits are deduplicated; malformed frames, conflicting overlaps, expiry, replay-admission failures, and capacity or byte/fragment/datagram limit failures fail closed. Forwarded QUIC sessions acquire the same total, per-IP, and named downstream connection leases as local HTTP/3 connections. QUIC SNI forwarding requires downstream HTTP/3 to be enabled.
- `[[stream_listeners]]` can bind dedicated TCP or UDP L4 listener addresses. TCP listeners preserve backward-compatible direct `target = "host:port"` configs and can also select `[[stream_upstream_pools]]`; UDP listeners pin each downstream client flow to a selected direct target or UDP pool server until idle expiry or capacity eviction. `udp_flow_state = "local"` is the compatibility default and keeps that mapping, admission state, and connected upstream socket in one process. `udp_flow_state = "shared_required"` stores an opaque, fenced logical mapping and its bounded token state in the explicitly selected Redis-compatible or PostgreSQL shared-state backend, then recreates local socket state after restart only while the active routing generation still authorizes the same configured route and target/server identity. Stream payloads stay passthrough: OxiBelt does not terminate TLS, perform HTTP routing, run WAF payload inspection, or emit UDP PROXY protocol egress on these listeners.
- Stream listener `sni_rules` classify only visible TCP TLS ClientHello SNI or UDP QUIC Initial SNI. Matching rules select a direct target or stream pool; no-SNI, malformed, or non-TLS/non-QUIC flows use the listener default target/pool when configured and otherwise fail closed.
- Shared UDP recovery is a logical-affinity guarantee, not transport-session migration. Owner-generation fencing prevents a stale process from touching or releasing a replacement owner's record; a mismatched routing generation is not reused. Already-local flows may continue during a post-activation store outage, but a flow that requires a shared lookup, claim, token decision, or ownership recovery is rejected under the fixed `reject_new_only` policy. Restart cannot preserve the old connected socket, upstream source port, NAT/conntrack entry, exact endpoint selected behind a Kubernetes Service, in-flight or upstream-initiated datagrams, or application/session protocol state.
- Deployments that enable HTTP/3 must expose every HTTPS bind address for both TCP and UDP.
- Downstream HTTP/3 always requires TLS 1.3.
- The same downstream client certificate policy is enforced for TCP TLS and HTTP/3/QUIC listeners.
- QUIC Retry/address validation can be enabled with `quic.retry`.
- HTTPS HTTP/1.1 and HTTP/2 responses advertise HTTP/3 with `Alt-Svc` when downstream HTTP/3 and `quic.alt_svc.enabled` are both enabled. The advertised port defaults to the HTTPS bind port and can be overridden per HTTPS bind for deployments where the client-visible UDP port differs from the local bind port. OxiBelt does not add that header on HTTP/3, plain HTTP, or `101 Switching Protocols` responses.
- TLS early data is disabled by default. `tls.ssl_early_data` and `routes.tls.ssl_early_data` accept `off`, `safe_methods`, and `on`; `safe_methods` permits only transport-verified `GET` and `HEAD`, while `on` accepts replayable requests for routes that explicitly tolerate replay. TCP TLS early data requires TLS 1.3 stateful resumption. Multi-certificate SNI selection may use resumption or early data only with explicit `tls.resumption.multi_certificate = "partition_by_sni"`, `tls.require_sni = true`, and `tls.reject_unknown_sni = true`, which partitions downstream TLS and QUIC resumption by selected certificate identity. HTTP/3 0-RTT transport admission remains controlled by `quic.zero_rtt`; `safe_methods` is the recommended 0-RTT mode. Disallowed transport-verified early-data requests receive `425 Too Early`; accepted requests get a verified upstream `Early-Data: 1` header, and untrusted downstream `Early-Data` headers are stripped.
- `quic.host_key_file` provides deployment-local host key material for stateless reset and Retry/validation tokens. It is cert-directory relative and hot-reload tracked; release images do not include shared key material.

Upstream protocol support:

- HTTP/1.1 supports `http://` and `https://` origins.
- HTTP/2 over `https://` uses TLS ALPN.
- HTTP/2 over `http://` uses h2c with prior knowledge.
- HTTP/3 requires an `https://` upstream origin.
- Ordinary upstream HTTP/3 forwarding uses a logical-origin-keyed QUIC connection pool and multiplexes requests over pooled HTTP/3 connections when `quic.upstream_pool.enabled = true`; when disabled, each ordinary request uses a one-shot QUIC connection. Its shared resolver retains bounded A and AAAA candidates until a clamped TTL, briefly caches selected negative answers, rotates eligible addresses with recent-success preference, applies bounded per-address cooldown, and staggers IPv6/IPv4 connection attempts. A concrete IP address is connection state rather than pool identity, and connections are never coalesced across authorities merely because addresses or certificates overlap. One-shot HTTP/3 and dedicated-per-session WebTransport use the same bounded resolver. DNS, connection coalescing, and slot waits obey the effective request deadline; candidate failover is pre-dispatch only and never implicitly replays a dispatched request.
- `proxy.auto_upgrade` controls the maximum upstream HTTP version OxiBelt may select.
- Route-level `upstream_http_version` can override backend protocol selection within the selected upstream capability.
- Route-level timeout overrides can adjust downstream body/send, upgrade idle, WebTransport idle, and upstream connect/first-byte/read/send behavior for individual routes. Route-level request body limits can override the global request body cap after route matching. TLS handshake and downstream header read timeouts remain listener-wide.
- PROXY protocol egress is supported only for TCP-based upstream connections and stream proxy targets, not HTTP/3/QUIC upstreams.

Upgrade and extended protocol behavior:

- WebSocket tunneling is implemented for HTTP/1.1 upgrade routes.
- WebSocket stream-WAF routes reject individual frame payloads larger than `waf.limits.max_body_inspection_bytes` before forwarding.
- Generic HTTP/1.1 upgrade and CONNECT tunneling are implemented when both global and route-level policy enables them.
- CONNECT tunneling targets the selected route upstream origin, not the downstream request target.
- WebTransport forwarding is supported for downstream HTTP/3 extended CONNECT requests when the selected upstream also uses HTTP/3 and has `webtransport = true`.
- Native OxiRule stream-phase WAF rules can inspect WebTransport stream chunks and datagrams in both directions before forwarding and can close the active session with `close_stream` or abort it without a protocol close payload with `silent_close`. The CRS compatibility layer does not inspect WebSocket or WebTransport stream payloads.
- WebRTC client-to-client media forwarding is supported through TURN listeners. Signaling HTTP requests can still be routed and inspected as ordinary HTTP traffic, while applications remain responsible for signaling, SDP exchange, and ICE candidate distribution. TURN `proxy_pool` forwards traffic to external TURN servers. TURN `edge_relay` terminates TURN authentication locally and allocates OxiBelt-managed UDP relay sockets for ICE candidates. Edge relay supports IPv4 and IPv6 relay families, including clients behind IPv4 NAT and IPv6 NAT/NAT66 when the listener is configured with the matching relay family and public address. TURN `REQUESTED-ADDRESS-FAMILY` selects one configured family, `ADDITIONAL-ADDRESS-FAMILY = IPv6` can allocate both IPv4 and IPv6 relay sockets, and missing family requests default to IPv4. Edge relay enforces peer permissions before forwarding peer-to-client traffic, returns TURN capacity errors instead of failing listeners, clamps allocation lifetimes, and denies private, loopback, link-local, unspecified, multicast, and broadcast peer addresses by default. IPv4 peers must use the IPv4 relay family; IPv4-mapped IPv6 peer addresses are rejected. TURN `edge_relay` TCP/TLS outbound queues are bounded per downstream connection by `stream_outbound_queue_capacity`; the default is `32`, `"auto"` resolves conservatively from available parallelism with a `32..=64` clamp, explicit values are limited to `1..=256`, and full queues fail closed.

## TLS and Identity

Downstream TLS uses configured certificate files from the cert directory and either local private key files or an IPC remote private-key signer. Additional downstream certificates can be selected by TLS SNI before HTTP routing; the default certificate remains the fallback unless SNI strictness is enabled. OxiBelt supports TLS 1.2 through TLS 1.3 for TCP TLS; HTTP/3 requires TLS 1.3.

Supported downstream TLS features:

- Server certificate chain loading with local private key loading or Unix socket remote signing, including multiple SNI-selected downstream certificates.
- Optional or required downstream client certificate authentication.
- Client CA roots from configured cert-directory files.
- Static file-based OCSP stapling and live OCSP fetch/refresh for downstream TLS.
- Optional downstream TLS early data with global and per-route policy controls.
- Experimental CRLite filter enforcement for configured downstream TLS certificates, including operator-supplied local filters and WebPKI-only managed Mozilla CRLite cache downloads.
- Opt-in outbound TLS revocation checks for runtime upstream clients using live OCSP fetch/cache and experimental CRLite local or WebPKI-only managed filters.
- Session tickets with configurable rotation interval.

Remote private-key signing is intended to keep downstream and TURN TLS private keys outside the OxiBelt process memory. OxiBelt connects to `oxibelt-keysigner` over a Unix domain socket, authenticates with a base64 32-byte token, verifies that the signer-reported public key matches the configured certificate, and requests signatures through rustls' signing interface. File-backed tokens use `keysigner-token.b64` by convention, take precedence over environment tokens, can be reloaded on a short interval, and preserve the last good token if a later rotation file is missing or invalid. An `unauthorized` signer response causes OxiBelt to force one immediate token-file reload and retry. The signer caps concurrently handled IPC connections and applies server-side request/response I/O deadlines before token validation, so local idle or trickled socket peers cannot hold signer tasks indefinitely. Signer sockets are restricted to `0600` or `0660`, with `0660` as the default for sidecar socket sharing; peer UID/GID allowlists can further restrict local clients, while empty allowlists remain compatibility mode and emit a startup warning. The signer defaults to TLS 1.3 server CertificateVerify inputs only; TLS 1.2 unstructured signing requires explicit opt-in on both OxiBelt and the signer sidecar.

Upstream TLS behavior:

- OxiBelt validates upstream HTTPS using the default web PKI roots plus configured `proxy.trusted_ca_certs`.
- Upstream TLS 1.3 ECH can be disabled, sent as GREASE, or sent from a configured TLS-encoded `ECHConfigList`.
- `proxy.upstream_revocation` can add outbound OCSP and CRLite checks after normal WebPKI chain and hostname validation. The handshake verifier never performs network revocation I/O; stapled OCSP responses or local caches are checked synchronously, and missing OCSP cache entries schedule bounded background fetches. Managed CRLite Remote Settings downloads use public WebPKI roots only and do not inherit `proxy.trusted_ca_certs`. Revoked OCSP or CRLite results fail closed.
- Downstream ECH termination is not configured by OxiBelt today; it depends on server-side ECH support in the TLS provider.

Person proof challenges in OxiRule are anti-automation controls. They are not authentication, identity proof, proof of legal personhood, or proof of benign intent. Public behavior is selected with `person_proof_mode`: `built_in` uses OxiBelt built-in PoW plus the built-in frontend, `openapi` uses the same PoW API with a custom frontend, `third_party_provider` uses built-in Cloudflare Turnstile, hCaptcha, or Friendly Captcha v2 adapters, and `custom_provider` calls a configured JSON HTTP provider. `custom_provider` can describe external Proof of Something flows, such as operator-defined Proof of Knowledge or external Proof of Work, with custom proof metadata while OxiBelt keeps session signing, replay protection, provider callout, and clearance issuance. Custom frontends are addressed by `custom_frontend_url`, an origin-relative URL routed by the same OxiBelt instance to either a static asset or proxied frontend backend. Clearance credentials can be carried by configured cookie keys, `Authorization: Bearer`, or configured request-header keys, with cookie, localStorage, and JSON issuance modes documented by the Person proof API metadata.

## Routing and Upstreams

Routes match by host and path prefix. Wildcard host routes such as `*.example.com` require at least one non-empty request-host label before the suffix. A route may rewrite the matched path prefix with legacy `replace_prefix_with`, or use `actions.rewrite` to render a bounded upstream path/query template before forwarding. A route may also use terminal `actions.redirect` with an origin-relative `Location`.

Targets may be:

- A named `[[upstreams]]` entry.
- A named `[[upstream_pools]]` entry.
- A `static_root` directory.
- A terminal `actions.redirect` response.

Static targets serve only verified regular files beneath the configured `static_root`; directory listing is forbidden. Route-level `[routes.static_files]` convenience resolution evaluates the requested file, configured directory indexes, `try_files`, SPA fallback, and configured static error pages without leaving the same root-confinement and verified-open boundary. Static hot-object cache fill and cached-hit refresh also open the current file inside that boundary, and cached hits serve bytes only when the current validator still matches the cached object. Precompressed static variants are negotiated from `Accept-Encoding` q-values, skipped for range requests, and keep response metadata such as MIME overrides and cache-control policy tied to the selected route and logical asset. When a route enables WAF HTTP body compression transform and response body WAF inspection is required, precompressed static variants are decoded before response WAF or fail closed if HTTP transform semantics are unsafe.

Routes may reference an `external_auth` provider. OxiBelt runs that authorization check after route-level rate limits and dynamic policy and before WAF/body handling or upstream selection. Client-supplied identity headers are stripped before trusted identity headers are injected from Authelia forward-auth responses, OAuth2 token introspection data, or OIDC UserInfo claims. Routes with external auth are excluded from plain proxy and static sendfile fast paths. Dynamic policy remains part of the pre-body-transform route decision path; the WAF HTTP body compression transform starts only when later OxiRule/CRS body inspection needs request or response body bytes.

Upstream pools maintain load-balancing state. The default algorithm is `power_of_two_choices`. Supported HTTP pool algorithms are `power_of_two_choices`, `weighted_least_conn`, `rendezvous_hash`, `rendezvous_ip_hash`, `ewma`, `least_time`, and `sticky_cookie`; legacy `round_robin`, `least_conn`, `least_connections`, `random`, `hash`, and `ip_hash` names are rejected by default rather than treated as aliases. The explicit migration profile `[config] lb_policy_compat_profile = "nginx"` or `"caddy"` converts only exact safe aliases: `least_conn` and `least_connections` become `weighted_least_conn`, and `ip_hash` becomes `rendezvous_ip_hash`. `round_robin`, `random`, and `hash` remain diagnostic-only because they do not have exact OxiBelt equivalents. The same profile applies before validation to HTTP pools, sticky-cookie fallbacks, TURN pools, and WAF `set_load_balancing_policy` actions, and `oxibeltctl config lb-policy-compat` can render a converted TOML report before operators commit canonical names. Sticky-cookie pools verify an HMAC-signed server-affinity cookie, reuse the selected server only while it remains healthy and capacity-available, and otherwise fall back to a configured non-sticky modern algorithm before issuing a fresh cookie. Pool health can be passive or active depending on configuration. Pool servers have stable IDs, source metadata, active counts, health state, and runtime state. `ready` servers accept new requests; `drain`, `down`, and `maintenance` servers do not receive new selections while existing in-flight requests complete. Optional slow start scales effective server weight for newly added, discovered, or recovered ready servers across all HTTP pool algorithms. Optional outlier ejection temporarily excludes servers after configured consecutive failures and fails closed when every eligible server is ejected or otherwise unavailable. Snapshot rebuilds preserve stable-ID runtime state such as EWMA samples, health counters, ejection state, and slow-start timestamps.

Active HTTP pool health checks build a probe request from the pool server origin plus `health_check.path`, optional `health_port`, configured method, custom non-reserved headers, optional request body, and optional `health_host` Host header override. `health_host` never changes TLS SNI or hostname verification; those remain based on the probe URI host. HTTP success requires an exact expected status or inclusive expected status range, and a configured body regex must also match within the configured bounded response-body window. Active schedules use `interval_ms` plus bounded `jitter_ms` to avoid synchronized probes. Active gRPC health checks preserve the gRPC health-check request and serving-status match while honoring shared health timing, custom non-reserved headers, `health_port`, `health_host`, and health-check TLS policy. Health-check-only CA roots and outbound revocation overrides build a separate health-check client pool; they do not mutate the forwarding clients used for selected upstream-pool traffic. Diagnostics upstream probes mirror the configured HTTP health request and match rules for pool servers.

Dynamic upstream discovery is supported for upstream pools. File discovery polls a JSON server list under the config directory. DNS discovery supports A, AAAA, combined A/AAAA, and SRV records and schedules refreshes from configured refresh intervals and DNS TTLs. Kubernetes discovery polls the core Endpoints API, Consul discovery polls health service entries, etcd discovery polls v3 KV ranges, and Nomad discovery polls or blocking-watches `GET /v1/service/:service_name`. DNS responses are accepted only when they are successful responses matching the sent transaction ID and question, and answer records must be owned by the queried name or a verified CNAME chain. Nomad responses are bounded and validated as untrusted service inventory before generated `http`/`https` origins are accepted. Discovery updates are staged: OxiBelt validates the generated pool and rebuilds upstream clients before atomically replacing the active pool view. Invalid discovery updates keep the previous active state.

Host forwarding is controlled by each upstream's `preserve_host` setting:

- `false`: use the upstream origin host.
- `true`: forward the effective downstream request host selected for routing and WAF evaluation.

Absolute-form request targets are accepted only when their URI authority matches the `Host` header after host and effective-port normalization. Mismatches are rejected with `400 Bad Request` so routing, WAF policy, forwarded headers, and upstream `Host` forwarding cannot observe different downstream authorities.

OxiBelt also manages `Forwarded` and `X-Forwarded-*` headers according to `proxy.forwarded_headers.mode`. By default, `X-Forwarded-For` uses the same resolved client identity as WAF, rate limiting, and external auth; `proxy.forwarded_headers.client_ip_source = "direct_peer"` keeps legacy immediate-peer forwarding when needed.

Downstream security response headers use `[security.headers]` as the default policy and optional named `[[security.header_policies]]` entries selected by route `security_headers`; omitted routes inherit the default, `default` selects it explicitly, `off` disables OxiBelt-managed insertion, and any other value must name a configured policy. Cached proxy responses store route-security-neutral metadata and reconcile OxiBelt-managed security headers at delivery time, so configured fields reflect the currently matched route policy while origin-provided values remain intact for fields that the current route policy leaves unset or disables. Downstream response compression is controlled by `[compression]` and optional route-level `compression` policy references. Support for `br`, `zstd`, `gzip`, and `deflate` is enabled by default, but OxiBelt only transforms responses when the downstream `Accept-Encoding`, request credential headers, response status, MIME type, size, existing response headers, and range/no-transform semantics allow it. Requests carrying `Cookie`, `Authorization`, or `Proxy-Authorization`, and responses carrying `Set-Cookie`, `Cache-Control: private`, or `Cache-Control: no-store`, are not compressed. `level` applies one nginx-style `1..9` quality setting to all enabled encoders. Requests carrying `Via` must also match the configured `proxied` predicates before dynamic compression is allowed; these predicates do not override credential or private/no-store response hardening. Dynamic compressed responses set `Content-Encoding`, optionally vary on `Accept-Encoding`, remove `Content-Length`, and weaken strong `ETag` values. OxiBelt strips upstream `Accept-Encoding` by default when compression is active; policies can opt into preserving the client header or sending the configured encoding list intersected with the downstream request, but response body WAF transforms and credential-bearing requests always force identity upstream requests. This downstream compression policy runs after response WAF, cache, and route response actions; WAF HTTP body compression transform first decodes upstream or static compressed responses into the WAF/cache identity view, then lets downstream compression negotiate a fresh client-facing encoding when enabled.

## WAF and OxiRule

OxiRule is a CEL-like, declarative WAF model. It separates:

- `when`: a side-effect-free boolean expression.
- `actions`: validated declarative side effects.

Rules can be attached globally under `[[waf.rules]]` or under `[[routes.waf.rules]]`. They may be inline TOML rules or external `.oxirule.toml` files loaded from the OxiRule directory.

Bounded user-defined functions can be attached globally under `[[waf.functions]]` or per route under `[[routes.waf.functions]]`. They are expression-valued, acyclic, evaluated under the caller's budgets, phase-validated where they are called, and available to WAF rule expressions plus WAF `emit_access_log` field expressions. Request-wide system access-log fields do not receive WAF functions in v1.

OxiRule `emit_mitigation` actions enqueue aggregate PostgreSQL mitigation intents for external DOTS, BGP FlowSpec, RTBH/blackhole, or provider-specific controllers. OxiBelt only writes the configured `[database.mitigation]` table, never calls ISP or IaaS APIs directly, and excludes request/response/stream payload bytes from mitigation records.

Request-phase rules can reject, silently close, rate-limit, mutate request headers, set transaction tags, require Person proof, or choose an upstream/pool before forwarding. Person proof `session_path`, `verify_path`, and `openapi_path` requests are intercepted after route matching, route rate limits, and dynamic policy, but before external auth, WAF forwarding, static files, or upstream selection. Response-phase rules can continue, replace, reject, or silently close responses, mutate response headers, and emit structured access logs. If a route opts into WAF HTTP body compression transform, request WAF body inspection decodes a single supported HTTP `Content-Encoding` after those pre-WAF route decisions, enforces decoded-size, expansion-ratio, timeout, and concurrency caps, evaluates OxiRule/OxiRule Group/CRS against the decoded view, and re-encodes the request stream to the original coding before upstream dispatch. Response WAF transform removes upstream `Accept-Encoding` when response body WAF is needed, decodes safe compressed upstream/static responses before WAF, strips response `Content-Encoding`/`Content-Length`, weakens strong validators, and fails closed when safe HTTP transform semantics cannot be preserved.

Client identity helpers are local, bounded request classifiers. ASN lookup is disabled by default and uses only an operator-supplied `prefix_asn_csv` database, loaded locally or from a managed HTTPS source with size, hash, cache, and refresh bounds. The IANA AS Numbers CSV registry can be configured as metadata/provenance, but it is not an IP prefix-to-origin-ASN database. OxiBelt therefore does not ship a default origin-ASN source URL. `Request.Client.Asn`, ASN rate-limit keys, composite-client rate-limit identities, and DynamicPolicy `asn*` subjects use the optional runtime lookup; DynamicPolicy hashed identity subjects use stable prefixed SHA-256 values for TLS fingerprints, token-binding payloads, verified Person proof clearance hashes, and composite-client parts. `Request.Client.GeoCountry` remains null.

Malicious intelligence scoring helpers are local, bounded OxiRule helpers for hostile automation, prompt-injection/tool-abuse language, malformed or layered payload shape, and suspicious automation fingerprints. They are not authentication, identity proof, bot reputation, Person proof, proof of legal personhood, or proof of benign or malicious intent. They perform no external LLM, classifier, reputation, or callback I/O and run only inside the same OxiRule budgets and bounded body prefixes as the calling rule. Client-supplied agent, crawler, or AI claims remain untrusted unless a future explicitly trusted agent authentication mechanism marks them otherwise.

The optional CRS compatibility layer loads ModSecurity-style CRS setup/rule files from the OxiRule directory. It supports request/response phases 1 through 4, bounded request/response body prefix inspection with replay, normalized CRS transforms, `tx` variables, chained rules, macro expansion, `setvar`, paranoia-level tags, and anomaly scoring. CRS defaults to `monitor`; `enforcing` mode blocks at configured inbound/outbound anomaly thresholds. Unsupported CRS syntax fails closed during configuration load/compile.

The rule engine is intentionally bounded:

- No loops, callbacks, imports, external I/O, or general-purpose scripting. User-defined functions are declarative bounded expressions, not imperative scripts.
- Runtime, step, memory, regex, body-inspection, helper, and mutation budgets.
- Bounded helper APIs for raw and normalized headers, query parameters, cookies, tags, body byte/text inspection, response body prefix inspection, body pattern scanning, and pattern sets.

See [OxiRule.md](OxiRule.md) for the full rule reference.

## Runtime and Operations

Runtime state is process-local unless `[shared_state].enabled = true`. With shared state disabled, cache indexes and locks, upstream health state, rate and connection limits, and Person proof single-use token state stay inside one process. Rate-limit bucket maps are bounded per configured limit by `max_buckets`; new identities fail closed in enforcing mode after the cap until refilled or expired buckets can be reclaimed. Rate-limit identities can bucket by client IP, route, path, hashed trusted access token, client IP prefix, hashed TLS fingerprint, ASN, hashed composite client parts, hashed Person proof token bindings, or hashed verified Person proof clearance credentials depending on whether the limit is top-level or WAF-owned. Access-token rate limits require `access_token_source` so operators explicitly choose either a trusted `Authorization: Bearer` credential or a trusted injected header, avoiding accidental bucket creation from arbitrary pre-auth bearer values.

When shared state is enabled, each feature maps to one configured Redis/Valkey-compatible or PostgreSQL backend. Rate limits use distributed token buckets keyed by client IP, route, path, trusted hashed access token, or other configured identity and enforce `max_buckets` before creating a new distributed identity bucket; connection limits use TTL-backed marker leases; Person proof can share its HMAC secret and single-use replay store; upstream pool health and active counts can be shared for selection; cache keeps local storage as L1 and uses the shared backend as L2 for collected cacheable objects, metadata, tags, fill locks, and purges; reload writes per-instance heartbeat records with config generation metadata. Each health transition, counter value-plus-expiry change, multi-scope lease acquire/release, Person proof legacy/hash replay transition, and Person proof revocation/tombstone change is one backend decision: Redis executes one script and PostgreSQL commits one transaction. Marker leases make cleanup idempotent, so a duplicated or stale release cannot decrement a later lease generation. The narrow Person proof revocation Admin retry contract stores only an `Idempotency-Key` digest and its hash-only response for the tombstone lifetime; it does not extend to general Admin mutations. Disk streaming cache fills keep their local disk L1 and publish bounded chunks plus committed metadata to shared L2, so another instance can read the completed object without treating partial chunks as a hit. Optional external cache handlers provide an HTTP L3 after L1/L2 misses and receive fills only after OxiBelt admits and commits the local/shared entry. Shared-state enumeration is namespace-scoped, cursor-based, and bounded by `enumeration_page_size`, `enumeration_max_items_per_operation`, and the operation deadline: Redis uses `SCAN`, batched `MGET`, and pipelined TTL reads rather than `KEYS` or a request per key, while PostgreSQL uses escaped-prefix keyset pages. Cache vary lookup never falls back to a namespace-wide legacy scan; a missing narrow index is a safe miss. Redis uses a bounded persistent connection pool per named backend, while PostgreSQL retains its existing bounded operation runtime. Redis pool checkouts and commands are async, FIFO, timeout-bounded, and cancellation-safe: a socket returns only after every expected RESP response of a command or pipeline; cancellation or ambiguous I/O discards it without replaying a mutation. `rediss://` uses verified TLS with an explicit WebPKI, native, or custom trust source, hostname verification, optional client-certificate authentication, additive SPKI pins, and ACL/password files; secure profiles can forbid plaintext `redis://`. New snapshots reuse unchanged plaintext Redis pools so unrelated full reloads do not churn sockets, while secure Redis pools are intentionally rebuilt on full reload to re-read trust and client-certificate material. File-auth and secure Redis connections must authenticate successfully before a new snapshot activates. Shared backend I/O is awaited directly on Tokio; request cancellation releases its admission and I/O resources instead of blocking an executor worker. Security-sensitive backend failures fail closed. Shared cache backend failures and external cache handler failures fall back to local/no shared cache for that request; an Admin cache purge whose bounded shared enumeration cannot finish returns `503` instead of a successful partial count.

Response caching supports tag extraction from configured response headers, exact/prefix/tag purges through the admin API, signed purge authentication, cache key explain, batch warming, collapsed forwarding with bounded follower waits, disk index recovery, admission filtering by status/MIME/body size/frequency, tenant partition keys, Surrogate-Control metadata, stale-if-error controls by error class or status, Vary explosion guards, fresh conditional `304` hits, `Age` on cached hits, single and multipart cached byte ranges, local disk streaming fills for large known-length objects, external L3 lookup/fill/revalidation/purge coordination, and background refresh for eligible stale-while-revalidate GET/HEAD responses. Cache-enabled routes emit bounded `X-OxiBelt-Cache` and `X-OxiBelt-Cache-Reason` status headers and strip origin-supplied values for those names before caching or forwarding. Cache keys include scheme and host by default; production configurations should keep host and trusted variation dimensions in the key, avoid credential-bearing requests, and prefer query allowlists when only specific query parameters affect representation selection.

Shared-state failure policies are evaluated only after the backend snapshot has activated; startup, secure-connection, and configured prewarm failures still leave the prior snapshot active. Distributed rate decisions and new connection leases never reuse stale results or retry an ambiguous mutation. The default policy rejects a failed distributed token decision, refuses only new connection leases while preserving existing holders, retains the last published upstream-health observation, falls back only to bounded local cache/sticky state, and treats reload heartbeats as best effort. Person proof replay, clearance revocation, and the Person proof Admin mutation remain fail closed.

Hot reload modes:

- `off`: no runtime reload.
- `oxirule`: reload WAF-owned configuration and external OxiRule files only.
- `downstream_tls`: reload the current downstream certificate, private key, static OCSP response, or live OCSP runtime.
- `full`: reload OxiRule, TOML configuration, upstream clients, access-log sinks, downstream TLS material, downstream listener bind/protocol settings, and admin listener enable/bind settings.

Configuration activation planning is deterministic, bounded, redacted, and
side-effect-free. For each effective-schema change it reports the native
activation, resolved operation, fixed reason, prerequisites, long-connection
effect, and rollback class, then aggregates the strongest safe operation.
Mixed specialized reloads may promote to a full snapshot. The report separates
the intrinsic minimum from the operation selected by the current executor and
deployment authority, so an Admin full-snapshot choice, process restart,
Kubernetes immutable rollout, fixed-member Admin rollout, confinement block,
or invalid candidate is explicit rather than represented as zero downtime.
Offline planning uses two production-loaded files; online planning adds active
runtime, listener, deployment, authorization, and bounded confinement context.

Planning never executes activation. It does not prepare or bind listeners,
publish a snapshot, drain connections, restart a process, mutate Kubernetes,
create rollout artifacts, or grant protected-write authority. Secret changes
are detected with process-local domain-separated HMAC equality tags and exposed
only as redacted change facts. Listener feasibility accounts for additions,
removals, rebinds, same-bind conflicts, HTTP/QUIC socket compatibility, TURN,
and the effective graceful/long-connection close bounds; unknown external port
ownership remains conditional. The fully resolved filesystem-access manifest
classifies exact paths, scopes, access rights, purposes, parent operations, and
optional entries, and the online planner compares those requirements with the
process-installed Landlock policy and captured mount evidence. Equal/subset
requirements fit, expansion requires restart or rollout, and an incompatible
required path, mount, or ABI right blocks activation. Seccomp fit uses the
kernel-observed filter and `no_new_privs` values plus a separately labeled
orchestrator assertion; requested settings and checked-in profiles are not
runtime evidence.

Reload apply behavior is failure-safe: invalid TOML, invalid rules, invalid certificate/key pairs, unreadable files, failed upstream client setup, failed database access-log setup, or failed listener binds leave the previous active state in place. Successful reloads publish a new data-plane snapshot and gracefully drain HTTP connections that captured the previous snapshot, even when listener binds do not change. Successful full reloads also activate replacement listeners before old listener generations drain, so readiness remains OK for the active instance while in-flight requests on the old generation finish. HTTP/1.1 and HTTP/2 listener or snapshot-generation drain asks Hyper to gracefully close old connections; HTTP/3 stops accepting new streams and sends graceful connection shutdown before its endpoint closes after the graceful timeout when a listener generation is retired. Upgraded tunnels, WebTransport, and TCP stream bridges are protected by the configured long-connection close delay, but new request streams received by a drained WebTransport HTTP/3 bridge are rejected instead of being evaluated against the old snapshot.

Kubernetes-native immutable rollout mode is intentionally outside this
in-process reload model. It requires `runtime.hot_reload.mode = "off"` and a
Pod-assigned immutable revision/digest. The data plane proves the exact mounted
generated include before startup succeeds, and its readiness remains false
until the assigned and applied revisions match.

High-risk Admin mutations can require a signed, expiring
`X-OxiBelt-Mutation` envelope backed by a PostgreSQL replay ledger. The strict
envelope binds a canonical request UUID, authenticated principal, method,
path/query, exact-body SHA-256 digest, previous and new logical revisions, and
required deterministic rollout target. Exact duplicates return a reduced,
bounded safe result with the retained HTTP status, without applying the side
effect again; the replay body need not match the first response. Conflicting request-ID reuse, expired
requests, stale revisions, digest mismatches, invalid signatures, unavailable
critical audit, and indeterminate prior commits fail closed. `If-Match`
is normalized from one strong quoted operational ETag, required to match the
active revision, and included in the signed transcript. The distinct signed
previous/new revisions belong to the durable
mutation ledger's logical revision chain.

The baseline signature suite is Ed25519. Builds with the post-quantum mutation
feature may require `ed25519_ml_dsa_44`, which verifies independent Ed25519 and
ML-DSA-44 signatures over the same suite-bound transcript and never
downgrades. Signer public keys are bound to IPM principals; private signing
keys remain outside the OxiBelt process.

`admin.mutations.rollout.mode = "admin_cluster"` is a PostgreSQL-backed,
fixed-member, all-ACK rollout authority for the protected mutation families.
It requires required signed mutations, same-backend enforcing audit, disabled
hot reload, an exact membership containing the local instance, and a shared
artifact-encryption key. Admission atomically records the signed bindings,
encrypted command, and exact target set. Every member validates; a
deterministic canary applies and passes a bounded observation interval; the
remaining members then apply. The request cannot return normal success and the
logical head cannot advance until every configured member has durably ACKed the
exact revision and digest.

Database-time leases and monotonic member/coordinator epochs fence cluster,
membership, instance, boot, logical revision, and artifact identity. Durable
assignments are the restart source of truth. NACK, timeout, readiness loss, or
evidence mismatch rolls back every possibly applied target. If neither the
candidate nor prior state can be proved across all members, the terminal state
is `indeterminate` and subsequent protected writes remain blocked. A client
disconnect does not cancel ordinary durable work; an exact duplicate while
active receives `409 mutation_in_progress` plus the receipt location. A
credential create/rotate that can emit a one-time token instead binds every
forward phase to a cancellation-safe response owner on the admission origin.
Because token plaintext is neither durable nor replayable, owner loss fails or
rolls back, and admission-origin restart cannot become a committed token-loss
success. Kubernetes immutable
rollout remains a separate workload-controller authority and does not
participate in this protocol.

The lifecycle drain configuration is:

- `runtime.drain.graceful_timeout_ms`: maximum listener-generation drain time, greater than zero.
- `runtime.drain.long_connection_close_delay_ms`: delay before force-closing long-lived upgrade, CONNECT, WebTransport, or TCP stream bridges after drain, greater than zero.
- `runtime.drain.shutdown_delay_ms`: optional delay after process shutdown marks the instance draining and before listeners begin draining; `0` is allowed.

Operational endpoints are optional:

- `[health]` exposes local readiness and liveness endpoints. Readiness returns `503` while an active-generation critical runtime subsystem is unavailable or a restartable-critical task has not recovered; liveness remains process-only and does not fail for a contained connection panic or a restartable task.
- `[metrics]` exposes Prometheus-style metrics. Basic mode keeps aggregate counters and gauges, including fixed-label `oxibelt_runtime_panics_total`, `oxibelt_runtime_task_restarts_total`, `oxibelt_runtime_task_state`, `oxibelt_runtime_lock_recoveries_total`, and `oxibelt_runtime_subsystem_state` series. Detailed mode adds bounded route/upstream/method/status/protocol/cache-reason style labels for HTTPS, HTTP/1.1, HTTP/2, HTTP/3 over QUIC, WebSocket, WebTransport, WebRTC TURN, and SNI-forwarding decision/session surfaces. Rule-level WAF names, IDs, tags, modes, routes, hit counters, and cost counters are intentionally excluded from this unauthenticated endpoint; use the authenticated admin WAF telemetry endpoint for rule-level snapshots.
- `[overload]` is an opt-in process-wide availability guard. It samples bounded process/resource and fixed-vocabulary work signals with soft-entry and recovery hysteresis. Soft pressure suppresses new cache fills, caps compression, reduces retries, and sheds only configuration-assigned background/crawler routes. Hard pressure refuses new public connections and HTTP streams/requests, rejects large or unknown-length request bodies before reads, disables nonessential work, enters a recoverable lifecycle drain, sends HTTP/1 `Connection: close` with the configured generic `5xx`/`Retry-After`, and preserves separately bounded health, metrics, and Admin listener capacity. Those dedicated control-plane connection/request bounds apply even when overload pressure sampling is disabled. HTTP/2 sends graceful connection shutdown and HTTP/3 sends graceful connection shutdown on lifecycle drain; liveness remains available while configured readiness reports overload. Client request priority metadata never grants a reserved class.
- `[circuit_breakers]` is an enabled-by-default, process-local bounded-admission layer. Global and configured route/pool capacity are intersected; queues are FIFO, timeout-bounded, cancellation-safe, and return generic `503`/`Retry-After` without changing readiness or forcibly closing HTTP/1. Its global downstream request boundary also has fixed priority classes: low-priority `background` and `crawler` traffic are share-capped by default, per-class queues and rejection policy are bounded, and strict request reservations are removed from shared capacity. A public route may use such a reservation only after independent local IPM authorization or a verified TCP TLS client-certificate match; route labels and client headers never create that authority. Dedicated Admin, health, and metrics listener slots remain separate from public route reservations. Upstream route/pool circuits use bounded failure windows plus consecutive-failure triggers, timed open state, and limited half-open probes. Retry attempts share a proportional retry budget and a single upstream deadline; automatic client-library retries are disabled so attempts remain observable and budgeted. Per-server passive health/outlier ejection remains independent from aggregate route/pool circuit state.
- `[telemetry.tracing]` is optional observability: it extracts incoming W3C `traceparent`, propagates trace context to upstream HTTP/1.1, HTTP/2, HTTP/3, and WebTransport CONNECT requests, and exports sampled spans to an OTLP HTTP/protobuf collector. Full hot reload and admin config load rebuild telemetry tracing from the replacement configuration; old-generation connections may keep the previous telemetry runtime only until their captured snapshot drains. Operator runbook and dashboard assets are documented in [Observability.md](Observability.md).
- `[admin]` exposes authenticated operations APIs such as OpenAPI metadata, cache purge, upstream-pool and stream-pool runtime control, dynamic policy automation, IPM management, config validation/load/rollback, explicit file sync, downstream TLS reload, and lifecycle drain/undrain on a dedicated listener. Plaintext admin traffic is loopback-allowlisted by default; non-loopback admin traffic uses TLS unless the operator explicitly configures a plaintext source allowlist. IPM (Identity Permission Management) authorizes Admin operations and opt-in data-plane routes with `Action`, `Resource`, and `Condition` policy statements; explicit deny wins, matching allow permits, and the default is deny. Opt-in `[admin.workload_identity]` applies only to Admin TCP TLS and Admin HTTP/3: a chain-verified mTLS certificate's exact SPIFFE/URI/DNS SAN maps to one effective IPM principal, and any bearer or break-glass credential must resolve to that same principal. Its optional bearer mode permits the mapped certificate alone. The legacy Admin RBAC `roles`, `permissions`, and `deny_permissions` model is rejected. Full hot reload starts, stops, or rebinds this listener when admin listener settings change.
- `[admin.mutations]` controls replay protection for configuration load/rollback, file sync, downstream TLS key reload, submitted typed secret-reference update, IPM writes, and break-glass activation/revocation. Active modes require PostgreSQL plus durable Admin audit coverage for every protected action on the same backend. A local fsynced-spool acknowledgement does not replace the P1-13 PostgreSQL replay ledger or transactional critical audit rows. Atomic secret-reference activation is available with mutation protection `off`, `optional`, or `required` in mutable `single_instance` mode and with required protection in fixed-member `admin_cluster` mode; Kubernetes immutable rollout mode rejects it with `409 immutable_rollout_conflict`. The ledger and audit records retain only bounded redacted results. Credential create/rotate returns a token only on first execution; an exact replay cannot re-emit it and reports `token_recoverable = false` in the reduced safe result.
- `[admin.operations]` controls the bounded long-running Admin operation runtime. `persistence = "postgres"` makes the PostgreSQL journal the API authority and requires the same backend as enforcing Admin audit; `auto` activates that authority when its prerequisites are available and otherwise exposes a bounded ephemeral fallback, while `ephemeral` is always process-local. Durable rows contain authenticated and redacted identities, keyed idempotency digests, explicit recovery classes, monotonic revisions, boot-bound fenced leases, bounded progress, encrypted command/checkpoint artifacts, safe error classes, terminal receipts, and bounded expiry/retention. Restart recovery may resume, restart, compensate, or mark an ambiguous operation `indeterminate`, but never infers success. Process-local WebTransport snapshot and drain operations remain explicitly ephemeral.
- `oxibelt-gateway-controller` is an optional Kubernetes control-plane binary. It watches Gateway API v1 `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute`, `TLSRoute`, `TCPRoute`, `UDPRoute`, `BackendTLSPolicy`, `ReferenceGrant`, `Service`, and exact referenced public-CA ConfigMaps; renders deterministic controller-owned TOML and public CA assets containing HTTP/gRPC routes and pools, Gateway HTTP external auth, bounded route actions, passthrough SNI rules, and raw TCP/UDP listeners and pools; validates the full artifact; and publishes a content-addressed immutable ConfigMap. TCPRoute and UDPRoute support one rule, protocol-compatible weighted core Service backends, exact parent/listener and ReferenceGrant enforcement, and oldest-creation-time winner selection without invalid-winner fallback. BackendTLSPolicy supports one same-namespace Service target with a required hostname and either System trust or one ConfigMap `ca.crt`; SAN overrides, options, Secret client identities, mTLS, and pins are rejected rather than approximated. Multiple replicas use an exact-name `coordination.k8s.io/v1` Lease; only the current `(Lease UID, leaseTransitions, holderIdentity)` term may publish, patch, roll back, clean up, or mutate status. It only patches an opt-in named Deployment or DaemonSet and commits Gateway `Programmed` status after a fresh resource-version-guarded source snapshot, selected workload UID/generation/resource version, immutable digest, exact controller-owner Pod UID chain, and current leadership proof agree. Persisted workload annotations and immutable ConfigMaps make replacement-leader recovery independent of process memory. A newly invalid or unauthorized route/reference produces a sanitized revision rather than retaining stale authority; global snapshot, authorization, artifact, and final-validation failures roll back to the last committed ConfigMap. The base HTTP/HTTPS listener, downstream TLS, Admin/IPM, ACME/certificate lifecycle, `[sni_forward].enabled`, and public Service ports remain operator-owned. Raw TCP/UDP payloads bypass the HTTP WAF. Generated `UDPRoute` listeners are refused unless the controller is explicitly set to `shared_required` and every selected data-plane Pod has the matching shared-state configuration.
- `[access_log]` controls request-wide, WAF, and Admin API access-log sources and projects records to Open Cybersecurity Schema Framework (OCSF) or Elastic Common Schema (ECS) JSON on stdout or OpenTelemetry Logs HTTP/protobuf. OCSF is the default projection for each sink; ECS is an opt-in alternative.
- `[logging.access_log]` keeps the request-wide field-expression list and legacy `enabled` compatibility flag for `scope = "system"` records. PostgreSQL access-log sinks are removed and `database.access_log` or `logging.access_log.database` fails configuration loading.
- OxiRule `emit_access_log` writes records with `scope = "waf"` into the shared access-log runtime, and `[access_log.stdout]` or `[access_log.otlp]` emits OCSF HTTP Activity JSON or ECS HTTP/security JSON for those records.
- Admin audit events are structured first-class Admin events. Canonical modes are `best_effort`, `durable_required`, and `durable_required_for_actions`; legacy `enforcing` aliases `durable_required`. Required events synchronously acknowledge either a PostgreSQL insert or an atomic, bounded, fsynced local-spool append before the protected side effect. A full or invalid spool, unavailable PostgreSQL acknowledgement, oversized event, or integrity/I/O failure rejects required work with `503`. The spool defaults to 64 MiB, 16,384 records, and 64 KiB per event, never evicts unacknowledged evidence, and replays idempotently to the optional PostgreSQL query store. Every `oxibelt.admin.audit/v1` event includes occurrence/event/instance identity, lifecycle phase, actor/workload/credential/source identity, action/revisions/content digest/result/error metadata, a redacted summary, and a domain-separated SHA-256 chain envelope; an optional exactly-32-byte base64 HMAC key authenticates the chain. Opt-in external anchoring transactionally accumulates per-instance chain ranges in a bounded PostgreSQL outbox, signs `oxibelt.admin.audit.checkpoint/v1` metadata with a purpose-bound Ed25519 keysigner key, and submits a predecessor-linked checkpoint to a separately administered PostgreSQL authority. Required anchoring withholds required-operation success and fails readiness until an authority receipt covers the event; best-effort anchoring retains pending evidence and reports degraded state. `[admin.audit.export]` remains best-effort OCSF/ECS stdout or OTLP observability. Historical PostgreSQL rows are exposed as `legacy-v0` without fabricated integrity data. `GET /admin/v1/audit` returns `409` without a query store and `503` when the configured store cannot be queried. When workload binding is active, raw certificates, bearer tokens, bodies, signatures, and keys are not retained.
- An external checkpoint contains namespace, deterministic stream and stable instance identity, optional cluster identity, membership/deployment epochs, checkpoint ordinal, local chain ID/range/head, predecessor digest, timestamps, signing-key identity, signature, and checkpoint digest, but no Admin event payload. The authority accepts only an exact replay or the next predecessor-linked ordinal. `oxibeltctl audit verify` uses operator-owned expected-stream inventory and trusted raw Ed25519 public keys to verify local event chains, checkpoint signatures/continuity, authority heads, and a separately retained monotonic witness. This detects rewriting or deletion at or before a witnessed checkpoint; it does not prove an uncheckpointed tail existed, discover streams omitted from the expected manifest, or survive simultaneous compromise of all evidence and witness authorities.
- Fsynced-spool admission reserves one record and `max_event_bytes` for the matching terminal Admin audit event before the handler runs, so concurrent evidence cannot consume outcome capacity after a required side effect is admitted.
- Admin API access logs use `scope = "admin"` when `[access_log.admin].enabled = true` and include safe operation, actor/principal/subject, IPM result, method, path, status, and request-summary metadata from the fine-grained token and TLS-secured Admin API audit path.

Runtime task failure policy is explicit. Public, Admin, operations, stream, and TURN connection futures are contained per connection, so one panic is counted and ends only that connection task. The health listener is fatal because losing the process-health endpoint requires process-level recovery. The metrics listener is restartable-optional. Active pool health, enabled overload sampling, and configured upstream discovery are restartable-critical; when their feature is inactive they remain restartable-optional. Restartable tasks use exponential delay from `100ms` through `30s`, report healthy after `5s` of stable execution, and reset backoff after `60s` of uninterrupted execution.

Poison handling follows subsystem ownership. Disposable request caches and registries are cleared or atomically replaced; disk response-cache reconstruction advances at most 256 directory entries per access and stops after 16,384 scanned entries. Admission, circuit-breaker, and other security-critical state fails closed and makes readiness fail instead of using poisoned data. Published application, policy, IPM, and ASN snapshots use atomic replacement so request reads do not acquire poisonable reader locks. The redacted support-bundle health section reports `runtime_status`, degraded/failed subsystems, and degraded/failed tasks for the active snapshot generation.

Lifecycle endpoints are:

- `GET /admin/v1/openapi.json`: requires `admin:ReadMetadata` on `metadata/openapi`, returns the canonical OpenAPI 3.1 Admin API contract embedded from `source/assets/admin-openapi.json`.
- `GET /admin/v1/capabilities`: requires `admin:ReadMetadata` on `metadata/capabilities`, returns API version, package version, feature flags, active mTLS workload-identity mode, Admin request-size limits, and bounded audit-anchoring policy/state/progress without authority, signer, credential, or event data.
- `GET /admin/v1/version`: requires `admin:ReadMetadata` on `metadata/version`, returns API version, package name/version, source revision, Person Proof API version, and SHA-256 identities for the embedded Person Proof and Admin OpenAPI assets.
- `GET /admin/v1/config/status`: requires `config:GetStatus`, returns active config revision, resolved operational-profile name/version when selected, ETag, rollback availability, and last admin operation status; immutable-rollout Pods additionally report their instance ID, rollout mode, desired/applied revision, raw digest, and apply state.
- `GET /admin/v1/config/instances`: returns the canonical fixed membership, durable authority/blocking state, active rollout summary, and bounded per-instance configured/live/ready/compatible revision, digest, and lease evidence. It is diagnostic; guarded terminal commit is convergence proof.
- `GET /admin/v1/mutations/{request_id}`: returns the caller-authorized redacted durable mutation receipt.
- `GET /admin/v1/config/effective`: requires `config:GetEffective`, returns the redacted active effective TOML and ETag, including the canonical profile/version and injected v1 defaults when a profile is selected.
- `POST /admin/v1/config/validate`: requires `config:Validate`, validates submitted TOML against the active path roots without installing it.
- `POST /admin/v1/config/diff`: requires the secret-equivalent `config:DiffSecrets` authority, preserves the redacted ordered `path`/`op` diff and returns activation-plan schema version `3` with per-field classification plus aggregate listener, connection, confinement, deployment, prerequisite, and rollback plans. Confinement emits at most 64 report-local, subject-tagged filesystem or seccomp differences; seccomp assertions never receive a fabricated path. Stable path-derived manifest and policy digests are withheld from this redacted surface. The policy-valid legacy `config:Diff` action does not authorize this endpoint. It accepts no apply authority and performs no mutation. Exact fixed-member target identities additionally require `config:GetInstances` on `instances/current`.
- `POST /admin/v1/config/load`: requires `config:Load` and matching `If-Match`, installs a runtime-only config snapshot. Changes to `[admin]` additionally require `admin:UpdateConfig` on `oxibelt:<namespace>:admin:config`; changes to `[ipm]` additionally require `ipm:UpdateConfig` on `oxibelt:<namespace>:ipm:config`. Kubernetes-native immutable rollout Pods reject this local mutation with `409`.
- `POST /admin/v1/config/rollback`: requires `config:Rollback` and matching `If-Match`, restores the last-good runtime snapshot. Rollbacks that change `[admin]` or `[ipm]` require the same protected config update actions as config load. Kubernetes-native immutable rollout Pods reject this local mutation with `409`.
- `POST /admin/v1/files/sync`: requires matching `If-Match`, writes an all-or-nothing batch under configured config/OxiRule roots, and can apply `none`, `oxirule`, `full`, or `downstream_tls`. Config-root writes require `config:SyncFiles`; OxiRule and OxiRule group writes require the matching `waf:PutOxiRule`, `waf:DeleteOxiRule`, `waf:PutOxiRuleGroup`, or `waf:DeleteOxiRuleGroup`. OxiRule file-sync roots are suffix-bound: `oxirule` accepts `.oxirule.toml` paths and `oxirule_group` accepts `.oxirule-group.toml` paths. `apply = "oxirule"` requires `waf:ReloadOxiRule`. Config-root writes and `apply = "full"` are prechecked so staged or disk-candidate `[admin]` and `[ipm]` changes require the protected config update actions before files are committed. Kubernetes-native immutable rollout Pods reject this local mutation with `409`.
- `POST /admin/v1/keys/rotate`: verifies and reloads only a digest-pinned, pre-provisioned default or SNI downstream TLS key path; raw key material is rejected.
- `POST /admin/v1/config/secret-references/update`: requires
  `config:UpdateSecretReference` on
  `secret-reference/<encoded-field>` and matching `If-Match`; accepts one
  schema-version-1 allowlisted environment or contained, digest-pinned file
  reference without accepting a secret value; preflights the complete resolved
  reference set and its dependent runtimes; and atomically installs the
  candidate in mutable `single_instance` or fixed-member `admin_cluster` mode.
  It returns `200` with only bounded revision/digest bindings on success; `400`
  for malformed, unsupported, non-allowlisted, or invalid references; `401`
  for invalid authentication or mutation-signer identity; `403` for failed IPM
  authorization or a forbidden file; `409` for immutable rollout, activation,
  preflight, snapshot, or mutation conflicts; `412` for a stale `If-Match`;
  `413` above the request limit; `428` when `If-Match` or required mutation
  metadata is missing; and `503` when a provider, entropy source, mutation
  store, audit authority, or cluster rollout dependency is unavailable.
- `GET /admin/v1/break-glass/activations/self`, `POST /admin/v1/break-glass/activations`, and `POST /admin/v1/break-glass/activations/{id}/revoke`: inspect, create, or revoke the authenticated principal's bounded two-factor break-glass activation.
- `GET /admin/v1/tls/downstream`: requires `config:ReadDownstreamTls`, returns downstream TLS material status.
- `POST /admin/v1/tls/downstream/reload`: requires `config:ReloadDownstreamTls` and matching `If-Match`, reloads configured certificate, key, and static OCSP files from disk or rebuilds the live OCSP runtime. Kubernetes-native immutable rollout Pods reject this local mutation with `409`.
- `GET /admin/v1/tls/upstream`: requires `config:ReadUpstreamTls`, returns bounded outbound revocation runtime status.
- `POST /admin/v1/tls/upstream/refresh`: requires `config:RefreshUpstreamTls`, refreshes known outbound OCSP cache contexts and returns bounded runtime status.
- `GET /admin/v1/lifecycle`: requires `lifecycle:Get`, returns draining state and reason.
- `POST /admin/v1/lifecycle/drain`: requires `lifecycle:Drain`, starts admin drain.
- `POST /admin/v1/lifecycle/undrain`: requires `lifecycle:Undrain`, clears admin drain.
- `GET /admin/v1/diagnostics/support-bundle?redact=true`: requires `diagnostics:ReadSupportBundle`, returns a redacted JSON support bundle with config status, redacted effective config when available, doctor output, runtime snapshot, WAF telemetry summaries, dynamic-policy summary, and Prometheus text. Optional `external_probe=KIND` query parameters require the same probe permissions as diagnostics preflight.
- `GET /admin/v1/runtime/snapshot?redact=true`: requires `runtime:ReadSnapshot`, returns the redacted runtime snapshot section used by the support bundle.
- `GET /admin/v1/runtime/introspection?redact=true`: requires `runtime:ReadIntrospection`, returns the redacted runtime snapshot plus live active counters for downstream connections, HTTP/1.1 requests, HTTP/2 streams, HTTP/3 requests, WebSocket tunnels, WebTransport sessions, stream listener TCP connections, stream listener UDP flows, and TURN TCP/TLS connections.
- `GET /admin/v1/waf/rule-hits`, `GET /admin/v1/waf/rule-costs`, and `GET /admin/v1/waf/crs/compatibility`: require the matching `waf:GetRuleHits`, `waf:GetRuleCosts`, and `waf:GetCrsCompatibility` actions.
- `POST /admin/v1/waf/rulepacks/plan`: requires `waf:PlanOxiRulePack`; route candidate inventory additionally requires `config:ReadRouteInventory`, content diff additionally requires `waf:ListOxiRulePacks`, and cost estimation additionally requires `waf:EstimateOxiRuleCost`. The endpoint is non-mutating, accepts schema version `2` rulepacks only, and returns route candidates without upstream origins, credentials, TLS details, token environment variables, or file paths.
- `POST /admin/v1/waf/oxirule/check`, `test`, `explain`, `cost`, and `replay`: require `waf:CheckOxiRule`, `waf:TestOxiRule`, `waf:ExplainOxiRule`, `waf:EstimateOxiRuleCost`, or `waf:ReplayOxiRule`; `check` also requires `waf:CheckOxiRuleGroup` when group candidates are supplied. Requests with `include_active_rules = true` require the same action on `oxirule/*`, except replay uses `replay/*`. These endpoints are synchronous, stateless, and never write OxiRule files.
- `GET /admin/v1/waf/oxirule/templates`, `POST /admin/v1/waf/oxirule/templates/render`, and `POST /admin/v1/waf/oxirule/false-positive`: require `waf:ListOxiRuleTemplates`, `waf:RenderOxiRuleTemplate`, and `waf:PlanOxiRuleFalsePositive`; they list/render built-in templates or return tuning suggestions without changing configuration.
- `GET /admin/v1/upstream-pools/status`: requires `upstream-pool:GetStatus` on `status/current`, returns the upstream-pool runtime generation and ETag used by server mutations.
- `POST/PATCH/DELETE /admin/v1/upstream-pools/{pool}/servers...`: require the matching upstream-pool server action and `If-Match` with the upstream-pool status ETag; missing ETags return `428`, stale ETags return `412`.
- `GET /admin/v1/stream-pools/status`: requires `stream-pool:GetStatus` on `status/current`, returns the stream-pool runtime generation and ETag used by TCP/UDP stream-pool server mutations.
- `GET /admin/v1/stream-pools` and `GET /admin/v1/stream-pools/{pool}`: require `stream-pool:List` or `stream-pool:Get` and return active stream-pool snapshots with server origin, state, active count, and health marker fields.
- `POST/PATCH/DELETE /admin/v1/stream-pools/{pool}/servers...`: require the matching stream-pool server action and `If-Match` with the stream-pool status ETag; missing ETags return `428`, stale ETags return `412`.
- `GET /admin/v1/dynamic-policies/status`: requires `dynamic-policy:GetStatus` on `status/current`, returns the PostgreSQL-backed dynamic-policy generation and ETag.
- `POST /admin/v1/dynamic-policies`, `POST /admin/v1/dynamic-policies/import`, `PATCH /admin/v1/dynamic-policies/{id}`, and `DELETE /admin/v1/dynamic-policies/{id}`: require matching `If-Match` with the dynamic-policy status ETag; missing ETags return `428`, stale ETags return `412`. `POST /admin/v1/dynamic-policies/apply` accepts optional `If-Match`: omitted ETags are allowed, supplied stale ETags return `412`.

Admin and process drain make readiness return `503 draining`, keep liveness `200 live`, and reject new data-plane requests with `503 draining` plus `Connection: close`. Existing in-flight requests continue. On Unix, `SIGUSR1` enters the same drain-only state without exiting, so a local supervisor can withdraw readiness and allow the ordinary/long-lived windows to run before final termination. HTTP/2 uses graceful shutdown/GOAWAY and HTTP/3 sends graceful connection shutdown while refusing new streams. `SIGTERM` and Ctrl-C follow the final shutdown sequence: mark or retain draining, wait `shutdown_delay_ms`, then drain listeners up to `graceful_timeout_ms`.

For Kubernetes Deployments, the chart's optional managed distribution adds
release-scoped hostname `DoNotSchedule` spread with `maxSkew: 1` and
`minDomains: 2`, best-effort zone `ScheduleAnyway` spread with `maxSkew: 1`,
and preferred same-release hostname anti-affinity. A PDB uses exactly one of
`minAvailable` or `maxUnavailable`; the secure companion selects three replicas
and `maxUnavailable: 1`. Its chart-owned pre-stop hook sends `SIGUSR1` and
waits 300 seconds within a 360-second termination grace. Kubernetes-only
placement policy is not added to DaemonSets, which already have one Pod per
eligible node; their secure rollout uses zero unavailable plus one surge.
The generic managed spread policy requires Kubernetes 1.30 or later and the
secure companion requires Kubernetes 1.31 or later. QUIC connection state is
process-local: clients may migrate addresses only while the original Pod is
alive and must reconnect when a Pod is replaced; HTTP/3/WebTransport session
state never transfers between replicas.

## Configuration and Path Model

The main configuration file is selected with `--config`. The default repository example is:

```sh
source/config/oxibelt.toml
```

The release container expects:

```sh
/etc/oxibelt/config/oxibelt.toml
```

Container deployments use purpose-specific directories:

```text
/etc/oxibelt/config   TOML configuration and included modules
/etc/oxibelt/cert     certificates, private keys, CA roots, OCSP, ECH files
/etc/oxibelt/oxirule  external .oxirule.toml files
```

Configuration includes are resolved relative to the file that declares them. Runtime files are resolved by purpose: TLS, CA, OCSP, database TLS, and ECH files under the cert directory; external OxiRule files under the oxirule directory.

Relative paths must be normalized, must not contain `.` or `..` components, and must resolve to existing regular files under the correct purpose-specific directory.

Native TOML has a build-validated, machine-readable JSON Schema identified by
an integer epoch. The schema supplies structural types, selected enums and
bounds, deprecation/replacement annotations, secret-reference classification,
and activation metadata. It is generated from the same checked key metadata
used by strict unknown-field validation, and CI compares the generator output
byte-for-byte with the embedded versioned artifact. The schema is intentionally
not a replacement for production validation: include expansion, operational
profile expansion, relative-path confinement, typed decoding, and cross-field
security checks remain `Config::load` and `Config::validate` responsibilities.

Configuration diagnostics and schema epochs evolve independently. Within an
epoch, incompatible structural changes are prohibited. Therefore,
incompatible shape changes require a new epoch and explicit migration.
Migration is local,
deterministic, comment-preserving where `toml_edit` permits,
ambiguity-rejecting, and validated against the original path roots before a
separate review tree is published. Admin explain operations consume the
already redacted effective configuration and never recover secret material.

## Non-Goals and Reserved Work

OxiBelt intentionally leaves these out of scope by design:

- ACME challenge handling, including HTTP-01 and DNS-01.
- General-purpose scripting, imports, loops, callbacks, and unbounded comprehensions.

Provision and renew public TLS certificates outside OxiBelt with an ACME client such as Certbot or Lego. Containerized deployments may use the `certbot/certbot` or `goacme/lego` Docker images and mount the generated certificate material into OxiBelt's cert directory.

Security rationale: ACME account keys, DNS provider API tokens, and challenge credentials should live outside the OxiBelt process and container trust boundary. If a proxy vulnerability ever allowed remote code execution, memory disclosure, or a logic error that exposed OxiBelt process state, the compromised proxy should not also hold credentials that can issue arbitrary new TLS certificates. DNS-01 credentials are especially sensitive because a stolen DNS provider token can affect certificate issuance for every zone or name that token can modify.

The current implementation reserves or defers this work:

- CRS stream-payload inspection for WebSocket and WebTransport traffic.
- Downstream ECH configuration.

See [FeatureStatus.md](FeatureStatus.md) for the canonical supported,
experimental, reserved, and removed feature matrix.
