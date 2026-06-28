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

OxiBelt currently targets Rust 1.96 and uses `rustls` with the `aws-lc-rs` crypto provider. The default downstream TLS 1.3 key exchange group set enables `X25519MLKEM768`, `X25519`, `secp256r1`, and `secp384r1`; downstream TLS 1.3 and TLS 1.2 cipher suites can be restricted with `tls.1_3.ciphers` and `tls.1_2.groups`. Deployments can omit the hybrid group with `tls.1_3.key_exchange_groups` when cold-handshake CPU cost matters more than post-quantum hybrid negotiation.

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

Data-plane TCP listeners can run one or more accept workers inside a single OxiBelt process. Runtime worker threads, TCP accept workers, and QUIC socket workers accept explicit positive counts or `"auto"`. Auto counts use Rust `std::thread::available_parallelism()`, apply the relevant `[runtime.worker_multipliers]` value, round up, and fall back to one worker if detection fails. Default multipliers are `runtime = 1.0`, `accept = 0.5`, and `quic_socket = 1.0`, so TCP accept loops are more conservative by default while runtime and HTTP/3 socket workers continue to track available parallelism. Explicit configs, including `runtime.worker_multipliers.accept = 1.0`, take precedence. When the resolved TCP accept count is greater than one, `runtime.accept.reuse_port = true` is required and OxiBelt creates a `SO_REUSEPORT` socket per worker so the kernel can distribute accepts. Downstream HTTP/3 can similarly create multiple UDP endpoints with `quic.socket.workers > 1` and `quic.socket.reuse_port = true`. Full hot reload rejects changes to `runtime.worker_threads`; listener worker changes can be applied by rebinding listeners. Kernel sysctl and file-limit changes are not applied by the OxiBelt binary; the optional `kernel-extension/` installer stages those Linux 7.0.x+ host tunings separately, with PAM `nofile` limits scoped to the `oxibelt` service account.

## Protocol Behavior

Downstream protocol support:

- HTTP/1.1 and HTTP/2 are served over TCP.
- HTTP/3 is served over QUIC on every configured `https_binds` UDP address. IPv6 listener sockets are IPv6-only, so dual-stack deployments configure explicit IPv4 and IPv6 binds.
- `[sni_forward]` can inspect visible TLS ClientHello SNI before OxiBelt terminates local traffic. Explicit SNI forwarding rules override local route hosts; otherwise configured route hosts remain local, and unknown SNI forwards only when `sni_forward.default_target` is configured. Missing, malformed, or unparseable SNI fails closed. Route host `"*"` does not count as a defined SNI name. QUIC SNI forwarding bounds pre-classification session state and local datagram queues with `[sni_forward]` limits.
- TCP SNI forwarding uses bounded `TcpStream::peek`, preserving the original ClientHello for raw TCP passthrough targets. Local matches continue through the normal rustls HTTP/1.1 and HTTP/2 path. Forwarded TCP sessions keep the accepted connection's global lease and, in Real-IP connection-limit modes, acquire the normal per-IP and named leases for the post-PROXY-protocol peer address before tunneling.
- QUIC SNI forwarding uses the same UDP addresses as downstream HTTP/3. OxiBelt decrypts QUIC Initial payloads, extracts CRYPTO frames, parses visible ClientHello SNI, and forwards matched sessions as UDP passthrough while local sessions are queued into Quinn. Forwarded QUIC sessions acquire the same total, per-IP, and named downstream connection leases as local HTTP/3 connections. QUIC SNI forwarding requires downstream HTTP/3 to be enabled.
- `[[stream_listeners]]` can bind dedicated TCP or UDP L4 listener addresses. TCP listeners preserve backward-compatible direct `target = "host:port"` configs and can also select `[[stream_upstream_pools]]`; UDP listeners pin each downstream client flow to a selected direct target or UDP pool server until idle expiry or capacity eviction. Stream payloads stay passthrough: OxiBelt does not terminate TLS, perform HTTP routing, run WAF payload inspection, or emit UDP PROXY protocol egress on these listeners.
- Stream listener `sni_rules` classify only visible TCP TLS ClientHello SNI or UDP QUIC Initial SNI. Matching rules select a direct target or stream pool; no-SNI, malformed, or non-TLS/non-QUIC flows use the listener default target/pool when configured and otherwise fail closed.
- Deployments that enable HTTP/3 must expose every HTTPS bind address for both TCP and UDP.
- Downstream HTTP/3 always requires TLS 1.3.
- The same downstream client certificate policy is enforced for TCP TLS and HTTP/3/QUIC listeners.
- QUIC Retry/address validation can be enabled with `quic.retry`.
- HTTPS HTTP/1.1 and HTTP/2 responses advertise HTTP/3 with `Alt-Svc` when downstream HTTP/3 and `quic.alt_svc.enabled` are both enabled. OxiBelt does not add that header on HTTP/3, plain HTTP, or `101 Switching Protocols` responses.
- TLS early data is disabled by default. `tls.ssl_early_data` and `routes.tls.ssl_early_data` accept `off`, `safe_methods`, and `on`; `safe_methods` permits only transport-verified `GET` and `HEAD`, while `on` accepts replayable requests for routes that explicitly tolerate replay. TCP TLS early data requires TLS 1.3 stateful resumption and is not supported with multi-certificate SNI selection. HTTP/3 0-RTT transport admission remains controlled by `quic.zero_rtt`. Disallowed transport-verified early-data requests receive `425 Too Early`; accepted requests get a verified upstream `Early-Data: 1` header, and untrusted downstream `Early-Data` headers are stripped.
- `quic.host_key_file` provides deployment-local host key material for stateless reset and Retry/validation tokens. It is cert-directory relative and hot-reload tracked; release images do not include shared key material.

Upstream protocol support:

- HTTP/1.1 supports `http://` and `https://` origins.
- HTTP/2 over `https://` uses TLS ALPN.
- HTTP/2 over `http://` uses h2c with prior knowledge.
- HTTP/3 requires an `https://` upstream origin.
- Ordinary upstream HTTP/3 forwarding uses a per-upstream QUIC connection pool and multiplexes requests over pooled HTTP/3 connections when `quic.upstream_pool.enabled = true`; when disabled, each ordinary HTTP/3 upstream request uses a one-shot QUIC connection. WebTransport uses a dedicated upstream QUIC connection per session.
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

Downstream response compression is controlled by `[compression]` and optional route-level `compression` policy references. Support for `br`, `zstd`, `gzip`, and `deflate` is enabled by default, but OxiBelt only transforms responses when the downstream `Accept-Encoding`, request credential headers, response status, MIME type, size, existing response headers, and range/no-transform semantics allow it. Requests carrying `Cookie`, `Authorization`, or `Proxy-Authorization`, and responses carrying `Set-Cookie`, `Cache-Control: private`, or `Cache-Control: no-store`, are not compressed. `level` applies one nginx-style `1..9` quality setting to all enabled encoders. Requests carrying `Via` must also match the configured `proxied` predicates before dynamic compression is allowed; these predicates do not override credential or private/no-store response hardening. Dynamic compressed responses set `Content-Encoding`, optionally vary on `Accept-Encoding`, remove `Content-Length`, and weaken strong `ETag` values. OxiBelt strips upstream `Accept-Encoding` by default when compression is active; policies can opt into preserving the client header or sending the configured encoding list intersected with the downstream request, but response body WAF transforms and credential-bearing requests always force identity upstream requests. This downstream compression policy runs after response WAF, cache, and route response actions; WAF HTTP body compression transform first decodes upstream or static compressed responses into the WAF/cache identity view, then lets downstream compression negotiate a fresh client-facing encoding when enabled.

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

When shared state is enabled, each feature maps to one configured Redis/Valkey-compatible or PostgreSQL backend. Rate limits use distributed token buckets keyed by client IP, route, path, trusted hashed access token, or other configured identity and enforce `max_buckets` before creating a new distributed identity bucket; connection limits use TTL-backed leases; Person proof can share its HMAC secret and single-use replay store; upstream pool health and active counts can be shared for selection; cache keeps local storage as L1 and uses the shared backend as L2 for collected cacheable objects, metadata, tags, fill locks, and purges; reload writes per-instance heartbeat records with config generation metadata. Disk streaming cache fills are local L1 only. Optional external cache handlers provide an HTTP L3 after L1/L2 misses and receive fills only after OxiBelt admits and commits the local/shared entry. Security-sensitive backend failures fail closed. Shared cache backend failures and external cache handler failures fall back to local/no shared cache for that request.

Response caching supports tag extraction from configured response headers, exact/prefix/tag purges through the admin API, signed purge authentication, cache key explain, batch warming, collapsed forwarding with bounded follower waits, disk index recovery, admission filtering by status/MIME/body size/frequency, tenant partition keys, Surrogate-Control metadata, stale-if-error controls by error class or status, Vary explosion guards, fresh conditional `304` hits, `Age` on cached hits, single and multipart cached byte ranges, local disk streaming fills for large known-length objects, external L3 lookup/fill/revalidation/purge coordination, and background refresh for eligible stale-while-revalidate GET/HEAD responses. Cache-enabled routes emit bounded `X-OxiBelt-Cache` and `X-OxiBelt-Cache-Reason` status headers and strip origin-supplied values for those names before caching or forwarding. Cache keys include scheme and host by default; production configurations should keep host and trusted variation dimensions in the key, avoid credential-bearing requests, and prefer query allowlists when only specific query parameters affect representation selection.

Hot reload modes:

- `off`: no runtime reload.
- `oxirule`: reload WAF-owned configuration and external OxiRule files only.
- `downstream_tls`: reload the current downstream certificate, private key, static OCSP response, or live OCSP runtime.
- `full`: reload OxiRule, TOML configuration, upstream clients, access-log sinks, downstream TLS material, downstream listener bind/protocol settings, and admin listener enable/bind settings.

Reload apply behavior is failure-safe: invalid TOML, invalid rules, invalid certificate/key pairs, unreadable files, failed upstream client setup, failed database access-log setup, or failed listener binds leave the previous active state in place. Successful reloads publish a new data-plane snapshot and gracefully drain HTTP connections that captured the previous snapshot, even when listener binds do not change. Successful full reloads also activate replacement listeners before old listener generations drain, so readiness remains OK for the active instance while in-flight requests on the old generation finish. HTTP/1.1 and HTTP/2 listener or snapshot-generation drain asks Hyper to gracefully close old connections; HTTP/3 stops accepting on drained generations and closes endpoints after the graceful timeout when a listener generation is retired. Upgraded tunnels, WebTransport, and TCP stream bridges are protected by the configured long-connection close delay, but new request streams received by a drained WebTransport HTTP/3 bridge are rejected instead of being evaluated against the old snapshot.

The lifecycle drain configuration is:

- `runtime.drain.graceful_timeout_ms`: maximum listener-generation drain time, greater than zero.
- `runtime.drain.long_connection_close_delay_ms`: delay before force-closing long-lived upgrade, CONNECT, WebTransport, or TCP stream bridges after drain, greater than zero.
- `runtime.drain.shutdown_delay_ms`: optional delay after process shutdown marks the instance draining and before listeners begin draining; `0` is allowed.

Operational endpoints are optional:

- `[health]` exposes local readiness and liveness endpoints.
- `[metrics]` exposes Prometheus-style metrics. Basic mode keeps aggregate counters and gauges. Detailed mode adds bounded route/upstream/method/status/protocol/cache-reason style labels for HTTPS, HTTP/1.1, HTTP/2, HTTP/3 over QUIC, WebSocket, WebTransport, WebRTC TURN, and SNI-forwarding decision/session surfaces. Rule-level WAF names, IDs, tags, modes, routes, hit counters, and cost counters are intentionally excluded from this unauthenticated endpoint; use the authenticated admin WAF telemetry endpoint for rule-level snapshots.
- `[telemetry.tracing]` is optional observability: it extracts incoming W3C `traceparent`, propagates trace context to upstream HTTP/1.1, HTTP/2, HTTP/3, and WebTransport CONNECT requests, and exports sampled spans to an OTLP HTTP/protobuf collector. Full hot reload and admin config load rebuild telemetry tracing from the replacement configuration; old-generation connections may keep the previous telemetry runtime only until their captured snapshot drains. Operator runbook and dashboard assets are documented in [Observability.md](Observability.md).
- `[admin]` exposes authenticated operations APIs such as OpenAPI metadata, cache purge, upstream-pool and stream-pool runtime control, dynamic policy automation, IPM management, config validation/load/rollback, explicit file sync, downstream TLS reload, and lifecycle drain/undrain on a dedicated listener. Plaintext admin traffic is loopback-allowlisted by default; non-loopback admin traffic uses TLS unless the operator explicitly configures a plaintext source allowlist. IPM (Identity Permission Management) authorizes Admin operations and opt-in data-plane routes with `Action`, `Resource`, and `Condition` policy statements; explicit deny wins, matching allow permits, and the default is deny. The legacy Admin RBAC `roles`, `permissions`, and `deny_permissions` model is rejected. Full hot reload starts, stops, or rebinds this listener when admin listener settings change.
- `oxibelt-gateway-controller` is an optional Kubernetes control-plane binary. It watches Gateway API `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute`, `TLSRoute`, `ReferenceGrant`, `Service`, and status-only `TCPRoute` resources, renders a deterministic controller-owned TOML include containing `[[routes]]`, `[[upstream_pools]]`, generated Gateway HTTP `[[external_auth]]`, route header/CORS/mirror actions, and passthrough `[[sni_forward.rules]]`, and applies that include through Admin `POST /admin/v1/files/sync` with full config validation. The base OxiBelt listener, downstream TLS, Admin/IPM, ACME/certificate lifecycle, and `[sni_forward].enabled` settings remain operator-owned. `TCPRoute` is intentionally not translated in v1.
- `[logging.access_log]` emits request-wide newline-delimited JSON access logs with `scope = "system"` and can use its own stdout and PostgreSQL sinks.
- OxiRule `emit_access_log` writes newline-delimited JSON with `scope = "waf"` to stdout and can optionally mirror records to PostgreSQL through the separate `[database.access_log]` sink.

Lifecycle endpoints are:

- `GET /admin/v1/openapi.json`: requires `admin:ReadMetadata` on `metadata/openapi`, returns the canonical OpenAPI 3.1 Admin API contract from `docs/admin-openapi.json`.
- `GET /admin/v1/capabilities`: requires `admin:ReadMetadata` on `metadata/capabilities`, returns API version, package version, feature flags, and Admin request-size limits.
- `GET /admin/v1/version`: requires `admin:ReadMetadata` on `metadata/version`, returns API version, package name, and package version.
- `GET /admin/v1/config/status`: requires `config:GetStatus`, returns active config revision, ETag, rollback availability, and last admin operation status.
- `GET /admin/v1/config/effective`: requires `config:GetEffective`, returns the redacted active effective TOML and ETag.
- `POST /admin/v1/config/validate`: requires `config:Validate`, validates submitted TOML against the active path roots without installing it.
- `POST /admin/v1/config/diff`: requires `config:Diff`, returns a coarse redacted effective-config diff for submitted TOML.
- `POST /admin/v1/config/load`: requires `config:Load` and matching `If-Match`, installs a runtime-only config snapshot. Changes to `[admin]` additionally require `admin:UpdateConfig` on `oxibelt:<namespace>:admin:config`; changes to `[ipm]` additionally require `ipm:UpdateConfig` on `oxibelt:<namespace>:ipm:config`.
- `POST /admin/v1/config/rollback`: requires `config:Rollback` and matching `If-Match`, restores the last-good runtime snapshot. Rollbacks that change `[admin]` or `[ipm]` require the same protected config update actions as config load.
- `POST /admin/v1/files/sync`: writes explicit files under configured config/OxiRule roots and can apply `none`, `oxirule`, `full`, or `downstream_tls`. Config-root writes require `config:SyncFiles`; OxiRule and OxiRule group writes require the matching `waf:PutOxiRule`, `waf:DeleteOxiRule`, `waf:PutOxiRuleGroup`, or `waf:DeleteOxiRuleGroup`. OxiRule file-sync roots are suffix-bound: `oxirule` accepts `.oxirule.toml` paths and `oxirule_group` accepts `.oxirule-group.toml` paths. `apply = "oxirule"` requires `waf:ReloadOxiRule`. Config-root writes and `apply = "full"` are prechecked so staged or disk-candidate `[admin]` and `[ipm]` changes require the protected config update actions before files are committed.
- `GET /admin/v1/tls/downstream`: requires `config:ReadDownstreamTls`, returns downstream TLS material status.
- `POST /admin/v1/tls/downstream/reload`: requires `config:ReloadDownstreamTls` and matching `If-Match`, reloads configured certificate, key, and static OCSP files from disk or rebuilds the live OCSP runtime.
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

Admin and process drain make readiness return `503 draining`, keep liveness `200 live`, and reject new data-plane requests with `503 draining` plus `Connection: close`. Existing in-flight requests continue. `SIGTERM` and Ctrl-C follow the same shutdown sequence: mark draining, wait `shutdown_delay_ms`, then drain listeners up to `graceful_timeout_ms`.

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
