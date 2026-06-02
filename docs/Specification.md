# OxiBelt Technical Specification

Status: Draft
Target project: OxiBelt Rust-based reverse proxy

This document is the compact behavior specification for OxiBelt. Configuration syntax is covered in [Configuration.md](Configuration.md), and OxiRule WAF syntax is covered in [OxiRule.md](OxiRule.md).

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

OxiBelt currently targets Rust 1.95 and uses `rustls` with the `aws-lc-rs` crypto provider. The default downstream TLS key exchange group set enables `X25519MLKEM768`, `X25519`, `secp256r1`, and `secp384r1`; deployments can omit the hybrid group with `tls.key_exchange_groups` when cold-handshake CPU cost matters more than post-quantum hybrid negotiation.

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
- HTTP/3 is served over QUIC on the configured `https_bind` UDP address.
- `[sni_forward]` can inspect visible TLS ClientHello SNI before OxiBelt terminates local traffic. Explicit SNI forwarding rules override local route hosts; otherwise configured route hosts remain local, and unknown SNI forwards only when `sni_forward.default_target` is configured. Missing, malformed, or unparseable SNI fails closed. Route host `"*"` does not count as a defined SNI name. QUIC SNI forwarding bounds pre-classification session state and local datagram queues with `[sni_forward]` limits.
- TCP SNI forwarding uses bounded `TcpStream::peek`, preserving the original ClientHello for raw TCP passthrough targets. Local matches continue through the normal rustls HTTP/1.1 and HTTP/2 path. Forwarded TCP sessions keep the accepted connection's global lease and, in Real-IP connection-limit modes, acquire the normal per-IP and named leases for the post-PROXY-protocol peer address before tunneling.
- QUIC SNI forwarding uses the same UDP address as downstream HTTP/3. OxiBelt decrypts QUIC Initial payloads, extracts CRYPTO frames, parses visible ClientHello SNI, and forwards matched sessions as UDP passthrough while local sessions are queued into Quinn. Forwarded QUIC sessions acquire the same total, per-IP, and named downstream connection leases as local HTTP/3 connections. QUIC SNI forwarding requires downstream HTTP/3 to be enabled.
- Deployments that enable HTTP/3 must expose the HTTPS bind address for both TCP and UDP.
- Downstream HTTP/3 always requires TLS 1.3.
- The same downstream client certificate policy is enforced for TCP TLS and HTTP/3/QUIC listeners.
- QUIC Retry/address validation can be enabled with `quic.retry`.
- HTTPS HTTP/1.1 and HTTP/2 responses advertise HTTP/3 with `Alt-Svc` when downstream HTTP/3 and `quic.alt_svc.enabled` are both enabled. OxiBelt does not add that header on HTTP/3, plain HTTP, or `101 Switching Protocols` responses.
- QUIC 0-RTT is disabled by default. `quic.zero_rtt = "safe_methods"` enables early data and only permits transport-verified early-data `GET` and `HEAD`; unsafe methods received as QUIC 0-RTT receive `425 Too Early`.
- `quic.host_key_file` provides deployment-local host key material for stateless reset and Retry/validation tokens. It is cert-directory relative and hot-reload tracked; release images do not include shared key material.

Upstream protocol support:

- HTTP/1.1 supports `http://` and `https://` origins.
- HTTP/2 over `https://` uses TLS ALPN.
- HTTP/2 over `http://` uses h2c with prior knowledge.
- HTTP/3 requires an `https://` upstream origin.
- Ordinary upstream HTTP/3 forwarding uses a per-upstream QUIC connection pool and multiplexes requests over pooled HTTP/3 connections when `quic.upstream_pool.enabled = true`; when disabled, each ordinary HTTP/3 upstream request uses a one-shot QUIC connection. WebTransport uses a dedicated upstream QUIC connection per session.
- `proxy.auto_upgrade` controls the maximum upstream HTTP version OxiBelt may select.
- Route-level `upstream_http_version` can override backend protocol selection within the selected upstream capability.
- Route-level timeout overrides can adjust downstream body/send, upgrade idle, WebTransport idle, and upstream connect/first-byte/read/send behavior for individual routes. TLS handshake and downstream header read timeouts remain listener-wide.
- PROXY protocol egress is supported only for TCP-based upstream connections and stream proxy targets, not HTTP/3/QUIC upstreams.

Upgrade and extended protocol behavior:

- WebSocket tunneling is implemented for HTTP/1.1 upgrade routes.
- WebSocket stream-WAF routes reject individual frame payloads larger than `waf.limits.max_body_inspection_bytes` before forwarding.
- Generic HTTP/1.1 upgrade and CONNECT tunneling are implemented when both global and route-level policy enables them.
- CONNECT tunneling targets the selected route upstream origin, not the downstream request target.
- WebTransport forwarding is supported for downstream HTTP/3 extended CONNECT requests when the selected upstream also uses HTTP/3 and has `webtransport = true`.
- Native OxiRule stream-phase WAF rules can inspect WebTransport stream chunks and datagrams in both directions before forwarding and can close the active session with `close_stream`. The CRS compatibility layer does not inspect WebSocket or WebTransport stream payloads.
- WebRTC media forwarding is supported through TURN listeners. Signaling HTTP requests can still be routed and inspected as ordinary HTTP traffic, while TURN media payloads are forwarded outside WAF inspection. TURN `edge_relay` TCP/TLS outbound queues are bounded per downstream connection by `stream_outbound_queue_capacity`; the default is `32`, `"auto"` resolves conservatively from available parallelism with a `32..=64` clamp, explicit values are limited to `1..=256`, and full queues fail closed.

## TLS and Identity

Downstream TLS uses configured certificate files from the cert directory and either a local private key file or an IPC remote private-key signer. OxiBelt supports TLS 1.2 through TLS 1.3 for TCP TLS; HTTP/3 requires TLS 1.3.

Supported downstream TLS features:

- Server certificate chain loading with local private key loading or Unix socket remote signing.
- Optional or required downstream client certificate authentication.
- Client CA roots from configured cert-directory files.
- Static file-based OCSP stapling.
- Session tickets with configurable rotation interval.

Remote private-key signing is intended to keep downstream and TURN TLS private keys outside the OxiBelt process memory. OxiBelt connects to `oxibelt-keysigner` over a Unix domain socket, authenticates with a base64 32-byte token, verifies that the signer-reported public key matches the configured certificate, and requests signatures through rustls' signing interface. The signer caps concurrently handled IPC connections and applies server-side request/response I/O deadlines before token validation, so local idle or trickled socket peers cannot hold signer tasks indefinitely. The signer defaults to TLS 1.3 server CertificateVerify inputs only; TLS 1.2 unstructured signing requires explicit opt-in on both OxiBelt and the signer sidecar.

Upstream TLS behavior:

- OxiBelt validates upstream HTTPS using the default web PKI roots plus configured `proxy.trusted_ca_certs`.
- Upstream TLS 1.3 ECH can be disabled, sent as GREASE, or sent from a configured TLS-encoded `ECHConfigList`.
- Downstream ECH termination is not configured by OxiBelt today; it depends on server-side ECH support in the TLS provider.

Person proof challenges in OxiRule are anti-automation controls. They are not authentication, identity proof, proof of legal personhood, or proof of benign intent. Public behavior is selected with `person_proof_mode`: `built_in` uses OxiBelt built-in PoW plus the built-in frontend, `openapi` uses the same PoW API with a custom frontend, `third_party_provider` uses built-in Cloudflare Turnstile, hCaptcha, or Friendly Captcha v2 adapters, and `custom_provider` calls a configured JSON HTTP provider. Custom frontends are addressed by `custom_frontend_url`, an origin-relative URL routed by the same OxiBelt instance to either a static asset or proxied frontend backend. Clearance credentials can be carried by configured cookie keys, `Authorization: Bearer`, or configured request-header keys, with cookie, localStorage, and JSON issuance modes documented by the Person proof API metadata.

## Routing and Upstreams

Routes match by host and path prefix. Wildcard host routes such as `*.example.com` require at least one non-empty request-host label before the suffix. A route may rewrite the matched path prefix with `replace_prefix_with` before forwarding.

Targets may be:

- A named `[[upstreams]]` entry.
- A named `[[upstream_pools]]` entry.

Routes may reference an `external_auth` provider. OxiBelt runs that authorization check after route-level rate limits and dynamic policy and before WAF/body handling or upstream selection. Client-supplied identity headers are stripped before trusted identity headers are injected from Authelia forward-auth responses, OAuth2 token introspection data, or OIDC UserInfo claims. Routes with external auth are excluded from plain proxy and static sendfile fast paths.

Upstream pools maintain load-balancing state. The default algorithm is `power_of_two_choices`. Supported HTTP pool algorithms are `power_of_two_choices`, `weighted_least_conn`, `rendezvous_hash`, `rendezvous_ip_hash`, `ewma`, `least_time`, and `sticky_cookie`; legacy `round_robin`, `least_conn`, `random`, `hash`, and `ip_hash` names are rejected rather than treated as aliases. Sticky-cookie pools verify an HMAC-signed server-affinity cookie, reuse the selected server only while it remains healthy and capacity-available, and otherwise fall back to a configured non-sticky modern algorithm before issuing a fresh cookie. Pool health can be passive or active depending on configuration. Pool servers have stable IDs, source metadata, active counts, health state, and runtime state. `ready` servers accept new requests; `drain`, `down`, and `maintenance` servers do not receive new selections while existing in-flight requests complete. Optional slow start scales effective server weight for newly added, discovered, or recovered ready servers across all HTTP pool algorithms. Optional outlier ejection temporarily excludes servers after configured consecutive failures and fails closed when every eligible server is ejected or otherwise unavailable. Snapshot rebuilds preserve stable-ID runtime state such as EWMA samples, health counters, ejection state, and slow-start timestamps.

Dynamic upstream discovery is supported for upstream pools. File discovery polls a JSON server list under the config directory. DNS discovery supports A, AAAA, combined A/AAAA, and SRV records and schedules refreshes from configured refresh intervals and DNS TTLs. Kubernetes discovery polls the core Endpoints API, Consul discovery polls health service entries, etcd discovery polls v3 KV ranges, and Nomad discovery polls or blocking-watches `GET /v1/service/:service_name`. DNS responses are accepted only when they are successful responses matching the sent transaction ID and question, and answer records must be owned by the queried name or a verified CNAME chain. Nomad responses are bounded and validated as untrusted service inventory before generated `http`/`https` origins are accepted. Discovery updates are staged: OxiBelt validates the generated pool and rebuilds upstream clients before atomically replacing the active pool view. Invalid discovery updates keep the previous active state.

Host forwarding is controlled by each upstream's `preserve_host` setting:

- `false`: use the upstream origin host.
- `true`: forward the effective downstream request host selected for routing and WAF evaluation.

Absolute-form request targets are accepted only when their URI authority matches the `Host` header after host and effective-port normalization. Mismatches are rejected with `400 Bad Request` so routing, WAF policy, forwarded headers, and upstream `Host` forwarding cannot observe different downstream authorities.

OxiBelt also manages `Forwarded` and `X-Forwarded-*` headers according to `proxy.forwarded_headers.mode`. By default, `X-Forwarded-For` uses the same resolved client identity as WAF, rate limiting, and external auth; `proxy.forwarded_headers.client_ip_source = "direct_peer"` keeps legacy immediate-peer forwarding when needed.

Downstream response compression is controlled by `[compression]` and optional route-level `compression` policy references. Support for `br`, `zstd`, `gzip`, and `deflate` is enabled by default, but OxiBelt only transforms responses when the downstream `Accept-Encoding`, request credential headers, response status, MIME type, size, existing response headers, and range/no-transform semantics allow it. Requests carrying `Cookie`, `Authorization`, or `Proxy-Authorization`, and responses carrying `Set-Cookie`, `Cache-Control: private`, or `Cache-Control: no-store`, are not compressed. Compressed responses set `Content-Encoding`, vary on `Accept-Encoding`, remove `Content-Length`, and weaken strong `ETag` values.

## WAF and OxiRule

OxiRule is a CEL-like, declarative WAF model. It separates:

- `when`: a side-effect-free boolean expression.
- `actions`: validated declarative side effects.

Rules can be attached globally under `[[waf.rules]]` or under `[[routes.waf.rules]]`. They may be inline TOML rules or external `.oxirule.toml` files loaded from the OxiRule directory.

Bounded user-defined functions can be attached globally under `[[waf.functions]]` or per route under `[[routes.waf.functions]]`. They are expression-valued, acyclic, evaluated under the caller's budgets, phase-validated where they are called, and available to WAF rule expressions plus WAF `emit_access_log` field expressions. Request-wide system access-log fields do not receive WAF functions in v1.

OxiRule `emit_mitigation` actions enqueue aggregate PostgreSQL mitigation intents for external DOTS, BGP FlowSpec, RTBH/blackhole, or provider-specific controllers. OxiBelt only writes the configured `[database.mitigation]` table, never calls ISP or IaaS APIs directly, and excludes request/response/stream payload bytes from mitigation records.

Request-phase rules can reject, rate-limit, mutate request headers, set transaction tags, require Person proof, or choose an upstream/pool before forwarding. Person proof `session_path`, `verify_path`, and `openapi_path` requests are intercepted after route matching, route rate limits, and dynamic policy, but before external auth, WAF forwarding, static files, or upstream selection. Response-phase rules can continue, replace, or reject responses, mutate response headers, and emit structured access logs.

Malicious intelligence scoring helpers are local, bounded OxiRule helpers for hostile automation, prompt-injection/tool-abuse language, malformed or layered payload shape, and suspicious automation fingerprints. They are not authentication, identity proof, bot reputation, Person proof, proof of legal personhood, or proof of benign or malicious intent. They perform no external LLM, classifier, reputation, or callback I/O and run only inside the same OxiRule budgets and bounded body prefixes as the calling rule. Client-supplied agent, crawler, or AI claims remain untrusted unless a future explicitly trusted agent authentication mechanism marks them otherwise.

The optional CRS compatibility layer loads ModSecurity-style CRS setup/rule files from the OxiRule directory. It supports request/response phases 1 through 4, bounded request/response body prefix inspection with replay, normalized CRS transforms, `tx` variables, chained rules, macro expansion, `setvar`, paranoia-level tags, and anomaly scoring. CRS defaults to `monitor`; `enforcing` mode blocks at configured inbound/outbound anomaly thresholds. Unsupported CRS syntax fails closed during configuration load/compile.

The rule engine is intentionally bounded:

- No loops, callbacks, imports, external I/O, or general-purpose scripting. User-defined functions are declarative bounded expressions, not imperative scripts.
- Runtime, step, memory, regex, body-inspection, helper, and mutation budgets.
- Bounded helper APIs for raw and normalized headers, query parameters, cookies, tags, body byte/text inspection, response body prefix inspection, body pattern scanning, and pattern sets.

See [OxiRule.md](OxiRule.md) for the full rule reference.

## Runtime and Operations

Runtime state is process-local unless `[shared_state].enabled = true`. With shared state disabled, cache indexes and locks, upstream health state, rate and connection limits, and Person proof single-use token state stay inside one process. Local rate-limit bucket maps are bounded per configured limit by `max_buckets`; new identities fail closed in enforcing mode after the cap until refilled buckets can be reclaimed.

When shared state is enabled, each feature maps to one configured Redis/Valkey-compatible or PostgreSQL backend. Rate limits use distributed token buckets keyed by client IP, route, path, or hashed access token according to configuration; connection limits use TTL-backed leases; Person proof can share its HMAC secret and single-use replay store; upstream pool health and active counts can be shared for selection; cache keeps local storage as L1 and uses the shared backend as L2 for cacheable objects, metadata, tags, fill locks, and purges; reload writes per-instance heartbeat records with config generation metadata. Security-sensitive backend failures fail closed. Shared cache backend failures fall back to local/no shared cache for that request.

Response caching supports tag extraction from configured response headers, exact/prefix/tag purges through the admin API, signed purge authentication, cache key explain, batch warming, collapsed forwarding with bounded follower waits, disk index recovery, admission filtering by status/MIME/body size/frequency, tenant partition keys, Surrogate-Control metadata, stale-if-error controls by error class or status, Vary explosion guards, and background refresh for eligible stale-while-revalidate GET/HEAD responses. Cache-enabled routes emit bounded `X-OxiBelt-Cache` and `X-OxiBelt-Cache-Reason` status headers and strip origin-supplied values for those names before caching or forwarding. Cache keys include scheme and host by default; production configurations should keep host and trusted variation dimensions in the key, avoid credential-bearing requests, and prefer query allowlists when only specific query parameters affect representation selection.

Hot reload modes:

- `off`: no runtime reload.
- `oxirule`: reload WAF-owned configuration and external OxiRule files only.
- `downstream_tls`: reload the current downstream certificate, private key, and static OCSP response.
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
- `[admin]` exposes authenticated operations APIs such as OpenAPI metadata, cache purge, upstream-pool runtime control, dynamic policy automation, IPM management, config validation/load/rollback, explicit file sync, downstream TLS reload, and lifecycle drain/undrain on a dedicated listener. Plaintext admin traffic is loopback-allowlisted by default; non-loopback admin traffic uses TLS unless the operator explicitly configures a plaintext source allowlist. IPM (Identity Permission Management) authorizes Admin operations and opt-in data-plane routes with `Action`, `Resource`, and `Condition` policy statements; explicit deny wins, matching allow permits, and the default is deny. The legacy Admin RBAC `roles`, `permissions`, and `deny_permissions` model is rejected. Full hot reload starts, stops, or rebinds this listener when admin listener settings change.
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
- `POST /admin/v1/tls/downstream/reload`: requires `config:ReloadDownstreamTls` and matching `If-Match`, reloads configured certificate, key, and static OCSP files from disk.
- `GET /admin/v1/lifecycle`: requires `lifecycle:Get`, returns draining state and reason.
- `POST /admin/v1/lifecycle/drain`: requires `lifecycle:Drain`, starts admin drain.
- `POST /admin/v1/lifecycle/undrain`: requires `lifecycle:Undrain`, clears admin drain.
- `GET /admin/v1/diagnostics/support-bundle?redact=true`: requires `diagnostics:ReadSupportBundle`, returns a redacted JSON support bundle with config status, redacted effective config when available, doctor output, runtime snapshot, WAF telemetry summaries, dynamic-policy summary, and Prometheus text. Optional `external_probe=KIND` query parameters require the same probe permissions as diagnostics preflight.
- `GET /admin/v1/runtime/snapshot?redact=true`: requires `runtime:ReadSnapshot`, returns the redacted runtime snapshot section used by the support bundle.
- `GET /admin/v1/runtime/introspection?redact=true`: requires `runtime:ReadIntrospection`, returns the redacted runtime snapshot plus live active counters for downstream connections, HTTP/1.1 requests, HTTP/2 streams, HTTP/3 requests, WebSocket tunnels, WebTransport sessions, stream listeners, and TURN TCP/TLS connections.
- `GET /admin/v1/waf/rule-hits`, `GET /admin/v1/waf/rule-costs`, and `GET /admin/v1/waf/crs/compatibility`: require the matching `waf:GetRuleHits`, `waf:GetRuleCosts`, and `waf:GetCrsCompatibility` actions.
- `POST /admin/v1/waf/oxirule/check`, `test`, `explain`, `cost`, and `replay`: require `waf:CheckOxiRule`, `waf:TestOxiRule`, `waf:ExplainOxiRule`, `waf:EstimateOxiRuleCost`, or `waf:ReplayOxiRule`; `check` also requires `waf:CheckOxiRuleGroup` when group candidates are supplied. Requests with `include_active_rules = true` require the same action on `oxirule/*`, except replay uses `replay/*`. These endpoints are synchronous, stateless, and never write OxiRule files.
- `GET /admin/v1/waf/oxirule/templates`, `POST /admin/v1/waf/oxirule/templates/render`, and `POST /admin/v1/waf/oxirule/false-positive`: require `waf:ListOxiRuleTemplates`, `waf:RenderOxiRuleTemplate`, and `waf:PlanOxiRuleFalsePositive`; they list/render built-in templates or return tuning suggestions without changing configuration.
- `GET /admin/v1/upstream-pools/status`: requires `upstream-pool:GetStatus` on `status/current`, returns the upstream-pool runtime generation and ETag used by server mutations.
- `POST/PATCH/DELETE /admin/v1/upstream-pools/{pool}/servers...`: require the matching upstream-pool server action and `If-Match` with the upstream-pool status ETag; missing ETags return `428`, stale ETags return `412`.
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

Provision and renew public TLS certificates outside OxiBelt with an ACME client such as Certbot. Containerized deployments may use the `certbot/certbot` Docker image and mount the generated certificate material into OxiBelt's cert directory.

Security rationale: ACME account keys, DNS provider API tokens, and challenge credentials should live outside the OxiBelt process and container trust boundary. If a proxy vulnerability ever allowed remote code execution, memory disclosure, or a logic error that exposed OxiBelt process state, the compromised proxy should not also hold credentials that can issue arbitrary new TLS certificates. DNS-01 credentials are especially sensitive because a stolen DNS provider token can affect certificate issuance for every zone or name that token can modify.

The current implementation reserves or defers this work:

- Live OCSP fetch and refresh workers.
- Sticky-cookie upstream sessions.
- CRS stream-payload inspection for WebSocket and WebTransport traffic.
- Downstream ECH configuration.
- General-purpose UDP stream proxying outside the configured same-port QUIC SNI forwarding path.
