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

OxiBelt currently targets Rust 1.95 and uses `rustls` with the `aws-lc-rs` crypto provider. The default rustls key exchange group order enables and prefers `X25519MLKEM768`.

## Request Pipeline

At a high level, each HTTP transaction follows this order:

1. Accept TCP or QUIC traffic from a downstream client.
2. Apply listener-level checks such as the global connection limit, PROXY protocol intake, configured per-IP connection-limit identity, TLS handshake limits, and optional TCP max-hop policy.
3. Terminate downstream TLS and collect transport metadata, including SNI, ALPN, client certificate presence, and QUIC metadata where available.
4. Parse the HTTP request and normalize the client IP used for Real-IP connection-limit modes, rate limits, and WAF evaluation.
5. Match a route by host and path prefix.
6. Evaluate request-phase OxiRule rules when WAF is enabled.
7. Select the configured upstream or upstream pool, optionally using request-phase routing actions.
8. Apply the effective request buffering policy, normalize forwarded headers, and forward the request upstream.
9. Build a response context from the upstream response or from a synthetic upstream-error response.
10. Evaluate response-phase OxiRule rules when WAF is enabled.
11. Apply response mutations, the effective response buffering policy, cache behavior, structured access-log actions, and response forwarding back to the downstream client.

If a validation, runtime, or WAF policy failure occurs, the configured fail policy determines whether OxiBelt rejects the transaction or allows it to continue.

HTTP request and response buffering is opt-in and defaults to streaming. `memory` buffers bounded bodies in memory, `spool` spills bytes beyond the memory threshold to explicit temp files and removes partial files if buffering fails, and route-level buffering overrides inherit omitted values from `[proxy.buffering]`. CONNECT tunnels, HTTP Upgrade, and WebTransport sessions remain streaming.

Data-plane TCP listeners can run one or more accept workers inside a single OxiBelt process. The default is one listener socket per logical HTTPS, plain HTTP, or TCP stream listener. When `runtime.accept.workers > 1`, `runtime.accept.reuse_port = true` is required and OxiBelt creates a `SO_REUSEPORT` socket per worker so the kernel can distribute accepts. Downstream HTTP/3 can similarly create multiple UDP endpoints with `quic.socket.workers > 1` and `quic.socket.reuse_port = true`. Kernel sysctl and file-limit changes are not applied by the OxiBelt binary; the optional `kernel-extension/` installer stages those Linux 7.0.x+ host tunings separately, with PAM `nofile` limits scoped to the `oxibelt` service account.

## Protocol Behavior

Downstream protocol support:

- HTTP/1.1 and HTTP/2 are served over TCP.
- HTTP/3 is served over QUIC on the configured `https_bind` UDP address.
- Deployments that enable HTTP/3 must expose the HTTPS bind address for both TCP and UDP.
- Downstream HTTP/3 always requires TLS 1.3.
- The same downstream client certificate policy is enforced for TCP TLS and HTTP/3/QUIC listeners.
- QUIC Retry/address validation can be enabled with `quic.retry`.
- HTTPS HTTP/1.1 and HTTP/2 responses advertise HTTP/3 with `Alt-Svc` when downstream HTTP/3 and `quic.alt_svc.enabled` are both enabled. OxiBelt does not add that header on HTTP/3, plain HTTP, or `101 Switching Protocols` responses.
- QUIC 0-RTT is disabled by default. `quic.zero_rtt = "safe_methods"` enables early data and only permits transport-verified early-data `GET` and `HEAD`; unsafe methods received as QUIC 0-RTT receive `425 Too Early`.
- `quic.host_key_file` provides shared host key material for stateless reset and Retry/validation tokens. It is cert-directory relative and hot-reload tracked.

Upstream protocol support:

- HTTP/1.1 supports `http://` and `https://` origins.
- HTTP/2 over `https://` uses TLS ALPN.
- HTTP/2 over `http://` uses h2c with prior knowledge.
- HTTP/3 requires an `https://` upstream origin.
- Ordinary upstream HTTP/3 forwarding uses a per-upstream QUIC connection pool and multiplexes requests over pooled HTTP/3 connections. WebTransport uses a dedicated upstream QUIC connection per session.
- `proxy.auto_upgrade` controls the maximum upstream HTTP version OxiBelt may select.
- Route-level `upstream_http_version` can override backend protocol selection within the selected upstream capability.
- Route-level timeout overrides can adjust downstream body/send, upgrade idle, WebTransport idle, and upstream connect/first-byte/read/send behavior for individual routes. TLS handshake and downstream header read timeouts remain listener-wide.
- PROXY protocol egress is supported only for TCP-based upstream connections and stream proxy targets, not HTTP/3/QUIC upstreams.

Upgrade and extended protocol behavior:

- WebSocket tunneling is implemented for HTTP/1.1 upgrade routes.
- Generic HTTP/1.1 upgrade and CONNECT tunneling are implemented when both global and route-level policy enables them.
- CONNECT tunneling targets the selected route upstream origin, not the downstream request target.
- WebTransport forwarding is supported for downstream HTTP/3 extended CONNECT requests when the selected upstream also uses HTTP/3 and has `webtransport = true`.
- WebTransport stream and datagram payload inspection is outside the current WAF implementation.
- WebRTC media forwarding is not implemented; signaling HTTP requests can still be routed and inspected as ordinary HTTP traffic.

## TLS and Identity

Downstream TLS uses configured certificate and private key files from the cert directory. OxiBelt supports TLS 1.2 through TLS 1.3 for TCP TLS; HTTP/3 requires TLS 1.3.

Supported downstream TLS features:

- Server certificate chain and private key loading.
- Optional or required downstream client certificate authentication.
- Client CA roots from configured cert-directory files.
- Static file-based OCSP stapling.
- Session tickets with configurable rotation interval.

Upstream TLS behavior:

- OxiBelt validates upstream HTTPS using the default web PKI roots plus configured `proxy.trusted_ca_certs`.
- Upstream TLS 1.3 ECH can be disabled, sent as GREASE, or sent from a configured TLS-encoded `ECHConfigList`.
- Downstream ECH termination is not configured by OxiBelt today; it depends on server-side ECH support in the TLS provider.

Person proof challenges in OxiRule are anti-automation controls. They are not authentication, identity proof, proof of legal personhood, or proof of benign intent.

## Routing and Upstreams

Routes match by host and path prefix. A route may rewrite the matched path prefix with `replace_prefix_with` before forwarding.

Targets may be:

- A named `[[upstreams]]` entry.
- A named `[[upstream_pools]]` entry.

Upstream pools maintain load-balancing state. Supported algorithms are `round_robin`, `least_conn`, `random`, `hash`, and `ip_hash`; `sticky_cookie` is reserved and rejected at startup. Pool health can be passive or active depending on configuration. Pool servers have stable IDs, source metadata, active counts, health state, and runtime state. `ready` servers accept new requests; `drain`, `down`, and `maintenance` servers do not receive new selections while existing in-flight requests complete.

Dynamic upstream discovery is supported for upstream pools. File discovery polls a JSON server list under the config directory. DNS discovery supports A, AAAA, combined A/AAAA, and SRV records and schedules refreshes from configured refresh intervals and DNS TTLs. DNS responses are accepted only when they are successful responses matching the sent transaction ID and question, and answer records must be owned by the queried name or a verified CNAME chain. Discovery updates are staged: OxiBelt validates the generated pool and rebuilds upstream clients before atomically replacing the active pool view. Invalid discovery updates keep the previous active state.

Host forwarding is controlled by each upstream's `preserve_host` setting:

- `false`: use the upstream origin host.
- `true`: preserve the downstream request host.

OxiBelt also manages `Forwarded` and `X-Forwarded-*` headers according to `proxy.forwarded_headers.mode`.

Downstream response compression is controlled by `[compression]` and optional route-level `compression` policy references. Support for `br`, `zstd`, `gzip`, and `deflate` is enabled by default, but OxiBelt only transforms responses when the downstream `Accept-Encoding`, request credential headers, response status, MIME type, size, existing response headers, and range/no-transform semantics allow it. Requests carrying `Cookie`, `Authorization`, or `Proxy-Authorization`, and responses carrying `Set-Cookie`, `Cache-Control: private`, or `Cache-Control: no-store`, are not compressed. Compressed responses set `Content-Encoding`, vary on `Accept-Encoding`, remove `Content-Length`, and weaken strong `ETag` values.

## WAF and OxiRule

OxiRule is a CEL-like, declarative WAF model. It separates:

- `when`: a side-effect-free boolean expression.
- `actions`: validated declarative side effects.

Rules can be attached globally under `[[waf.rules]]` or under `[[routes.waf.rules]]`. They may be inline TOML rules or external `.oxirule.toml` files loaded from the OxiRule directory.

Request-phase rules can reject, rate-limit, mutate request headers, set transaction tags, require Person proof, or choose an upstream/pool before forwarding. Response-phase rules can continue, replace, or reject responses, mutate response headers, and emit structured access logs.

The rule engine is intentionally bounded:

- No loops, callbacks, user-defined functions, imports, external I/O, or general-purpose scripting.
- Runtime, step, memory, regex, body-inspection, helper, and mutation budgets.
- Bounded helper APIs for headers, query parameters, cookies, tags, body byte inspection, and pattern sets.

See [OxiRule.md](OxiRule.md) for the full rule reference.

## Runtime and Operations

Runtime state is process-local unless `[shared_state].enabled = true`. With shared state disabled, cache indexes and locks, upstream health state, rate and connection limits, and Person proof single-use token state stay inside one process. Local rate-limit bucket maps are bounded per configured limit by `max_buckets`; new identities fail closed in enforcing mode after the cap until refilled buckets can be reclaimed.

When shared state is enabled, each feature maps to one configured Redis/Valkey-compatible or PostgreSQL backend. Rate limits use distributed token buckets keyed by client IP, route, path, or hashed access token according to configuration; connection limits use TTL-backed leases; Person proof can share its HMAC secret and single-use replay store; upstream pool health and active counts can be shared for selection; cache keeps local storage as L1 and uses the shared backend as L2 for cacheable objects, metadata, fill locks, and purges; reload writes per-instance heartbeat records with config generation metadata. Security-sensitive backend failures fail closed. Shared cache backend failures fall back to local/no shared cache for that request.

Hot reload modes:

- `off`: no runtime reload.
- `oxirule`: reload WAF-owned configuration and external OxiRule files only.
- `downstream_tls`: reload the current downstream certificate, private key, and static OCSP response.
- `full`: reload OxiRule, TOML configuration, upstream clients, access-log sinks, downstream TLS material, downstream listener bind/protocol settings, and admin listener enable/bind settings.

Reload apply behavior is failure-safe: invalid TOML, invalid rules, invalid certificate/key pairs, unreadable files, failed upstream client setup, failed database access-log setup, or failed listener binds leave the previous active state in place.

Operational endpoints are optional:

- `[health]` exposes local readiness and liveness endpoints.
- `[metrics]` exposes Prometheus-style metrics. Rule-level WAF telemetry is intentionally excluded from this unauthenticated endpoint; use the authenticated admin WAF telemetry endpoint for rule names, IDs, modes, routes, and per-rule hit counters.
- `[admin]` exposes authenticated operations APIs such as cache purge and upstream-pool runtime control on a dedicated listener. Plaintext admin traffic is loopback-allowlisted by default; non-loopback admin traffic uses TLS unless the operator explicitly configures a plaintext source allowlist. Admin RBAC maps bearer-token environment variables to `viewer`, `cache_operator`, `upstream_operator`, or `admin` roles; the legacy `admin.bearer_token_env` token has the `admin` role. Full hot reload starts, stops, or rebinds this listener when admin listener settings change.
- `[logging.access_log]` emits request-wide newline-delimited JSON access logs with `scope = "system"` and can use its own stdout and PostgreSQL sinks.
- OxiRule `emit_access_log` writes newline-delimited JSON with `scope = "waf"` to stdout and can optionally mirror records to PostgreSQL through the separate `[database.access_log]` sink.

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

The current implementation intentionally leaves these as future work:

- ACME HTTP-01 challenge handling.
- Live OCSP fetch and refresh workers.
- Sticky-cookie upstream sessions.
- WebRTC media forwarding.
- TCP stream proxying, generic HTTP upgrade, CONNECT tunneling, gRPC health checks, gRPC-Web translation, and PROXY protocol egress for TCP upstreams.
- Passing `103 Early Hints`.
- Streaming-safe WAF text scanning helpers such as `Body.contains`, `Body.matches`, and `Body.scan`.
- Response body byte inspection.
- WAF frame-level or datagram-level WebTransport inspection.
- Downstream ECH configuration.
- General-purpose scripting, user-defined OxiRule functions, imports, loops, callbacks, and unbounded comprehensions.
