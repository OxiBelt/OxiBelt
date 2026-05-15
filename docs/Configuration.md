# OxiBelt Configuration Reference

Status: Draft
Target project: OxiBelt Rust-based reverse proxy

This document describes the OxiBelt TOML configuration format. For behavior-level context, see [Specification.md](Specification.md). For OxiRule rule syntax, see [OxiRule.md](OxiRule.md).

The repository example configuration is:

```sh
source/config/oxibelt.toml
```

The release container entrypoint expects:

```sh
/etc/oxibelt/config/oxibelt.toml
```

Validate a configuration without starting listeners:

```sh
oxibelt --config source/config/oxibelt.toml --check
```

Print the merged, redacted effective configuration:

```sh
oxibelt --config source/config/oxibelt.toml --dump-effective-config
```

## Path Model

Container deployments use three purpose-specific directories:

```text
/etc/oxibelt/config   TOML configuration and included TOML modules
/etc/oxibelt/cert     TLS certificates, keys, CA roots, OCSP, and ECH files
/etc/oxibelt/oxirule  External .oxirule.toml rule files
```

Relative paths are resolved by purpose:

- `include`: relative to the TOML file that declares it.
- TLS, CA, OCSP, PostgreSQL TLS, and ECH files: under the cert directory.
- External OxiRule files: under the oxirule directory.

Runtime file paths must be relative, normalized paths without `.` or `..` components. They must resolve to existing regular files under the correct purpose-specific directory before startup continues.

## Top-Level Shape

A typical configuration may contain:

```toml
include = ["conf.d/*.toml"]

[config]
[logging]
[logging.access_log]
[[logging.access_log.fields]]
[logging.access_log.database]
[logging.access_log.database.tls]
[runtime]
[runtime.worker_multipliers]
[runtime.accept]
[runtime.drain]
[runtime.hot_reload]
[listeners]
[listeners.proxy_protocol]
[tls]
[tls.client_auth]
[tls.ocsp]
[proxy]
[proxy.forwarded_headers]
[proxy.real_ip]
[proxy.auto_upgrade]
[proxy.upgrades]
[proxy.retry]
[proxy.buffering]
[proxy.http]
[limits]
[shared_state]
[[shared_state.backends]]
[shared_state.backends.tls]
[compression]
[[compression.policies]]
[cache]
[admin]
[admin.tls]
[[admin.tls.certificates]]
[admin.tls.client_auth]
[metrics]
[health]
[security.headers]
[database.access_log]
[database.access_log.tls]
[waf]
[waf.limits]

[[waf.pattern_sets]]
[[waf.rules]]
[[rate_limits]]
[[connection_limits]]
[[upstreams]]
[[upstream_pools]]
[[routes]]
```

Required routing inputs:

- At least one `[[routes]]`; upstreams and upstream pools are optional when every route serves local static files.
- Each route must set exactly one of `upstream`, `upstream_pool`, or `static_root`.

## Includes

The main entry file can include modular TOML files:

```toml
include = [
  "conf.d/upstreams.toml",
  "conf.d/routes/*.toml",
]
```

`include` may be a single string or an array of strings. Include entries support exact file paths and glob patterns using `*`, `?`, and `[...]`.

Include behavior:

- Entries must be relative paths under the declaring file's directory.
- Absolute paths, `.` components, and `..` components are rejected.
- Exact include paths must exist.
- Glob matches are sorted before loading for deterministic startup.
- Glob entries that match no files are allowed.
- Included files may contain their own `include` entries.
- Include cycles are rejected.
- Include symlinks or glob matches that resolve outside the declaring file's directory are rejected.

TOML merge behavior:

- Included files are merged before the declaring file.
- Tables are merged recursively.
- Arrays are appended in include expansion order, then the declaring file's own array entries are appended.
- Duplicate scalar keys and incompatible value types are rejected.

Example split:

```toml
# source/config/oxibelt.toml
include = ["conf.d/*.toml"]

[listeners]
https_bind = "0.0.0.0:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"
```

```toml
# source/config/conf.d/10-upstreams.toml
[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2"
```

```toml
# source/config/conf.d/20-routes.toml
[[routes]]
name = "app-root"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
```

## Core Sections

```toml
[config]
strict_unknown_fields = true
warn_on_deprecated_fields = true

[logging]
level = "info"

[logging.access_log]
enabled = false
stdout = true
```

`strict_unknown_fields` defaults to `true`; unknown keys fail startup after includes are merged. `level` is passed to the tracing filter and defaults to `info`.

`logging.access_log` enables request-wide structured access logs without requiring an OxiRule `emit_access_log` action. When enabled, OxiBelt emits one newline-delimited JSON record for each finalized HTTP response with `event = "oxibelt.access"` and `scope = "system"`. The default fields include request/response IDs, transaction ID, method, URI, client IP, route, status, upstream name, upstream timing fields, and a duplicate-safe `user_agent` collection from `Request.Headers.getAll('User-Agent')`.

Custom fields use the same expression syntax as OxiRule access-log fields:

```toml
[logging.access_log]
enabled = true
stdout = true

[[logging.access_log.fields]]
name = "method"
value = "Request.Http.Method"

[[logging.access_log.fields]]
name = "status"
expression = "Response.Http.Status"
```

`[logging.access_log.database]` has the same shape as `[database.access_log]`, but it is a separate sink used only for system-wide access logs.

```toml
[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = "auto"

[runtime.worker_multipliers]
runtime = 1.0
accept = 1.0
quic_socket = 1.0

[runtime.accept]
workers = "auto"
reuse_port = true
backlog = 8192
accept_error_backoff_ms = 10

[runtime.drain]
graceful_timeout_ms = 30000
long_connection_close_delay_ms = 300000
shutdown_delay_ms = 0

[runtime.hot_reload]
mode = "off" # off | oxirule | downstream_tls | full
poll_interval_ms = 2000
```

`unprivileged_mode = true` rejects listener ports below `1024`. `worker_threads` accepts a positive integer or `"auto"`; omitted values default to `"auto"`. Auto worker sizing uses Rust `std::thread::available_parallelism()`, falls back to `1` when detection fails, multiplies by `[runtime.worker_multipliers].runtime`, and rounds up. Full hot reload rejects changes to the resolved `runtime.worker_threads` value because the Tokio runtime cannot be resized in-process.

`[runtime.accept]` controls data-plane TCP accept loops for HTTPS, plain HTTP, and TCP stream listeners. `workers` accepts a positive integer or `"auto"`; omitted values default to `"auto"` and use `[runtime.worker_multipliers].accept`. Set `reuse_port = true` whenever the resolved worker count can be greater than one; OxiBelt fails startup instead of silently enabling `SO_REUSEPORT`. `backlog` is passed to `listen(2)`. `accept_error_backoff_ms` throttles repeated accept errors.

`[runtime.drain]` controls reload and shutdown draining. `graceful_timeout_ms` is the maximum time a stopped listener generation waits for active HTTP/1.1 and HTTP/2 requests to finish before force-closing remaining connection tasks. Successful reloads also drain existing HTTP connections that captured the previous data-plane snapshot, even when listener binds do not change, so new requests use the replacement snapshot on new connections. `long_connection_close_delay_ms` protects upgraded WebSocket/generic Upgrade, CONNECT, WebTransport, and TCP stream bridges after a drain signal before they are closed; drained WebTransport bridges keep existing sessions for that grace window but reject new request streams immediately. `shutdown_delay_ms` marks the instance draining and waits before listener drain begins; `0` is allowed. `graceful_timeout_ms` and `long_connection_close_delay_ms` must be greater than zero.

`poll_interval_ms` must be greater than zero. CLI flags `--hot-reload-mode` and `--hot-reload-poll-interval-ms` override TOML values and emit warnings when they differ.

Reload modes:

- `off`: no reload.
- `oxirule`: reload only WAF-owned configuration and external rule files.
- `downstream_tls`: reload the current downstream certificate, key, and static OCSP response.
- `full`: reload OxiRule policy, TOML configuration, upstream clients, access-log sinks, downstream TLS material, downstream listener bind/protocol settings, and admin listener enable/bind settings.

Reload failures keep the previous active state.

Successful full reloads start replacement listeners before draining old listener generations. Successful OxiRule, downstream TLS, full, and runtime pool snapshot replacements drain previous HTTP connection generations as well. Local readiness stays OK for a successful reload because the active replacement snapshot is serving; existing requests on the old generation finish within `graceful_timeout_ms`, and long-lived upgraded or stream connections keep their drain grace from `long_connection_close_delay_ms`. During that grace period, new WebTransport CONNECT or ordinary HTTP/3 request streams on a drained WebTransport connection are rejected with `503` instead of using the previous snapshot.

## Listeners and TLS

```toml
[listeners]
https_bind = "0.0.0.0:8443"
http_bind = "0.0.0.0:8080"
http_mode = "redirect_to_https" # off | redirect_to_https | proxy
http1 = true
http2 = true
http3 = false

[listeners.proxy_protocol]
enabled = false
version = "any" # v1 | v2 | any
trusted_sources = []
```

At least one downstream HTTP version must be enabled. HTTP/1.1 and HTTP/2 listen on TCP. HTTP/3 listens on UDP using the same `https_bind` address and port. PROXY protocol is accepted only from configured trusted sources.

```toml
[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"
min_version = "tls1.3"
max_version = "tls1.3"
session_tickets = true
session_ticket_rotation_seconds = 86400

[tls.remote_signer]
enabled = false
# socket_path = "/run/oxibelt-keysigner/sign.sock"
# key_id = "edge-default"
token_env = "OXIBELT_KEYSIGNER_TOKEN"
connect_timeout_ms = 250
sign_timeout_ms = 1000
allow_tls12_unstructured_signing = false

[tls.client_auth]
mode = "off" # off | optional | require
ca_certs = []
verify_depth = 4

[tls.ocsp]
mode = "disabled" # disabled | static_file | live_fetch
# response_file = "ocsp.der"
```

`cert_chain` is always required. `private_key` is required unless `tls.remote_signer.enabled = true`; when remote signing is enabled, `private_key` must not be set. The remote signer uses a Unix domain socket and a base64 32-byte token from `token_env`; `socket_path` must be absolute, and `key_id` selects the signer-held key. By default, remote signing is limited to TLS 1.3 server CertificateVerify inputs. Set `allow_tls12_unstructured_signing = true` only when TLS 1.2 compatibility is required and the signer sidecar is started with the same opt-in.

Run the sidecar as a separate UID that can read private key files. OxiBelt should be able to read certificate chains and connect to the socket, but should not be able to read private keys. The sidecar command is:

```sh
oxibelt-keysigner \
  --socket /run/oxibelt-keysigner/sign.sock \
  --key edge-default=/etc/oxibelt/cert/privkey.pem \
  --token-env OXIBELT_KEYSIGNER_TOKEN \
  --socket-mode 0660 \
  --max-connections 256 \
  --io-timeout-ms 5000 \
  --allow-peer-uid 10001
```

The signer enforces its own IPC availability controls before token validation: `--max-connections` caps concurrently handled Unix-socket clients, and `--io-timeout-ms` bounds request-frame reads and response writes so idle or trickled local peers cannot hold signer tasks indefinitely. Keep the socket directory and mode restrictive, and prefer `--allow-peer-uid` or `--allow-peer-gid` in sidecar deployments.

Remote signing is compatible with read-only root filesystems, but the socket directory itself must be writable. The signer creates the Unix socket file at `socket_path`, so a container started with `--read-only` should provide a tmpfs or shared volume for the parent directory, for example `--tmpfs /run/oxibelt-keysigner:rw,noexec,nosuid,nodev,mode=0770`. In a sidecar deployment, mount that same socket directory into both containers. Mount private keys read-only into the signer container only; OxiBelt should receive certificate chains and the signer socket, not private key files. If the signer cannot create the socket, OxiBelt cannot describe the remote key: startup fails for initial config load, and hot reload rejects the new TLS config while preserving the active one.

`tls.client_auth.ca_certs` is required when client authentication mode is not `off`. `tls.ocsp.mode = "static_file"` requires `response_file`; `live_fetch` is reserved and rejected. HTTP/3 requires `tls.min_version = "tls1.3"`.

OxiBelt does not perform ACME issuance, HTTP-01 or DNS-01 challenge handling, or certificate renewal itself. Provision and renew TLS files with external automation such as Certbot or the `certbot/certbot` Docker image, then point `cert_chain` and `private_key` at the generated files under the cert directory. Use `runtime.hot_reload.mode = "downstream_tls"` or `full` when renewed TLS material should be picked up without a process restart.

Keep ACME credentials, DNS-01 provider tokens, renewal state, and private signing keys out of the OxiBelt process/container when possible. This limits blast radius if a proxy vulnerability ever exposes process memory or permits remote code execution: the running proxy may have access to certificate chains and remote signing capability, but it should not also contain private keys or the DNS/ACME credentials needed to mint arbitrary new certificates. A compromised OxiBelt process that still has signer socket and token access may request signatures while that access remains valid, so socket permissions, peer UID/GID allowlists, token rotation, and process isolation remain important.

## QUIC Sections

```toml
[quic]
retry = true
zero_rtt = "off" # off | safe_methods
# host_key_file = "quic-host-key.b64"

[quic.alt_svc]
enabled = true
max_age_seconds = 86400
persist = false

[quic.transport]
max_concurrent_bidi_streams = 512
max_concurrent_uni_streams = 512
idle_timeout_ms = 30000
datagram_receive_buffer_bytes = 1048576
datagram_send_buffer_bytes = 1048576
max_udp_payload_size = 1472
gso = true

[quic.socket]
receive_buffer_bytes = 16777216
send_buffer_bytes = 16777216
workers = "auto"
reuse_port = true

[quic.upstream_pool]
enabled = true
max_connections_per_upstream = 1
max_lifetime_ms = 600000
```

`retry = true` enables QUIC Retry/address validation for unvalidated downstream HTTP/3 connection attempts. `zero_rtt = "safe_methods"` enables QUIC TLS early data and rejects unsafe requests that the QUIC transport reports as early data with `425 Too Early`; only early-data `GET` and `HEAD` are accepted.

`host_key_file` is optional and is resolved under the cert directory. It must contain base64 for exactly 64 random bytes. OxiBelt derives QUIC stateless reset and Retry/validation token keys from this material. The file is included in runtime reload fingerprints and in downstream TLS reload inputs. Do not reuse a key baked into an image; generate deployment-local material, for example `openssl rand -base64 64 > /etc/oxibelt/cert/quic-host-key.b64`, then mount it with the rest of the certificate material.

When downstream HTTP/3 is enabled and `quic.alt_svc.enabled = true`, HTTPS HTTP/1.1 and HTTP/2 responses advertise `Alt-Svc: h3=":<https port>"; ma=<max_age_seconds>`. `persist = true` appends `; persist=1`. OxiBelt does not add `Alt-Svc` to downstream HTTP/3 responses, plain HTTP responses, or `101 Switching Protocols`.

`quic.socket.receive_buffer_bytes = 0` and `send_buffer_bytes = 0` keep the OS defaults. Nonzero socket buffer values are applied to UDP sockets, and startup fails if the OS rejects an explicitly configured buffer size. `quic.socket.workers` accepts a positive integer or `"auto"`; omitted values default to `"auto"` and use `[runtime.worker_multipliers].quic_socket`. When HTTP/3 is enabled, set `reuse_port = true` whenever the resolved worker count can be greater than one, which creates one `SO_REUSEPORT` UDP socket per downstream HTTP/3 worker. Other QUIC transport, socket, and pool numeric values must be greater than zero; `max_udp_payload_size` must be in the QUIC-valid range `1200..=65527`.

The upstream HTTP/3 pool multiplexes ordinary HTTP/3 request forwarding over reusable QUIC connections when `quic.upstream_pool.enabled = true`. When disabled, ordinary HTTP/3 upstream requests use one-shot QUIC connections. WebTransport forwarding keeps a dedicated QUIC connection per session.

## Proxy Sections

```toml
[proxy]
trusted_ca_certs = []

[proxy.forwarded_headers]
mode = "overwrite" # overwrite | append

[proxy.real_ip]
enabled = false
trusted_proxies = []
header = "x-forwarded-for" # x-forwarded-for | x-real-ip | forwarded | cf-connecting-ip
recursive = true
fail_on_untrusted_forwarded_headers = false

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2" # h1 | h2 | h3

[proxy.upgrades]
websocket = true
generic_http_upgrade = false
connect_tunneling = false

[proxy.grpc_web]
enabled = false

[proxy.retry]
enabled = false
tries = 2
timeout_ms = 5000
on = ["connect_error", "read_timeout", "502", "503", "504"]
retry_non_idempotent = false

[proxy.buffering]
request = "streaming"  # streaming | memory | spool | reject_if_too_large
response = "streaming" # streaming | memory | spool | reject_if_too_large
max_memory_body_bytes = 1048576
max_temp_file_bytes = 0
# temp_dir = "/var/cache/oxibelt"

[proxy.static_files]
sendfile = "off" # off | auto
inline_max_bytes = 16384

[proxy.http]
early_hints = "drop" # drop | pass
trailers = "pass"    # pass | drop
expect_continue = "auto" # auto | reject
priority = "pass"    # pass | ignore
sse_auto_streaming = true

[proxy.http.grpc]
enabled = true
respect_grpc_timeout = true
retry = "off"        # off | safe_unary

[proxy.http.errors]
mode = "legacy_plain" # legacy_plain | plain | json
```

`trusted_ca_certs` adds upstream TLS trust roots from the cert directory. `forwarded_headers.mode = "overwrite"` replaces inbound forwarding metadata; `append` preserves and extends the inbound `X-Forwarded-For` chain. `real_ip` affects the client IP used by rate limiting and WAF evaluation only when the direct peer is trusted, and can also drive connection limits when `limits.connection_limit_identity` selects a Real-IP mode.

`generic_http_upgrade` and `connect_tunneling` enable the global capability only. Individual routes must also opt in with `generic_http_upgrade = true` or `connect_tunneling = true`. CONNECT tunnels are not open-proxy tunnels; OxiBelt connects only to the selected route upstream origin. `proxy.grpc_web.enabled` enables the global gRPC-Web transformer, and each route must also set `grpc_web = true`.

`proxy.buffering` controls ordinary HTTP request and response body buffering. `streaming` keeps the previous streaming behavior. `memory` reads the full body into memory up to `max_memory_body_bytes`. `spool` keeps up to `max_memory_body_bytes` in memory and spills the remainder to `temp_dir`, capped by `max_temp_file_bytes` per body. `reject_if_too_large` is memory-only and rejects bodies that exceed `max_memory_body_bytes`. `spool` requires `max_temp_file_bytes > 0` and a writable `temp_dir`; OxiBelt removes `oxibelt-buffer-*` temp files when the buffered body is dropped, when spooled buffering fails before ownership is transferred, and when cleaning stale matching files on initial startup.

`proxy.static_files` controls built-in static file transfer behavior. `inline_max_bytes` reads static response bodies at or below the configured size into a single response frame; `0` disables this small-file inline path. `sendfile = "auto"` enables a guarded Linux `sendfile(2)` fast path only for plaintext HTTP/1.1 `GET` and `HEAD` requests that can be proven equivalent to the normal static route path. Sendfile responses honor the route or global `response_send_timeout_ms` while waiting on downstream write backpressure. HTTPS, HTTP/2, HTTP/3, WAF, dynamic policy, rate limits, compression, security response headers, system access logs, Real-IP connection-limit modes, request bodies, upgrades, CONNECT, ambiguous `Content-Length`, and `Transfer-Encoding` all use the general Hyper path instead.

`proxy.http` controls HTTP compatibility details. `early_hints = "pass"` relays upstream `103 Early Hints` where the downstream transport supports interim responses; `drop` keeps the legacy behavior. `trailers = "drop"` removes body trailer frames for ordinary HTTP traffic while preserving native gRPC trailers. `expect_continue = "auto"` accepts `Expect: 100-continue` and rejects unsupported `Expect` values with `417`; `reject` rejects all `Expect` values. `priority = "ignore"` strips RFC 9218 `Priority` headers instead of forwarding them. `sse_auto_streaming = true` keeps `text/event-stream` responses streaming even when response buffering is enabled.

`proxy.http.grpc` enables native gRPC HTTP semantics. When enabled, OxiBelt preserves gRPC trailers, honors `grpc-timeout` by capping upstream first-byte and read timeouts, maps generated upstream failures to gRPC status trailers, and only retries gRPC requests when `retry = "safe_unary"`. If a client `grpc-timeout` deadline is the reason an upstream first-byte wait expires, OxiBelt returns the gRPC deadline response without counting that event as a passive upstream-pool health failure.

`proxy.http.errors.mode = "json"` changes proxy-generated error bodies to JSON with stable `error`, `status`, `code`, and `request_id` fields. `legacy_plain` preserves the historical body text without setting a content type; `plain` emits the same text with `text/plain`.

## Limits, Cache, and Ops

```toml
[limits]
max_connections = 65536
max_connections_per_ip = 128
max_webtransport_sessions = 65536
max_webtransport_sessions_per_ip = 128
max_webtransport_sessions_per_connection = 256
connection_limit_identity = "proxy_protocol" # proxy_protocol | first_request_real_ip | per_request_real_ip
max_requests_per_connection = 1000
client_header_timeout_ms = 10000
client_body_timeout_ms = 30000
client_idle_timeout_ms = 75000
websocket_idle_timeout_ms = 75000
webtransport_idle_timeout_ms = 75000
tls_handshake_timeout_ms = 10000
response_send_timeout_ms = 60000
max_headers = 128
max_header_name_bytes = 128
max_header_value_bytes = 8192
max_total_header_bytes = 65536
max_uri_bytes = 8192
max_request_body_bytes = 10485760

[[rate_limits]]
name = "per-ip"
key = "client_ip"
rate = "10r/s"
burst = 50
max_buckets = 16384
mode = "enforcing" # enforcing | monitor
status = 429

[[rate_limits]]
name = "per-api-token-route"
key = "access_token_route"
routes = ["api"]
token_header = "X-Api-Token"
rate = "60r/m"
burst = 60
max_buckets = 16384
status = 429

[[connection_limits]]
name = "per-ip-connections"
key = "client_ip"
limit = 64
status = 429
```

Limit values must be greater than zero. Rate limit keys are `client_ip`, `client_ip_route`, `client_ip_path`, `access_token`, `access_token_route`, and `access_token_path`; `client-ip` style spellings are accepted as compatibility aliases. `routes` restricts a rate limit to named routes. Access-token limits read `Authorization: Bearer <token>` first and then optional `token_header`; token values are hashed before storage, and missing tokens fall back to the client IP bucket. `max_buckets` caps the number of local process buckets kept for a single rate limit, defaults to `16384`, and should be lowered for attacker-controlled key modes when a route expects low identity cardinality. In process-local enforcing mode, a request that would create a new bucket after the cap is reached is rejected with the rate limit status until an existing bucket has fully refilled and can be reclaimed; monitor mode stops adding new buckets after the cap. Rate and connection limit state is process-local by default. When `[shared_state].enabled = true` and the relevant feature maps to a backend, route rate token buckets, WAF `rate_limit` action buckets, and downstream connection leases are shared across instances. This shared rate-limit path supports both Redis-compatible and PostgreSQL backends. `max_connections` applies at downstream accept time. `max_connections_per_ip` and `[[connection_limits]]` use the configured `connection_limit_identity`: `proxy_protocol` counts the direct peer or trusted PROXY protocol source for the whole connection, `first_request_real_ip` binds the connection to the first trusted Real-IP header value, and `per_request_real_ip` acquires a lease per HTTP request until its response body finishes. Active WebTransport sessions also acquire dedicated total and per-IP session leases; in Real-IP modes they must also acquire the same normal per-IP and named connection leases as ordinary requests for that identity. When not set, `max_webtransport_sessions` and `max_webtransport_sessions_per_ip` inherit `max_connections` and `max_connections_per_ip`, while `max_webtransport_sessions_per_connection` caps multiplexing on one downstream HTTP/3 connection. For HTTP/1 CONNECT, Upgrade tunnels, and WebTransport sessions, Real-IP connection leases remain held until the upgraded tunnel, session, or first-request connection context closes. TCP stream listeners use direct peer IPs. TLS handshake and header timeouts are listener-wide because no route is known yet; body, response-send, WebSocket, and WebTransport idle timeouts can be overridden per route.

```toml
[shared_state]
enabled = false
namespace = "oxibelt"
instance_id_env = "OXIBELT_INSTANCE_ID"
default_backend = "cluster"
operation_timeout_ms = 500
connection_lease_ms = 120000
cache_lock_ms = 10000
rate_limits_backend = "cluster"
connection_limits_backend = "cluster"
person_proof_backend = "cluster"
upstream_health_backend = "cluster"
cache_backend = "cluster"
reload_backend = "cluster"
dynamic_policy_backend = "cluster"

[[shared_state.backends]]
name = "cluster"
kind = "redis" # redis | postgres
connection_url_env = "OXIBELT_SHARED_STATE_URL"
max_connections = 4
connect_timeout_ms = 3000

[shared_state.backends.tls]
mode = "off" # off | verify_full, PostgreSQL only
# ca_cert = "postgres-ca.pem"
# client_cert = "postgres-client.pem"
# client_key = "postgres-client.key"
```

Shared state is opt-in. If it is disabled, features keep their local in-process behavior. When it is enabled, an omitted feature mapping uses `default_backend`, or the first configured backend when `default_backend` is not set. Backends are named, and each feature maps to one backend; OxiBelt does not mirror writes or fall back through backend chains. Exactly one of `connection_url` or `connection_url_env` is required per backend. Effective config dumps redact shared-state `connection_url` values.

Redis backends target Redis-protocol compatible Redis, Valkey, and KeyDB single-endpoint deployments. PostgreSQL backends create OxiBelt-managed shared-state tables at startup. Security-sensitive operations such as rate limits, connection leases, and Person proof fail closed when the configured shared backend errors. Shared cache operations fall back to the local/no-shared-cache path for the current request.

```toml
[dynamic_policy]
enabled = false
backend = "cluster"
refresh_interval_ms = 2000
max_policies = 10000
fail_policy = "use_last_good" # use_last_good | fail_closed_on_startup | disabled_on_error
default_status = 429
default_body = "Blocked by dynamic policy"

[dynamic_policy.automation_api]
enabled = false
require_ttl = true
signature_key_env = "OXIBELT_DYNAMIC_POLICY_HMAC_KEY"
# default_source_quota = 1000 # shared by all sources without an explicit source_quotas entry

[[dynamic_policy.automation_api.source_quotas]]
source = "vaultwarden"
max_active_policies = 100

[dynamic_policy.matching]
trust_route_name = true
normalize_path = true

[shared_state]
enabled = true
namespace = "oxibelt"
dynamic_policy_backend = "cluster"

[[shared_state.backends]]
name = "cluster"
kind = "postgres"
connection_url_env = "OXIBELT_SHARED_STATE_URL"
max_connections = 4
connect_timeout_ms = 3000
```

Dynamic policy is an opt-in PostgreSQL-backed policy snapshot for external security automation. The selected backend comes from `dynamic_policy.backend`, then `shared_state.dynamic_policy_backend`, then `shared_state.default_backend`, and must be a PostgreSQL shared-state backend. PostgreSQL is only the policy source: OxiBelt creates dedicated `oxibelt_dynamic_policies`, `oxibelt_dynamic_policy_generation`, and `oxibelt_dynamic_policy_audit` tables, periodically loads active rows into an immutable in-memory snapshot, and never runs PostgreSQL queries from the request hot path. Legacy external translators, such as a Vaultwarden stdout sidecar, may write this supported policy API table while `dynamic_policy.automation_api.enabled = false`; they should not write `oxibelt_shared_state` or `oxibelt_shared_counters`.

When `[dynamic_policy.automation_api]` is enabled, `[admin]` must also be enabled and `signature_key_env` must point to base64 for exactly 32 random bytes. The Admin API signs rows with HMAC-SHA256 and the snapshot loader rejects active rows whose `signature_version` or `row_signature` does not verify. `require_ttl = true` requires `expires_at` or `ttl_seconds` for Admin-created/imported active policies and for active signed rows loaded into a snapshot. Admin create, import, and patch writes enforce `dynamic_policy.max_policies` before they can add another active row, so the automation API cannot create a snapshot that would exceed the loader cap. Explicit `source_quotas` bound active policies for the matching source. `default_source_quota` bounds the shared bucket for all sources that do not have an explicit `source_quotas` entry, preventing clients from rotating arbitrary source names to gain fresh quota.

Active rows must match `shared_state.namespace`, have `enabled = true`, and be unexpired. `action` is `allow`, `reject`, or `rate_limit`; `subject_type` is `client_ip`, `client_ip_cidr`, `client_ip_route`, or `client_ip_path`. Composite subjects use a pipe separator: `client_ip` stores `203.0.113.10`, `client_ip_cidr` stores `203.0.113.0/24`, `client_ip_route` stores `203.0.113.10|app-route`, and `client_ip_path` stores `203.0.113.10|/identity`. IP portions are parsed and canonicalized when snapshots load, including equivalent IPv6 spellings such as expanded uppercase addresses. `client_ip_route` rows require `route_name`; `client_ip_path` rows require `path_prefix`. Optional `method`, `route_name`, and `path_prefix` further narrow the match. `mode = "dry_run"` records a match without applying an `allow`, `reject`, or `rate_limit`; `mode = "enforce"` applies the selected policy.

When multiple policies match, OxiBelt chooses the most specific match before applying the action: rows with `route_name` beat route-agnostic rows, longer `path_prefix` beats shorter prefixes, exact IP subjects beat CIDR subjects, longer CIDR prefixes beat shorter prefixes, then lower `priority`, then lower `id`. The first enforcing `allow` permits the request; the first enforcing `reject` or `rate_limit` applies as usual. If only dry-run policies match, `DynamicPolicy.*` context is populated and the request continues.

OxiBelt initializes the policy API schema:

```sql
CREATE TABLE IF NOT EXISTS oxibelt_dynamic_policies (
  id bigserial PRIMARY KEY,
  namespace text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  priority integer NOT NULL DEFAULT 100,
  name text NOT NULL,
  source text NOT NULL DEFAULT 'external',
  action text NOT NULL,
  subject_type text NOT NULL,
  subject text NOT NULL,
  route_name text NULL,
  method text NULL,
  path_prefix text NULL,
  rate text NULL,
  burst integer NULL,
  status integer NULL,
  body text NULL,
  reason text NULL,
  code text NULL,
  mode text NOT NULL DEFAULT 'enforce',
  writer_identity text NULL,
  signature_version text NULL,
  row_signature text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS oxibelt_dynamic_policies_active_idx
ON oxibelt_dynamic_policies (namespace, enabled, expires_at, priority);

CREATE INDEX IF NOT EXISTS oxibelt_dynamic_policies_subject_idx
ON oxibelt_dynamic_policies (namespace, subject_type, subject);

CREATE INDEX IF NOT EXISTS oxibelt_dynamic_policies_source_name_idx
ON oxibelt_dynamic_policies (namespace, source, name);

CREATE TABLE IF NOT EXISTS oxibelt_dynamic_policy_generation (
  namespace text PRIMARY KEY,
  generation bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oxibelt_dynamic_policy_audit (
  id bigserial PRIMARY KEY,
  namespace text NOT NULL,
  policy_id bigint NULL,
  actor text NOT NULL,
  operation text NOT NULL,
  source text NULL,
  name text NULL,
  outcome text NOT NULL,
  error text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
```

Example Vaultwarden translator output for a TTL block:

```sql
INSERT INTO oxibelt_dynamic_policies
  (namespace, priority, name, source, action, subject_type, subject, path_prefix, status, body, reason, expires_at)
VALUES
  ('oxibelt', 10, 'vaultwarden-login-block', 'vaultwarden-stdout', 'reject',
   'client_ip_path', '203.0.113.10|/identity', '/identity', 429,
   'Blocked by dynamic policy', 'repeated Vaultwarden login failures',
   now() + interval '15 minutes');

INSERT INTO oxibelt_dynamic_policy_generation (namespace, generation, updated_at)
VALUES ('oxibelt', 1, now())
ON CONFLICT (namespace)
DO UPDATE SET generation = oxibelt_dynamic_policy_generation.generation + 1,
              updated_at = now();
```

For layered login protection, keep a static route/path rate limit and let the translator add short-lived dynamic blocks when Vaultwarden logs repeated failures:

```toml
[[rate_limits]]
name = "vaultwarden-identity-path"
key = "client_ip_path"
routes = ["vaultwarden"]
rate = "30r/m"
burst = 30
status = 429

[[routes]]
name = "vaultwarden"
hosts = ["vault.example.com"]
path_prefix = "/identity"
upstream = "vaultwarden"
```

```toml
[cache]
enabled = false
store = "memory" # memory | tmpfs | disk | memory_then_disk
tmpfs_dir = "/dev/shm/oxibelt-cache"
# disk_dir = "/var/cache/oxibelt"
max_size_bytes = 1073741824
# memory_max_size_bytes = 536870912
# disk_max_size_bytes = 10737418240
memory_auto_fraction = 0.5
default_ttl_seconds = 60
cache_methods = ["GET", "HEAD"]
cache_key = "{scheme}:{host}:{uri}"
partition_key = ""
respect_cache_control = true
stream_large_objects = true
stream_chunk_bytes = 1048576
stale_if_error_seconds = 30
stale_while_revalidate_seconds = 30
lock = true
lock_wait_timeout_ms = 10000
tag_headers = ["Surrogate-Key", "Cache-Tag"]
max_tags_per_entry = 32
max_tag_bytes = 128
max_vary_fields = 8
max_vary_variants_per_key = 64
bypass_request_headers = ["Authorization", "Cookie", "Proxy-Authorization"]
background_refresh = true
background_refresh_max_concurrent = 16
negative_statuses = []
negative_ttl_seconds = 0

[cache.surrogate]
enabled = true
strip_response_header = true

[cache.admission]
statuses = [200, 203, 204, 301, 308]
content_types = []
max_body_bytes = 0
min_hits = 1
max_tracked_keys = 16384

[cache.stale_if_error]
connect_error = true
read_timeout = true
statuses = []
max_upstream_stale_seconds = 0

[[cache.policies]]
name = "assets"
store = "memory_then_disk"

[[cache.policies.rules]]
mime_types = ["image/*", "text/css", "application/javascript"]
store = "disk"

[admin]
enabled = false
bind = "127.0.0.1:9092"
bearer_token_env = "OXIBELT_ADMIN_TOKEN"
transport = "auto" # auto | tls | plaintext_allowlist | plaintext
allow_insecure_plaintext = false
plaintext_allowed_source_cidrs = ["127.0.0.0/8", "::1/128"]

[admin.cache_purge_signing]
enabled = false
key_env = "OXIBELT_CACHE_PURGE_HMAC_KEY"
max_skew_seconds = 300
nonce_ttl_seconds = 600

[[admin.rbac.tokens]]
name = "upstream-ops"
bearer_token_env = "OXIBELT_UPSTREAM_TOKEN"
roles = ["viewer", "upstream_operator"]

[admin.tls]
enabled = false
min_version = "tls1.3"
max_version = "tls1.3"
session_tickets = false
require_sni = true
reject_unknown_sni = true

[[admin.tls.certificates]]
server_names = ["admin.example.com", "*.ops.example.com"]
cert_chain = "admin-fullchain.pem"
private_key = "admin-privkey.pem"
default = true

[admin.tls.client_auth]
mode = "off"
ca_certs = []

[metrics]
enabled = false
bind = "127.0.0.1:9090"
format = "prometheus"

[health]
enabled = false
bind = "127.0.0.1:9091"
ready_path = "/ready"
live_path = "/live"

[security.headers]
hsts = false
hsts_max_age_seconds = 31536000
hsts_include_subdomains = true
hsts_preload = false
# x_content_type_options = "nosniff"
# referrer_policy = "strict-origin-when-cross-origin"
# permissions_policy = "default"

[compression]
enabled = true
gzip = true
deflate = true
zstd = true
br = true
min_size_bytes = 1024
statuses = [200]
mime_types = [
  "text/*",
  "application/json",
  "application/*+json",
  "application/javascript",
  "application/xml",
  "application/*+xml",
  "image/svg+xml",
]
max_concurrent_responses = 0
```

Compression support is enabled by default for `br`, `zstd`, `gzip`, and `deflate`. OxiBelt only compresses downstream responses when the client permits an enabled encoding, the request does not carry `Cookie`, `Authorization`, or `Proxy-Authorization`, the response is not already encoded or secret-bearing, the status/MIME/size policy matches, and HTTP semantics such as `Cache-Control: no-transform` and range responses allow transformation. Responses with `Set-Cookie`, `Cache-Control: private`, or `Cache-Control: no-store` are not compressed. `max_concurrent_responses = 0` uses an automatic CPU budget. Named `[[compression.policies]]` entries can be selected with route `compression`; policy names must not be `default` or `off` because those exact lowercase values are reserved for route selection.

`cache.store = "tmpfs"` validates `tmpfs_dir` under `/dev/shm` when cache is enabled. `disk` and `memory_then_disk` require an explicit writable `disk_dir` and `disk_max_size_bytes`; OxiBelt does not choose a disk path implicitly. If `memory_then_disk` omits `memory_max_size_bytes`, OxiBelt uses `memory_auto_fraction` of the detected cgroup/container memory limit, falling back to system memory. `cache_key` and `partition_key` support `{scheme}`, `{host}`, `{uri}`, `{path}`, `{query}`, `{query:name}`, `{header:Name}`, and `{cookie:name}`. Named cache policies are selected by `routes.cache`; `default` refers to the top-level `[cache]` policy. Policy rules select storage after the upstream response MIME type is known. When `cache_backend` maps to a shared backend, the configured local cache remains L1 and the shared backend stores full cacheable objects, metadata, fill locks, and purge-visible L2 entries.

The cache honors HTTP cache metadata including `Cache-Control`, `Expires`, `ETag`, `Last-Modified`, and `Vary`. It can revalidate stale entries, serve stale entries on configured upstream errors, serve cached byte ranges from full stored responses, and cache configured negative statuses with `negative_statuses` and `negative_ttl_seconds`. Named policies may override negative-cache defaults so routes can opt into different negative caching by selecting a policy. `stale-if-error` serving is controlled separately for connect errors, read timeouts, configured HTTP statuses, and `max_upstream_stale_seconds`, where `0` leaves stale lifetime uncapped beyond the response metadata.

`[cache.surrogate]` parses `Surrogate-Control` for `no-store`, `max-age`, `stale-if-error`, and `stale-while-revalidate`. When enabled, those directives control OxiBelt cache metadata ahead of origin `Cache-Control`, and `strip_response_header = true` removes `Surrogate-Control` before downstream delivery and cached hits. `tag_headers` extracts whitespace- or comma-separated cache tags from response headers such as `Surrogate-Key` and `Cache-Tag`; admin tag purge can remove all entries carrying a tag. `background_refresh` serves a stale response immediately during `stale-while-revalidate` and refreshes eligible GET/HEAD responses in the background. OxiBelt skips background refresh for response-WAF inspected routes, HTTP/3 upstreams, and PROXY protocol egress routes, which continue to use foreground revalidation. `lock_wait_timeout_ms` bounds collapsed-forwarding followers so a stuck fill cannot block indefinitely.

`[cache.admission]` filters what is admitted into cache after HTTP cacheability checks. `statuses` limits response status codes, `content_types` optionally limits MIME patterns, `max_body_bytes = 0` means unlimited, `min_hits` requires repeated fills before storing, and `max_tracked_keys` bounds frequency tracking memory. `max_vary_fields` and `max_vary_variants_per_key` reject unbounded `Vary` explosions before storing. `bypass_request_headers` keeps credential-bearing requests out of cache by default. Cache fills collect only responses whose announced body size is no greater than both `cache.max_size_bytes` and `proxy.buffering.max_memory_body_bytes`; larger or unknown-size responses are streamed downstream without being stored. `stream_large_objects` is retained for configuration compatibility, but it does not raise the in-memory cache-fill collection limit. Named `[[cache.policies]]` may override partition keys, tag headers, tag limits, Vary limits, background refresh settings, lock wait timeout, admission, stale-if-error behavior, and negative-cache defaults.

Cache poisoning defenses should be explicit in production configs. Keep `Authorization` and `Cookie` requests out of cache unless the cache key intentionally varies by a safe credential-derived token; include the effective `Host` in `cache_key`; rely on upstream `Vary` for negotiated headers; and prefer `{query:name}` allowlist-style keys over broad `{query}` when only selected query parameters affect the response.

`[admin]` exposes operations APIs such as cache purge and upstream-pool runtime control. `transport = "auto"` accepts plaintext only from `plaintext_allowed_source_cidrs`; other clients must use TLS. Use `plaintext_allowlist` for Docker bridge or same-host management networks that intentionally use plaintext, and add those CIDRs explicitly. `transport = "plaintext"` is rejected unless `allow_insecure_plaintext = true`. When admin TLS is enabled, `server_names` are matched case-insensitively and may use a leftmost wildcard such as `*.ops.example.com`; missing or unknown SNI is rejected by default. Admin requests always require `Authorization: Bearer <token>`, even when mTLS is enabled.

`admin.bearer_token_env` remains the backward-compatible built-in admin token and receives the `admin` role. Additional `[[admin.rbac.tokens]]` entries name token environment variables and roles. Roles are `viewer`, `cache_operator`, `upstream_operator`, `security_operator`, and `admin`; `admin` implies all scopes. Cache purge requires `cache_operator` or a valid `[admin.cache_purge_signing]` HMAC signature; upstream-pool reads require `viewer`; upstream-pool mutations require `upstream_operator`; dynamic policy automation APIs require `security_operator`. Full hot reload starts, stops, or rebinds the dedicated admin listener when `admin.enabled` or `admin.bind` changes.

Admin lifecycle endpoints:

- `GET /admin/v1/lifecycle`
- `POST /admin/v1/lifecycle/drain`
- `POST /admin/v1/lifecycle/undrain`

Lifecycle read requires `viewer` or `admin` and returns `{"draining": bool, "reason": string}`. Drain and undrain require `admin`. Admin drain makes `/ready` return `503 draining`, keeps `/live` at `200 live`, and rejects new data-plane requests with `503 draining` and `Connection: close`; in-flight requests continue. Undrain clears only admin-initiated drain state.

Admin WAF telemetry endpoint:

- `GET /admin/v1/waf/rule-hits`
- `GET /admin/v1/waf/crs/compatibility`

These endpoints require `viewer` or `admin`. Rule hits returns active rule hit counters with `scope`, `route`, `phase`, `name`, optional `id`, `effective_mode`, and `hits`. CRS rule hit entries also include `tags`, `tuned_hits`, latest observed anomaly scores, and latest blocking scores when available. The CRS compatibility endpoint returns the OxiBelt-supported CRS release lines, supported directives/operators/transforms/variables/actions, accepted-but-ignored syntax, fail-closed policy, and known unsupported surfaces.

Admin upstream-pool endpoints:

- `GET /admin/v1/upstream-pools`
- `GET /admin/v1/upstream-pools/{pool}`
- `POST /admin/v1/upstream-pools/{pool}/servers`
- `PATCH /admin/v1/upstream-pools/{pool}/servers/{server_id}`
- `DELETE /admin/v1/upstream-pools/{pool}/servers/{server_id}`

Runtime server mutation accepts JSON fields `id`, `origin`, `state`, `weight`, `backup`, and `max_conns` where applicable. `DELETE` is limited to servers created by the admin API. Every admin mutation emits a structured audit log with actor, peer, operation, target, outcome, and validation error when rejected.

Dynamic policy automation endpoints:

- `GET /admin/v1/dynamic-policies`
- `GET /admin/v1/dynamic-policies/{id}`
- `POST /admin/v1/dynamic-policies`
- `PATCH /admin/v1/dynamic-policies/{id}`
- `DELETE /admin/v1/dynamic-policies/{id}`
- `GET /admin/v1/dynamic-policies/export`
- `POST /admin/v1/dynamic-policies/import`

Create/import JSON accepts `source`, `name`, `action`, `subject_type`, `subject`, optional `route_name`, `path_prefix`, `method`, `rate`, `burst`, `status`, `body`, `reason`, `code`, `mode`, and either `expires_at` or `ttl_seconds` when TTL is required. Create, import, and patch reject changes that would exceed either the global active policy cap or the matching source quota bucket. Import payloads use `{ "policies": [...] }` and upsert by `namespace + source + name`; duplicate rows beyond the lowest `id` are disabled. `DELETE` disables the row instead of physically removing it.

Admin purge endpoints:

```sh
POST /cache/purge?policy=default&scheme=https&host=example.test&uri=/path
POST /cache/purge-prefix?policy=default&scheme=https&host=example.test&path_prefix=/assets/
POST /cache/purge-tag?policy=default&tag=release-2026-05-09
```

Purge requests also accept optional `partition`. When `[admin.cache_purge_signing]` is enabled, purge requests may authenticate with `X-OxiBelt-Cache-Timestamp`, `X-OxiBelt-Cache-Nonce`, and `X-OxiBelt-Cache-Signature` instead of a bearer token. The signature is base64 HMAC-SHA256 over `OXIBELT-CACHE-PURGE-V1\n{method}\n{path_and_query}\n{sha256(body)}\n{timestamp}\n{nonce}`; signed purge requests must use an empty body.

Admin cache diagnostics and warming endpoints:

```sh
POST /admin/v1/cache/key-explain
POST /admin/v1/cache/warm
```

`key-explain` requires `viewer` and accepts `{ "policy": "default", "method": "GET", "scheme": "https", "host": "example.test", "uri": "/asset.css", "headers": {}, "response_headers": {} }`. It returns the selected policy, partition, base key, optional variant key, Vary fields, and cacheability reasons. `warm` requires `cache_operator` and accepts `{ "items": [{ "scheme": "https", "host": "example.test", "uri": "/asset.css", "method": "GET", "headers": {} }] }`; methods are limited to `GET` and `HEAD`, and each item returns `stored`, `not_cacheable`, `upstream_error`, or `validation_error`.

Health paths must start with `/`. Readiness returns `503 draining` while lifecycle drain is active; liveness remains `200 live` so process supervisors can distinguish intentional drain from process failure. Prometheus metrics omit detailed WAF rule names, IDs, modes, routes, and per-rule hit counters because the metrics listener is intended for unauthenticated operational scraping. Use the authenticated admin WAF telemetry endpoint for that rule-level data.

## Database Access Log Sink

```toml
[database.access_log]
enabled = false
connection_url_env = "OXIBELT_ACCESS_LOG_DATABASE_URL"
table = "oxibelt_access_log"
max_connections = 4
connect_timeout_ms = 3000
queue_capacity = 1024

[database.access_log.tls]
mode = "off" # off | verify_full
# ca_cert = "postgres-ca.pem"
# client_cert = "postgres-client.pem"
# client_key = "postgres-client.key"
```

This optional PostgreSQL sink mirrors OxiRule `emit_access_log` records. It does not receive request-wide system access logs; use `[logging.access_log.database]` for that separate sink. When enabled, exactly one of `connection_url` or `connection_url_env` is required, and `table` is required.

The target table must already exist:

```sql
CREATE TABLE audit.access_log (
  event text NOT NULL,
  timestamp_unix_ms bigint NOT NULL,
  record jsonb NOT NULL
);
```

`table` may be unqualified, such as `oxibelt_access_log`, or schema-qualified, such as `audit.access_log`. Identifier segments must contain only ASCII letters, digits, and underscores. `ca_cert`, `client_cert`, and `client_key` are valid only with `mode = "verify_full"`; client cert and key must be configured together.

## WAF Attachment

```toml
[waf]
enabled = false
mode = "enforcing"      # enforcing | monitor
fail_policy = "closed"  # closed | open
duplicate_metadata_policy = "fail_closed" # fail_closed | null_on_duplicate | reject_request

[waf.limits]
max_rule_runtime_ms = 5
max_total_waf_runtime_ms = 20
max_expression_steps = 2000
max_memory_bytes = 262144
max_string_bytes = 8192
max_body_inspection_bytes = 1048576
max_header_count = 128
max_header_value_bytes = 8192
max_mutations = 32
max_regex_runtime_ms = 2
max_helper_items = 128
max_helper_pattern_count = 32
max_helper_result_bytes = 8192
max_person_proof_reuse_tokens = 4096

[[waf.pattern_sets]]
name = "sql-injection-keywords"
kind = "contains" # contains | regex
patterns = ["UNION SELECT", "DROP TABLE", "information_schema"]

[waf.crs]
enabled = false
mode = "monitor" # monitor | enforcing
setup_file = "crs/crs-setup.conf"
rule_files = ["crs/rules/*.conf"]
paranoia_level = 1
inbound_anomaly_score_threshold = 5
outbound_anomaly_score_threshold = 4
unsupported_directive_policy = "fail_closed"

[[waf.crs.rule_overrides]]
name = "monitor-sqli-rule"
rule_ids = ["942100"]
tags = ["attack-sqli"]
mode = "monitor" # enforcing | monitor | disabled
reason = "known application false positive"

[[waf.crs.allowlists]]
name = "allow-editor-html"
rule_ids = ["941320"]
methods = ["POST"]
routes = ["app-root"]
path_prefixes = ["/editor/"]
reason = "editor intentionally submits HTML"
```

`max_body_inspection_bytes` also bounds WebSocket stream-WAF frame buffering: an individual WebSocket frame payload larger than this value is closed fail-closed instead of being buffered for prefix inspection.

Inline global rules are configured under `[[waf.rules]]`; route-level rules use `[[routes.waf.rules]]`. External rule entries use `path` and resolve under the oxirule directory. A rule entry must specify exactly one of `when` or `path`.

```toml
[[waf.rules]]
name = "block-public-admin"
id = "block-admin-public"
tags = ["access-control", "admin"]
mode = "monitor" # optional: enforcing | monitor; defaults to [waf].mode
phase = "request"
priority = 100
when = "Request.Http.Path.startsWith('/admin')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Forbidden"
```

`[waf].mode` sets the default mode for all rules. A rule-level `mode` overrides that default in both directions: `monitor` counts matches without applying actions, while `enforcing` applies actions normally.

`[waf.crs]` enables the CRS-compatible execution layer. It loads `setup_file` and each `rule_files` glob from the OxiRule directory, using the same normalized relative path restrictions as external OxiRule files. CRS starts in `monitor` mode by default so hits and anomaly scores are recorded without blocking; set `mode = "enforcing"` to apply inbound and outbound anomaly thresholds. Unsupported CRS directives, operators, transforms, variables, or actions fail closed at configuration load/compile time and report the file and line that must be changed.

`[[waf.crs.rule_overrides]]` applies the first matching static rule override. Select rules with `rule_ids`, `tags`, or `msg_contains`; at least one selector is required. `mode = "monitor"` records observed hits and anomaly score without contributing to blocking score, `mode = "enforcing"` can enforce even when global CRS mode is monitor, and `mode = "disabled"` records hits without scoring/actions.

`[[waf.crs.allowlists]]` is for scoped false-positive tuning. It uses the same rule selectors and also requires at least one traffic selector: `methods`, `routes`, or `path_prefixes`. Traffic selector categories are ANDed together, while values within a category are ORed. A matching allowlist suppresses CRS scoring/actions for that transaction and increments `tuned_hits`; broad rule disables should use `rule_overrides` instead. `header_equals` is rejected for CRS allowlists because inbound request headers are client-controlled before proxy forwarding.

Recommended CRS rollout is monitor first, inspect `/admin/v1/waf/rule-hits`, add scoped allowlists or per-rule overrides for confirmed false positives, then switch `[waf.crs].mode` to `enforcing`. The compatibility matrix is available from `/admin/v1/waf/crs/compatibility`; OxiBelt targets the CRS current release and `v4.25.x` LTS line as of 2026-05-10. Official CRS references: [v4.25.0 LTS announcement](https://coreruleset.org/20260321/announcing-crs-v4-25-lts/), [false positives and tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/), and [installation](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/).

Response body CRS inspection uses the same bounded prefix behavior as OxiRule response body inspection and can affect cache/background refresh behavior. Treat response inspection as a targeted control for leakage detection, not a substitute for upstream output encoding. WebTransport frame/datagram payload inspection is not supported by the CRS layer.

Rule syntax, actions, helpers, and Person proof settings are documented in [OxiRule.md](OxiRule.md).

## Upstreams

```toml
[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2" # h1 | h2 | h3
connect_timeout_ms = 3000
request_timeout_ms = 30000
first_byte_timeout_ms = 30000
read_timeout_ms = 30000
send_timeout_ms = 30000
idle_timeout_ms = 75000
preserve_host = false
websocket = true
webrtc = true
webtransport = true
proxy_protocol_egress = "off" # off | v1 | v2

[upstreams.tls.ech]
mode = "disabled" # disabled | grease | config_list
# config_list_file = "app.echconfiglist"
```

Upstream origins must use `http://` or `https://`. `max_http_version = "h3"` requires an `https://` origin. ECH `config_list_file` is required only with `mode = "config_list"` and is invalid for other modes. `proxy_protocol_egress` writes a PROXY protocol header to TCP-based upstream connections and is rejected with HTTP/3 upstream selection.

`request_timeout_ms` is the compatibility upper bound for sending a request and receiving response headers. `first_byte_timeout_ms` separately controls the response-header/first-byte wait and is capped by `request_timeout_ms` when both are configured. `read_timeout_ms` is an upstream response body idle timeout. `send_timeout_ms` controls upstream request body send backpressure.

```toml
[[upstream_pools]]
name = "app-pool"
algorithm = "round_robin" # round_robin | least_conn | random | hash | ip_hash
# hash_key = "Request.Http.Path"

[upstream_pools.keepalive]
max_idle = 32
idle_timeout_ms = 75000
max_lifetime_ms = 300000

[[upstream_pools.servers]]
id = "app-1"
origin = "https://app-1.internal.example"
weight = 1
max_conns = 1024
backup = false
state = "ready" # ready | drain | down | maintenance

[[upstream_pools.discovery]]
provider = "file"
file = "discovery/app-pool.json"
refresh_interval_ms = 5000

[[upstream_pools.discovery]]
provider = "dns"
name = "app.internal.example"
record_type = "a_aaaa" # a | aaaa | a_aaaa | srv
scheme = "http"
port = 8080
refresh_interval_ms = 30000
min_ttl_ms = 1000

[upstream_pools.health_check]
enabled = true
mode = "passive" # passive | active
protocol = "http" # http | grpc
path = "/health"
interval_ms = 10000
timeout_ms = 2000
healthy_threshold = 2
unhealthy_threshold = 3
expected_status = [200]
grpc_service = ""
grpc_expected_statuses = ["SERVING"]
```

Pool names and upstream names are separate namespaces. `sticky_cookie` is reserved and rejected. `algorithm = "hash"` requires `hash_key`. Pool servers must use `http://` or `https://`, server IDs must be unique within a pool, and server weights must be greater than zero.

Pool server `state` controls new request selection. `ready` accepts traffic. `drain`, `down`, and `maintenance` stop new selection while already selected in-flight requests finish naturally.

Dynamic discovery applies to `upstream_pools` only. `provider = "file"` reads a JSON document from a path under the config directory, for example `source/config/discovery/app-pool.json` when running from the repository layout. The document shape is:

```json
{
  "servers": [
    {
      "id": "app-2",
      "origin": "http://app-2.internal.example:8080",
      "weight": 1,
      "max_conns": 1024,
      "backup": false
    }
  ]
}
```

`provider = "dns"` resolves `name` using `record_type = "a"`, `"aaaa"`, `"a_aaaa"`, or `"srv"`. A/AAAA discovery requires `port`; SRV discovery uses the SRV target port. DNS refresh uses the lower of the configured `refresh_interval_ms` and the observed DNS TTL, bounded by `min_ttl_ms`. DNS discovery rejects unsuccessful responses and responses whose transaction ID, question, answer owner, or verified CNAME chain does not match the active query. `kubernetes`, `consul`, and `etcd` are reserved provider names and are rejected in this version.

## Routes

```toml
[[routes]]
name = "api-v1"
hosts = ["api.example.com"]
path_prefix = "/v1"
replace_prefix_with = "/"
upstream = "app"
# upstream_pool = "app-pool"
# static_root = "public"
# upstream_http_version = "h2" # h1 | h2 | h3
# generic_http_upgrade = false
# connect_tunneling = false
# grpc_web = false
# cache = "default"
# compression = "default" # default | off | named policy

[routes.timeouts]
# client_body_timeout_ms = 15000
# response_send_timeout_ms = 30000
# websocket_idle_timeout_ms = 60000
# webtransport_idle_timeout_ms = 60000
# upstream_connect_timeout_ms = 1000
# upstream_request_timeout_ms = 15000
# upstream_first_byte_timeout_ms = 2000
# upstream_read_timeout_ms = 10000
# upstream_send_timeout_ms = 10000

[routes.buffering]
# request = "streaming"
# response = "streaming"
# max_memory_body_bytes = 1048576
# max_temp_file_bytes = 0
```

`upstream_http_version` is a route-level backend protocol override and must not exceed the selected upstream capability. HTTP/3 overrides are rejected for upstream-pool routes and for upstreams with PROXY protocol egress enabled.

Route timeout overrides are optional. Omitted values inherit from `[limits]` for downstream behavior and from the selected `[[upstreams]]` entry for upstream behavior. TLS handshake and downstream header read timeouts are not route-level because route matching has not happened yet.

Route buffering overrides are optional. Omitted values inherit from `[proxy.buffering]`; `temp_dir` is always global. CONNECT tunnels, HTTP Upgrade, and WebTransport forwarding remain streaming even when buffering is enabled.

Fields:

- `name`: unique route name.
- `hosts`: host match list; defaults to `["*"]`.
- `path_prefix`: path prefix match; defaults to `/`.
- `replace_prefix_with`: optional upstream path prefix replacement.
- `upstream`, `upstream_pool`, or `static_root`: exactly one target.
- `cache`: optional cache reference; `default` uses `[cache]`, and any other value must match `[[cache.policies]].name`.
- `compression`: optional downstream response compression policy; omitted means `default`, `off` disables compression for the route, and any other value must match `[[compression.policies]].name`. Named compression policies must not use the exact lowercase names `default` or `off`.

Route path values must start with `/` and must not contain control characters, backslashes, query strings, fragments, dot segments, or encoded dot/slash separators such as `%2e`, `%2f`, or `%5c`.

`static_root` enables the built-in static file server for the route. The value must resolve to an existing directory; absolute paths are accepted, and relative paths loaded through `Config::load` resolve under the configuration directory. OxiBelt strips the matched `path_prefix`, percent-decodes each remaining path segment, and serves only regular files whose canonical path stays under `static_root`. Directory listing is forbidden, and symlinks are allowed only when their canonical target remains inside the static root. Opened file descriptors are rechecked through `/proc/self/fd`, and response metadata, validators, ranges, and bytes are all derived from that same verified descriptor. Static routes accept `GET` and `HEAD`, emit `ETag`, `Last-Modified`, and `Accept-Ranges`, support a single `Range: bytes=...` request, and honor `If-None-Match` and `If-Modified-Since`. Request WAF, response WAF, rate limits, dynamic policy, security headers, compression, and Alt-Svc still apply on the general path. Static routes reject upstream-only options such as `replace_prefix_with`, `cache`, `upstream_http_version`, `generic_http_upgrade`, `connect_tunneling`, and `grpc_web`.

## TCP Stream Listeners

```toml
[[stream_listeners]]
name = "postgres"
bind = "0.0.0.0:15432"
target = "db.internal.example:5432"
connect_timeout_ms = 3000
idle_timeout_ms = 75000
proxy_protocol_egress = "off" # off | v1 | v2
```

Stream listeners proxy raw TCP from a dedicated bind address to a single `host:port` target. They do not perform HTTP routing, TLS termination, SNI routing, HTTP rate limiting, or WAF inspection, but their downstream connections are counted by the global connection limits.

## WebRTC TURN Listeners

```toml
[[turn_upstream_pools]]
name = "turn-udp"
algorithm = "round_robin"

[[turn_upstream_pools.servers]]
id = "turn-a"
origin = "turn://turn-a.internal.example:3478"
weight = 1

[[turn_upstream_pools]]
name = "turn-tcp"
algorithm = "round_robin"

[[turn_upstream_pools.servers]]
id = "turn-tcp-a"
origin = "turn+tcp://turn-a.internal.example:3478"
weight = 1

[[turn_upstream_pools]]
name = "turn-tls"
algorithm = "round_robin"

[[turn_upstream_pools.servers]]
id = "turn-tls-a"
origin = "turns://turn-a.internal.example:5349"
weight = 1

[[webrtc_turn_listeners]]
name = "turn-edge"
mode = "proxy_pool" # proxy_pool | edge_relay
bind_udp = "0.0.0.0:3478"
bind_tcp = "0.0.0.0:3478"
bind_tls = "0.0.0.0:5349"
realm = "example.test"
udp_pool = "turn-udp"
tcp_pool = "turn-tcp"
tls_pool = "turn-tls"
idle_timeout_ms = 75000

[webrtc_turn_listeners.auth]
mode = "validate" # pass_through | validate | enforce
rest_shared_secret_env = "OXIBELT_TURN_REST_SECRET"
```

`mode = "proxy_pool"` forwards TURN UDP, TCP, and TLS traffic to `[[turn_upstream_pools]]`. Upstream servers use `turn://`, `turn+tcp://`, or `turns://` origins and advertise their own relay addresses. Listener pool fields are transport-specific: `udp_pool` must reference `turn://` servers, `tcp_pool` must reference `turn+tcp://` servers, and `tls_pool` must reference `turns://` servers. `auth.mode = "validate"` checks authenticated TURN messages when credentials are present, but lets the upstream TURN server issue nonce challenges and remain authoritative.

```toml
[[webrtc_turn_listeners]]
name = "edge-relay"
mode = "edge_relay"
bind_udp = "0.0.0.0:3478"
bind_tcp = "0.0.0.0:3478"
bind_tls = "0.0.0.0:5349"
realm = "example.test"
public_ip = "203.0.113.10"
relay_bind_ip = "0.0.0.0"
idle_timeout_ms = 75000

[webrtc_turn_listeners.relay_port_range]
start = 49152
end = 49200

[webrtc_turn_listeners.auth]
mode = "enforce"

[[webrtc_turn_listeners.auth.static_credentials]]
username = "media-user"
password_env = "OXIBELT_TURN_MEDIA_PASSWORD"
```

`mode = "edge_relay"` makes OxiBelt allocate UDP relay sockets and advertise `public_ip` with a port from `relay_port_range`. It requires enforced TURN authentication and rejects open relay configurations. TURN over TLS reuses `[tls]` certificate material by default; set `[webrtc_turn_listeners.tls] cert_chain` plus exactly one of `private_key` or `remote_signer_key_id` to override it for a listener. `remote_signer_key_id` uses the global `[tls.remote_signer]` socket and token. TURN payloads are protocol-forwarded only; OxiRule/WAF inspection applies to signaling HTTP, not SRTP/media payloads.

Route-level WAF example:

```toml
[[routes.waf.rules]]
name = "api-large-body-guard"
phase = "request"
priority = 100
when = "Request.Http.Method == 'POST' && Request.Http.Body.Size > 1048576"

[[routes.waf.rules.actions]]
type = "reject"
status = 413
body = "Payload Too Large"
```

## Validation Summary

Configuration validation rejects:

- Invalid include values, include cycles, escaped include paths, and missing exact include files.
- Duplicate scalar keys or incompatible value types across included TOML files.
- Unknown keys when `config.strict_unknown_fields = true`.
- No enabled downstream HTTP versions.
- Privileged listener ports when `runtime.unprivileged_mode = true`.
- Non-Linux runtime when `runtime.linux_only = true`.
- Invalid hot reload mode, zero worker counts, non-positive worker multipliers, zero `poll_interval_ms`, zero accept backlog/backoff values, accept worker counts greater than one without `runtime.accept.reuse_port = true`, or HTTP/3 QUIC socket worker counts greater than one without `quic.socket.reuse_port = true`.
- No upstreams/pools, no routes, duplicate names, empty route hosts, or unknown route targets.
- Routes that set both `upstream` and `upstream_pool`, or neither.
- Unsafe route paths.
- Unsupported upstream schemes or HTTP/3 upstreams without HTTPS.
- Invalid runtime file paths or runtime files outside their purpose-specific directory.
- `runtime.drain.graceful_timeout_ms = 0` or `runtime.drain.long_connection_close_delay_ms = 0`.
- TLS client auth without CA roots, invalid TLS version ranges, static OCSP without `response_file`, or reserved live OCSP mode.
- Reserved sticky-cookie settings, and spool buffering without a writable `temp_dir` and positive temp-file quota.
- Invalid WebRTC TURN listener binds, missing proxy pools, open `edge_relay` auth, invalid TURN upstream schemes, or invalid relay port ranges.
- Invalid rate, connection, cache, health, security-header, database, WAF, pattern-set, OxiRule, or budget settings.

## Minimal Example

```toml
[logging]
level = "info"

[logging.access_log]
enabled = false
stdout = true

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true

[runtime.hot_reload]
mode = "off"
poll_interval_ms = 2000

[listeners]
https_bind = "0.0.0.0:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

[proxy.forwarded_headers]
mode = "overwrite"

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"

[compression]
enabled = true
gzip = true
deflate = true
zstd = true
br = true
min_size_bytes = 1024
statuses = [200]
mime_types = ["text/*", "application/json", "application/*+json"]
max_concurrent_responses = 0

[database.access_log]
enabled = false
connection_url_env = "OXIBELT_ACCESS_LOG_DATABASE_URL"
table = "oxibelt_access_log"

[waf]
enabled = false
mode = "enforcing"
fail_policy = "closed"
duplicate_metadata_policy = "fail_closed"

[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2"

[[routes]]
name = "app-root"
hosts = ["example.com", "www.example.com"]
path_prefix = "/"
upstream = "app"
```
