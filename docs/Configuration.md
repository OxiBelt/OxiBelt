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
[sni_forward]
[[sni_forward.rules]]
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
[telemetry]
[telemetry.tracing]
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

- At least one `[[routes]]`, `[sni_forward]` rule/default target, `[[stream_listeners]]`, or `[[webrtc_turn_listeners]]`.
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
accept = 0.5
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

`unprivileged_mode = true` rejects listener ports below `1024`. `worker_threads` accepts a positive integer or `"auto"`; omitted values default to `"auto"`. Auto worker sizing uses Rust `std::thread::available_parallelism()`, falls back to `1` when detection fails, multiplies by `[runtime.worker_multipliers].runtime`, and rounds up. `[runtime.worker_multipliers]` defaults to `runtime = 1.0`, `accept = 0.5`, and `quic_socket = 1.0`; the lower accept default keeps TCP accept loops more conservative while runtime and HTTP/3 socket worker counts continue to track available parallelism. Existing configurations that set `runtime.worker_multipliers.accept = 1.0` keep the previous CPU-count accept-worker behavior. Full hot reload rejects changes to the resolved `runtime.worker_threads` value because the Tokio runtime cannot be resized in-process.

`[runtime.accept]` controls data-plane TCP accept loops for HTTPS, plain HTTP, and TCP stream listeners. `workers` accepts a positive integer or `"auto"`; omitted values default to `"auto"` and use `[runtime.worker_multipliers].accept`. Set `reuse_port = true` whenever the resolved worker count can be greater than one; OxiBelt fails startup instead of silently enabling `SO_REUSEPORT`. `backlog` is passed to `listen(2)`. `accept_error_backoff_ms` throttles repeated accept errors.

`[runtime.drain]` controls reload and shutdown draining. `graceful_timeout_ms` is the maximum time a stopped listener generation waits for active HTTP/1.1 and HTTP/2 requests to finish before force-closing remaining connection tasks. Successful reloads also drain existing HTTP connections that captured the previous data-plane snapshot, even when listener binds do not change, so new requests use the replacement snapshot on new connections. `long_connection_close_delay_ms` protects upgraded WebSocket/generic Upgrade, CONNECT, WebTransport, and TCP stream bridges after a drain signal before they are closed; drained WebTransport bridges keep existing sessions for that grace window but reject new request streams immediately. `shutdown_delay_ms` marks the instance draining and waits before listener drain begins; `0` is allowed. `graceful_timeout_ms` and `long_connection_close_delay_ms` must be greater than zero.

`poll_interval_ms` must be greater than zero. CLI flags `--hot-reload-mode` and `--hot-reload-poll-interval-ms` override TOML values and emit warnings when they differ.

Reload modes:

- `off`: no reload.
- `oxirule`: reload only WAF-owned configuration and external rule files.
- `downstream_tls`: reload the current downstream certificate, key, and static OCSP response.
- `full`: reload OxiRule policy, TOML configuration, upstream clients, access-log sinks, downstream TLS material, downstream listener bind/protocol settings, and admin listener enable/bind settings.

Reload failures keep the previous active state.

Successful full reloads start replacement listeners before draining old listener generations. Successful OxiRule, downstream TLS, full, and runtime pool snapshot replacements drain previous HTTP connection generations as well. Local readiness stays OK for a successful reload because the active replacement snapshot is serving; existing requests on the old generation finish within `graceful_timeout_ms`, and long-lived upgraded or stream connections keep their drain grace from `long_connection_close_delay_ms`. Full reload and admin config load rebuild telemetry tracing from the replacement configuration, though old-generation connections may keep the previous telemetry runtime until their captured snapshot drains. During that grace period, new WebTransport CONNECT or ordinary HTTP/3 request streams on a drained WebTransport connection are rejected with `503` instead of using the previous snapshot.

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
key_exchange_groups = ["x25519mlkem768", "x25519", "secp256r1", "secp384r1"]
session_tickets = true
session_ticket_rotation_seconds = 86400

[tls.resumption]
mode = "stateful" # off | stateful | stateless
session_cache_size = 4096
tls13_ticket_count = 2
rotation_seconds = 86400

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
# Maximum presented client certificate chain length: leaf + intermediates,
# excluding the configured trust anchor.
verify_depth = 4

[tls.ocsp]
mode = "disabled" # disabled | static_file | live_fetch
# response_file = "ocsp.der"
```

`cert_chain` is always required. `private_key` is required unless `tls.remote_signer.enabled = true`; when remote signing is enabled, `private_key` must not be set. `key_exchange_groups` controls the downstream TCP TLS, HTTP/3 TLS, and TURN TLS groups exposed through the aws-lc-rs provider. The default keeps rustls' post-quantum hybrid first: `["x25519mlkem768", "x25519", "secp256r1", "secp384r1"]`. For handshake-heavy deployments that prefer lower cold-handshake CPU cost over post-quantum hybrid negotiation, omit `x25519mlkem768`, for example `["x25519", "secp256r1", "secp384r1"]`. In TLS 1.3 server mode, rustls chooses from the client supported-group order, so moving `x25519mlkem768` later does not force classical ECDHE when clients offer the hybrid group first. The remote signer uses a Unix domain socket and a base64 32-byte token from `token_env`; `socket_path` must be absolute, and `key_id` selects the signer-held key. By default, remote signing is limited to TLS 1.3 server CertificateVerify inputs. Set `allow_tls12_unstructured_signing = true` only when TLS 1.2 compatibility is required and the signer sidecar is started with the same opt-in.

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

`tls.resumption.mode = "stateful"` uses a bounded in-memory server session cache and preserves QUIC 0-RTT compatibility. `stateless` uses the rustls/aws-lc-rs ticket producer with provider-managed key rotation; it cannot be combined with `quic.zero_rtt = "safe_methods"`. `off` disables server-side resumption. `session_tickets` and `session_ticket_rotation_seconds` are legacy aliases for the nested resumption table and must not conflict with it. `tls.client_auth.ca_certs` is required when client authentication mode is not `off`, and `tls.client_auth.verify_depth` must be greater than `0` when enabled. `verify_depth` limits the presented client certificate chain length, counting the leaf certificate and any intermediates while excluding the configured trust anchor. `tls.ocsp.mode = "static_file"` requires `response_file`; `live_fetch` is reserved and rejected. HTTP/3 requires `tls.min_version = "tls1.3"`.

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
keep_alive_interval_ms = 0
stream_receive_window_bytes = 1250000
receive_window_bytes = 8388608
send_window_bytes = 10000000
send_fairness = true
datagram_receive_buffer_bytes = 1048576
datagram_send_buffer_bytes = 1048576
max_udp_payload_size = 1472
gso = true
initial_mtu = 1200
min_mtu = 1200

[quic.transport.mtu_discovery]
enabled = true
upper_bound = 1452
interval_ms = 600000
black_hole_cooldown_ms = 60000
minimum_change = 20

[quic.downstream.transport]
# inherits from [quic.transport]
keep_alive_interval_ms = 10000

[quic.upstream.transport]
# inherits from [quic.transport]
stream_receive_window_bytes = 2097152

[quic.upstream.transport.mtu_discovery]
upper_bound = 1472

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

`[quic.transport]` is the shared QUIC transport baseline for both downstream HTTP/3 clients and upstream HTTP/3 forwarding. `[quic.downstream.transport]` and `[quic.upstream.transport]` are partial endpoint-specific overrides; unset values inherit from `[quic.transport]`, including nested `mtu_discovery` values. Existing configurations that only use `[quic.transport]` keep the same behavior for both endpoints.

`keep_alive_interval_ms = 0` disables QUIC keep-alive packets. Nonzero keep-alive intervals must be lower than `idle_timeout_ms`. `stream_receive_window_bytes`, `receive_window_bytes`, and `send_window_bytes` tune QUIC flow-control and send buffering. Larger windows can improve high-bandwidth or high-RTT HTTP/3 throughput, but they also raise worst-case per-connection memory exposure when many peers consume the full window. `receive_window_bytes` must be no larger than `stream_receive_window_bytes * max(max_concurrent_bidi_streams, max_concurrent_uni_streams)` so one connection cannot advertise more aggregate receive credit than its configured stream concurrency can justify.

`initial_mtu`, `min_mtu`, `max_udp_payload_size`, and `mtu_discovery.upper_bound` must be in the QUIC UDP payload range `1200..=65527`; `min_mtu` must not exceed `initial_mtu`, and enabled MTU discovery requires `upper_bound >= initial_mtu`. Keep `min_mtu = 1200` for public internet deployments unless the network path is fully controlled. MTU discovery is enabled by default and periodically probes up to `upper_bound`; disabling it keeps the configured initial/minimum MTU behavior.

`quic.socket.receive_buffer_bytes = 0` and `send_buffer_bytes = 0` keep the OS defaults. Nonzero socket buffer values are applied to UDP sockets, and startup fails if the OS rejects an explicitly configured buffer size. `quic.socket.workers` accepts a positive integer or `"auto"`; omitted values default to `"auto"` and use `[runtime.worker_multipliers].quic_socket`. When HTTP/3 is enabled, set `reuse_port = true` whenever the resolved worker count can be greater than one, which creates one `SO_REUSEPORT` UDP socket per downstream HTTP/3 worker. QUIC transport and pool numeric values must be greater than zero, except `keep_alive_interval_ms = 0`; socket receive/send buffer `0` is the explicit OS-default sentinel.

The upstream HTTP/3 pool multiplexes ordinary HTTP/3 request forwarding over reusable QUIC connections when `quic.upstream_pool.enabled = true`. When disabled, ordinary HTTP/3 upstream requests use one-shot QUIC connections. WebTransport forwarding keeps a dedicated QUIC connection per session.

## SNI Forwarding

`[sni_forward]` enables opt-in L4 forwarding before OxiBelt terminates downstream TLS. It inspects only the visible TLS ClientHello SNI value. ECH-hidden inner names are not available to this matcher.

```toml
[sni_forward]
enabled = true
client_hello_max_bytes = 65536
idle_timeout_ms = 75000
quic_max_sessions = 8192
quic_local_queue_capacity = 1024
# default_target = "10.0.10.20:443"

[[sni_forward.rules]]
name = "legacy-tls"
server_names = ["legacy.example.com", "*.legacy.example.com"]
target = "10.0.10.10:443"
protocols = ["tcp_tls", "quic"]
connect_timeout_ms = 3000
idle_timeout_ms = 75000
tcp_proxy_protocol_egress = "off"
```

Matching order is explicit `[[sni_forward.rules]]` first, then local `[[routes]].hosts`, then `sni_forward.default_target` when configured. A route host of `"*"` is not treated as a defined SNI name. Missing, malformed, or unparseable SNI fails closed when SNI forwarding is enabled. Exact SNI patterns and leftmost wildcard patterns such as `"*.example.com"` are accepted; duplicate rule names or duplicate SNI patterns across forwarding rules are rejected.

For TCP TLS, OxiBelt peeks at a bounded ClientHello before `rustls` accepts the connection. Forwarded sessions are raw TCP tunnels, and the original ClientHello remains unread by OxiBelt because `peek` does not consume bytes. Local SNI matches continue through the normal HTTP/1.1 and HTTP/2 TLS termination path. Forwarded TCP sessions count against the same global connection limit as local TLS; when `limits.connection_limit_identity` uses a Real-IP mode, they also acquire the normal per-IP and named connection leases for the post-PROXY-protocol peer address because no HTTP request headers are available before forwarding.

For QUIC, `protocols = ["quic"]` uses the same UDP address as downstream HTTP/3 and therefore requires `listeners.http3 = true`. OxiBelt decrypts QUIC Initial packets, reassembles visible CRYPTO frames, extracts ClientHello SNI, and forwards matched sessions as UDP passthrough while local sessions are queued into Quinn. Forwarded QUIC sessions acquire the same total, per-IP, and named downstream connection leases as local HTTP/3 connections. QUIC forwarding tracks connection IDs and expires idle sessions using the rule or global idle timeout.

`quic_max_sessions` caps SNI-forwarding QUIC pre-classification state across local and forwarded clients; when the cap is exceeded, the oldest tracked client is evicted and forwarded sessions are ended with a `capacity` outcome. `quic_local_queue_capacity` caps queued local QUIC datagrams waiting for Quinn; excess local datagrams are dropped instead of growing memory without bound. Both values must be greater than zero.

Prometheus metrics include aggregate SNI-forward decision, parse-failure, session, active-QUIC-session, TCP-byte, and UDP-byte counters. With `metrics.detail = "detailed"`, bounded labels add protocol, decision, rule, target, and outcome. SNI forwarding emits structured `tracing` log events for session start, end, and failure; those events include the protocol, rule, target, SNI, peer, duration, error, and byte-count fields that are available at that point.

## Proxy Sections

```toml
[proxy]
trusted_ca_certs = []

[proxy.forwarded_headers]
mode = "overwrite" # overwrite | append
client_ip_source = "resolved" # resolved | direct_peer

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
total_budget_ms = 5000
per_attempt_timeout_ms = 1000
on = ["connect_error", "read_timeout", "502", "503", "504"]
retry_non_idempotent = false
backoff_base_ms = 0
backoff_max_ms = 0
jitter = false
reselect_pool_on_retry = true
exclude_failed_pool_upstreams = true
report_passive_health = true

[proxy.buffering]
request = "streaming"  # streaming | memory | spool | reject_if_too_large
response = "streaming" # streaming | memory | spool | reject_if_too_large
max_memory_body_bytes = 1048576
max_temp_file_bytes = 0
# temp_dir = "/var/cache/oxibelt"

[proxy.static_files]
sendfile = "off" # off | auto
inline_max_bytes = 16384
open_file_cache_max_entries = 0
open_file_cache_ttl_ms = 0
hot_object_cache_max_bytes = 0
hot_object_cache_max_file_bytes = 65536

[proxy.http]
early_hints = "drop" # drop | pass
trailers = "pass"    # pass | drop
expect_continue = "auto" # auto | reject
priority = "pass"    # pass | ignore
sse_auto_streaming = true

[proxy.http2]
adaptive_window = true
# initial_stream_window_bytes = 1048576
# initial_connection_window_bytes = 16777216
# max_frame_size_bytes = 65535
max_concurrent_streams = 1024
max_send_buf_size = 1048576
keep_alive_interval_ms = 0
keep_alive_timeout_ms = 20000
keep_alive_while_idle = false

[proxy.http.grpc]
enabled = true
respect_grpc_timeout = true
retry = "off"        # off | safe_unary

[proxy.http.errors]
mode = "legacy_plain" # legacy_plain | plain | json
```

`trusted_ca_certs` adds upstream TLS trust roots from the cert directory. `forwarded_headers.mode = "overwrite"` replaces inbound forwarding metadata; `append` preserves and extends the inbound `X-Forwarded-For` chain. `forwarded_headers.client_ip_source = "resolved"` emits the same trusted client IP used by WAF, rate limiting, external auth, and Real-IP-aware connection limits; set it to `"direct_peer"` only for legacy upstreams that expect the immediate peer address. `X-Forwarded-Port` is derived from the downstream request authority, or the scheme default when no port is present. `real_ip` resolves the client IP only when the direct peer is trusted; that identity is used by rate limiting and WAF evaluation, by forwarded headers when `client_ip_source = "resolved"`, and by connection limits when `limits.connection_limit_identity` selects a Real-IP mode.

`generic_http_upgrade` and `connect_tunneling` enable the global capability only. Individual routes must also opt in with `generic_http_upgrade = true` or `connect_tunneling = true`. CONNECT tunnels are not open-proxy tunnels; OxiBelt connects only to the selected route upstream origin. `proxy.grpc_web.enabled` enables the global gRPC-Web transformer, and each route must also set `grpc_web = true`.

`proxy.buffering` controls ordinary HTTP request and response body buffering. `streaming` keeps the previous streaming behavior. `memory` reads the full body into memory up to `max_memory_body_bytes`. `spool` keeps up to `max_memory_body_bytes` in memory and spills the remainder to `temp_dir`, capped by `max_temp_file_bytes` per body. `reject_if_too_large` is memory-only and rejects bodies that exceed `max_memory_body_bytes`. `spool` requires `max_temp_file_bytes > 0` and a writable `temp_dir`; OxiBelt removes `oxibelt-buffer-*` temp files when the buffered body is dropped, when spooled buffering fails before ownership is transferred, and when cleaning stale matching files on initial startup.

`proxy.retry` controls ordinary HTTP retry behavior. `tries` is the maximum number of attempts including the first attempt. `timeout_ms` remains supported as the legacy total retry-loop budget; `total_budget_ms` is preferred and takes precedence when both are set. `per_attempt_timeout_ms` caps the first-byte wait for each upstream attempt. `on` accepts `connect_error`, `read_timeout`, and retryable response statuses such as `502`, `503`, and `504`. Backoff is disabled when `backoff_base_ms` or `backoff_max_ms` is `0`; otherwise OxiBelt sleeps between retryable failures up to the configured maximum, optionally applying jitter. For upstream pools, `reselect_pool_on_retry` picks a fresh backend on each retry, `exclude_failed_pool_upstreams` avoids retrying an upstream that already failed in the same request, and `report_passive_health` records retryable failures in passive health. Set `retry_non_idempotent = true` only when the upstream can tolerate duplicate write-side effects from retried POST, PATCH, or other non-idempotent requests.

`proxy.static_files` controls built-in static file transfer behavior. `inline_max_bytes` reads static response bodies at or below the configured size into a single response frame; `0` disables this small-file inline path. `sendfile = "auto"` enables a guarded Linux `sendfile(2)` fast path only for plaintext HTTP/1.1 `GET` and `HEAD` requests that can be proven equivalent to the normal static route path. OxiBelt opens each configured static root directory once per active configuration generation and uses that directory file descriptor for Linux `openat2(2)` resolution, reducing per-request root-open cost while keeping path resolution anchored to the validated root. OxiBelt probes the real kernel `sendfile(2)` path once at runtime; when the probe fails or the platform is not Linux, static routes fall back to the general path, including the small-file inline path. Sendfile responses honor the route or global `response_send_timeout_ms` while waiting on downstream write backpressure. Configured security response headers and request-wide system access logs are preserved on the sendfile path. Header-only and size-only WAF rules may run on the sendfile fast path and use the same resolved Real-IP client identity as the general path. HTTPS, HTTP/2, HTTP/3, WAF rules that require request or response body bytes, dynamic policy, rate limits, compression, Real-IP connection-limit modes, request bodies, upgrades, CONNECT, ambiguous `Content-Length`, and `Transfer-Encoding` all use the general Hyper path instead.

Static hot-object caching is opt-in. Set `open_file_cache_max_entries`, `open_file_cache_ttl_ms`, and `hot_object_cache_max_bytes` to enable a bounded TTL cache for verified small static responses. `open_file_cache_max_entries` and `open_file_cache_ttl_ms` bound the entry count and freshness window; `hot_object_cache_max_bytes` and `hot_object_cache_max_file_bytes` bound body memory globally and per file. Cached hits preserve validators and range behavior, and expired entries are re-opened through the same secure static-root resolution path. During the TTL, file updates may not be visible immediately; use `0` values to keep the default no-cache behavior.

`proxy.http` controls HTTP compatibility details. `early_hints = "pass"` relays upstream `103 Early Hints` where the downstream transport supports interim responses; `drop` keeps the legacy behavior. `trailers = "drop"` removes body trailer frames for ordinary HTTP traffic while preserving native gRPC trailers. `expect_continue = "auto"` accepts `Expect: 100-continue` and rejects unsupported `Expect` values with `417`; `reject` rejects all `Expect` values. `priority = "ignore"` strips RFC 9218 `Priority` headers instead of forwarding them. `sse_auto_streaming = true` keeps `text/event-stream` responses streaming even when response buffering is enabled.

`proxy.http2` applies to downstream HTTP/2 connections and upstream HTTP/2 clients. `adaptive_window = true` lets Hyper tune flow-control windows dynamically and is the default recommended performance path. Manual `initial_stream_window_bytes`, `initial_connection_window_bytes`, and `max_frame_size_bytes` values are accepted only when `adaptive_window = false`; they are intended as an escape hatch for controlled deployments that need fixed HTTP/2 windows. `max_concurrent_streams` is the advertised remote-initiated stream cap for downstream H2 and the initial locally initiated stream cap for upstream H2. `max_send_buf_size` caps the per-stream HTTP/2 send buffer. `keep_alive_interval_ms = 0` disables HTTP/2 ping keep-alives; when set, `keep_alive_timeout_ms` is the ping acknowledgement timeout and `keep_alive_while_idle` also allows upstream clients to ping idle pooled H2 connections.

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
name = "global-edge-budget"
key = "global"
rate = "1000r/s"
burst = 2000
max_buckets = 1
status = 429

[[rate_limits]]
name = "per-route-budget"
key = "route"
routes = ["api"]
rate = "500r/s"
burst = 1000
max_buckets = 128
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

Limit values must be greater than zero. Rate limit keys are `global`, `route`, `client_ip`, `client_ip_route`, `client_ip_path`, `access_token`, `access_token_route`, and `access_token_path`; `client-ip` style spellings are accepted as compatibility aliases for the client-IP keys. `global` uses one bucket shared by all clients, and when it has no `routes` filter it runs before route matching for the earliest rejection point. `route` uses one bucket per resolved route. `routes` restricts a rate limit to named routes. Access-token limits read `Authorization: Bearer <token>` first and then optional `token_header`; token values are hashed before storage, and missing tokens fall back to the client IP bucket. `max_buckets` caps the number of local process buckets kept for a single rate limit, defaults to `16384`, and should be lowered for attacker-controlled key modes when a route expects low identity cardinality. In process-local enforcing mode, a request that would create a new bucket after the cap is reached is rejected with the rate limit status until an existing bucket has fully refilled and can be reclaimed; monitor mode stops adding new buckets after the cap. Rate and connection limit state is process-local by default. When `[shared_state].enabled = true` and the relevant feature maps to a backend, route rate token buckets, WAF `rate_limit` action buckets, and downstream connection leases are shared across instances. This shared rate-limit path supports both Redis-compatible and PostgreSQL backends. `max_connections` applies at downstream accept time. `max_connections_per_ip` and `[[connection_limits]]` use the configured `connection_limit_identity`: `proxy_protocol` counts the direct peer or trusted PROXY protocol source for the whole connection, `first_request_real_ip` binds the connection to the first trusted Real-IP header value, and `per_request_real_ip` acquires a lease per HTTP request until its response body finishes. Active WebTransport sessions also acquire dedicated total and per-IP session leases; in Real-IP modes they must also acquire the same normal per-IP and named connection leases as ordinary requests for that identity. When not set, `max_webtransport_sessions` and `max_webtransport_sessions_per_ip` inherit `max_connections` and `max_connections_per_ip`, while `max_webtransport_sessions_per_connection` caps multiplexing on one downstream HTTP/3 connection. For HTTP/1 CONNECT, Upgrade tunnels, and WebTransport sessions, Real-IP connection leases remain held until the upgraded tunnel, session, or first-request connection context closes. TCP stream listeners use direct peer IPs. TLS handshake and header timeouts are listener-wide because no route is known yet; body, response-send, WebSocket, and WebTransport idle timeouts can be overridden per route.

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

[ipm]
enabled = false
namespace = "oxibelt"
fail_closed = true

[[ipm.principals]]
id = "upstream-ops"
subject = "upstream-ops@example.com"
groups = ["upstream-operators"]

[[ipm.credentials]]
name = "upstream-ops"
principal = "upstream-ops"
bearer_token_env = "OXIBELT_UPSTREAM_TOKEN"

[[ipm.policies]]
name = "upstream-pool-ops"

[[ipm.policies.statements]]
effect = "allow"
actions = ["upstream-pool:*"]
resources = ["oxibelt:oxibelt:upstream-pool:*"]

[[ipm.bindings]]
group = "upstream-operators"
policy = "upstream-pool-ops"

[admin.tls]
enabled = false
min_version = "tls1.3"
max_version = "tls1.3"
session_tickets = false
require_sni = true
reject_unknown_sni = true

[admin.tls.resumption]
mode = "off" # off | stateful | stateless
session_cache_size = 1024
tls13_ticket_count = 2
rotation_seconds = 86400

[[admin.tls.certificates]]
server_names = ["admin.example.com", "*.ops.example.com"]
cert_chain = "admin-fullchain.pem"
private_key = "admin-privkey.pem"
default = true

[admin.tls.client_auth]
mode = "off"
ca_certs = []
verify_depth = 4

[metrics]
enabled = false
bind = "127.0.0.1:9090"
format = "prometheus"
detail = "detailed"
histogram_buckets_ms = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]

[telemetry.tracing]
enabled = false
endpoint = "http://127.0.0.1:4318/v1/traces"
service_name = "oxibelt"
sample_ratio = 1.0
export_timeout_ms = 3000
propagate_trace_context = true

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

IPM (Identity Permission Management) is the authorization model for Admin APIs and opt-in data-plane authorization. The legacy `admin.rbac.tokens`, role names, and `permissions`/`deny_permissions` fields are rejected; use `[ipm]`, `[[ipm.credentials]]`, `[[ipm.principals]]`, `[[ipm.policies]]`, and `[[ipm.bindings]]` instead. IPM evaluates `Action`, `Resource`, and `Condition` statements with explicit deny first, matching allow second, and default deny otherwise. `admin.bearer_token_env` is retained only as a bootstrap fallback when `[ipm].enabled = false`.

Actions use `service:Action` syntax. Initial services are `ipm`, `config`, `cache`, `upstream-pool`, `dynamic-policy`, `waf`, `lifecycle`, `route`, `stream`, and `turn`; `service:*` and `*` wildcards are accepted. WAF actions include telemetry reads (`waf:GetRuleHits`, `waf:GetRuleCosts`, `waf:GetCrsCompatibility`) and OxiRule file management (`waf:PutOxiRule`, `waf:DeleteOxiRule`, `waf:PutOxiRuleGroup`, `waf:DeleteOxiRuleGroup`, `waf:ReloadOxiRule`). Resources use `oxibelt:<namespace>:<service>:<resource>`, for example `oxibelt:oxibelt:route:app`, `oxibelt:oxibelt:cache:policy/default`, or `oxibelt:oxibelt:waf:oxirule/rules/block.oxirule.toml`. Conditions support `StringEquals`, `StringLike`, `StringNotEquals`, `IpAddress`, `NotIpAddress`, `Bool`, `DateBefore`, and `DateAfter` over keys such as `principal.subject`, `principal.groups`, `request.source_ip`, `request.method`, `request.host`, `request.path`, `request.route`, `request.protocol`, `resource.service`, `resource.name`, `time.now`, and `claim.<name>`. Admin API request conditions use the admin listener peer IP for `request.source_ip` and the Admin HTTP request method, normalized host, path, and protocol for the corresponding `request.*` keys.

`[ipm].backend` optionally names a PostgreSQL `[[shared_state.backends]]` entry used to initialize the `oxibelt_ipm_*` operational tables. If `backend` is omitted and no shared-state default backend is configured, OxiBelt uses static TOML-defined IPM principals, credentials, policies, and bindings only. With `[ipm].enabled = true`, each `[[ipm.credentials]]` bearer-token environment variable must be set and non-empty at startup.

```toml
[ipm]
enabled = true
namespace = "oxibelt"
backend = "cluster"
fail_closed = true

[[ipm.principals]]
id = "admin"
subject = "admin@example.com"
groups = ["platform-admins"]

[[ipm.credentials]]
name = "admin-env-token"
principal = "admin"
bearer_token_env = "OXIBELT_ADMIN_TOKEN"

[[ipm.policies]]
name = "admin-full-access"

[[ipm.policies.statements]]
effect = "allow"
actions = ["*"]
resources = ["*"]

[[ipm.bindings]]
group = "platform-admins"
policy = "admin-full-access"

[shared_state]
enabled = true
namespace = "oxibelt"
default_backend = "cluster"

[[shared_state.backends]]
name = "cluster"
kind = "postgres"
connection_url_env = "OXIBELT_SHARED_STATE_URL"
```

Full hot reload starts, stops, or rebinds the dedicated admin listener when `admin.enabled` or `admin.bind` changes.

Admin config and downstream TLS endpoints:

- `GET /admin/v1/config/status`
- `GET /admin/v1/config/effective`
- `POST /admin/v1/config/validate`
- `POST /admin/v1/config/diff`
- `POST /admin/v1/config/load`
- `POST /admin/v1/config/rollback`
- `GET /admin/v1/tls/downstream`
- `POST /admin/v1/tls/downstream/reload`
- `GET /admin/v1/ipm/principals`
- `GET /admin/v1/ipm/credentials`
- `GET /admin/v1/ipm/policies`
- `GET /admin/v1/ipm/bindings`
- `POST /admin/v1/ipm/simulate`

Config read endpoints use `config:GetStatus` and `config:GetEffective`; validate, diff, load, rollback, file sync, and downstream TLS operations use the matching `config:*` IPM actions. `POST /admin/v1/config/load` installs a validated runtime snapshot only; it does not write TOML back to disk. `POST /admin/v1/config/rollback` swaps back to the last good runtime snapshot kept by the admin control loop. Mutating endpoints require `If-Match` with the active config ETag from `/admin/v1/config/status` or `/admin/v1/config/effective`; stale ETags are rejected before applying changes. Downstream TLS reload re-reads configured certificate, key, and static OCSP files from disk and preserves the active TLS state if validation fails.

OxiBelt initializes the IPM schema when `[ipm].backend` is configured:

```sql
CREATE TABLE IF NOT EXISTS oxibelt_ipm_principals (
  id bigserial PRIMARY KEY,
  namespace text NOT NULL,
  principal_id text NOT NULL,
  subject text NOT NULL,
  groups text[] NOT NULL DEFAULT ARRAY[]::text[]
);
CREATE TABLE IF NOT EXISTS oxibelt_ipm_credentials (...);
CREATE TABLE IF NOT EXISTS oxibelt_ipm_policies (...);
CREATE TABLE IF NOT EXISTS oxibelt_ipm_policy_bindings (...);
CREATE TABLE IF NOT EXISTS oxibelt_ipm_generation (...);
CREATE TABLE IF NOT EXISTS oxibelt_ipm_audit (...);
```

Admin file sync endpoint:

- `POST /admin/v1/files/sync`

File sync authorizes each operation by root and operation type. `root = "config"` requires `config:SyncFiles`, and config deletes also require `config:SyncFiles` on resource `delete`. `root = "oxirule"` requires `waf:PutOxiRule` or `waf:DeleteOxiRule` on `oxibelt:<namespace>:waf:oxirule/<path>`. `root = "oxirule_group"` requires `waf:PutOxiRuleGroup` or `waf:DeleteOxiRuleGroup` on `oxibelt:<namespace>:waf:oxirule-group/<path>`. `apply = "oxirule"` requires `waf:ReloadOxiRule` on `*`, `apply = "full"` also requires `config:Load`, and `apply = "downstream_tls"` also requires `config:ReloadDownstreamTls`. The request body is explicit: missing files are never implicitly removed.

```json
{
  "apply": "full",
  "operations": [
    {
      "op": "put",
      "root": "config",
      "path": "oxibelt.toml",
      "expected_sha256": "existing-file-sha256-or-null",
      "content": "[proxy]\n..."
    },
    {
      "op": "put",
      "root": "oxirule_group",
      "path": "groups/bot.oxirule-group.toml",
      "content": "[[rule_groups]]\nname = \"bot\"\n..."
    }
  ]
}
```

`root` is `config`, `oxirule`, or `oxirule_group`. Paths are UTF-8 relative paths, normalized, and must stay under the configured root. `put` writes `content`, optionally guarded by `expected_sha256`; `delete` removes exactly the named file. `apply` defaults to `none`; `oxirule` reloads rule policy from disk, `full` reloads the full TOML/runtime view from disk, and `downstream_tls` reloads downstream TLS material. File sync commits with same-directory temporary files and restores touched files if validation or apply fails. The endpoint is not a certificate lifecycle API: private key upload, ACME credentials, DNS provider credentials, and ACME issuance are out of scope.

Admin lifecycle endpoints:

- `GET /admin/v1/lifecycle`
- `POST /admin/v1/lifecycle/drain`
- `POST /admin/v1/lifecycle/undrain`

Lifecycle read requires `lifecycle:Get` and returns `{"draining": bool, "reason": string}`. Drain and undrain require `lifecycle:Drain` and `lifecycle:Undrain`. Admin drain makes `/ready` return `503 draining`, keeps `/live` at `200 live`, and rejects new data-plane requests with `503 draining` and `Connection: close`; in-flight requests continue. Undrain clears only admin-initiated drain state.

Admin WAF telemetry endpoint:

- `GET /admin/v1/waf/rule-hits`
- `GET /admin/v1/waf/rule-costs`
- `GET /admin/v1/waf/crs/compatibility`

These endpoints require the matching `waf:*` IPM actions. Rule hits returns active rule hit counters with `scope`, `route`, `phase`, `name`, optional `id`, `effective_mode`, and `hits`. Rule costs returns OxiRule evaluation counters and total/average runtime in nanoseconds using the same authenticated rule metadata; CRS rule cost accounting is intentionally not exposed through the public metrics listener. CRS rule hit entries also include `tags`, `tuned_hits`, latest observed anomaly scores, and latest blocking scores when available. The CRS compatibility endpoint returns the OxiBelt-supported CRS release lines, supported directives/operators/transforms/variables/actions, accepted-but-ignored syntax, fail-closed policy, and known unsupported surfaces.

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
POST /admin/v1/cache/purge
```

The `/admin/v1/cache/purge` endpoint accepts JSON with `"type": "exact"`, `"prefix"`, or `"tag"`, plus the same selectors used by the query endpoints. Exact purge uses `policy`, `scheme`, `host`, `uri`, and optional `partition`; prefix purge uses `path_prefix`; tag purge uses `tag` plus optional `scheme`, `host`, and `partition`. It returns `{"purged": number}` and requires the matching `cache:PurgeObject`, `cache:PurgePrefix`, or `cache:PurgeTag` IPM action.

Query-string purge requests also accept optional `partition`. When `[admin.cache_purge_signing]` is enabled, the `/cache/purge*` query endpoints may authenticate with `X-OxiBelt-Cache-Timestamp`, `X-OxiBelt-Cache-Nonce`, and `X-OxiBelt-Cache-Signature` instead of a bearer token. The signature is base64 HMAC-SHA256 over `OXIBELT-CACHE-PURGE-V1\n{method}\n{path_and_query}\n{sha256(body)}\n{timestamp}\n{nonce}`; signed purge requests must use an empty body. The JSON v1 purge endpoint is bearer-token only.

Admin cache diagnostics and warming endpoints:

```sh
POST /admin/v1/cache/key-explain
POST /admin/v1/cache/warm
```

`key-explain` requires `cache:ExplainKey` and accepts `{ "policy": "default", "method": "GET", "scheme": "https", "host": "example.test", "uri": "/asset.css", "headers": {}, "response_headers": {} }`. It returns the selected policy, partition, base key, optional variant key, Vary fields, and cacheability reasons. `warm` requires `cache:Warm` and accepts `{ "items": [{ "scheme": "https", "host": "example.test", "uri": "/asset.css", "method": "GET", "headers": {} }] }`; methods are limited to `GET` and `HEAD`, and each item returns `stored`, `not_cacheable`, `upstream_error`, or `validation_error`.

Health paths must start with `/`. Readiness returns `503 draining` while lifecycle drain is active; liveness remains `200 live` so process supervisors can distinguish intentional drain from process failure. Prometheus metrics include aggregate TLS server session storage diagnostic counters for stateful resumption cache calls and approximate lock/put timing. With `metrics.detail = "detailed"`, Prometheus also includes bounded-label HTTP, upstream, cache, TLS handshake, QUIC Retry, WebSocket, WebTransport, and TURN counters/histograms using route/upstream/protocol/status/cache-reason style labels. Cache miss reasons include lookup misses, fill lock timeouts, shared fill lock conflicts, and fills that completed without storing an entry. Detailed mode also emits `oxibelt_cache_fill_stage_duration_ms` with `route`, `policy`, `stage`, and `outcome` labels for `lock_wait`, `head_decision`, `body_collect`, `local_store`, and `shared_store`. `metrics.detail = "basic"` keeps only aggregate counters and gauges. `metrics.histogram_buckets_ms` must be a non-empty strictly increasing list of positive millisecond buckets. The public metrics listener omits detailed WAF rule names, IDs, modes, routes, and per-rule hit/cost counters because it is intended for unauthenticated operational scraping. Use the authenticated admin WAF telemetry endpoints for rule-level data.

`[telemetry.tracing]` enables W3C `traceparent` extraction/injection and OTLP HTTP/protobuf trace export. `enabled = false` is the default. The v1 exporter supports `http://` OTLP collector endpoints, uses `service_name` as the OpenTelemetry resource service name, samples new root traces with `sample_ratio`, and bounds blocking exporter I/O with `export_timeout_ms`. Export failures after startup or reload are logged and dropped; they do not block data-plane requests. `propagate_trace_context = true` forwards trace context to upstream HTTP/1.1, HTTP/2, HTTP/3, and WebTransport CONNECT requests. Full reload and admin config load apply telemetry changes to the replacement snapshot.

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

## Database Mitigation Sink

```toml
[database.mitigation]
enabled = false
mode = "managed" # managed | existing
connection_url_env = "OXIBELT_MITIGATION_DATABASE_URL"
# backend = "cluster"
table = "oxibelt_mitigation_events"
namespace = "oxibelt"
queue_capacity = 8192
dedupe_window_ms = 60000
ttl_seconds = 300
failure_policy = "open" # open | closed
```

This optional PostgreSQL sink receives OxiRule `emit_mitigation` actions for external DOTS, BGP FlowSpec, RTBH/blackhole, or provider-specific mitigation controllers. OxiBelt only writes PostgreSQL rows; it does not call ISP or IaaS APIs directly.

Set either `connection_url`/`connection_url_env` or `backend`. `backend` must name a PostgreSQL `[[shared_state.backends]]` entry. In `managed` mode OxiBelt creates `oxibelt_mitigation_events`; in `existing` mode the table must already expose compatible `namespace`, `dedupe_key`, `status`, `count`, `first_seen`, `last_seen`, `expires_at`, and `record jsonb` columns plus a unique conflict target on `(namespace, dedupe_key)`.

Rows are aggregated by dedupe key and time window. OxiBelt preserves controller-owned statuses such as `processing`, `applied`, `failed`, and `withdrawn`; rows start as `observing` when an action sets `min_count > 1` and promote to `pending` when the aggregate count reaches that threshold.

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

`max_body_inspection_bytes` controls the request body, response body, and native stream payload prefix captured for OxiRule and CRS body inspection. The default is `1048576` bytes. Bytes after this prefix are forwarded or replayed without inspection and are reflected through `Body.IsTruncated` or `Stream.Payload.IsTruncated`. The same value also bounds WebSocket stream-WAF frame buffering: an individual WebSocket frame payload larger than this value is closed fail-closed instead of being buffered for prefix inspection.

Inline global rules are configured under `[[waf.rules]]`; route-level rules use `[[routes.waf.rules]]`. Reusable rule groups are configured under `[[waf.rule_groups]]` or `[[routes.waf.rule_groups]]` and are referenced from rules with `groups = ["name"]`. Shared group files can be loaded with `[waf] rule_group_files = ["groups/*.oxirule-group.toml"]` and route-level `rule_group_files`. Each group file uses a top-level `[[rule_groups]]` array and the same fields as inline `WafRuleGroupConfig`. Exact file paths must exist; glob entries may match zero files and are loaded in sorted order. External rule entries use `path` and resolve under the oxirule directory. A rule entry may use inline `when`, `groups`, or both; `path` cannot be combined with inline `when`, `merge_condition_as`, `groups`, or `actions` on the same rule entry.

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

`merge_condition_as = "and" | "or" | "override"` controls how a rule or group `when` joins earlier referenced group conditions and defaults to `and`. Action-level `priority` defaults to `0`; grouped and rule-local actions are sorted together by lower priority first, with declaration order preserved for ties.

`[waf].mode` sets the default mode for all rules. A rule-level `mode` overrides that default in both directions: `monitor` counts matches without applying actions, while `enforcing` applies actions normally.

`[waf.crs]` enables the CRS-compatible execution layer. It loads `setup_file` and each `rule_files` glob from the OxiRule directory, using the same normalized relative path restrictions as external OxiRule files. CRS starts in `monitor` mode by default so hits and anomaly scores are recorded without blocking; set `mode = "enforcing"` to apply inbound and outbound anomaly thresholds. Unsupported CRS directives, operators, transforms, variables, or actions fail closed at configuration load/compile time and report the file and line that must be changed.

`[[waf.crs.rule_overrides]]` applies the first matching static rule override. Select rules with `rule_ids`, `tags`, or `msg_contains`; at least one selector is required. `mode = "monitor"` records observed hits and anomaly score without contributing to blocking score, `mode = "enforcing"` can enforce even when global CRS mode is monitor, and `mode = "disabled"` records hits without scoring/actions.

`[[waf.crs.allowlists]]` is for scoped false-positive tuning. It uses the same rule selectors and also requires at least one traffic selector: `methods`, `routes`, or `path_prefixes`. Traffic selector categories are ANDed together, while values within a category are ORed. A matching allowlist suppresses CRS scoring/actions for that transaction and increments `tuned_hits`; broad rule disables should use `rule_overrides` instead. `header_equals` is rejected for CRS allowlists because inbound request headers are client-controlled before proxy forwarding.

Recommended CRS rollout is monitor first, inspect `/admin/v1/waf/rule-hits`, add scoped allowlists or per-rule overrides for confirmed false positives, then switch `[waf.crs].mode` to `enforcing`. The compatibility matrix is available from `/admin/v1/waf/crs/compatibility`; OxiBelt targets the CRS current release and `v4.25.x` LTS line as of 2026-05-10. Official CRS references: [v4.25.0 LTS announcement](https://coreruleset.org/20260321/announcing-crs-v4-25-lts/), [false positives and tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/), and [installation](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/).

Response body CRS inspection uses the same bounded prefix behavior as OxiRule response body inspection and can affect cache/background refresh behavior. Treat response inspection as a targeted control for leakage detection, not a substitute for upstream output encoding. WebTransport frame/datagram payload inspection is not supported by the CRS layer.

Rule syntax, actions, helpers, and Person proof settings are documented in [OxiRule.md](OxiRule.md).

Person proof uses `person_proof_mode` to select one of four public modes. `built_in` is OxiBelt built-in PoW plus the built-in challenge frontend. `openapi` uses OxiBelt built-in PoW session/verify/OpenAPI endpoints with a custom challenge frontend. `third_party_provider` uses OxiBelt's built-in Turnstile, hCaptcha, or Friendly Captcha v2 adapters. `custom_provider` calls a configured JSON HTTP provider that returns `{ "success": true|false }`.

`custom_frontend_url` is not a filesystem path. It is an origin-relative URL routed by the same OxiBelt instance, either to a static route asset or to a proxied challenge frontend backend. Custom frontends call OxiBelt's `session_path` and `verify_path`; browser code should not call provider-native server APIs directly. Clearance tokens can be issued to a cookie, localStorage, or JSON response, and protected requests can read them from configured cookie keys, `Authorization: Bearer`, or configured header keys.

```toml
[waf.person_proof]
session_path = "/.oxibelt/person-proof/session"
verify_path = "/.oxibelt/person-proof/verify"
openapi_path = "/.oxibelt/person-proof/openapi.json"

[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "third_party_provider"
third_party_provider = "turnstile"
custom_frontend_url = "/person-proof/index.html"
site_key = "0x4AAAA..."
secret_env = "OXIBELT_TURNSTILE_SECRET"
provider_fail_policy = "closed"
clearance.issue_to = "cookie"
clearance.cookie.key = "__oxibelt_person_proof"

[[waf.rules.actions.clearance.sources]]
type = "cookie"
key = "__oxibelt_person_proof"
```

The built-in PoW page embeds a signed `session` and uses the same `session_path` and `verify_path` as custom frontends; the old direct `token.nonce` proof cookie flow is not used. A challenge redirect includes `session`, `session_path`, `verify_path`, `openapi_path`, `return_path`, and `expires_unix_ms`. Challenge issuance does not reserve replay state. Provider-specific values such as `site_key` and clearance storage metadata are returned by `GET session_path?session=...`. Verification accepts only JSON `POST verify_path` with `{ "session": "...", "response": { "token": "...", "fields": {} } }`. `single_use` defaults to `true`; with it enabled, the session is consumed before PoW/provider verification, including failed provider responses. In localStorage mode, the browser must send the stored token on later protected requests using `clearance.local_storage.request_header` because servers cannot read localStorage directly.

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
pool_max_idle_per_host = 128
preserve_host = false
websocket = true
webrtc = true
webtransport = true
proxy_protocol_egress = "off" # off | v1 | v2

[upstreams.tls.ech]
mode = "disabled" # disabled | grease | config_list
# config_list_file = "app.echconfiglist"

[upstreams.tls.resumption]
mode = "enabled" # enabled | disabled
session_cache_size = 1024
tls12 = "session_id_or_tickets" # disabled | session_id_only | session_id_or_tickets
```

Upstream origins must use `http://` or `https://`. `max_http_version = "h3"` requires an `https://` origin. ECH `config_list_file` is required only with `mode = "config_list"` and is invalid for other modes. Upstream TLS resumption controls OxiBelt's client-side cache only; the upstream server still chooses whether its own tickets are stateful or stateless. `proxy_protocol_egress` writes a PROXY protocol header to TCP-based upstream connections and is rejected with HTTP/3 upstream selection.

`request_timeout_ms` is the compatibility upper bound for sending a request and receiving response headers. `first_byte_timeout_ms` separately controls the response-header/first-byte wait and is capped by `request_timeout_ms` when both are configured. `read_timeout_ms` is an upstream response body idle timeout. `send_timeout_ms` controls upstream request body send backpressure.

`idle_timeout_ms` is also the idle connection timeout for the upstream Hyper client pool. `pool_max_idle_per_host` caps idle HTTP/1.1 and HTTP/2 TCP upstream connections retained per origin; `0` disables keeping idle connections for that upstream. For `[[upstream_pools]]`, each synthetic upstream server uses `[upstream_pools.keepalive].max_idle` as this cap.

```toml
[[external_auth]]
name = "edge-auth"
provider = "authelia" # authelia | oauth2 | oidc
endpoint = "https://auth.internal.example/api/authz/forward-auth"
timeout_ms = 2000
fail_policy = "closed" # closed | open
forward_headers = ["authorization", "cookie"]
identity_headers = ["remote-user", "remote-groups", "remote-email", "remote-name"]
terminal_response_headers = ["location", "www-authenticate", "set-cookie"]
max_response_body_bytes = 65536
# OAuth2 introspection only:
# client_id_env = "OAUTH2_INTROSPECTION_CLIENT_ID"
# client_secret_env = "OAUTH2_INTROSPECTION_CLIENT_SECRET"
# required_scopes = ["openid", "profile"]

[[external_auth.required_claims]]
name = "aud"
value = "oxibelt"

[[external_auth.claim_headers]]
claim = "sub"
header = "remote-user"
```

`[[external_auth]]` defines authorization checks that routes can reference with `external_auth = "edge-auth"`. OxiBelt does not implement the browser login flow. For `provider = "authelia"`, it performs a forward-auth GET to `endpoint`, forwarding the configured request headers plus `X-Forwarded-*` context; 2xx allows the request and non-2xx becomes the downstream terminal response with only allowlisted response headers. For `provider = "oauth2"`, it requires an inbound `Authorization: Bearer` token and POSTs to an OAuth2 token introspection endpoint; `required_scopes` must all be present when configured. For `provider = "oidc"`, it calls an OIDC UserInfo endpoint with the bearer token and enforces `required_claims`.

Before forwarding upstream, OxiBelt strips configured `identity_headers` from the client request and injects identity headers only from the trusted auth response/token claims. Routes with `external_auth` use the general proxy path so fast paths cannot bypass the check. `timeout_ms` is a wall-clock deadline for the full auth exchange, including request send, response headers, and response body collection. `max_response_body_bytes` caps the auth response body size but is not a time limit. `fail_policy = "closed"` returns `503` on auth-service errors; `open` allows the request and records an auth error metric.

```toml
[[upstream_pools]]
name = "app-pool"
algorithm = "power_of_two_choices" # power_of_two_choices | weighted_least_conn | rendezvous_hash | rendezvous_ip_hash | ewma | least_time | sticky_cookie

[upstream_pools.sticky_cookie]
cookie_name = "oxibelt_sticky"
ttl_seconds = 3600
fallback_algorithm = "power_of_two_choices" # power_of_two_choices | weighted_least_conn | rendezvous_hash | rendezvous_ip_hash | ewma | least_time
secret_env = "OXIBELT_STICKY_COOKIE_SECRET"
secure = true
http_only = true
same_site = "lax" # lax | strict | none
path = "/"

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

[[upstream_pools.discovery]]
provider = "kubernetes"
endpoint = "https://kubernetes.default.svc"
namespace = "default"
service = "app"
port_name = "http"
kubernetes_resource = "endpoints" # endpoints | endpoint_slice
watch = false
watch_timeout_seconds = 300
update_debounce_ms = 250
# token_env = "KUBERNETES_SERVICE_TOKEN"
refresh_interval_ms = 30000

[[upstream_pools.discovery]]
provider = "consul"
endpoint = "http://consul.service.consul:8500"
service = "app"
# namespace = "default"
# datacenter = "dc1"
# filter = "Service.Meta.version == v1"
# token_env = "CONSUL_HTTP_TOKEN"
refresh_interval_ms = 30000

[[upstream_pools.discovery]]
provider = "etcd"
endpoint = "https://etcd.internal.example:2379"
key_prefix = "/oxibelt/upstreams/app/"
# token_env = "ETCD_TOKEN"
refresh_interval_ms = 30000

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

Pool names and upstream names are separate namespaces. `algorithm` defaults to `power_of_two_choices`. HTTP pools support `power_of_two_choices`, `weighted_least_conn`, `rendezvous_hash`, `rendezvous_ip_hash`, `ewma`, `least_time`, and `sticky_cookie`. `algorithm = "sticky_cookie"` selects an upstream by a signed affinity cookie when present, otherwise it uses `sticky_cookie.fallback_algorithm` and emits `Set-Cookie`; the fallback must be one of the non-sticky modern algorithms. Legacy names such as `round_robin`, `least_conn`, `random`, `hash`, and `ip_hash` are rejected during parsing or validation and must be migrated explicitly. The cookie HMAC secret comes from `sticky_cookie.secret_env` when set, from `[shared_state].sticky_sessions_backend` when configured, or from a process-local generated secret. Pool servers must use `http://` or `https://`, server IDs must be unique within a pool, and server weights must be greater than zero.

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

`provider = "dns"` resolves `name` using `record_type = "a"`, `"aaaa"`, `"a_aaaa"`, or `"srv"`. A/AAAA discovery requires `port`; SRV discovery uses the SRV target port. DNS refresh uses the lower of the configured `refresh_interval_ms` and the observed DNS TTL, bounded by `min_ttl_ms`. DNS discovery rejects unsuccessful responses and responses whose transaction ID, question, answer owner, or verified CNAME chain does not match the active query.

`provider = "kubernetes"` defaults to polling the core Endpoints API at `/api/v1/namespaces/{namespace}/endpoints/{service}` and uses ready endpoint addresses with either `port` or `port_name`. Set `kubernetes_resource = "endpoint_slice"` to use the stable EndpointSlice API at `/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices`; EndpointSlice discovery selects endpoints with `conditions.ready = true` and `conditions.terminating != true`, ignores FQDN endpoint slices, and accepts IPv4/IPv6 endpoint addresses. Set `watch = true` only with `kubernetes_resource = "endpoint_slice"` to maintain a streaming watch with `resourceVersion`, `allowWatchBookmarks`, `watch_timeout_seconds`, and `update_debounce_ms` coalescing before pool updates. EndpointSlice watch rejects any single streamed watch event line above 8 MiB and reconnects locally after `watch_timeout_seconds` plus one `refresh_interval_ms` grace interval if the stream has not ended. The Kubernetes service account needs `list` for polling and `list,watch` for EndpointSlice watch on `endpointslices.discovery.k8s.io` in the configured namespace. `provider = "consul"` polls `/v1/health/service/{service}?passing=true` and uses service addresses and ports. `provider = "etcd"` polls the v3 KV range API under `key_prefix`; each value may be a URL string or a JSON object with `origin`, optional `id`, `weight`, `max_conns`, `backup`, and `state`. Kubernetes and etcd `token_env` values are sent as bearer tokens; Consul uses `X-Consul-Token`.

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
# external_auth = "edge-auth"
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

[routes.retry]
# enabled = true
# tries = 2
# total_budget_ms = 5000
# per_attempt_timeout_ms = 1000
# on = ["connect_error", "read_timeout", "502", "503", "504"]
# retry_non_idempotent = false
# backoff_base_ms = 0
# backoff_max_ms = 0
# jitter = false
# reselect_pool_on_retry = true
# exclude_failed_pool_upstreams = true
# report_passive_health = true
```

`upstream_http_version` is a route-level backend protocol override and must not exceed the selected upstream capability. HTTP/3 overrides are rejected for upstream-pool routes and for upstreams with PROXY protocol egress enabled.

Route timeout overrides are optional. Omitted values inherit from `[limits]` for downstream behavior and from the selected `[[upstreams]]` entry for upstream behavior. TLS handshake and downstream header read timeouts are not route-level because route matching has not happened yet.

Route buffering overrides are optional. Omitted values inherit from `[proxy.buffering]`; `temp_dir` is always global. CONNECT tunnels, HTTP Upgrade, and WebTransport forwarding remain streaming even when buffering is enabled.

Route retry overrides are optional. Omitted values inherit from `[proxy.retry]`, while each configured `[routes.retry]` field replaces only that global field. A route can set `enabled = true` to opt into retry when global retry is disabled, or `enabled = false` to opt out when global retry is enabled. The same duplicate-write warning for global `retry_non_idempotent = true` applies to route-level retry.

Fields:

- `name`: unique route name.
- `hosts`: host match list; defaults to `["*"]`. Wildcard hosts such as `*.example.com` match only request hosts with at least one non-empty label before the suffix.
- `path_prefix`: path prefix match; defaults to `/`.
- `replace_prefix_with`: optional upstream path prefix replacement.
- `upstream`, `upstream_pool`, or `static_root`: exactly one target.
- `cache`: optional cache reference; `default` uses `[cache]`, and any other value must match `[[cache.policies]].name`.
- `compression`: optional downstream response compression policy; omitted means `default`, `off` disables compression for the route, and any other value must match `[[compression.policies]].name`. Named compression policies must not use the exact lowercase names `default` or `off`.

Route path values must start with `/` and must not contain control characters, backslashes, query strings, fragments, dot segments, or encoded dot/slash separators such as `%2e`, `%2f`, or `%5c`.

`static_root` enables the built-in static file server for the route. The value must resolve to an existing directory; absolute paths are accepted, and relative paths loaded through `Config::load` resolve under the configuration directory. OxiBelt strips the matched `path_prefix`, percent-decodes each remaining path segment, and serves only regular files whose resolved path stays under `static_root`. Directory listing is forbidden, and symlinks are allowed only when secure resolution can prove they remain inside the static root. On Linux kernels with `openat2(2)`, OxiBelt opens static files relative to a read-only `static_root` directory file descriptor with `RESOLVE_BENEATH` and `RESOLVE_NO_MAGICLINKS`; this path does not require `/proc/self/fd` and is compatible with read-only root filesystems. On kernels without `openat2`, and on non-Linux platforms, OxiBelt falls back to opening the file and rechecking the opened descriptor through `/proc/self/fd`; if that verification is unavailable, the request fails closed instead of serving an unverified file. Response metadata, validators, ranges, and bytes are all derived from the same verified descriptor. Static routes accept `GET` and `HEAD`, emit `ETag`, `Last-Modified`, and `Accept-Ranges`, support a single `Range: bytes=...` request, and honor `If-None-Match` and `If-Modified-Since`. Request WAF, response WAF, rate limits, dynamic policy, security headers, compression, and Alt-Svc still apply on the general path. Static routes reject upstream-only options such as `replace_prefix_with`, `cache`, `upstream_http_version`, `generic_http_upgrade`, `connect_tunneling`, and `grpc_web`.

Static routes are one supported deployment path for custom Person proof challenge pages. Place frontend files under a configured `static_root` and use the origin-relative asset URL as the WAF action's `custom_frontend_url`. `custom_frontend_url` may also point to a separate frontend backend proxied by the same OxiBelt instance.

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

Stream listeners proxy raw TCP from a dedicated bind address to a single `host:port` target. They do not perform HTTP routing, TLS termination, HTTP rate limiting, or WAF inspection, but their downstream connections are counted by the global connection limits. Use `[sni_forward]` when TLS or QUIC traffic on `listeners.https_bind` must be selected by visible SNI before local HTTP termination.

## WebRTC TURN Listeners

```toml
[[turn_upstream_pools]]
name = "turn-udp"
algorithm = "power_of_two_choices"

[[turn_upstream_pools.servers]]
id = "turn-a"
origin = "turn://turn-a.internal.example:3478"
weight = 1

[[turn_upstream_pools]]
name = "turn-tcp"
algorithm = "power_of_two_choices"

[[turn_upstream_pools.servers]]
id = "turn-tcp-a"
origin = "turn+tcp://turn-a.internal.example:3478"
weight = 1

[[turn_upstream_pools]]
name = "turn-tls"
algorithm = "power_of_two_choices"

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

`mode = "proxy_pool"` forwards TURN UDP, TCP, and TLS traffic to `[[turn_upstream_pools]]`. Upstream servers use `turn://`, `turn+tcp://`, or `turns://` origins and advertise their own relay addresses. TURN pools default to `power_of_two_choices` and support `power_of_two_choices`, `weighted_least_conn`, `rendezvous_hash`, and `rendezvous_ip_hash`; HTTP-only algorithms `ewma`, `least_time`, and `sticky_cookie` are rejected. Listener pool fields are transport-specific: `udp_pool` must reference `turn://` servers, `tcp_pool` must reference `turn+tcp://` servers, and `tls_pool` must reference `turns://` servers. `auth.mode = "validate"` checks authenticated TURN messages when credentials are present, but lets the upstream TURN server issue nonce challenges and remain authoritative.

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
- No enabled downstream HTTP versions or SNI forwarding protocols.
- Privileged listener ports when `runtime.unprivileged_mode = true`.
- Non-Linux runtime when `runtime.linux_only = true`.
- Invalid hot reload mode, zero worker counts, non-positive worker multipliers, zero `poll_interval_ms`, zero accept backlog/backoff values, accept worker counts greater than one without `runtime.accept.reuse_port = true`, or HTTP/3 QUIC socket worker counts greater than one without `quic.socket.reuse_port = true`.
- Missing all `[[routes]]`, `[sni_forward]` rule/default targets, `[[stream_listeners]]`, and `[[webrtc_turn_listeners]]`; duplicate names; empty route hosts; or unknown route targets.
- Invalid SNI forwarding targets, duplicate SNI forwarding rule names or server-name patterns, unsupported wildcard placement, zero SNI forwarding timeouts, or QUIC SNI forwarding without downstream HTTP/3.
- Routes that set zero or more than one of `upstream`, `upstream_pool`, or `static_root`.
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
client_ip_source = "resolved"

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
