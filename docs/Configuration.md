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

- At least one of `[[upstreams]]` or `[[upstream_pools]]`.
- At least one `[[routes]]`.
- Each route must set exactly one of `upstream` or `upstream_pool`.

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

[runtime.hot_reload]
mode = "off" # off | oxirule | downstream_tls | full
poll_interval_ms = 2000
```

`unprivileged_mode = true` rejects listener ports below `1024`. `poll_interval_ms` must be greater than zero. CLI flags `--hot-reload-mode` and `--hot-reload-poll-interval-ms` override TOML values and emit warnings when they differ.

Reload modes:

- `off`: no reload.
- `oxirule`: reload only WAF-owned configuration and external rule files.
- `downstream_tls`: reload the current downstream certificate, key, and static OCSP response.
- `full`: reload OxiRule policy, TOML configuration, upstream clients, access-log sinks, downstream TLS material, downstream listener bind/protocol settings, and admin listener enable/bind settings.

Reload failures keep the previous active state.

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

[tls.client_auth]
mode = "off" # off | optional | require
ca_certs = []
verify_depth = 4

[tls.ocsp]
mode = "disabled" # disabled | static_file | live_fetch
# response_file = "ocsp.der"
```

`cert_chain` and `private_key` are required. `tls.client_auth.ca_certs` is required when client authentication mode is not `off`. `tls.ocsp.mode = "static_file"` requires `response_file`; `live_fetch` is reserved and rejected. HTTP/3 requires `tls.min_version = "tls1.3"`.

## QUIC Sections

```toml
[quic]
retry = false
zero_rtt = "off" # off | safe_methods
# host_key_file = "quic-host-key.b64"

[quic.alt_svc]
enabled = true
max_age_seconds = 86400
persist = false

[quic.transport]
max_concurrent_bidi_streams = 100
max_concurrent_uni_streams = 100
idle_timeout_ms = 30000
datagram_receive_buffer_bytes = 1048576
datagram_send_buffer_bytes = 1048576
max_udp_payload_size = 1472
gso = true

[quic.socket]
receive_buffer_bytes = 0
send_buffer_bytes = 0

[quic.upstream_pool]
enabled = true
max_connections_per_upstream = 1
max_lifetime_ms = 600000
```

`retry = true` enables QUIC Retry/address validation for unvalidated downstream HTTP/3 connection attempts. `zero_rtt = "safe_methods"` enables QUIC TLS early data and rejects unsafe requests that the QUIC transport reports as early data with `425 Too Early`; only early-data `GET` and `HEAD` are accepted.

`host_key_file` is optional and is resolved under the cert directory. It must contain base64 for exactly 64 random bytes. OxiBelt derives QUIC stateless reset and Retry/validation token keys from this material. The file is included in runtime reload fingerprints and in downstream TLS reload inputs.

When downstream HTTP/3 is enabled and `quic.alt_svc.enabled = true`, HTTPS HTTP/1.1 and HTTP/2 responses advertise `Alt-Svc: h3=":<https port>"; ma=<max_age_seconds>`. `persist = true` appends `; persist=1`. OxiBelt does not add `Alt-Svc` to downstream HTTP/3 responses, plain HTTP responses, or `101 Switching Protocols`.

`quic.socket.receive_buffer_bytes = 0` and `send_buffer_bytes = 0` keep the OS defaults. Nonzero socket buffer values are applied to the UDP socket. Other QUIC transport and pool numeric values must be greater than zero; `max_udp_payload_size` must be in the QUIC-valid range `1200..=65527`.

The upstream HTTP/3 pool multiplexes ordinary HTTP/3 request forwarding over reusable QUIC connections. WebTransport forwarding keeps a dedicated QUIC connection per session.

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
request = "streaming" # streaming | memory | reject_if_too_large
response = "streaming"
max_memory_body_bytes = 1048576
max_temp_file_bytes = 0

[proxy.http]
early_hints = "drop" # drop | pass
trailers = "pass"    # pass | drop
```

`trusted_ca_certs` adds upstream TLS trust roots from the cert directory. `forwarded_headers.mode = "overwrite"` replaces inbound forwarding metadata; `append` preserves and extends the inbound `X-Forwarded-For` chain. `real_ip` affects the client IP used by rate limiting and WAF evaluation only when the direct peer is trusted.

`generic_http_upgrade` and `connect_tunneling` enable the global capability only. Individual routes must also opt in with `generic_http_upgrade = true` or `connect_tunneling = true`. CONNECT tunnels are not open-proxy tunnels; OxiBelt connects only to the selected route upstream origin. `proxy.grpc_web.enabled` enables the global gRPC-Web transformer, and each route must also set `grpc_web = true`.

Reserved or constrained values:

- `proxy.http.early_hints = "pass"` is rejected.
- Disk buffering is not implemented; `max_temp_file_bytes` must be `0`.

## Limits, Cache, and Ops

```toml
[limits]
max_connections = 65536
max_connections_per_ip = 128
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
mode = "enforcing" # enforcing | monitor
status = 429

[[connection_limits]]
name = "per-ip-connections"
key = "client_ip"
limit = 64
status = 429
```

Limit values must be greater than zero. Rate and connection limit state is process-local by default. When `[shared_state].enabled = true` and the relevant feature maps to a backend, rate token buckets and downstream connection leases are shared across instances. `max_connections`, `max_connections_per_ip`, and `[[connection_limits]]` apply to downstream HTTP/HTTPS and TCP stream listener connections. TLS handshake and header timeouts are listener-wide because no route is known yet; body, response-send, WebSocket, and WebTransport idle timeouts can be overridden per route.

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
respect_cache_control = true
stale_if_error_seconds = 30
stale_while_revalidate_seconds = 30
lock = true
negative_statuses = []
negative_ttl_seconds = 0

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

Compression support is enabled by default for `br`, `zstd`, `gzip`, and `deflate`. OxiBelt only compresses downstream responses when the client permits an enabled encoding, the request does not carry `Cookie`, `Authorization`, or `Proxy-Authorization`, the response is not already encoded or secret-bearing, the status/MIME/size policy matches, and HTTP semantics such as `Cache-Control: no-transform` and range responses allow transformation. Responses with `Set-Cookie`, `Cache-Control: private`, or `Cache-Control: no-store` are not compressed. `max_concurrent_responses = 0` uses an automatic CPU budget.

`cache.store = "tmpfs"` validates `tmpfs_dir` under `/dev/shm` when cache is enabled. `disk` and `memory_then_disk` require an explicit writable `disk_dir` and `disk_max_size_bytes`; OxiBelt does not choose a disk path implicitly. If `memory_then_disk` omits `memory_max_size_bytes`, OxiBelt uses `memory_auto_fraction` of the detected cgroup/container memory limit, falling back to system memory. `cache_key` supports `{scheme}`, `{host}`, `{uri}`, `{path}`, `{query}`, `{query:name}`, `{header:Name}`, and `{cookie:name}`. Named cache policies are selected by `routes.cache`; `default` refers to the top-level `[cache]` policy. Policy rules select storage after the upstream response MIME type is known. When `cache_backend` maps to a shared backend, the configured local cache remains L1 and the shared backend stores full cacheable objects, metadata, fill locks, and purge-visible L2 entries.

The cache honors HTTP cache metadata including `Cache-Control`, `Expires`, `ETag`, `Last-Modified`, and `Vary`. It can revalidate stale entries, serve stale entries on upstream error, serve cached byte ranges from full stored responses, and cache configured negative statuses with `negative_statuses` and `negative_ttl_seconds`.

`[admin]` exposes operations APIs such as cache purge and upstream-pool runtime control. `transport = "auto"` accepts plaintext only from `plaintext_allowed_source_cidrs`; other clients must use TLS. Use `plaintext_allowlist` for Docker bridge or same-host management networks that intentionally use plaintext, and add those CIDRs explicitly. `transport = "plaintext"` is rejected unless `allow_insecure_plaintext = true`. When admin TLS is enabled, `server_names` are matched case-insensitively and may use a leftmost wildcard such as `*.ops.example.com`; missing or unknown SNI is rejected by default. Admin requests always require `Authorization: Bearer <token>`, even when mTLS is enabled.

`admin.bearer_token_env` remains the backward-compatible built-in admin token and receives the `admin` role. Additional `[[admin.rbac.tokens]]` entries name token environment variables and roles. Roles are `viewer`, `cache_operator`, `upstream_operator`, and `admin`; `admin` implies all scopes. Cache purge requires `cache_operator`; upstream-pool reads require `viewer`; upstream-pool mutations require `upstream_operator`. Full hot reload starts, stops, or rebinds the dedicated admin listener when `admin.enabled` or `admin.bind` changes.

Admin WAF telemetry endpoint:

- `GET /admin/v1/waf/rule-hits`

This endpoint requires `viewer` or `admin` and returns active rule hit counters with `scope`, `route`, `phase`, `name`, optional `id`, `effective_mode`, and `hits`.

Admin upstream-pool endpoints:

- `GET /admin/v1/upstream-pools`
- `GET /admin/v1/upstream-pools/{pool}`
- `POST /admin/v1/upstream-pools/{pool}/servers`
- `PATCH /admin/v1/upstream-pools/{pool}/servers/{server_id}`
- `DELETE /admin/v1/upstream-pools/{pool}/servers/{server_id}`

Runtime server mutation accepts JSON fields `id`, `origin`, `state`, `weight`, `backup`, and `max_conns` where applicable. `DELETE` is limited to servers created by the admin API. Every admin mutation emits a structured audit log with actor, peer, operation, target, outcome, and validation error when rejected.

Admin purge endpoints:

```sh
POST /cache/purge?policy=default&scheme=https&host=example.test&uri=/path
POST /cache/purge-prefix?policy=default&scheme=https&host=example.test&path_prefix=/assets/
```

Health paths must start with `/`. When WAF is enabled, metrics include `oxibelt_waf_rule_hits_total{scope,route,phase,mode,rule_name,rule_id}` for active global and route rules, including zero-hit rules.

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
```

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
```

`upstream_http_version` is a route-level backend protocol override and must not exceed the selected upstream capability. HTTP/3 overrides are rejected for upstream-pool routes and for upstreams with PROXY protocol egress enabled.

Route timeout overrides are optional. Omitted values inherit from `[limits]` for downstream behavior and from the selected `[[upstreams]]` entry for upstream behavior. TLS handshake and downstream header read timeouts are not route-level because route matching has not happened yet.

Fields:

- `name`: unique route name.
- `hosts`: host match list; defaults to `["*"]`.
- `path_prefix`: path prefix match; defaults to `/`.
- `replace_prefix_with`: optional upstream path prefix replacement.
- `upstream` or `upstream_pool`: exactly one target.
- `cache`: optional cache reference; currently only `default` is accepted.
- `compression`: optional downstream response compression policy; omitted means `default`, `off` disables compression for the route, and any other value must match `[[compression.policies]].name`.

Route path values must start with `/` and must not contain control characters, backslashes, query strings, fragments, dot segments, or encoded dot/slash separators such as `%2e`, `%2f`, or `%5c`.

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
- Invalid hot reload mode or zero `poll_interval_ms`.
- No upstreams/pools, no routes, duplicate names, empty route hosts, or unknown route targets.
- Routes that set both `upstream` and `upstream_pool`, or neither.
- Unsafe route paths.
- Unsupported upstream schemes or HTTP/3 upstreams without HTTPS.
- Invalid runtime file paths or runtime files outside their purpose-specific directory.
- TLS client auth without CA roots, invalid TLS version ranges, static OCSP without `response_file`, or reserved live OCSP mode.
- Reserved early-hints, disk-buffering, or sticky-cookie settings.
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
