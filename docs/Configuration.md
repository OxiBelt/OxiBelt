# OxiBelt Configuration

Status: Draft 0.1  
Target project: OxiBelt Rust-based reverse proxy

This document describes the OxiBelt TOML configuration file format. The default example configuration lives at:

```sh
source/config/oxibelt.toml
```

OxiBelt loads configuration from the path passed with `--config`. The default container entrypoint uses:

```sh
/etc/oxibelt/config/oxibelt.toml
```

That file is the main entry configuration. It may include additional modular TOML files with the top-level `include` key.

The standard container layout has three purpose-specific directories:

```sh
/etc/oxibelt/config   # OxiBelt TOML configuration and included TOML modules
/etc/oxibelt/cert     # TLS certificates, private keys, CA roots, OCSP responses, ECH config lists
/etc/oxibelt/oxirule  # External .oxirule.toml rule files
```

This layout can be mounted from separate host directories or volumes. For release deployments, keep these mounts read-only and pair them with Docker runtime hardening:

```sh
docker run --rm -p 8443:8443 \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --mount type=bind,src=/mnt/user0/oxibelt/config,dst=/etc/oxibelt/config,readonly \
  --mount type=bind,src=/mnt/user0/oxibelt/cert,dst=/etc/oxibelt/cert,readonly \
  --mount type=bind,src=/mnt/user0/oxibelt/oxirule,dst=/etc/oxibelt/oxirule,readonly \
  oxibelt
```

If the main file has a different host-side name, bind it to the entrypoint path:

```sh
docker run --rm -p 8443:8443 \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --mount type=bind,src=/mnt/user0/oxibelt/config,dst=/etc/oxibelt/config,readonly \
  --mount type=bind,src=/mnt/user0/oxibelt/config/main.toml,dst=/etc/oxibelt/config/oxibelt.toml,readonly \
  --mount type=bind,src=/mnt/user0/oxibelt/cert,dst=/etc/oxibelt/cert,readonly \
  --mount type=bind,src=/mnt/user0/oxibelt/oxirule,dst=/etc/oxibelt/oxirule,readonly \
  oxibelt
```

With this nested file mount, OxiBelt still sees the main file as `/etc/oxibelt/config/oxibelt.toml`. Other included config files are resolved from the container-visible `/etc/oxibelt/config` directory, which is the parent directory mount above. Make sure bind-mount sources already exist and use Docker's `--mount` form so a missing file source is reported as an error instead of being created as a directory.

The release image runs as UID/GID `10001:10001`. Mounted configuration, certificate, and OxiRule files must be readable by that container identity.

Relative paths in `include` entries are resolved relative to the TOML file that declares them. Include entries must stay under that declaring file's directory. Runtime file paths inside the merged configuration are resolved by purpose: TLS, CA, OCSP, and ECH files are resolved under the cert directory, and external OxiRule files are resolved under the oxirule directory.

File paths referenced from configuration must be relative, normalized paths without `.` or `..` components. Runtime file paths must resolve to existing regular files under their purpose-specific directory before startup continues.

OxiRule WAF rule syntax is documented separately in [OxiRule.md](OxiRule.md). This document only describes how OxiRule entries are placed inside the OxiBelt TOML configuration.

## 1. Top-Level Shape

A typical configuration contains these sections:

```toml
include = ["conf.d/*.toml"]

[config]
[logging]
[runtime]
[runtime.hot_reload]
[listeners]
[listeners.proxy_protocol]
[tls]
[tls.client_auth]
[proxy]
[proxy.forwarded_headers]
[proxy.real_ip]
[proxy.upgrades]
[proxy.retry]
[proxy.buffering]
[proxy.http]
[limits]
[compression]
[cache]
[metrics]
[health]
[security.headers]
[database]
[waf]

[[rate_limits]]
[[connection_limits]]
[[upstreams]]
[[upstream_pools]]
[[routes]]
```

Required top-level sections:

- `[listeners]`
- `[tls]`
- `[[upstreams]]`
- `[[routes]]`

Most other sections have defaults.

### 1.2 Strict keys and config checks

```toml
[config]
strict_unknown_fields = true
warn_on_deprecated_fields = true
```

`strict_unknown_fields` defaults to `true`. After includes are merged, unknown OxiBelt configuration keys fail startup so misspelled security settings are not silently ignored. Set it to `false` only for compatibility testing.

The CLI can validate without binding listeners or print a redacted merged configuration:

```sh
oxibelt --config source/config/oxibelt.toml --check
oxibelt --config source/config/oxibelt.toml --dump-effective-config
```

### 1.1 Modular includes

The main entry file can include modular TOML files:

```toml
include = [
  "conf.d/upstreams.toml",
  "conf.d/routes/*.toml",
]
```

`include` may be a single string or an array of strings. Include entries support exact file paths and glob patterns using `*`, `?`, and `[...]`.

Include behavior:

- Include entries must be relative paths under the declaring file's directory.
- Absolute include paths and include paths containing `.` or `..` components are rejected.
- Exact include paths must point to an existing file.
- Glob include matches are sorted before loading so startup behavior is deterministic.
- Glob include entries that match no files are allowed.
- Included files may contain their own top-level `include` entries.
- Include cycles are rejected.
- Include symlinks or glob matches that resolve outside the declaring file's directory are rejected.

TOML documents are merged before OxiBelt decodes and validates the final configuration:

- Included files are merged before the file that declared them.
- Tables are merged recursively.
- Arrays are appended in include expansion order, then the declaring file's own array entries are appended.
- Duplicate scalar keys across files are rejected instead of silently overridden.
- Incompatible value types for the same key are rejected.

This is intended for splitting repeated or environment-specific sections into separate files, for example:

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

## 2. Logging

```toml
[logging]
level = "info"
```

`level` is passed to the tracing filter. The default is `info`.

## 2.1 Database Access Log Sink

```toml
[database.access_log]
enabled = false
connection_url_env = "OXIBELT_ACCESS_LOG_DATABASE_URL"
table = "oxibelt_access_log"
max_connections = 4
connect_timeout_ms = 3000
queue_capacity = 1024

[database.access_log.tls]
mode = "off"
# ca_cert = "postgres-ca.pem"
# client_cert = "postgres-client.pem"
# client_key = "postgres-client.key"
```

`database.access_log` configures the optional PostgreSQL sink for OxiRule `emit_access_log` records. When enabled, OxiBelt validates the PostgreSQL connection and target table before the listeners start. The stdout access log remains enabled; PostgreSQL receives an additional copy.

`connection_url` may hold a PostgreSQL connection URL directly. Prefer `connection_url_env` for deployments so secrets stay outside committed TOML. Exactly one of `connection_url` or `connection_url_env` is required when `enabled = true`.

`table` is the access-log table name. It may be an unqualified table name such as `oxibelt_access_log` or a schema-qualified name such as `audit.access_log`. Identifier segments must contain only ASCII letters, digits, and underscores, and each segment is quoted when SQL is generated.

The target table must already exist with this shape:

```sql
CREATE TABLE audit.access_log (
  event text NOT NULL,
  timestamp_unix_ms bigint NOT NULL,
  record jsonb NOT NULL
);
```

`record` stores the complete newline-delimited JSON object that `emit_access_log` also writes to stdout. OxiBelt validates the table with a zero-row `INSERT ... SELECT ... WHERE false`, so startup catches missing columns and missing insert permission without writing a row.

`database.access_log.tls.mode` controls PostgreSQL TLS negotiation. The default is `off`.

- `off`: do not use TLS.
- `verify_full`: require TLS, validate the chain, and verify the server name.

`ca_cert` imports a custom PostgreSQL server CA from the cert directory and is valid only with `verify_full`.

`client_cert` and `client_key` enable PostgreSQL mutual TLS client authentication. They must be configured together, are read from the cert directory, and are valid only with `mode = "verify_full"`.

## 3. Runtime

```toml
[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true

[runtime.hot_reload]
mode = "off"
poll_interval_ms = 2000
```

Runtime defaults are conservative for container deployment:

- `linux_only`: reject startup on non-Linux targets.
- `read_only_rootfs_compatible`: declare that runtime state should not require root filesystem writes.
- `memory_only_state`: declare that runtime state should stay in memory.
- `unprivileged_mode`: reject privileged listener ports below `1024`.

`[runtime.hot_reload]` controls runtime reload behavior. The default is `off`, so existing deployments keep restart-only semantics unless this section or the matching CLI flags enable reload.

Supported modes:

- `off`: disable hot reload. OxiBelt ignores `SIGHUP` for reload purposes.
- `oxirule`: reload WAF policy only. Inline global WAF rules, route-level WAF rules, pattern sets, and external `.oxirule.toml` files may change. Any non-WAF configuration difference is rejected and the previous active state stays in use.
- `full`: reload OxiRule policy, OxiBelt TOML configuration, upstream clients, access-log sinks, downstream TLS material, and listener bind/protocol settings.
- `downstream_tls`: reload only the currently configured downstream `tls.cert_chain`, `tls.private_key`, and static OCSP response file. This mode is intended for short-lived certificate renewals such as Let's Encrypt.

`poll_interval_ms` controls how often OxiBelt fingerprints reload-relevant files. It must be greater than zero. On Unix, sending `SIGHUP` to the process triggers an immediate reload check:

```sh
kill -HUP <oxibelt-pid>
```

The same settings can be supplied on the CLI:

```sh
oxibelt --config source/config/oxibelt.toml \
  --hot-reload-mode full \
  --hot-reload-poll-interval-ms 1000
```

CLI values override TOML values. When a CLI value differs from TOML, OxiBelt emits a `warn!` log message to stdout and uses the CLI value.

Reload apply behavior is failure-safe. Invalid TOML, invalid rules, invalid certificate/key pairs, unreadable files, failed upstream client construction, failed database access-log setup, and failed listener binds all leave the previous active state in place. Reload failure diagnostics are emitted with `warn!` to stdout.

In `full` mode, listener bind or protocol changes are supervised. If TCP or UDP bind settings change, OxiBelt binds replacement listeners before committing the new snapshot, but starts their accept loops only after the new snapshot is active. If the replacement listener cannot bind, the old listeners and old configuration remain active. If HTTP/3 remains on the same bind address, new QUIC connections receive the reloaded server TLS configuration without rebinding the endpoint.

OxiBelt tracks both configured logical paths and validated canonical paths for reloadable files. This lets certificate renewals that update a stable symlink, for example `fullchain.pem -> archive/example/fullchain42.pem`, be detected and revalidated safely. Keep renewed certificate, private-key, OCSP, and OxiRule files inside their purpose-specific directories so path validation continues to pass after reload.

## 4. Listeners

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

At least one downstream HTTP version must be enabled.

Current implementation notes:

- HTTP/1.1 and HTTP/2 listen on TCP.
- HTTP/3 listens on UDP using the same `https_bind` address and port. Deployments must expose both TCP and UDP when all three downstream versions are enabled.
- `http_mode = "redirect_to_https"` returns permanent redirects from `http_bind`; `proxy` accepts plain HTTP and forwards it through the normal route pipeline.
- PROXY protocol is accepted only from configured trusted sources.

## 5. Downstream TLS

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
mode = "disabled"
```

`cert_chain` and `private_key` are required. Paths are resolved relative to the cert directory. Both paths must resolve to existing regular files under that directory.

OCSP modes:

- `disabled`: do not staple an OCSP response.
- `static_file`: load a stapled OCSP response from `response_file`.
- `live_fetch`: reserved but not implemented yet.

Example static OCSP configuration:

```toml
[tls.ocsp]
mode = "static_file"
response_file = "ocsp.der"
```

`response_file` is required when `mode = "static_file"` and must resolve to an existing regular file under the cert directory.

TCP TLS can be configured for TLS 1.2 through TLS 1.3. HTTP/3 always requires TLS 1.3. Client certificate authentication can be optional or required when `tls.client_auth.ca_certs` names CA files under the cert directory.

## 6. Proxy

```toml
[proxy]
trusted_ca_certs = []

[proxy.forwarded_headers]
mode = "overwrite"

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"

[proxy.real_ip]
enabled = false
trusted_proxies = []
header = "x-forwarded-for"
recursive = true
fail_on_untrusted_forwarded_headers = false

[proxy.upgrades]
websocket = true
generic_http_upgrade = false
connect_tunneling = false

[proxy.retry]
enabled = false
tries = 2
timeout_ms = 5000
on = ["connect_error", "read_timeout", "502", "503", "504"]
retry_non_idempotent = false

[proxy.buffering]
request = "streaming"
response = "streaming"
max_memory_body_bytes = 1048576
max_temp_file_bytes = 0

[proxy.http]
early_hints = "drop"
trailers = "pass"
```

`trusted_ca_certs` is a list of additional CA certificate files used for upstream TLS verification. Paths are resolved relative to the cert directory. Each entry must resolve to an existing regular file under that directory.

`proxy.forwarded_headers.mode` controls how OxiBelt handles inbound forwarding metadata before sending a request upstream:

- `overwrite` (default): remove client-supplied `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-Port`, then set OxiBelt's direct peer address, downstream host, HTTPS scheme, and peer port.
- `append`: remove `Forwarded`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-Port`, preserve any existing `X-Forwarded-For` chain, and append OxiBelt's direct peer address.

`proxy.auto_upgrade` controls upstream HTTP version selection:

- `enabled`: allow OxiBelt to negotiate up to the configured maximum.
- `max_http_version`: `h1`, `h2`, or `h3`.

Current implementation notes:

- Upstream HTTP/1.1 supports `http://` and `https://` origins.
- Upstream HTTP/2 over `https://` uses TLS ALPN negotiation.
- Upstream HTTP/2 over `http://` uses cleartext h2c with prior knowledge. OxiBelt does not use the HTTP/1.1 Upgrade flow for h2c.
- Upstream HTTP/3 uses QUIC and requires an `https://` upstream origin. When `max_http_version = "h3"` is selected, OxiBelt forwards ordinary HTTP requests over HTTP/3.
- `proxy.real_ip` rewrites the client IP used by rate limiting and WAF evaluation only when the direct peer is trusted.
- WebSocket tunneling is implemented for HTTP/1.1 upgrade requests. Generic upgrades and CONNECT tunneling remain reserved.
- `early_hints = "pass"` is reserved; use the default `drop`.

## 6.1 Limits, Cache, and Ops Endpoints

```toml
[limits]
max_connections = 65536
max_connections_per_ip = 128
max_requests_per_connection = 1000
client_header_timeout_ms = 10000
max_headers = 128
max_uri_bytes = 8192
max_request_body_bytes = 10485760

[[rate_limits]]
name = "per-ip"
key = "client_ip"
rate = "10r/s"
burst = 50
status = 429

[[connection_limits]]
name = "per-ip-connections"
key = "client_ip"
limit = 64
status = 429

[cache]
enabled = false
store = "memory" # memory | tmpfs
tmpfs_dir = "/dev/shm/oxibelt-cache"

[metrics]
enabled = false
bind = "127.0.0.1:9090"

[health]
enabled = false
bind = "127.0.0.1:9091"
ready_path = "/ready"
live_path = "/live"
```

Limits are process-local. `store = "tmpfs"` validates that `tmpfs_dir` is an existing writable directory under `/dev/shm`; cached response bodies are written there while metadata remains in OxiBelt's bounded process state.

`[security.headers]` can add HSTS, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy` to proxied responses.

## 7. Compression

```toml
[compression]
enabled = true
gzip = true
deflate = true
zstd = true
```

When compression is enabled, OxiBelt advertises supported upstream response encodings with `Accept-Encoding`.

## 8. Global WAF

```toml
[waf]
enabled = true
mode = "enforcing"      # enforcing | monitor
fail_policy = "closed"  # closed | open
duplicate_metadata_policy = "fail_closed"
```

`enabled` controls whether WAF rules are evaluated.

Modes:

- `enforcing`: apply blocking, rewrite, mutation, and routing decisions.
- `monitor`: evaluate and log WAF decisions without enforcing blocking actions.

Failure policies:

- `closed`: reject the transaction when WAF execution fails.
- `open`: allow the transaction to continue when WAF execution fails.

Security-sensitive deployments should prefer `fail_policy = "closed"`.

`duplicate_metadata_policy` controls single-value OxiRule helpers such as `Request.Headers.get(...)`, `Request.QueryParams.get(...)`, and `Request.Cookies.get(...)` when attacker-controlled metadata contains duplicate names:

- `fail_closed` rejects through the WAF failure policy when a requested name has more than one value. This is the default.
- `null_on_duplicate` returns `null` for duplicate names.
- `reject_request` rejects requests with any duplicate request header, query parameter, or cookie name before rule evaluation with `400 Bad Request`.

Use `getAll(...)` helpers when a rule intentionally needs to inspect duplicate values.

### 8.1 WAF limits

```toml
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
```

These limits constrain OxiRule parsing, evaluation, helper scans, derived strings, body inspection, binary format signature checks, regex use, mutations, and single-use Person proof token state.

### 8.2 Pattern sets

Pattern sets are global WAF data and may be referenced from OxiRule helpers.

```toml
[[waf.pattern_sets]]
name = "sql-injection-keywords"
kind = "contains"
patterns = ["UNION SELECT", "DROP TABLE", "information_schema"]

[[waf.pattern_sets]]
name = "xss-regexes"
kind = "regex"
patterns = ["(?i)<script", "(?i)javascript:"]
```

Supported `kind` values:

- `contains`
- `regex`

Pattern set names must be unique. Pattern counts and pattern lengths are constrained by `[waf.limits]`.

### 8.3 Global OxiRule entries

Inline global rules are configured under `[[waf.rules]]`:

```toml
[[waf.rules]]
name = "block-public-admin"
id = "block-admin-public"
tags = ["access-control", "admin"]
phase = "request"
priority = 100
when = """
Request.Http.Path.startsWith('/admin') &&
!Request.Client.Ip.inCidr('10.0.0.0/8')
"""

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Forbidden"
```

External rule files are referenced with `path`:

```toml
[[waf.rules]]
name = "global-request-policy"
id = "global-request"
tags = ["baseline"]
phase = "request"
priority = 10
path = "rules/global-request.oxirule.toml"
```

A rule entry must specify exactly one of `when` or `path`. `id` is optional and must be unique when non-empty. `id` and entries in `tags` must match `[A-Za-z0-9-]{0,32}`.
External rule file paths are resolved relative to the oxirule directory. Absolute paths and paths containing `.` or `..` components are rejected.

An external `.oxirule.toml` file contains only the rule body:

```toml
when = "Request.Headers.anyValueContains('sqlmap')"

[[actions]]
type = "reject"
status = 403
body = "Blocked by WAF"
```

Request-phase OxiRule entries may also require a bounded Person proof challenge:

```toml
[[waf.rules]]
name = "require-person-proof-for-unknown-browser"
phase = "request"
priority = 50
when = "Request.Client.PersonProof.State != 'valid' && Request.Client.Bot.Disposition != 'normal'"

[[waf.rules.actions]]
type = "require_person_proof"
algorithm = "pow_sha256_v1"
difficulty = 18
token_validity_seconds = 300
cookie = "__oxibelt_person_proof"
token_bindings = ["user_agent", "route", "direct_peer_ip_network_prefix"]
direct_peer_ipv4_prefix_bits = 24
direct_peer_ipv6_prefix_bits = 56
# Required when token_bindings contains "tcp_max_hop".
# tcp_max_hop = 16
single_use = false
success_tag = "PersonProof"
```

`require_person_proof` is documented in [OxiRule.md](OxiRule.md#require_person_proof). It is a defense-in-depth anti-automation challenge, not authentication and not a complete denial-of-service defense.
When `success_tag` is set, a validated proof or clearance emits that transaction tag with value `valid`, making it available to later request-phase rules and response-phase rules through `Request.Tags`.
Challenge and clearance tokens are bound to the specific `require_person_proof` policy that issued them. A proof for one rule does not satisfy a different rule that uses the same cookie.

## 9. Upstreams

```toml
[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2"
connect_timeout_ms = 3000
request_timeout_ms = 30000
read_timeout_ms = 30000
send_timeout_ms = 30000
idle_timeout_ms = 75000
preserve_host = false
websocket = true
webrtc = true
webtransport = true
```

Fields:

- `name`: unique upstream name.
- `origin`: upstream `http://` or `https://` URL.
- `max_http_version`: `h1`, `h2`, or `h3`.
- `connect_timeout_ms`: upstream connection timeout.
- `request_timeout_ms`: upstream request timeout.
- `read_timeout_ms`, `send_timeout_ms`, `idle_timeout_ms`: upstream I/O and pool idle timeout settings.
- `preserve_host`: forward the original `Host` when true; use the upstream origin host when false.
- `websocket`, `webrtc`, `webtransport`: protocol capability flags used by routing and protocol-specific forwarding behavior.

Current implementation notes:

- `max_http_version = "h3"` requires an `https://` origin.
- `max_http_version = "h2"` with an `http://` origin uses cleartext h2c with prior knowledge.
- WebTransport forwarding is supported for downstream HTTP/3 extended CONNECT requests when the selected upstream also uses HTTP/3 and `webtransport = true`.
- WebTransport streams and datagrams are forwarded between downstream and upstream sessions. WAF rules evaluate the CONNECT request metadata before the session is accepted; frame-level and datagram payload inspection remain outside the current WAF implementation.

### 9.2 Upstream pools

```toml
[[upstream_pools]]
name = "app-pool"
algorithm = "round_robin" # round_robin | least_conn | random | hash | ip_hash

[[upstream_pools.servers]]
origin = "https://app-1.internal.example"
weight = 1
max_conns = 1024
backup = false

[upstream_pools.health_check]
enabled = true
mode = "passive"
unhealthy_threshold = 3
```

Routes may set `upstream_pool = "app-pool"` instead of `upstream`. Sticky-cookie pools are reserved and rejected at startup.

### 9.1 Upstream TLS ECH

OxiBelt can enable TLS 1.3 Encrypted ClientHello for upstream HTTPS connections where OxiBelt acts as the TLS client.

ECH is configured per upstream because a real ECH configuration is specific to the upstream name that published it.

```toml
[[upstreams]]
name = "private-api"
origin = "https://api.internal.example"
max_http_version = "h2"

[upstreams.tls.ech]
mode = "config_list" # disabled | grease | config_list
config_list_file = "private-api.echconfiglist"
```

Modes:

- `disabled`: do not send ECH. This is the default.
- `grease`: send GREASE ECH for anti-ossification testing. The upstream does not need to support ECH.
- `config_list`: send real ECH using a TLS-encoded `ECHConfigList` file.

Validation rules:

- `tls.ech.config_list_file` is required when `tls.ech.mode = "config_list"`.
- `tls.ech.config_list_file` is invalid for `disabled` and `grease`.
- `tls.ech.config_list_file` must resolve to an existing regular file under the cert directory when it is configured.
- Enabling ECH selects TLS 1.3 for that upstream TLS client, matching the rustls ECH requirement.
- Downstream ECH termination is not configured here; it requires server-side ECH support in the TLS provider.

## 10. Routes

```toml
[[routes]]
name = "api-v1"
hosts = ["api.example.com"]
path_prefix = "/v1"
replace_prefix_with = "/"
upstream = "app"
```

Fields:

- `name`: unique route name.
- `hosts`: host match list. Defaults to `["*"]`.
- `path_prefix`: path prefix match. Defaults to `/`.
- `replace_prefix_with`: optional upstream path prefix replacement.
- `upstream`: target upstream name.

Validation requires each route to reference an existing upstream.
Route path values must begin with `/` and must not contain control characters, backslashes, query strings, fragments, dot segments, or encoded dot/slash separators such as `%2e`, `%2f`, or `%5c`.

### 10.1 Route-level OxiRule entries

Route-level WAF rules are scoped to one route:

```toml
[[routes]]
name = "api"
hosts = ["api.example.com"]
path_prefix = "/v1"
upstream = "app"

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

Route-level rule syntax is the same OxiRule syntax used by global rules.

## 11. Validation Summary

Configuration validation rejects:

- Invalid include values.
- Absolute include paths, parent-directory include paths, or include symlinks that escape the declaring directory.
- Missing exact include files.
- Include cycles.
- Duplicate scalar keys or incompatible value types across included TOML files.
- No enabled downstream HTTP versions.
- Privileged listener ports when `runtime.unprivileged_mode = true`.
- Non-Linux runtime when `runtime.linux_only = true`.
- Invalid hot reload mode or `runtime.hot_reload.poll_interval_ms = 0`.
- Empty upstream or route lists.
- Duplicate upstream or route names.
- Upstream origins that are not `http://` or `https://`.
- Routes with empty host matches.
- Absolute include/runtime file paths or relative configuration file paths containing `.` or `..` components.
- Runtime file paths that do not resolve to existing regular files under their purpose-specific directory.
- External OxiRule paths that are absolute or escape the oxirule directory.
- Invalid or duplicate non-empty OxiRule IDs, or invalid OxiRule tags.
- Route `path_prefix` or `replace_prefix_with` values that do not start with `/` or contain unsafe path syntax.
- Routes that reference unknown upstreams.
- OCSP `static_file` mode without `response_file`.
- Enabled `database.access_log` without a connection URL source, target table, or valid TLS/CA settings.
- Reserved but unimplemented HTTP/3 modes.
- Invalid WAF rules, pattern sets, actions, phases, expressions, duplicate metadata policy, or budgets.

## 12. Complete Minimal Example

```toml
[logging]
level = "info"

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
