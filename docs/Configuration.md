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

[logging]
[runtime]
[listeners]
[tls]
[proxy]
[compression]
[waf]

[[upstreams]]
[[routes]]
```

Required top-level sections:

- `[listeners]`
- `[tls]`
- `[[upstreams]]`
- `[[routes]]`

Most other sections have defaults.

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

## 3. Runtime

```toml
[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
```

Runtime defaults are conservative for container deployment:

- `linux_only`: reject startup on non-Linux targets.
- `read_only_rootfs_compatible`: declare that runtime state should not require root filesystem writes.
- `memory_only_state`: declare that runtime state should stay in memory.
- `unprivileged_mode`: reject privileged listener ports below `1024`.

## 4. Listeners

```toml
[listeners]
https_bind = "0.0.0.0:8443"
http1 = true
http2 = true
http3 = false
```

At least one downstream HTTP version must be enabled.

Current implementation notes:

- HTTP/1.1 and HTTP/2 are implemented.
- HTTP/3 is reserved in configuration but currently rejected during validation.

## 5. Downstream TLS

```toml
[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"

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

## 6. Proxy

```toml
[proxy]
trusted_ca_certs = []

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"
```

`trusted_ca_certs` is a list of additional CA certificate files used for upstream TLS verification. Paths are resolved relative to the cert directory. Each entry must resolve to an existing regular file under that directory.

`proxy.auto_upgrade` controls upstream HTTP version selection:

- `enabled`: allow OxiBelt to negotiate up to the configured maximum.
- `max_http_version`: `h1`, `h2`, or `h3`.

Current implementation notes:

- Upstream HTTP/1.1 and HTTP/2 are implemented.
- HTTP/3 is reserved but currently rejected during validation.

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
```

`enabled` controls whether WAF rules are evaluated.

Modes:

- `enforcing`: apply blocking, rewrite, mutation, and routing decisions.
- `monitor`: evaluate and log WAF decisions without enforcing blocking actions.

Failure policies:

- `closed`: reject the transaction when WAF execution fails.
- `open`: allow the transaction to continue when WAF execution fails.

Security-sensitive deployments should prefer `fail_policy = "closed"`.

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
```

These limits constrain OxiRule parsing, evaluation, helper scans, derived strings, body inspection, regex use, and mutations.

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
phase = "request"
priority = 10
path = "rules/global-request.oxirule.toml"
```

A rule entry must specify exactly one of `when` or `path`.
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

## 9. Upstreams

```toml
[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2"
connect_timeout_ms = 3000
request_timeout_ms = 30000
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
- `preserve_host`: forward the original `Host` when true; use the upstream origin host when false.
- `websocket`, `webrtc`, `webtransport`: protocol capability flags reserved for routing behavior.

Current implementation notes:

- `max_http_version = "h3"` is reserved but currently rejected during validation.
- `websocket`, `webrtc`, and `webtransport` flags are configuration surface for protocol support; full forwarding support is not complete in this initial implementation.

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
- Empty upstream or route lists.
- Duplicate upstream or route names.
- Upstream origins that are not `http://` or `https://`.
- Routes with empty host matches.
- Absolute include/runtime file paths or relative configuration file paths containing `.` or `..` components.
- Runtime file paths that do not resolve to existing regular files under their purpose-specific directory.
- External OxiRule paths that are absolute or escape the oxirule directory.
- Route `path_prefix` or `replace_prefix_with` values that do not start with `/` or contain unsafe path syntax.
- Routes that reference unknown upstreams.
- OCSP `static_file` mode without `response_file`.
- Reserved but unimplemented HTTP/3 modes.
- Invalid WAF rules, pattern sets, actions, phases, expressions, or budgets.

## 12. Complete Minimal Example

```toml
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true

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

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"

[compression]
enabled = true
gzip = true
deflate = true
zstd = true

[waf]
enabled = false
mode = "enforcing"
fail_policy = "closed"

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
