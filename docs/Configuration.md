# OxiBelt Configuration

Status: Draft 0.1  
Target project: OxiBelt Rust-based reverse proxy

This document describes the OxiBelt TOML configuration file format. The default example configuration lives at:

```sh
source/config/oxibelt.toml
```

OxiBelt loads configuration from the path passed with `--config`. Relative file paths inside the configuration are resolved relative to that main configuration file.

OxiRule WAF rule syntax is documented separately in [OxiRule.md](OxiRule.md). This document only describes how OxiRule entries are placed inside the OxiBelt TOML configuration.

## 1. Top-Level Shape

A typical configuration contains these sections:

```toml
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
cert_chain = "/etc/oxibelt/tls/fullchain.pem"
private_key = "/etc/oxibelt/tls/privkey.pem"

[tls.ocsp]
mode = "disabled"
```

`cert_chain` and `private_key` are required. Relative paths are resolved relative to the main configuration file.

OCSP modes:

- `disabled`: do not staple an OCSP response.
- `static_file`: load a stapled OCSP response from `response_file`.
- `live_fetch`: reserved but not implemented yet.

Example static OCSP configuration:

```toml
[tls.ocsp]
mode = "static_file"
response_file = "tls/ocsp.der"
```

`response_file` is required when `mode = "static_file"`.

## 6. Proxy

```toml
[proxy]
trusted_ca_certs = []

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"
```

`trusted_ca_certs` is a list of additional CA certificate files used for upstream TLS verification. Relative paths are resolved relative to the main configuration file.

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

An external `.oxirule.toml` file contains only the rule body:

```toml
when = "Request.Headers.anyValueContains('sqlmap')"

[[actions]]
type = "reject"
status = 403
body = "Blocked by WAF"
```

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
config_list_file = "tls/private-api.echconfiglist"
```

Modes:

- `disabled`: do not send ECH. This is the default.
- `grease`: send GREASE ECH for anti-ossification testing. The upstream does not need to support ECH.
- `config_list`: send real ECH using a TLS-encoded `ECHConfigList` file.

Validation rules:

- `tls.ech.config_list_file` is required when `tls.ech.mode = "config_list"`.
- `tls.ech.config_list_file` is invalid for `disabled` and `grease`.
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

- No enabled downstream HTTP versions.
- Privileged listener ports when `runtime.unprivileged_mode = true`.
- Non-Linux runtime when `runtime.linux_only = true`.
- Empty upstream or route lists.
- Duplicate upstream or route names.
- Upstream origins that are not `http://` or `https://`.
- Routes with empty host matches.
- Route `path_prefix` or `replace_prefix_with` values that do not start with `/`.
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
cert_chain = "/etc/oxibelt/tls/fullchain.pem"
private_key = "/etc/oxibelt/tls/privkey.pem"

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
