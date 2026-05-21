# OxiRule Examples

Status: Draft
Target project: OxiBelt Rust-based reverse proxy

This cookbook gives practical OxiRule examples grouped by intent. The formal rule reference is [../OxiRule.md](../OxiRule.md), and configuration placement is documented in [../Configuration.md](../Configuration.md).

Examples shown with `[[waf.rules]]` are global rules. The same rule shape may be used under `[[routes.waf.rules]]` when the policy should apply only after a route is matched.

## Baseline Request Controls

### Block Public Admin Paths

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

### Block Dangerous HTTP Methods

```toml
[[waf.rules]]
name = "block-dangerous-methods"
tags = ["method-policy"]
phase = "request"
priority = 100
when = """
Request.Http.Method == 'TRACE' ||
Request.Http.Method == 'TRACK' ||
Request.Http.Method == 'CONNECT'
"""

[[waf.rules.actions]]
type = "reject"
status = 405
body = "Method Not Allowed"
```

### Block Dotfile and Backup File Reads

```toml
[[waf.rules]]
name = "block-hidden-and-backup-files"
tags = ["path-policy"]
phase = "request"
priority = 110
when = """
Request.Http.Path.matches('(^|/)\\.[^/]+') ||
Request.Http.Path.matches('(?i)(\\.bak|\\.old|~)$')
"""

[[waf.rules.actions]]
type = "reject"
status = 404
body = "Not Found"
```

### Reject Suspicious Path Traversal Attempts

```toml
[[waf.rules]]
name = "block-path-traversal"
tags = ["path-policy", "attack-signature"]
phase = "request"
priority = 120
when = """
Request.Http.Uri.matches('(?i)(\\.\\.|%2e%2e|%252e%252e)') ||
Request.Http.Uri.matches('(?i)(%2f|%5c|%252f|%255c)')
"""

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Blocked"
```

## Header, Query, and Cookie Inspection

### Block Scanner User Agents

```toml
[[waf.rules]]
name = "block-scanner-user-agents"
tags = ["bot", "scanner"]
phase = "request"
priority = 150
when = """
Request.Headers.has('User-Agent') &&
Request.Headers.get('User-Agent').matches('(?i)(sqlmap|nikto|masscan|nmap)')
"""

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Blocked"
```

### Reject Duplicate Forwarded Headers

```toml
[[waf.rules]]
name = "reject-duplicate-forwarded"
tags = ["forwarded-headers"]
phase = "request"
priority = 160
when = """
Request.Headers.getAll('Forwarded').Count > 1 ||
Request.Headers.getAll('X-Forwarded-For').Count > 1
"""

[[waf.rules.actions]]
type = "reject"
status = 400
body = "Bad Request"
```

### Block Debug Headers Outside Internal Networks

```toml
[[waf.rules]]
name = "block-public-debug-headers"
tags = ["debug", "header-policy"]
phase = "request"
priority = 170
when = """
Request.Headers.anyNameMatches('(?i)^x-debug-') &&
!Request.Client.Ip.inCidr('10.0.0.0/8')
"""

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Debug headers are not allowed"
```

### Block SQL Injection Query Patterns

```toml
[[waf.rules]]
name = "block-sqli-query"
tags = ["query", "attack-signature"]
phase = "request"
priority = 180
when = "Request.QueryParams.anyValueMatches('(?i)(union\\s+select|information_schema|sleep\\s*\\()')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Blocked"
```

### Match Duplicate Header Values with a Pattern Set

```toml
[[waf.pattern_sets]]
name = "private-forwarded-values"
kind = "regex"
patterns = ["(?i)for=10\\.", "(?i)for=192\\.168\\."]

[[waf.rules]]
name = "reject-private-forwarded-chain"
tags = ["forwarded-headers"]
phase = "request"
priority = 185
when = "Request.Headers.getAll('Forwarded').matchesAny('private-forwarded-values')"

[[waf.rules.actions]]
type = "reject"
status = 400
body = "Bad Forwarded header"
```

### Block Session Cookies Without Downstream TLS

```toml
[[waf.rules]]
name = "block-session-cookie-without-tls"
tags = ["cookie", "transport-policy"]
phase = "request"
priority = 190
when = """
!Request.Tls.Enabled &&
Request.Cookies.has('session')
"""

[[waf.rules.actions]]
type = "reject"
status = 400
body = "Session cookies require downstream TLS"
```

### Match Encoded Input Through the Normalized View

```toml
[[waf.rules]]
name = "normalized-admin-and-sqli"
tags = ["normalization", "attack-signature"]
phase = "request"
priority = 195
when = """
Request.Normalized.Http.Path == '/admin/secret' ||
Request.Normalized.Http.Query.contains('union select') ||
Request.Normalized.Headers.anyValueContains('sqlmap')
"""

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Blocked"
```

## Request Body and Upload Guards

### Reject Oversized POST Requests

```toml
[[waf.rules]]
name = "reject-large-post-body"
tags = ["body-limit"]
phase = "request"
priority = 200
when = """
Request.Http.Method == 'POST' &&
Request.Http.Body.Size > 10485760
"""

[[waf.rules.actions]]
type = "reject"
status = 413
body = "Payload Too Large"
```

### Allow Only Image Signatures on Uploads

```toml
[[routes.waf.rules]]
name = "uploads-must-be-images"
tags = ["upload", "file-format"]
phase = "request"
priority = 210
when = """
Request.Http.Method == 'POST' &&
Request.Http.Path.startsWith('/upload') &&
Request.Body.Bytes != null &&
!Request.Body.Bytes.isFormat('png') &&
!Request.Body.Bytes.isFormat('jpeg') &&
!Request.Body.Bytes.isFormat('webp')
"""

[[routes.waf.rules.actions]]
type = "reject"
status = 415
body = "Unsupported Media Type"
```

### Reject Executable Uploads

```toml
[[routes.waf.rules]]
name = "reject-executable-upload"
tags = ["upload", "malware-guard"]
phase = "request"
priority = 220
when = """
Request.Http.Path.startsWith('/upload') &&
Request.Body.Bytes != null &&
(
  Request.Body.Bytes.isFormat('exe') ||
  Request.Body.Bytes.isFormat('pe') ||
  Request.Body.Bytes.isFormat('elf')
)
"""

[[routes.waf.rules.actions]]
type = "reject"
status = 415
body = "Executable uploads are not allowed"
```

### Tag Truncated Body Inspection

```toml
[[waf.rules]]
name = "tag-truncated-body-inspection"
tags = ["observability", "body-limit"]
phase = "request"
priority = 230
when = "Request.Body.IsTruncated"

[[waf.rules.actions]]
type = "set_tag"
key = "BodyInspectionTruncated"
value = "true"
```

### Reuse Conditions and Actions with Rule Groups

```toml
[[waf.rule_groups]]
name = "scanner-signals"
when = "Request.Headers.anyValueMatches('(?i)(sqlmap|nikto)')"
merge_condition_as = "and"

[[waf.rule_groups.actions]]
type = "set_tag"
key = "ScannerSignal"
value = "true"

[[waf.rule_groups.actions]]
priority = 10
type = "set_request_header"
name = "X-OxiBelt-Scanner-Signal"
value = "true"

[[waf.rules]]
name = "block-public-scanner-signals"
phase = "request"
priority = 235
groups = ["scanner-signals"]
when = "!Request.Client.Ip.inCidr('10.0.0.0/8')"
merge_condition_as = "and"

[[waf.rules.actions]]
priority = 20
type = "reject"
status = 403
body = "Blocked by WAF"
```

### Scan Request and Response Body Prefixes

```toml
[[waf.pattern_sets]]
name = "leak-markers"
kind = "contains"
patterns = ["BEGIN PRIVATE KEY", "secret-leak"]

[[waf.rules]]
name = "block-secret-request-body"
phase = "request"
priority = 240
when = "Request.Body.scan('leak-markers').Matched"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Request body blocked"

[[waf.rules]]
name = "block-secret-response-body"
phase = "response"
priority = 241
when = "Response.Body.scan('leak-markers').Matched"

[[waf.rules.actions]]
type = "reject_response"
status = 502
body = "Response body blocked"
```

## Header Mutation and Response Policy

### Add Baseline Security Response Headers

```toml
[[waf.rules]]
name = "security-response-headers"
tags = ["response-headers"]
phase = "response"
priority = 300
when = "true"

[[waf.rules.actions]]
type = "set_response_header"
name = "X-Content-Type-Options"
value = "nosniff"

[[waf.rules.actions]]
type = "set_response_header"
name = "Referrer-Policy"
value = "no-referrer"

[[waf.rules.actions]]
type = "set_response_header"
name = "Permissions-Policy"
value = "geolocation=(), microphone=(), camera=()"
```

### Remove Upstream Debug Headers

```toml
[[waf.rules]]
name = "strip-upstream-debug-headers"
tags = ["response-headers"]
phase = "response"
priority = 310
when = "true"

[[waf.rules.actions]]
type = "remove_response_header"
name = "X-Debug-Trace"

[[waf.rules.actions]]
type = "remove_response_header"
name = "X-Powered-By"
```

### Mark WAF-Checked Requests Before Forwarding

```toml
[[waf.rules]]
name = "mark-waf-checked-request"
tags = ["request-headers"]
phase = "request"
priority = 320
when = "true"

[[waf.rules.actions]]
type = "set_request_header"
name = "X-OxiBelt-WAF"
value = "checked"
```

## Tags and Multi-Phase Policy

### Pass Login Context to Response Rules

```toml
[[waf.rules]]
name = "tag-login-request"
tags = ["login", "tag"]
phase = "request"
priority = 400
when = "Request.Http.Path.startsWith('/login')"

[[waf.rules.actions]]
type = "set_tag"
key = "LoginRequest"
value = "true"

[[waf.rules]]
name = "no-store-login-errors"
tags = ["login", "response-headers"]
phase = "response"
priority = 410
when = "Request.Tags.get('LoginRequest') == 'true' && Response.Http.Status >= 500"

[[waf.rules.actions]]
type = "set_response_header"
name = "Cache-Control"
value = "no-store"
```

### Tag Sensitive API Requests and Strip Cache Headers

```toml
[[waf.rules]]
name = "tag-sensitive-api"
tags = ["api", "tag"]
phase = "request"
priority = 420
when = """
Request.Http.Host == 'api.example.com' &&
Request.Http.Path.startsWith('/v1/private')
"""

[[waf.rules.actions]]
type = "set_tag"
key = "SensitiveApi"
value = "true"

[[waf.rules]]
name = "private-api-no-cache"
tags = ["api", "response-headers"]
phase = "response"
priority = 430
when = "Request.Tags.get('SensitiveApi') == 'true'"

[[waf.rules.actions]]
type = "set_response_header"
name = "Cache-Control"
value = "no-store"

[[waf.rules.actions]]
type = "remove_response_header"
name = "ETag"
```

## Routing and Upstream Selection

### Route Beta Requests to a Canary Upstream

```toml
[[waf.rules]]
name = "route-beta-header-to-canary"
tags = ["routing", "canary"]
phase = "request"
priority = 500
when = "Request.Headers.get('X-Beta') == '1'"

[[waf.rules.actions]]
type = "route_to_upstream"
upstream = "app-canary"
```

### Route API Traffic to an Upstream Pool

```toml
[[waf.rules]]
name = "route-api-to-pool"
tags = ["routing", "pool"]
phase = "request"
priority = 510
when = """
Request.Http.Host == 'api.example.com' &&
Request.Http.Path.startsWith('/v1')
"""

[[waf.rules.actions]]
type = "route_to_pool"
pool = "api-v1-pool"
```

### Prefer Least-Connection Balancing for Low-Priority Work

```toml
[[waf.rules]]
name = "low-priority-weighted-least-conn"
tags = ["routing", "load-balancing"]
phase = "request"
priority = 520
when = "Request.Headers.get('X-Priority') == 'low'"

[[waf.rules.actions]]
type = "set_load_balancing_policy"
policy = "weighted_least_conn"
```

## Person Proof Policy

### Weight-Based Explicit Challenge

```toml
[[waf.rules]]
name = "weigh-headless-automation"
tags = ["person-proof", "weight"]
phase = "request"
priority = 580
when = "Request.Client.UserAgent.contains('Headless')"

[[waf.rules.actions]]
type = "weigh_person_proof"
weight = 50

[[waf.rules]]
name = "allow-health-person-proof"
tags = ["person-proof", "allow"]
phase = "request"
priority = 590
when = "Request.Http.Path == '/healthz'"

[[waf.rules.actions]]
type = "allow_person_proof"

[[waf.rules]]
name = "challenge-high-person-proof-weight"
tags = ["person-proof", "challenge"]
phase = "request"
priority = 600
when = """
Request.Client.PersonProof.Weight >= 50 &&
Request.Client.PersonProof.State != 'valid'
"""

[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "built_in"
difficulty = 18
token_validity_seconds = 300
clearance.cookie.key = "__oxibelt_person_proof"
token_bindings = ["user_agent", "route", "direct_peer_ip_network_prefix"]
direct_peer_ipv4_prefix_bits = 24
direct_peer_ipv6_prefix_bits = 56
single_use = true
success_tag = "PersonProof"
status = 403
```

### Challenge Unknown Browser Traffic

```toml
[[waf.rules]]
name = "require-person-proof-for-unknown-browser"
id = "person-proof-entry"
tags = ["person-proof", "challenge"]
phase = "request"
priority = 600
when = """
Request.Client.PersonProof.State != 'valid' &&
Request.Client.Bot.Disposition != 'normal'
"""

[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "built_in"
difficulty = 18
token_validity_seconds = 300
clearance.cookie.key = "__oxibelt_person_proof"
token_bindings = ["user_agent", "route", "direct_peer_ip_network_prefix"]
direct_peer_ipv4_prefix_bits = 24
direct_peer_ipv6_prefix_bits = 56
single_use = true
success_tag = "PersonProof"
status = 403
```

### Store Clearance in localStorage and Send a Header

```toml
[[waf.rules]]
name = "person-proof-local-storage"
tags = ["person-proof", "challenge"]
phase = "request"
priority = 605
when = """
Request.Client.PersonProof.State != 'valid' &&
Request.Http.Path.startsWith('/app')
"""

[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "built_in"
difficulty = 18
token_validity_seconds = 300
clearance.issue_to = "local_storage"
clearance.local_storage.key = "oxibelt.personProof"
clearance.local_storage.request_header = "X-OxiBelt-Person-Proof"
success_tag = "PersonProof"
```

### Chain Person Proof Success into Request Headers

```toml
[[waf.rules]]
name = "mark-person-proof-success"
tags = ["person-proof", "request-headers"]
phase = "request"
priority = 610
when = "Request.Tags.get('PersonProof') == 'valid'"

[[waf.rules.actions]]
type = "set_request_header"
name = "X-OxiBelt-Person-Proof"
value = "valid"
```

### Require Stronger Binding for Admin Paths

```toml
[[waf.rules]]
name = "admin-person-proof-exact-peer"
tags = ["person-proof", "admin"]
phase = "request"
priority = 620
when = """
Request.Http.Path.startsWith('/admin') &&
Request.Client.PersonProof.State != 'valid'
"""

[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "built_in"
difficulty = 22
token_validity_seconds = 180
clearance.cookie.key = "__oxibelt_admin_proof"
token_bindings = ["user_agent", "route", "direct_peer_ip_network_prefix", "tls_fingerprint"]
direct_peer_ipv4_prefix_bits = 32
direct_peer_ipv6_prefix_bits = 128
single_use = true
success_tag = "AdminPersonProof"
status = 403
```

## Response Handling and Upstream Failures

### Replace Upstream 5xx Responses

```toml
[[waf.rules]]
name = "replace-upstream-5xx"
tags = ["upstream", "response-policy"]
phase = "response"
priority = 700
when = "Response.Http.Status >= 500"

[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "Temporary upstream error"
```

### Replace Synthetic Upstream Failures

```toml
[[waf.rules]]
name = "replace-upstream-forwarding-failure"
tags = ["upstream", "response-policy"]
phase = "response"
priority = 710
when = "Response.Upstream.Error != null"

[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "Upstream unavailable"
```

### Reject Unexpected Redirects from Private APIs

```toml
[[waf.rules]]
name = "reject-private-api-redirect"
tags = ["api", "response-policy"]
phase = "response"
priority = 720
when = """
Request.Http.Host == 'api.example.com' &&
Request.Http.Path.startsWith('/v1/private') &&
Response.Http.Status >= 300 &&
Response.Http.Status < 400
"""

[[waf.rules.actions]]
type = "reject_response"
status = 502
body = "Unexpected upstream redirect"
```

## Structured Access Logs

### Emit a Minimal Access Log

```toml
[[waf.rules]]
name = "access-log-basic"
tags = ["access-log"]
phase = "response"
priority = 900
when = "true"

[[waf.rules.actions]]
type = "emit_access_log"

[[waf.rules.actions.fields]]
name = "method"
value = "Request.Http.Method"

[[waf.rules.actions.fields]]
name = "path"
value = "Request.Http.Path"

[[waf.rules.actions.fields]]
name = "status"
value = "Response.Http.Status"

[[waf.rules.actions.fields]]
name = "route"
value = "Context.RouteName"
```

### Emit Upstream Failure Access Log Fields

```toml
[[waf.rules]]
name = "access-log-upstream-failures"
tags = ["access-log", "security"]
phase = "response"
priority = 910
when = "Response.Upstream.Error != null"

[[waf.rules.actions]]
type = "emit_access_log"

[[waf.rules.actions.fields]]
name = "client_ip"
value = "Request.Client.Ip"

[[waf.rules.actions.fields]]
name = "user_agent"
value = "Request.Headers.getAll('User-Agent')"

[[waf.rules.actions.fields]]
name = "tls_fingerprint"
value = "Request.Tls.Fingerprint"

[[waf.rules.actions.fields]]
name = "upstream_error"
value = "Response.Upstream.Error.Code"
```

## Protocol-Specific Rules

### Block Admin WebSocket Upgrades

```toml
[[waf.rules]]
name = "block-admin-websocket"
tags = ["websocket", "access-control"]
phase = "request"
priority = 1000
when = """
Request.Protocol == 'websocket' &&
Request.Http.Path.startsWith('/admin-ws')
"""

[[waf.rules.actions]]
type = "reject"
status = 403
body = "WebSocket endpoint blocked"
```

### Require HTTP/3 WebTransport to Use an Expected Host

```toml
[[waf.rules]]
name = "webtransport-host-policy"
tags = ["webtransport", "http3"]
phase = "request"
priority = 1010
when = """
Request.Protocol == 'webtransport' &&
Request.Transport.Network == 'udp' &&
Request.Http.Host != 'transport.example.com'
"""

[[waf.rules.actions]]
type = "reject"
status = 421
body = "Misdirected Request"
```

### Match QUIC TLS Fingerprint Metadata

```toml
[[waf.rules]]
name = "tag-http3-fingerprint-source"
tags = ["http3", "tls"]
phase = "request"
priority = 1020
when = "Request.Tls.FingerprintScheme == 'quinn-rustls-quic-v2'"

[[waf.rules.actions]]
type = "set_tag"
key = "Http3TlsFingerprint"
value = "quinn-rustls-quic-v2"
```

## External Rule File Example

Attach the external rule from the main configuration:

```toml
[[waf.rules]]
name = "global-scanner-policy"
phase = "request"
priority = 100
path = "rules/global-scanner-policy.oxirule.toml"
```

The external file contains only the rule body. File-local groups may be defined after the root-level rule fields:

```toml
# /etc/oxibelt/oxirule/rules/global-scanner-policy.oxirule.toml
groups = ["scanner-signals"]

[[actions]]
priority = 10
type = "reject"
status = 403
body = "Blocked by WAF"

[[rule_groups]]
name = "scanner-signals"
when = """
Request.Headers.anyValueMatches('(?i)(sqlmap|nikto)') ||
Request.QueryParams.anyValueMatches('(?i)(union\\s+select|sleep\\s*\\()')
"""
```

## CRS Compatibility Example

Operators can place OWASP CRS v4.x setup and rule files under the configured OxiRule directory and enable the CRS-compatible layer separately from OxiRule rules:

```toml
[waf.crs]
enabled = true
mode = "monitor"
setup_file = "crs/crs-setup.conf"
rule_files = ["crs/rules/*.conf"]
paranoia_level = 1
inbound_anomaly_score_threshold = 5
outbound_anomaly_score_threshold = 4
unsupported_directive_policy = "fail_closed"

[[waf.crs.rule_overrides]]
name = "shadow-sqli-tuning"
tags = ["attack-sqli"]
mode = "monitor"
reason = "observe SQLi false positives before enforcing"

[[waf.crs.allowlists]]
name = "editor-html-posts"
rule_ids = ["941320"]
methods = ["POST"]
routes = ["app-root"]
path_prefixes = ["/editor/"]
reason = "trusted editor route intentionally accepts HTML fragments"
```

Switch `mode` to `enforcing` after reviewing `/admin/v1/waf/rule-hits` for rule hits, `tuned_hits`, observed anomaly scores, and blocking scores. Scope allowlists with `methods`, `routes`, or `path_prefixes`; `header_equals` is rejected because inbound request headers are client-controlled before proxy forwarding. Use `/admin/v1/waf/crs/compatibility` to inspect the CRS compatibility matrix exposed by the running binary. OxiBelt targets the CRS current release and `v4.25.x` LTS line as of 2026-05-10; see the official CRS [LTS announcement](https://coreruleset.org/20260321/announcing-crs-v4-25-lts/), [false-positive tuning guide](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/), and [installation guide](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/).

Response body CRS inspection uses bounded prefix scanning and should be enabled only for routes that need response leak detection. WebTransport frame/datagram payload inspection is not supported by the CRS layer.
