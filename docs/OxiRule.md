# OxiBelt OxiRule WAF Specification

Status: Draft 0.4  
Target project: OxiBelt Rust-based reverse proxy

## Current Rust Implementation Status

The current Rust implementation includes the initial OxiRule execution path for HTTP request and response traffic:

- Global and route-level `[[waf.rules]]` configuration.
- External `.oxirule.toml` rule files loaded relative to the main config file.
- Request-phase `reject`, `set_request_header`, `remove_request_header`, `set_tag`, and `route_to_upstream`.
- Response-phase `continue_response`, `replace_response`, `reject_response`, `set_response_header`, and `remove_response_header`.
- CEL-like boolean expressions with object property access, string helpers, header/query/cookie/tag helpers, regex matching, CIDR checks, and request/response phase validation.
- Synthetic response context for upstream forwarding failures, exposed to response-phase rules as `Response.Upstream.Error`.
- Runtime, expression-step, and mutation budgets.

The following parts of this draft remain reserved for a later implementation:

- Streaming-safe request/response body content inspection helpers such as `Body.contains`, `Body.matches`, and `Body.scan`.
- `route_to_pool` and `set_load_balancing_policy`, pending an upstream-pool/load-balancing configuration model.
- HTTP/3, WebTransport, UDP-flow metadata, and frame/datagram-level inspection.

## 1. Purpose

OxiRule is a CEL-like, declarative WAF rule model for OxiBelt, a Rust-based reverse proxy. OxiRule is used to inspect HTTP, WebSocket, WebRTC, and WebTransport traffic and decide whether a transaction should be forwarded, load-balanced, rejected, rewritten, tagged, or inspected further.

OxiRule uses a strict separation between:

1. `when`: a CEL-like, side-effect-free boolean expression.
2. `actions`: declarative side effects executed by OxiBelt only when `when` evaluates to `true`.

This separation keeps rule conditions readable and safe while preserving WAF functionality such as request rejection, upstream routing, response replacement, header mutation, tagging, and bounded body inspection.

Rules must be usable in two forms:

1. Inline inside a TOML configuration file.
2. Linked from a TOML configuration file as an external rule file.

The two primary data objects available to rule conditions are:

- `Request`
- `Response`

`Response` is available only in response-phase rules or transaction-response rules after OxiBelt has received an upstream response or created a synthetic upstream-error response.

OxiRule object properties use `PascalCase`, for example `Request.Http.Path`, `Request.Client.Ip`, and `Response.Http.Status`. CEL-like functions use `lowerCamelCase`, for example `startsWith`, `contains`, `matches`, and `inCidr`.

## 2. Design Goals

OxiRule is designed to be easy to write, deterministic, and safe to execute inside a high-throughput proxy.

Goals:

- Use CEL-like expressions for policy conditions.
- Avoid embedding a full JavaScript, TypeScript, or general-purpose scripting runtime.
- Keep rule conditions side-effect-free.
- Keep side effects declarative and validated by OxiBelt before traffic is accepted.
- Support request inspection before upstream forwarding.
- Support response inspection after upstream forwarding but before returning data to the external client/source.
- Support protocol metadata for TCP and UDP flows.
- Allow rules to influence upstream forwarding, route selection, and load balancing.
- Prevent unbounded computation, unbounded memory growth, external I/O, and hidden side effects.

Non-goals for the initial version:

- General-purpose scripting.
- User-defined functions.
- Dynamic imports.
- File system access.
- Network access from rules.
- Process execution.
- Environment variable access.
- Unbounded loops, comprehensions, or recursion.
- Arbitrary mutation inside expressions.

## 3. Rule Model

### 3.1 Basic rule shape

A rule has metadata, a CEL-like `when` expression, and one or more declarative actions.

```toml
[[waf.rules]]
name = "block-admin-from-public"
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

The `when` expression must evaluate to `Bool`. If it evaluates to `false`, the rule is skipped and no action from that rule is executed.

### 3.2 Why CEL-like instead of TypeScript-like

OxiRule intentionally avoids TypeScript-like imperative constructs such as `if`, `let`, `const`, `await`, `return`, assignment, function declarations, imports, and exports.

Instead of this imperative style:

```typescript
if (Request.Http.Path.StartsWith('/admin')) {
  Request.Reject(403, 'Forbidden')
  return
}
```

OxiRule uses this declarative style:

```toml
[[waf.rules]]
name = "block-admin"
phase = "request"
priority = 100
when = "Request.Http.Path.startsWith('/admin')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Forbidden"
```

This makes policy evaluation easier to parse, validate, cost-account, test, cache, and optimize in Rust.

### 3.3 Rule result model

Each matched rule may produce one of these effects:

- A terminal request decision, such as `reject`.
- A terminal response decision, such as `continue`, `replace`, or `reject`.
- A non-terminal mutation, such as setting a header or adding a tag.
- A non-terminal routing hint, such as selecting an upstream pool.

If no terminal request action is produced after all applicable request rules run, the request continues to the configured route, load-balancing, and upstream forwarding pipeline.

If no terminal response action is produced after all applicable response rules run, the response continues to the external client/source.

## 4. TOML Configuration Integration

### 4.1 Global WAF configuration

```toml
[waf]
enabled = true
mode = "enforcing"      # enforcing | monitor
fail_policy = "closed"  # closed | open

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

### 4.2 Inline request rule

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

### 4.3 Inline response rule

Response rules run after upstream forwarding completes and before the response is sent to the external client/source.

```toml
[[waf.rules]]
name = "replace-upstream-5xx"
phase = "response"
priority = 100
when = "Response.Http.Status >= 500"

[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "Temporary upstream error"
```

### 4.4 Header mutation rule

```toml
[[waf.rules]]
name = "security-response-headers"
phase = "response"
priority = 200
when = "true"

[[waf.rules.actions]]
type = "set_response_header"
name = "X-Content-Type-Options"
value = "nosniff"

[[waf.rules.actions]]
type = "set_response_header"
name = "Referrer-Policy"
value = "no-referrer"
```

Because no terminal response action is specified, OxiBelt continues the response after all applicable response rules finish successfully.

### 4.5 Route-level rule

```toml
[[routes]]
name = "api"
match.host = "api.example.com"
match.path_prefix = "/v1"
upstream_pool = "api-pool"

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

### 4.6 External rule file

```toml
[[waf.rules]]
name = "global-request-policy"
phase = "request"
priority = 10
path = "rules/global-request.oxirule.toml"

[[waf.rules]]
name = "global-response-policy"
phase = "response"
priority = 20
path = "rules/global-response.oxirule.toml"
```

A rule entry must specify exactly one of:

- `when`
- `path`

Specifying both is a configuration validation error. Specifying neither is also a configuration validation error.

An external `.oxirule.toml` file should contain a single rule body without route attachment metadata:

```toml
when = "Request.Headers.anyValueContains('sqlmap')"

[[actions]]
type = "reject"
status = 403
body = "Blocked by WAF"
```

### 4.7 Pattern sets

Pattern sets are configured in TOML and referenced from CEL-like helper functions.

```toml
[[waf.pattern_sets]]
name = "sql-injection-keywords"
kind = "contains"
patterns = ["UNION SELECT", "DROP TABLE", "information_schema"]

[[waf.pattern_sets]]
name = "xss-regexes"
kind = "regex"
patterns = ["(?i)<script", "(?i)javascript:"]

[[waf.pattern_sets]]
name = "private-forwarded-values"
kind = "regex"
patterns = ["(?i)for=10\\.", "(?i)for=192\\.168\\."]
```

Pattern set validation requirements:

- `contains` pattern sets use literal substring matching.
- `regex` pattern sets must use the configured safe regex engine.
- Pattern count is capped by `max_helper_pattern_count`.
- Each pattern length is capped by `max_string_bytes`.
- Pattern sets are loaded and validated before traffic is accepted.

## 5. Rule Execution Phases

### 5.1 Request phase

A request rule runs after OxiBelt receives traffic from a client/source and before the request is forwarded upstream or passed to the load-balancing pipeline.

A request rule may:

- Reject the request.
- Modify request headers.
- Add routing hints.
- Select an upstream pool.
- Select a named upstream target.
- Attach tags for later response rules.
- Inspect a bounded amount of request body data.
- Apply policy based on TCP or UDP metadata.

If request rules do not reject the request, OxiBelt continues to route selection, load balancing, and upstream forwarding.

### 5.2 Response phase

A response rule runs after OxiBelt receives a response from an upstream target and before OxiBelt returns the response to the external client/source.

A response rule may:

- Allow the response to continue.
- Reject or replace the response.
- Modify response headers.
- Add security headers.
- Inspect a bounded amount of response body data.
- Apply policy based on upstream metadata.
- Apply policy based on tags stored during the request phase.

The response is not sent to the client/source until all applicable response rules complete successfully or a terminal response action is produced.

### 5.3 Transaction behavior without imperative `Continue()`

In the previous TypeScript-like model, a transaction rule used `Request.Continue()` as a phase barrier. In the CEL-like model, this barrier is represented by the OxiBelt execution pipeline instead of user-written code:

1. Evaluate request-phase rules.
2. If no request rule rejects the request, forward to route selection, load balancing, and upstream forwarding.
3. Create a `Response` object from the upstream response or from a synthetic upstream-error response.
4. Evaluate response-phase rules.
5. Return, replace, or reject the response.

This preserves response inspection after upstream forwarding without exposing `await`, `return`, or mutation calls inside the rule language.

### 5.4 Response availability

`Response` is unavailable in request-phase rule conditions. Accessing `Response.Http`, `Response.Headers`, `Response.Body`, or `Response.Upstream` from a request-phase rule is a validation error.

`Response` is available in response-phase rule conditions. The response object is created only after upstream forwarding completes or after OxiBelt creates a synthetic upstream-error response.

### 5.5 Forwarding failure handling

If upstream forwarding fails, OxiBelt should expose a synthetic response to response-phase rules instead of throwing a rule-level exception.

Example:

```toml
[[waf.rules]]
name = "replace-upstream-failure"
phase = "response"
priority = 100
when = "Response.Upstream.Error != null"

[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "Upstream unavailable"
```

The synthetic response should include:

- `Response.Http.Status`, usually `502`, `503`, or `504`.
- `Response.Upstream.Error` with a bounded error code.
- Empty or bounded body data.
- Normal response-phase mutability through declarative actions.

## 6. CEL-like Expression Language

### 6.1 Expression examples

```cel
Request.Http.Path.startsWith('/login')
```

```cel
Request.Headers.has('User-Agent') &&
Request.Headers.get('User-Agent').contains('sqlmap')
```

```cel
Request.Protocol == 'webtransport' &&
Request.Transport.Network == 'udp' &&
Request.Transport.Udp != null &&
Request.Transport.Udp.DatagramSize > 1200
```

```cel
Response.Http.Status >= 500 || Response.Upstream.Error != null
```

### 6.2 Literals

Supported literals:

```cel
true
false
null
123
'bounded string'
```

String literals use single quotes inside CEL-like expressions. TOML strings may use normal TOML syntax around the expression.

### 6.3 Operators

Supported operators:

```cel
== !=
< <= > >=
&& || !
+
```

`+` may be used only for bounded string concatenation if enabled by configuration. Arithmetic operators other than comparisons should be avoided in v1 unless OxiBelt can charge them precisely to the expression budget.

### 6.4 Forbidden constructs

The expression language must not include:

- `if`, `else`, `for`, `while`, `do`, `switch`.
- `let`, `const`, assignment, or mutation.
- `function`, closures, lambdas, callbacks, or arrow functions.
- `import`, `export`, or module declarations.
- `new`, classes, prototypes, or dynamic object construction.
- `try`, `catch`, `throw`.
- `await`, promises, or user-visible async control flow.
- List comprehensions in v1.
- Map construction in v1.
- External I/O, clock, random, process, file, environment, or network access.

### 6.5 Null behavior

OxiRule should use safe null behavior:

- Accessing a property on `null` is a validation error when it can be proven statically.
- Runtime nullable properties must be checked before nested access.
- Functions on `null` return a runtime error unless the function explicitly supports nullable receivers.

Recommended style:

```cel
Request.Transport.Tcp != null &&
Request.Transport.Tcp.Sni == 'blocked.example.com'
```

### 6.6 String functions

Available on `String` values:

```cel
Value.contains('needle')
Value.startsWith('/prefix')
Value.endsWith('.php')
Value.matches('(?i)sqlmap')
Value.lowerAscii()
Value.upperAscii()
Value.size()
```

All returned strings are bounded by `max_string_bytes` and `max_helper_result_bytes`.

### 6.7 IP and CIDR functions

Available on `IpAddress` and string-compatible IP values:

```cel
Request.Client.Ip.inCidr('10.0.0.0/8')
Request.Transport.RemoteIp.inCidr('192.168.0.0/16')
```

Invalid CIDR literals must be rejected at configuration validation time when they are static strings.

## 7. Declarative Actions

Actions are configured as TOML tables under a rule. Actions execute in order only when the rule's `when` expression evaluates to `true`.

### 7.1 Terminal request actions

#### `reject`

```toml
[[waf.rules.actions]]
type = "reject"
status = 403
body = "Forbidden"
```

`reject` stops request processing and creates a local response.

### 7.2 Terminal response actions

#### `continue_response`

```toml
[[waf.rules.actions]]
type = "continue_response"
```

`continue_response` explicitly allows the current response to be sent after all earlier mutations from the same rule are applied. This action is optional because OxiBelt may continue by default after all response rules complete without terminal replacement or rejection.

#### `replace_response`

```toml
[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "Temporary upstream error"
```

`replace_response` replaces the upstream response with a local response.

#### `reject_response`

```toml
[[waf.rules.actions]]
type = "reject_response"
status = 403
body = "Blocked response"
```

`reject_response` stops response forwarding and emits a local response.

### 7.3 Routing actions

#### `route_to_pool`

```toml
[[waf.rules.actions]]
type = "route_to_pool"
pool = "api-v1-pool"
```

#### `route_to_upstream`

```toml
[[waf.rules.actions]]
type = "route_to_upstream"
upstream = "api-primary-1"
```

#### `set_load_balancing_policy`

```toml
[[waf.rules.actions]]
type = "set_load_balancing_policy"
policy = "least_connections"
```

Routing actions are valid only in request-phase rules before upstream forwarding.

### 7.4 Header mutation actions

#### `set_request_header`

```toml
[[waf.rules.actions]]
type = "set_request_header"
name = "X-OxiBelt-Checked"
value = "true"
```

#### `remove_request_header`

```toml
[[waf.rules.actions]]
type = "remove_request_header"
name = "X-Debug-Mode"
```

#### `set_response_header`

```toml
[[waf.rules.actions]]
type = "set_response_header"
name = "X-Content-Type-Options"
value = "nosniff"
```

#### `remove_response_header`

```toml
[[waf.rules.actions]]
type = "remove_response_header"
name = "Server"
```

Header mutation actions count against `max_mutations`.

### 7.5 Tag actions

Tags allow request-side logic to pass bounded metadata to response-side logic.

```toml
[[waf.rules.actions]]
type = "set_tag"
key = "SuspiciousLoginPath"
value = "true"
```

A response rule may read the tag:

```toml
[[waf.rules]]
name = "login-response-cache-guard"
phase = "response"
priority = 200
when = "Request.Tags.get('SuspiciousLoginPath') == 'true' && Response.Http.Status >= 500"

[[waf.rules.actions]]
type = "set_response_header"
name = "Cache-Control"
value = "no-store"
```

Tag count and tag value size are bounded by OxiBelt limits.

### 7.6 Body replacement actions

Body replacement is allowed only through explicit response actions and must obey body size limits.

```toml
[[waf.rules.actions]]
type = "replace_response"
status = 403
body = "Blocked by WAF"
```

Streaming response body modification should be a future extension unless OxiBelt can guarantee bounded memory and latency.

## 8. Object Model

All object properties use `PascalCase`.

### 8.1 Context object

```text
Context.Phase: 'request' | 'response'
Context.RuleName: String
Context.RouteName: String | Null
Context.TransactionId: String
Context.Mode: 'enforcing' | 'monitor'
```

### 8.2 Request object

```text
Request.Id: String
Request.Protocol: 'http' | 'websocket' | 'webrtc' | 'webtransport'
Request.ReceivedAtUnixMs: Int
Request.Client: ClientMetadata
Request.Transport: TransportMetadata
Request.Http: HttpRequestMetadata
Request.Headers: HeaderMap
Request.QueryParams: QueryParamMap
Request.Cookies: CookieMap
Request.Body: BodyView
Request.Tls: TlsMetadata | Null
Request.Tags: TagMap
```

### 8.3 Response object

```text
Response.Id: String
Response.Protocol: 'http' | 'websocket' | 'webrtc' | 'webtransport'
Response.ReceivedAtUnixMs: Int
Response.Upstream: UpstreamMetadata
Response.Transport: TransportMetadata
Response.Http: HttpResponseMetadata
Response.Headers: HeaderMap
Response.Cookies: CookieMap
Response.Body: BodyView
Response.Tls: TlsMetadata | Null
Response.Tags: TagMap
```

`Response` is available only in response-phase rules.

### 8.4 Client metadata

```text
ClientMetadata.Ip: IpAddress
ClientMetadata.Port: Int
ClientMetadata.SourceAddress: String
ClientMetadata.UserAgent: String | Null
ClientMetadata.GeoCountry: String | Null
ClientMetadata.Asn: Int | Null
```

### 8.5 Transport metadata

```text
TransportMetadata.Network: 'tcp' | 'udp'
TransportMetadata.LocalIp: IpAddress
TransportMetadata.LocalPort: Int
TransportMetadata.RemoteIp: IpAddress
TransportMetadata.RemotePort: Int
TransportMetadata.ConnectionId: String
TransportMetadata.BytesReceived: Int
TransportMetadata.BytesSent: Int
TransportMetadata.IsEncrypted: Bool
TransportMetadata.Tcp: TcpMetadata | Null
TransportMetadata.Udp: UdpMetadata | Null
```

### 8.6 TCP metadata

```text
TcpMetadata.State: 'accepted' | 'connected' | 'closing' | 'closed'
TcpMetadata.TlsDetected: Bool
TcpMetadata.Alpn: String | Null
TcpMetadata.Sni: String | Null
TcpMetadata.Mss: Int | Null
TcpMetadata.RttMs: Int | Null
```

### 8.7 UDP metadata

```text
UdpMetadata.DatagramSize: Int
UdpMetadata.FlowId: String
UdpMetadata.QuicDetected: Bool
UdpMetadata.ConnectionId: String | Null
```

### 8.8 HTTP request metadata

```text
HttpRequestMetadata.Version: '1.0' | '1.1' | '2' | '3'
HttpRequestMetadata.Method: String
HttpRequestMetadata.Scheme: 'http' | 'https'
HttpRequestMetadata.Host: String
HttpRequestMetadata.Path: String
HttpRequestMetadata.Query: String
HttpRequestMetadata.Uri: String
HttpRequestMetadata.Body: BodyMetadata
```

### 8.9 HTTP response metadata

```text
HttpResponseMetadata.Version: '1.0' | '1.1' | '2' | '3'
HttpResponseMetadata.Status: Int
HttpResponseMetadata.Reason: String | Null
HttpResponseMetadata.Body: BodyMetadata
```

### 8.10 Upstream metadata

```text
UpstreamMetadata.Name: String
UpstreamMetadata.Pool: String
UpstreamMetadata.Ip: IpAddress
UpstreamMetadata.Port: Int
UpstreamMetadata.Scheme: String
UpstreamMetadata.ConnectTimeMs: Int | Null
UpstreamMetadata.FirstByteTimeMs: Int | Null
UpstreamMetadata.Error: UpstreamError | Null
```

### 8.11 Upstream error metadata

```text
UpstreamError.Code: 'dns_error' | 'connect_timeout' | 'connect_error' | 'tls_error' | 'read_timeout' | 'protocol_error'
UpstreamError.Message: String
```

### 8.12 TLS metadata

```text
TlsMetadata.Enabled: Bool
TlsMetadata.Version: String | Null
TlsMetadata.CipherSuite: String | Null
TlsMetadata.Sni: String | Null
TlsMetadata.Alpn: String | Null
TlsMetadata.ClientCertificatePresent: Bool
```

## 9. Bounded Helper API

### 9.1 Purpose

OxiRule forbids loops, user-defined functions, callbacks, and comprehensions in v1. Repeated data such as headers, query parameters, cookies, tags, and body content must be inspected through bounded helper functions implemented by OxiBelt.

A bounded helper is allowed only if OxiBelt can enforce all of the following limits:

- Maximum inspected items.
- Maximum inspected bytes.
- Maximum configured patterns.
- Maximum regex runtime.
- Maximum returned data size.
- Maximum expression steps charged to the rule.

### 9.2 HeaderMap helpers

```text
Request.Headers.count(): Int
Request.Headers.has(Name: String): Bool
Request.Headers.get(Name: String): String | Null
Request.Headers.getAll(Name: String): BoundedStringList
Request.Headers.anyNameMatches(Pattern: String): Bool
Request.Headers.anyValueContains(Value: String): Bool
Request.Headers.anyValueMatches(Pattern: String): Bool
Request.Headers.anyEntryMatches(NamePattern: String, ValuePattern: String): Bool
Request.Headers.allEntriesMatch(NamePattern: String, ValuePattern: String): Bool
```

Examples:

```cel
Request.Headers.anyEntryMatches('^X-Debug-', '.+')
```

```cel
Request.Headers.anyValueContains('sqlmap')
```

Header names are case-insensitive. Values returned to rules must respect `max_header_value_bytes` and `max_helper_result_bytes`.

### 9.3 QueryParamMap helpers

```text
Request.QueryParams.count(): Int
Request.QueryParams.has(Name: String): Bool
Request.QueryParams.get(Name: String): String | Null
Request.QueryParams.getAll(Name: String): BoundedStringList
Request.QueryParams.anyNameMatches(Pattern: String): Bool
Request.QueryParams.anyValueContains(Value: String): Bool
Request.QueryParams.anyValueMatches(Pattern: String): Bool
Request.QueryParams.anyEntryMatches(NamePattern: String, ValuePattern: String): Bool
```

Example:

```cel
Request.QueryParams.anyValueMatches('(?i)(union select|sleep\\()')
```

### 9.4 CookieMap helpers

```text
Request.Cookies.count(): Int
Request.Cookies.has(Name: String): Bool
Request.Cookies.get(Name: String): String | Null
Request.Cookies.anyNameMatches(Pattern: String): Bool
Request.Cookies.anyValueContains(Value: String): Bool
Request.Cookies.anyValueMatches(Pattern: String): Bool
Request.Cookies.anyEntryMatches(NamePattern: String, ValuePattern: String): Bool
```

Example:

```cel
Request.Cookies.anyValueMatches('(?i)(<script|javascript:)')
```

### 9.5 BodyView helpers

```text
Request.Body.Size: Int
Request.Body.IsTruncated: Bool
Request.Body.Text: String | Null
Request.Body.Bytes: Bytes | Null
Request.Body.contains(Value: String): Bool
Request.Body.matches(Pattern: String): Bool
Request.Body.containsAny(PatternSetName: String): Bool
Request.Body.matchesAny(PatternSetName: String): Bool
Request.Body.scan(PatternSetName: String): BodyScanResult
```

The same helpers are available on `Response.Body` in response-phase rules.

Examples:

```cel
Request.Body.containsAny('sql-injection-keywords')
```

```cel
Response.Body.matchesAny('xss-regexes')
```

The visible body is limited by `max_body_inspection_bytes`. If the original body is larger than the visible limit, `IsTruncated` must be `true`.

### 9.6 TagMap helpers

```text
Request.Tags.count(): Int
Request.Tags.has(Key: String): Bool
Request.Tags.get(Key: String): String | Null
Request.Tags.anyKeyMatches(Pattern: String): Bool
Request.Tags.anyValueContains(Value: String): Bool
Request.Tags.anyEntryMatches(KeyPattern: String, ValuePattern: String): Bool
```

Response-phase rules may read `Request.Tags` values created by request-phase actions.

### 9.7 BoundedStringList

```text
BoundedStringList.Count: Int
BoundedStringList.IsTruncated: Bool
BoundedStringList.First: String | Null
BoundedStringList.contains(Value: String): Bool
BoundedStringList.containsAny(PatternSetName: String): Bool
BoundedStringList.matchesAny(PatternSetName: String): Bool
```

`BoundedStringList` is not a normal array. It cannot be indexed and cannot be iterated by user code. It exists so rules can safely inspect duplicate headers or query parameters without loops.

Example:

```cel
Request.Headers.getAll('Forwarded').Count > 1
```

```cel
Request.Headers.getAll('Forwarded').matchesAny('private-forwarded-values')
```

### 9.8 BodyScanResult

```text
BodyScanResult.Matched: Bool
BodyScanResult.MatchCount: Int
BodyScanResult.FirstPattern: String | Null
BodyScanResult.FirstOffset: Int | Null
BodyScanResult.IsTruncated: Bool
```

`BodyScanResult` provides bounded metadata only. It must not expose unbounded match arrays or arbitrary capture groups.

Example:

```cel
Response.Body.scan('xss-regexes').Matched
```

### 9.9 No callback syntax

The helper API must not use callback, arrow-function, or user-defined predicate syntax.

Forbidden:

```typescript
Request.Headers.Any((Header) => Header.Name.StartsWith('X-'))
Request.Cookies.All(function CookiePredicate(Cookie) { return Cookie.Value != '' })
```

Allowed:

```cel
Request.Headers.anyNameMatches('^X-')
```

This keeps OxiRule free of user-defined functions while still allowing bounded collection-style checks.

### 9.10 Cost accounting

Each helper call must charge the rule budget. The engine should charge at least:

- One expression step for the method call.
- One or more expression steps per inspected item.
- Additional steps per inspected byte range.
- Regex budget for each regex evaluation.
- Memory budget for every derived string or result object.

If a helper reaches a configured limit before finishing its scan, it must fail closed inside the helper result when possible. For boolean helpers, the conservative default should be `false` for allow-style checks and a runtime budget error for security-sensitive ambiguous checks.

## 10. Security and Resource Model

### 10.1 Why loops are banned in v1

`for`, `while`, comprehensions, callbacks, and similar user-controlled iteration constructs are forbidden in the initial rule language.

A per-rule execution time limit is required, but it is not sufficient by itself as the only denial-of-service mitigation.

Reasons:

- Timeouts are usually cooperative or checked at instruction boundaries. A pathological expression can still consume CPU until the next check.
- A large number of requests can each consume the maximum allowed runtime, turning a small timeout into a sustained CPU exhaustion vector.
- User-controlled iteration is harder to statically estimate, audit, cache, and optimize.
- Iteration can combine with body inspection, header scans, string operations, and regex operations to create expensive behavior.
- Time limits do not directly cap memory allocation, regex backtracking, output mutation count, or body-buffer growth.
- Deterministic rule cost is important for a reverse proxy because the rule engine runs on the traffic path.

Therefore, OxiBelt should use both approaches:

1. Ban unbounded language constructs in v1.
2. Enforce strict runtime, memory, body, regex, and operation budgets.

Rules may inspect repeated data only through bounded, engine-provided helper APIs, where OxiBelt controls maximum iteration count, inspected bytes, regex cost, and temporary memory.

### 10.2 Required execution limits

Every rule execution must be constrained by limits configured in TOML.

Recommended global defaults:

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

Recommended behavior:

- `max_rule_runtime_ms` limits a single rule invocation.
- `max_total_waf_runtime_ms` limits all WAF processing for a single transaction.
- `max_expression_steps` limits interpreter or VM instruction count.
- `max_memory_bytes` limits temporary allocations owned by rule evaluation.
- `max_string_bytes` limits derived string size.
- `max_body_inspection_bytes` limits request or response body bytes visible to rule conditions.
- `max_mutations` limits header, tag, routing, and response replacement mutations.
- `max_regex_runtime_ms` limits individual regex operations.
- `max_helper_items` limits how many headers, query parameters, cookies, tags, or body matches a helper may inspect.
- `max_helper_pattern_count` limits how many configured patterns a helper may evaluate.
- `max_helper_result_bytes` limits derived helper output, including joined values and captured samples.

### 10.3 Failure policy

When a rule fails because of timeout, parser error, runtime error, budget exhaustion, or forbidden operation, OxiBelt must apply the configured failure policy.

```toml
[waf]
fail_policy = "closed" # closed | open
mode = "enforcing"    # enforcing | monitor
```

Behavior:

- `fail_policy = "closed"`: reject the transaction when WAF execution fails.
- `fail_policy = "open"`: allow the transaction to continue when WAF execution fails.
- `mode = "monitor"`: log the decision but do not enforce blocking actions.
- `mode = "enforcing"`: apply blocking, rewrite, and routing decisions.

Security-sensitive deployments should prefer `fail_policy = "closed"`.

## 11. Protocol Notes

### 11.1 HTTP

HTTP rules may inspect and modify headers, URI metadata, method, status, and bounded body data.

### 11.2 WebSocket

The request side applies to the HTTP upgrade request. After upgrade, frame-level inspection is optional and must be configured separately.

```toml
[[waf.rules]]
name = "block-admin-websocket"
phase = "request"
priority = 100
when = "Request.Protocol == 'websocket' && Request.Http.Path.startsWith('/admin-ws')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "WebSocket endpoint blocked"
```

### 11.3 WebRTC

WebRTC rules may inspect signaling HTTP requests when signaling passes through OxiBelt. UDP flow metadata may be exposed through `Request.Transport.Udp` when applicable.

### 11.4 WebTransport

WebTransport over HTTP/3 may expose HTTP metadata and UDP/QUIC-related transport metadata.

```toml
[[waf.rules]]
name = "route-webtransport-h3"
phase = "request"
priority = 100
when = "Request.Protocol == 'webtransport' && Request.Transport.Network == 'udp'"

[[waf.rules.actions]]
type = "route_to_pool"
pool = "h3-pool"
```

## 12. Examples

### 12.1 Block public access to `/admin`

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

### 12.2 Route API traffic to a pool

```toml
[[waf.rules]]
name = "route-api-v1"
phase = "request"
priority = 100
when = "Request.Http.Host == 'api.example.com' && Request.Http.Path.startsWith('/v1')"

[[waf.rules.actions]]
type = "route_to_pool"
pool = "api-v1-pool"
```

### 12.3 Apply a load-balancing hint

```toml
[[waf.rules]]
name = "low-priority-load-balancing"
phase = "request"
priority = 100
when = "Request.Headers.get('X-Priority') == 'low'"

[[waf.rules.actions]]
type = "set_load_balancing_policy"
policy = "least_connections"
```

### 12.4 Block suspicious request body content

```toml
[[waf.rules]]
name = "block-sqli-body"
phase = "request"
priority = 100
when = "Request.Http.Body.Size > 0 && Request.Body.containsAny('sql-injection-keywords')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Suspicious request body"
```

### 12.5 Add response security headers

```toml
[[waf.rules]]
name = "add-security-headers"
phase = "response"
priority = 200
when = "true"

[[waf.rules.actions]]
type = "set_response_header"
name = "X-Content-Type-Options"
value = "nosniff"

[[waf.rules.actions]]
type = "set_response_header"
name = "Referrer-Policy"
value = "no-referrer"
```

### 12.6 Replace an upstream error response

```toml
[[waf.rules]]
name = "replace-upstream-5xx"
phase = "response"
priority = 100
when = "Response.Http.Status >= 500"

[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "Temporary upstream error"
```

### 12.7 Handle upstream forwarding failure

```toml
[[waf.rules]]
name = "replace-upstream-failure"
phase = "response"
priority = 100
when = "Response.Upstream.Error != null"

[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "Upstream unavailable"
```

### 12.8 Use TCP metadata

```toml
[[waf.rules]]
name = "block-sni"
phase = "request"
priority = 100
when = """
Request.Transport.Network == 'tcp' &&
Request.Transport.Tcp != null &&
Request.Transport.Tcp.Sni == 'blocked.example.com'
"""

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Blocked SNI"
```

### 12.9 Use UDP metadata

```toml
[[waf.rules]]
name = "block-large-udp-datagram"
phase = "request"
priority = 100
when = """
Request.Transport.Network == 'udp' &&
Request.Transport.Udp != null &&
Request.Transport.Udp.DatagramSize > 1200
"""

[[waf.rules.actions]]
type = "reject"
status = 403
body = "UDP datagram too large"
```

### 12.10 Use bounded helpers without loops

```toml
[[waf.rules]]
name = "block-debug-headers"
phase = "request"
priority = 100
when = "Request.Headers.anyEntryMatches('^X-Debug-', '.+')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Debug headers are not allowed"

[[waf.rules]]
name = "block-xss-response"
phase = "response"
priority = 100
when = "Response.Body.matchesAny('xss-regexes')"

[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "Unsafe upstream response"
```

### 12.11 Pass request-side context to response rules with tags

```toml
[[waf.rules]]
name = "tag-login-request"
phase = "request"
priority = 100
when = "Request.Http.Path.startsWith('/login')"

[[waf.rules.actions]]
type = "set_tag"
key = "LoginRequest"
value = "true"

[[waf.rules]]
name = "no-store-login-errors"
phase = "response"
priority = 100
when = "Request.Tags.get('LoginRequest') == 'true' && Response.Http.Status >= 500"

[[waf.rules.actions]]
type = "set_response_header"
name = "Cache-Control"
value = "no-store"
```

## 13. Validation Rules

Configuration validation must reject:

- A rule with both `when` and `path`.
- A rule with neither `when` nor `path`.
- Duplicate rule names in the same scope.
- Unsupported phase values.
- Negative priorities.
- Unsupported expression operators.
- Forbidden imperative constructs.
- User-defined functions.
- Callback, arrow-function, or user-defined predicate syntax.
- External I/O attempts.
- Property names that do not exist in the object model.
- Function calls that do not exist in the object model.
- Rule files outside allowed configuration directories.
- Access to `Response` from request-phase rules.
- Response mutation actions in request-phase rules.
- Request routing actions in response-phase rules.
- Header mutation actions that exceed `max_mutations`.
- Pattern sets that exceed configured pattern count, pattern length, or safe-regex requirements.

## 14. Implementation Notes for Rust

The Rust implementation should prefer a dedicated WAF module such as:

- `source/src/waf.rs`
- `source/src/security/waf.rs`
- `source/src/proxy/filter.rs`

The WAF implementation should not be placed inside TLS-only or HTTP-only modules unless it is strictly protocol-specific.

Suggested internal stages:

1. Load TOML configuration.
2. Resolve inline and external rules.
3. Parse CEL-like `when` expressions into an AST.
4. Validate object access, phase access, functions, actions, and forbidden constructs.
5. Precompile pattern sets and safe regexes.
6. Compile expressions into a bounded internal representation or bytecode.
7. Execute request-phase rules with budgets.
8. Apply request actions or forward the request through routing and load balancing.
9. Create the `Response` object from the upstream response or a synthetic upstream-error response.
10. Execute response-phase rules with budgets.
11. Apply response actions and return, replace, or reject the response.

The evaluator should maintain:

- Expression step budget.
- Time budget.
- Memory budget.
- Body inspection budget.
- Helper scan budget.
- Regex budget.
- Mutation count.
- Terminal decision state.
- Phase-specific object availability.

## 15. Future Extensions

Possible future features:

- Reusable named rule sets.
- Precompiled safe regex sets.
- Rule versioning.
- Structured audit logs.
- Rule testing CLI.
- Dry-run simulation mode.
- Per-route limit overrides.
- Signed external rule bundles.
- Safe limited comprehensions if OxiBelt can statically or mechanically guarantee bounded execution.
- Streaming response inspection with bounded windows.

Loops, callbacks, and user-defined functions should remain forbidden unless OxiBelt can guarantee bounded execution and simple cost accounting.

## 16. Compatibility Requirements

The rule condition language is CEL-like, not fully CEL-compatible.

OxiBelt must document differences clearly:

- No general-purpose CEL comprehensions in v1.
- No user-defined functions.
- No macros unless explicitly provided by OxiBelt.
- No JavaScript or TypeScript runtime globals.
- No standard library access outside OxiBelt-approved functions.
- No dynamic object mutation inside expressions.
- No `Date`, `Math.random`, `fetch`, `eval`, `Function`, or imports.
- No unbounded loops.
- No `import` or `export` declarations.

## 17. Summary

OxiRule provides a restricted, deterministic, CEL-like rule model for request and response policy decisions in a Rust reverse proxy.

The core design is:

```toml
[[waf.rules]]
name = "example"
phase = "request"
priority = 100
when = "Request.Http.Path.startsWith('/admin')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Forbidden"
```

This design preserves the request and response data accessibility needed by a WAF while avoiding imperative scripting in the hot path. A per-rule execution time limit is useful and required, but it should not replace the v1 ban on loops, callbacks, comprehensions, and user-defined functions. The safest initial design is to use side-effect-free CEL-like conditions, declarative actions, strict instruction and time budgets, memory and body limits, and bounded OxiBelt-controlled helper functions.
