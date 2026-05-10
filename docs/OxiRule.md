# OxiRule WAF Reference

Status: Draft
Target project: OxiBelt Rust-based reverse proxy

OxiRule is OxiBelt's CEL-like, declarative WAF rule model. For proxy behavior and runtime scope, see [Specification.md](Specification.md). For TOML placement and WAF limits, see [Configuration.md](Configuration.md). For a larger cookbook of practical rules, see [example/OxiRule.md](example/OxiRule.md).

## Rule Model

An OxiRule rule has:

- Metadata: `name`, optional `id`, optional `tags`, optional `mode`, `phase`, and `priority`.
- A side-effect-free boolean condition in `when`, or an external rule `path`.
- One or more declarative `actions`.

Basic inline rule:

```toml
[[waf.rules]]
name = "block-admin-from-public"
id = "block-admin-public"
tags = ["access-control", "admin"]
mode = "monitor"
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

`when` must evaluate to `Bool`. If it evaluates to `false`, the rule is skipped and no action from that rule executes.

Public rule `id` values are optional but must be unique when non-empty. `id` and entries in `tags` must match `[A-Za-z0-9-]{0,32}`. OxiBelt also assigns each compiled rule an internal runtime UUID for diagnostics; that UUID is not configured and is not stable across restarts.

Rule `mode` is optional and defaults to `[waf].mode`. A `monitor` rule counts and logs matches without applying actions. An `enforcing` rule applies actions normally, even when the global WAF mode is `monitor`.

Rule metadata tags are available through `Context.RuleTags`. Transaction tags created by actions such as `set_tag` and `require_person_proof.success_tag` are available through `Request.Tags`.

## Attachment and Files

Rules may be attached globally:

```toml
[[waf.rules]]
name = "global-request-policy"
phase = "request"
priority = 10
path = "rules/global-request.oxirule.toml"
```

Or on a route:

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

A rule entry must specify exactly one of `when` or `path`.

External rule files resolve under the configured OxiRule directory. Absolute paths and paths containing `.` or `..` components are rejected. An external `.oxirule.toml` file contains only the rule body:

```toml
when = "Request.Headers.anyValueContains('sqlmap')"

[[actions]]
type = "reject"
status = 403
body = "Blocked by WAF"
```

Pattern sets are configured globally and referenced by helper functions:

```toml
[[waf.pattern_sets]]
name = "xss-regexes"
kind = "regex"
patterns = ["(?i)<script", "(?i)javascript:"]
```

Supported pattern set kinds are `contains` and `regex`.

## CRS Compatibility

OxiBelt can run a CRS-compatible WAF layer alongside OxiRule rules:

```toml
[waf.crs]
enabled = true
mode = "monitor" # monitor | enforcing
setup_file = "crs/crs-setup.conf"
rule_files = ["crs/rules/*.conf"]
paranoia_level = 1
inbound_anomaly_score_threshold = 5
outbound_anomaly_score_threshold = 4
unsupported_directive_policy = "fail_closed"
```

CRS files resolve under the OxiRule directory and must use normalized relative paths or globs. The CRS layer supports request/response phases 1, 2, 3, and 4, CRS-style `tx` variables, macro expansion, `setvar`, chained rules, paranoia-level tags, transforms used by the supported CRS v4.x surface, and anomaly scoring. CRS validation operators such as `@validateUrlEncoding` and `@validateUtf8Encoding` follow CRS detection semantics by matching malformed encodings. Unsupported CRS syntax fails closed during configuration load/compile and includes file/line context.

CRS `monitor` mode records rule hits and latest inbound/outbound anomaly summaries through `/admin/v1/waf/rule-hits` without blocking. CRS `enforcing` mode blocks requests with `403` when the inbound blocking threshold is met and suppresses blocked upstream response bodies with a `502` response when the outbound blocking threshold is met. Prometheus metrics intentionally do not expose CRS rule IDs, names, or tags as labels.

The CRS compatibility matrix is available at `GET /admin/v1/waf/crs/compatibility` for `viewer` or `admin` users. It returns the targeted CRS release lines, currently including CRS `v4.25.0` and the `v4.25.x` LTS line as of 2026-05-10, plus supported directives, operators, transforms, variables, action syntax, accepted-but-ignored syntax, and known unsupported surfaces.

OxiBelt-native CRS tuning is configured under `[waf.crs]`:

```toml
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
header_equals = { "x-app-context" = "trusted-editor" }
reason = "editor intentionally submits HTML"
```

Rule selectors match by `rule_ids`, `tags`, or `msg_contains`; at least one selector is required. Allowlists also require a traffic selector. Traffic selector categories are ANDed together, and values within one category are ORed. A matching allowlist suppresses CRS scoring/actions for that transaction, increments `tuned_hits`, and leaves the original hit visible for review. `rule_overrides` are for broader per-rule policy changes: `monitor` observes without contributing to blocking score, `enforcing` can enforce under global monitor mode, and `disabled` records hits without scoring/actions.

Recommended rollout is monitor first, review `/admin/v1/waf/rule-hits`, add scoped allowlists or per-rule overrides for confirmed false positives, then switch CRS mode to `enforcing`. This mirrors the CRS tuning model while keeping OxiBelt's supported tuning surface in TOML rather than implementing the full ModSecurity exclusion language. See the official CRS [v4.25.0 LTS announcement](https://coreruleset.org/20260321/announcing-crs-v4-25-lts/), [false positives and tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/), and [installation](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/) references.

Response body inspection is bounded by `waf.limits.max_body_inspection_bytes`, records whether the inspected prefix was truncated, and should be enabled only where the deployment needs response leak detection. WebTransport frame and datagram payload inspection is not supported by CRS compatibility mode.

## Execution Phases

Request rules run after OxiBelt parses the request and matches a route, but before upstream forwarding. They can reject the request, mutate request headers, set transaction tags, require Person proof, or override the upstream/pool selection.

Response rules run after OxiBelt receives an upstream response or creates a synthetic upstream-error response, but before returning data to the downstream client. They can continue, replace, or reject the response, mutate response headers, and emit access logs.

Rules that read request or response body content trigger bounded prefix inspection before forwarding that side of the transaction. OxiBelt scans up to `waf.limits.max_body_inspection_bytes`, replays the captured prefix, and forwards data beyond the inspection window unchanged with `Body.IsTruncated = true`.

Rules run by ascending `priority`, with rule name as a tie-breaker. Tags created by request rules are visible to later request rules and to response rules for the same transaction.

`Response` is not available in request-phase expressions. Reading `Response.Http`, `Response.Headers`, `Response.Body`, or `Response.Upstream` from a request rule is a validation error.

When upstream forwarding fails, response rules receive a synthetic response with a status such as `502`, `503`, or `504` and `Response.Upstream.Error` populated:

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

## Expression Language

Object properties use `PascalCase`, such as `Request.Http.Path`. Functions use `lowerCamelCase`, such as `startsWith` and `inCidr`.

Supported literals:

```cel
true
false
null
123
'bounded string'
```

Supported operators:

```cel
== !=
< <= > >=
&& || !
+
```

Examples:

```cel
Request.Http.Path.startsWith('/login')
```

```cel
Request.Headers.has('User-Agent') &&
Request.Headers.get('User-Agent').contains('sqlmap')
```

```cel
Request.Protocol == 'webtransport' &&
Request.Transport.Network == 'udp'
```

```cel
Response.Http.Status >= 500 || Response.Upstream.Error != null
```

String functions:

```cel
Value.contains('needle')
Value.startsWith('/prefix')
Value.endsWith('.php')
Value.matches('(?i)sqlmap')
Value.lowerAscii()
Value.upperAscii()
Value.size()
```

IP/CIDR helper:

```cel
Request.Client.Ip.inCidr('10.0.0.0/8')
```

Forbidden constructs:

- `if`, `else`, `for`, `while`, `switch`, `try`, `catch`, `throw`.
- `let`, `const`, assignment, mutation, classes, or `new`.
- Functions, closures, callbacks, arrow functions, user-defined predicates, and imports.
- `await`, promises, external I/O, file access, environment access, network access, clock access, random access, or process execution.
- Unbounded loops, comprehensions, and map construction in v1.

Dynamic policy integration does not change this sandbox: OxiRule can only read `DynamicPolicy.*` values already computed from the current in-memory snapshot.

Nullable values must be checked before nested access:

```cel
Request.Transport.Tcp != null &&
Request.Transport.Tcp.Sni == 'blocked.example.com'
```

## Actions

Actions run in order only when `when` evaluates to `true`.

Request-phase terminal actions:

```toml
[[waf.rules.actions]]
type = "reject"
status = 403
body = "Forbidden"
```

```toml
[[waf.rules.actions]]
type = "rate_limit"
name = "login-token-limit"
key = "access_token_route"
token_header = "X-Api-Token"
rate = "10r/m"
burst = 10
max_buckets = 16384
status = 429
body = "rate limit exceeded"
```

```toml
[[waf.rules.actions]]
type = "require_person_proof"
algorithm = "pow_sha256_v1"
difficulty = 18
token_validity_seconds = 300
cookie = "__oxibelt_person_proof"
token_bindings = ["user_agent", "route", "direct_peer_ip_network_prefix"]
direct_peer_ipv4_prefix_bits = 24
direct_peer_ipv6_prefix_bits = 56
single_use = false
success_tag = "PersonProof"
status = 403
```

`rate_limit` is request-phase only. Supported keys are `client_ip`, `client_ip_route`, `client_ip_path`, `access_token`, `access_token_route`, and `access_token_path`; `client-ip` style aliases are accepted. Access-token limits read `Authorization: Bearer <token>` first and then optional `token_header`. Token values are hashed before storage, and requests without a token fall back to the client IP bucket. `max_buckets` defaults to `16384` and caps process-local buckets for a single WAF rate-limit action; in enforcing mode, new identities are rejected after the cap until a fully refilled bucket can be reclaimed. When shared state maps rate limits to a backend, WAF `rate_limit` actions use the same Redis-compatible or PostgreSQL token-bucket storage as route rate limits. Monitor-mode rules count matches without consuming rate-limit tokens.

Response-phase terminal actions:

```toml
[[waf.rules.actions]]
type = "continue_response"
```

```toml
[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "Temporary upstream error"
```

```toml
[[waf.rules.actions]]
type = "reject_response"
status = 403
body = "Blocked response"
```

Request routing actions:

```toml
[[waf.rules.actions]]
type = "route_to_pool"
pool = "api-pool"
```

```toml
[[waf.rules.actions]]
type = "route_to_upstream"
upstream = "api-primary"
```

```toml
[[waf.rules.actions]]
type = "set_load_balancing_policy"
policy = "least_conn"
```

Supported load-balancing policies are `round_robin`, `least_conn`, `least_connections`, `random`, `hash`, and `ip_hash`.

Header mutation actions:

```toml
[[waf.rules.actions]]
type = "set_request_header"
name = "X-OxiBelt-Checked"
value = "true"

[[waf.rules.actions]]
type = "remove_request_header"
name = "X-Debug-Mode"
```

```toml
[[waf.rules.actions]]
type = "set_response_header"
name = "X-Content-Type-Options"
value = "nosniff"

[[waf.rules.actions]]
type = "remove_response_header"
name = "Server"
```

Tag action:

```toml
[[waf.rules.actions]]
type = "set_tag"
key = "LoginRequest"
value = "true"
```

Tag keys and Person proof `success_tag` values must match `[A-Za-z0-9-]{1,32}`. Header, tag, routing, and response replacement mutations count against `waf.limits.max_mutations`.

## Person Proof

`require_person_proof` is a request-phase anti-automation challenge. It is not authentication, identity proof, proof of biological or legal status, bot reputation, or proof of benign intent.

The supported algorithm is `pow_sha256_v1`: the client computes a nonce such that `SHA-256(challenge || "." || nonce)` has the configured number of leading zero bits. If the proof is valid and unexpired, OxiBelt appends an `HttpOnly` clearance cookie and forwards the request. Later requests validate the signed clearance cookie instead of recomputing proof.

Tokens are signed with a startup-local secret by default, or a shared cluster secret when `[shared_state].person_proof_backend` is configured. They are bound to the cookie name, issuing policy, downstream host, HTTP method, challenge value, difficulty, issue time, expiration time, and configured `token_bindings`.

Supported token bindings:

- `user_agent`: the `User-Agent` request header.
- `tls_fingerprint`: OxiBelt's downstream TLS fingerprint.
- `route`: the matched OxiBelt route name.
- `direct_peer_ip_network_prefix`: the direct peer IP prefix, not a forwarded-header value.
- `tcp_max_hop`: the configured TCP max-hop policy.

Defaults are `["user_agent", "route", "direct_peer_ip_network_prefix"]`, `/24` for IPv4, and `/56` for IPv6. Use `/32` and `/128` to bind to exact direct peer IPs.

When any policy sets `tcp_max_hop`, OxiBelt applies the strictest configured value listener-wide at accept time using Linux `IP_MINTTL` for IPv4 and `IPV6_MINHOPCOUNT` for IPv6. This is not route-local because the route is not known until after TLS and request parsing.

`single_use = true` tracks challenge and clearance reuse in memory by default, or in the configured Person proof shared backend when shared state is enabled. It rotates the clearance cookie after each valid request. Local in-memory state is bounded by `waf.limits.max_person_proof_reuse_tokens`; exhaustion fails closed with `429 Too Many Requests`.

Validation constraints:

- `algorithm` must be `pow_sha256_v1`.
- `difficulty` must be between `1` and `30`.
- `token_validity_seconds` must be between `1` and `86400`.
- `ttl_seconds` and `token_ttl_seconds` are compatibility aliases.
- `cookie` may contain only ASCII letters, digits, `_`, `-`, or `.`.
- `token_bindings` must not be empty and may not contain duplicates.
- IPv4 prefix bits must be `0..32`; IPv6 prefix bits must be `0..128`.
- `tcp_max_hop`, when set, must be `0..255`.
- `token_bindings` containing `tcp_max_hop` must also set `tcp_max_hop`.
- `status` must be a valid HTTP status code.

`Request.TokenBindings` exposes the normalized binding values to expressions.

## Access Log Action

`emit_access_log` is valid only in response-phase rules:

```toml
[[waf.rules]]
name = "stdout-access-log"
phase = "response"
priority = 1000
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
```

The emitted newline-delimited JSON object always includes `event = "oxibelt.access"`, `timestamp_unix_ms`, and `scope = "waf"` unless a field named `scope` is explicitly configured. If `database.access_log.enabled = true`, OxiBelt also writes the same record to the configured PostgreSQL table.

Field `value` may also be written as `expression`. Field expressions may read response-phase `Request`, `Response`, and `Context` values. They may evaluate to scalar JSON values (`Bool`, `Int`, `String`, or `Null`) or bounded JSON collections/objects exposed by the OxiRule object model, such as `Request.Headers`, `Request.QueryParams`, `Request.Cookies`, `Request.Tags`, `Context.RuleTags`, or `Request.Headers.getAll(...)`. Field names must match `[A-Za-z0-9_.-]{1,64}` and may not be `event` or `timestamp_unix_ms`. Fields that read request body bytes are rejected.

If `fields` is omitted, OxiBelt emits the default access-log field set. In that default set, `user_agent` is a bounded collection from `Request.Headers.getAll('User-Agent')`, so duplicate `User-Agent` headers are preserved instead of failing the whole log record.

## Object Model

Top-level objects:

```text
Context.Phase: 'request' | 'response'
Context.RuleName: String
Context.RuleId: String | Null
Context.RuleTags: RuleTagSet
Context.RouteName: String | Null
Context.TransactionId: String
Context.Mode: 'enforcing' | 'monitor' # effective mode for the current rule, or global mode outside a rule
```

```text
DynamicPolicy.Matched: Bool
DynamicPolicy.Action: 'allow' | 'reject' | 'rate_limit' | Null
DynamicPolicy.Name: String | Null
DynamicPolicy.Reason: String | Null
DynamicPolicy.Code: String | Null
DynamicPolicy.Mode: 'enforce' | 'dry_run' | Null
DynamicPolicy.Source: String | Null
```

`DynamicPolicy.*` is read-only request context from OxiBelt's in-memory dynamic policy snapshot. It does not perform SQL or any other external I/O while evaluating an OxiRule expression. Terminal dynamic policy rejects happen before request-phase OxiRule evaluation, so these fields are mainly useful for requests that matched an allowed dynamic `allow`, non-terminal `rate_limit`, or `dry_run` policy and for response/access-log expressions.

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
Request.Normalized: NormalizedRequestView
Request.Body: BodyView
Request.Tls: TlsMetadata | Null
Request.Tags: TagMap
Request.TokenBindings: PersonProofTokenBindingView
```

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

Important nested fields:

```text
ClientMetadata.Kind: 'person' | 'unknown'
ClientMetadata.Ip: IpAddress
ClientMetadata.Port: Int
ClientMetadata.SourceAddress: String
ClientMetadata.UserAgent: String | Null
ClientMetadata.PersonProof: PersonProofMetadata
ClientMetadata.Agent: AgentMetadata
ClientMetadata.Bot: BotMetadata
ClientMetadata.GeoCountry: String | Null
ClientMetadata.Asn: Int | Null

PersonProofMetadata.State: 'absent' | 'valid' | 'failed' | 'expired'
PersonProofMetadata.Method: String | Null
PersonProofMetadata.Difficulty: Int | Null
PersonProofMetadata.IssuedAtUnixMs: Int | Null
PersonProofMetadata.ExpiresAtUnixMs: Int | Null

AgentMetadata.Verified: Bool
AgentMetadata.Kind: String | Null
AgentMetadata.Provider: String | Null
AgentMetadata.Model: String | Null
AgentMetadata.AuthMethod: String | Null

BotMetadata.Disposition: 'unknown' | 'normal' | 'malicious'
BotMetadata.Malicious: Bool | Null
BotMetadata.Score: Int
BotMetadata.Reason: String | Null

PersonProofTokenBindingView.UserAgent: String
PersonProofTokenBindingView.TlsFingerprint: String
PersonProofTokenBindingView.Route: String
PersonProofTokenBindingView.DirectPeerIpNetworkPrefix: String
PersonProofTokenBindingView.TcpMaxHop: String
PersonProofTokenBindingView.directPeerIpNetworkPrefix(Ipv4PrefixBits, Ipv6PrefixBits): String
PersonProofTokenBindingView.tcpMaxHop(ConfiguredMaxHop): String
```

```text
TransportMetadata.Network: 'tcp' | 'udp'
TransportMetadata.RemoteIp: IpAddress
TransportMetadata.RemotePort: Int
TransportMetadata.IsEncrypted: Bool
TransportMetadata.Tcp: TcpMetadata | Null
TransportMetadata.Udp: UdpMetadata | Null
```

```text
TcpMetadata.Sni: String | Null
TcpMetadata.Alpn: String | Null
TcpMetadata.MaxHop: Int | Null
TcpMetadata.Mss: Int | Null
TcpMetadata.RttMs: Int | Null
```

```text
UdpMetadata.DatagramSize: Int | Null
UdpMetadata.QuicDetected: Bool
UdpMetadata.ConnectionId: String | Null
```

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

```text
NormalizedRequestView.Http: NormalizedHttpRequestMetadata
NormalizedRequestView.Headers: HeaderMap
NormalizedRequestView.QueryParams: QueryParamMap
NormalizedRequestView.Cookies: CookieMap

NormalizedHttpRequestMetadata.Path: String
NormalizedHttpRequestMetadata.Query: String
NormalizedHttpRequestMetadata.Uri: String
```

`Request.Normalized` is a WAF-only view. It does not replace raw `Request.Http.*`, `Request.Headers`, `Request.QueryParams`, or `Request.Cookies`. The view applies URL/Unicode decoding, Unicode NFC normalization, null removal, whitespace compression, lower-case text transforms, path segment normalization, and duplicate metadata policy handling through the same bounded map helpers.

```text
HttpResponseMetadata.Version: '1.0' | '1.1' | '2' | '3'
HttpResponseMetadata.Status: Int
HttpResponseMetadata.Reason: String | Null
HttpResponseMetadata.Body: BodyMetadata
```

```text
UpstreamMetadata.Name: String
UpstreamMetadata.Pool: String
UpstreamMetadata.Scheme: String
UpstreamMetadata.ConnectTimeMs: Int | Null
UpstreamMetadata.FirstByteTimeMs: Int | Null
UpstreamMetadata.Error: UpstreamError | Null

UpstreamError.Code: 'dns_error' | 'connect_timeout' | 'connect_error' | 'tls_error' | 'read_timeout' | 'protocol_error'
UpstreamError.Message: String
```

```text
TlsMetadata.Enabled: Bool
TlsMetadata.Version: String | Null
TlsMetadata.CipherSuite: String | Null
TlsMetadata.Sni: String | Null
TlsMetadata.Alpn: String | Null
TlsMetadata.Fingerprint: String | Null
TlsMetadata.FingerprintScheme: String | Null
TlsMetadata.ClientCertificatePresent: Bool
```

Current implementation notes:

- TCP request rules expose TCP transport metadata; HTTP/3 and WebTransport request rules expose UDP/QUIC metadata.
- HTTP/3 TLS fingerprints use the `quinn-rustls-quic-v2` scheme.
- `Request.Id`, `Response.Id`, `Context.TransactionId`, request/response receive timestamps, and upstream first-byte timing are populated for HTTP request-wide and OxiRule access-log contexts.
- Upstream connect timing is populated only where the proxy can measure it directly; otherwise it evaluates to `null`.
- Some local endpoint fields, connection IDs, byte counters, UDP datagram sizes, TCP MSS, and RTT fields are reserved and may evaluate to `null`.

## Bounded Helpers

OxiRule forbids user-controlled iteration. Repeated data is inspected through bounded helpers that charge runtime, step, memory, regex, helper-item, and result-size budgets.

Header helpers:

```text
Request.Headers.count(): Int
Request.Headers.has(Name): Bool
Request.Headers.get(Name): String | Null
Request.Headers.getAll(Name): BoundedStringList
Request.Headers.anyNameMatches(Pattern): Bool
Request.Headers.anyValueContains(Value): Bool
Request.Headers.anyValueMatches(Pattern): Bool
Request.Headers.anyEntryMatches(NamePattern, ValuePattern): Bool
Request.Headers.allEntriesMatch(NamePattern, ValuePattern): Bool
```

The same single-value duplicate behavior applies to query parameters and cookies according to `waf.duplicate_metadata_policy`. Use `getAll(...)` when duplicates are expected.

Query parameter helpers:

```text
Request.QueryParams.count(): Int
Request.QueryParams.has(Name): Bool
Request.QueryParams.get(Name): String | Null
Request.QueryParams.getAll(Name): BoundedStringList
Request.QueryParams.anyNameMatches(Pattern): Bool
Request.QueryParams.anyValueContains(Value): Bool
Request.QueryParams.anyValueMatches(Pattern): Bool
Request.QueryParams.anyEntryMatches(NamePattern, ValuePattern): Bool
```

Cookie helpers:

```text
Request.Cookies.count(): Int
Request.Cookies.has(Name): Bool
Request.Cookies.get(Name): String | Null
Request.Cookies.getAll(Name): BoundedStringList
Request.Cookies.anyNameMatches(Pattern): Bool
Request.Cookies.anyValueContains(Value): Bool
Request.Cookies.anyValueMatches(Pattern): Bool
Request.Cookies.anyEntryMatches(NamePattern, ValuePattern): Bool
```

Tag helpers:

```text
Request.Tags.count(): Int
Request.Tags.has(Key): Bool
Request.Tags.get(Key): String | Null
Request.Tags.anyKeyMatches(Pattern): Bool
Request.Tags.anyValueContains(Value): Bool
Request.Tags.anyEntryMatches(KeyPattern, ValuePattern): Bool

Context.RuleTags.count(): Int
Context.RuleTags.has(Tag): Bool
Context.RuleTags.anyMatches(Pattern): Bool
```

Bounded string lists:

```text
BoundedStringList.Count: Int
BoundedStringList.IsTruncated: Bool
BoundedStringList.First: String | Null
BoundedStringList.contains(Value): Bool
BoundedStringList.containsAny(PatternSetName): Bool
BoundedStringList.matchesAny(PatternSetName): Bool
```

Body view:

```text
Request.Body.Size: Int
Request.Body.IsTruncated: Bool
Request.Body.Text: String | Null
Request.Body.Bytes: Bytes | Null
Request.Body.isFormat(Format): Bool
Request.Body.contains(Value): Bool
Request.Body.matches(Pattern): Bool
Request.Body.containsAny(PatternSetName): Bool
Request.Body.matchesAny(PatternSetName): Bool
Request.Body.scan(PatternSetName): BodyScanResult
```

The same shape is supported for `Response.Body` in response-phase rules. Body content helpers are bounded by `waf.limits.max_body_inspection_bytes`; bytes beyond that prefix are replayed but not inspected.

`Body.scan(PatternSetName)` returns:

```text
BodyScanResult.Matched: Bool
BodyScanResult.Pattern: String | Null
BodyScanResult.Offset: Int | Null
BodyScanResult.Match: String | Null
BodyScanResult.IsTruncated: Bool
```

Bytes helpers:

```text
Bytes.size(): Int
Bytes.isFormat(Format): Bool
Bytes.isBinaryFormat(Format): Bool
Bytes.matchesFormat(Format): Bool
```

Supported binary format checks include common image, audio, video, document, archive, data-container, font, and executable signatures such as `png`, `jpeg`, `webp`, `mp3`, `webm`, `pdf`, `zip`, `gzip`, `tar`, `woff`, `woff2`, `elf`, `exe`, and `pe`, plus unambiguous MIME aliases. Text formats such as `svg`, `html`, `json`, `yaml`, `css`, `csv`, and `markdown` are intentionally not matched by the binary signature helper.

## Protocol Notes

- HTTP rules may inspect and mutate headers, URI metadata, methods, status, and bounded body metadata.
- WebSocket rules apply to the HTTP upgrade request; frame-level inspection is not implemented.
- WebRTC signaling HTTP requests can be inspected when they pass through OxiBelt; TURN media payloads are forwarded by WebRTC TURN listeners outside OxiRule/WAF inspection.
- WebTransport over HTTP/3 exposes the CONNECT request as `Request.Protocol == 'webtransport'` with UDP/QUIC transport metadata. Frame-level and datagram payload inspection is not implemented.

## Validation Summary

OxiRule validation rejects:

- Rules with both `when` and `path`, or neither.
- Duplicate rule names in the same scope.
- Duplicate non-empty public rule IDs.
- Invalid rule IDs, rule tags, transaction tag keys, or Person proof `success_tag` values.
- Unsupported phases, negative priorities, unsupported operators, unknown properties, or unknown functions.
- Forbidden imperative constructs, callbacks, user-defined functions, imports, or external I/O.
- Request-phase access to `Response`.
- Response mutation actions in request-phase rules.
- Request routing actions in response-phase rules.
- `emit_access_log` outside response phase.
- Header mutations or other mutations that exceed `max_mutations`.
- Pattern sets that exceed configured count, length, regex, or budget limits.
- `route_to_upstream` or `route_to_pool` references to unknown targets.
- Invalid Person proof settings.

## Examples

Block public access to `/admin`:

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

Add response security headers:

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

Pass request-side context to a response rule:

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

Chain Person proof success into a later request rule:

```toml
[[waf.rules]]
name = "require-person-proof"
phase = "request"
priority = 100
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
success_tag = "PersonProof"

[[waf.rules]]
name = "mark-verified-person"
phase = "request"
priority = 110
when = "Request.Tags.get('PersonProof') == 'valid'"

[[waf.rules.actions]]
type = "set_request_header"
name = "X-OxiBelt-Person-Proof"
value = "valid"
```
