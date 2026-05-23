# OxiRule WAF Reference

Status: Draft
Target project: OxiBelt Rust-based reverse proxy

OxiRule is OxiBelt's CEL-like, declarative WAF rule model. For proxy behavior and runtime scope, see [Specification.md](Specification.md). For TOML placement and WAF limits, see [Configuration.md](Configuration.md). For a larger cookbook of practical rules, see [example/OxiRule.md](example/OxiRule.md).

## Rule Model

An OxiRule rule has:

- Metadata: `name`, optional `id`, optional `tags`, optional `mode`, `phase`, and `priority`.
- A side-effect-free boolean condition in `when`, reusable `groups`, or an external rule `path`.
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

The effective condition must evaluate to `Bool`. If it evaluates to `false`, the rule is skipped and no action from that rule executes.

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

A rule entry may specify `when`, `groups`, or both. External rule entries use `path`, and `path` cannot be combined with inline `when`, `merge_condition_as`, `groups`, or `actions` on the same rule entry.

External rule files resolve under the configured OxiRule directory. Absolute paths and paths containing `.` or `..` components are rejected. An external `.oxirule.toml` file contains only the rule body:

```toml
when = "Request.Headers.anyValueContains('sqlmap')"

[[actions]]
type = "reject"
status = 403
body = "Blocked by WAF"
```

External rule files may also define file-local rule groups. Because TOML keys after an array table belong to that table, place root-level `groups`, `when`, `merge_condition_as`, and `[[actions]]` before `[[rule_groups]]` definitions:

```toml
groups = ["scanner"]

[[actions]]
type = "reject"
status = 403

[[rule_groups]]
name = "scanner"
when = "Request.Headers.anyValueMatches('(?i)(sqlmap|nikto)')"
```

Pattern sets are configured globally and referenced by helper functions:

```toml
[[waf.pattern_sets]]
name = "xss-regexes"
kind = "regex"
patterns = ["(?i)<script", "(?i)javascript:"]
```

Supported pattern set kinds are `contains` and `regex`.

Bounded user-defined functions can be configured globally or per route:

```toml
[[waf.functions]]
name = "is_bad_path"
params = ["path"]
expression = "path.lowerAscii().contains('/wp-admin')"

[[routes.waf.functions]]
name = "is_bad_path"
params = ["path"]
expression = "path.startsWith('/admin')"
```

Functions are expression-valued helpers evaluated inside the same OxiRule sandbox and budgets as the calling rule. Function names and parameters must be valid OxiRule identifiers, cannot use reserved keywords or top-level objects such as `Request`, `Response`, `Stream`, `Context`, or `DynamicPolicy`, and cannot repeat parameter names. Function bodies may return any existing OxiRule value; rule `when` expressions still must evaluate to `Bool`.

Functions may call other functions when the call graph is acyclic. Global rules can call only global functions. Route rules can call global functions plus functions declared under that route; route functions override same-named global functions for that route. Global function bodies always resolve nested calls against global functions only, while route function bodies resolve against the route override set plus globals. Function bodies are phase-validated at call sites: a function that reads `Response` is valid only from response-phase expressions, and a function that reads `Stream` is valid only from stream-phase expressions. Rules that pass `Request.Body` or `Response.Body` into a function still trigger bounded body inspection when the callee, including nested callees, reads body content. Function definitions are allowed in TOML configuration only; external `.oxirule.toml` rule files remain rule-body-only.

## Rule Groups

Rule groups bundle reusable condition fragments and actions. Define global groups under `[[waf.rule_groups]]`, route-local groups under `[[routes.waf.rule_groups]]`, external file-local groups under `[[rule_groups]]` inside an external `.oxirule.toml` file, or shared group files referenced by `[waf] rule_group_files` and route-level `rule_group_files`. Shared group files use a top-level `[[rule_groups]]` array, resolve under the OxiRule directory, and use the same group fields as inline TOML groups. Exact paths must exist; glob entries may match zero files and are loaded in sorted order.

```toml
[[waf.rule_groups]]
name = "bot-defense"
when = "Request.Headers.anyValueMatches('(?i)(sqlmap|nikto)')"
merge_condition_as = "and"

[[waf.rule_groups.actions]]
priority = 10
type = "set_tag"
key = "BotDefense"
value = "matched"

[[waf.rules]]
name = "block-bot-defense"
phase = "request"
priority = 100
groups = ["bot-defense"]
when = "!Request.Client.Ip.inCidr('10.0.0.0/8')"
merge_condition_as = "and"

[[waf.rules.actions]]
priority = 20
type = "reject"
status = 403
```

Group lookup order is external file-local, then route-local, then global. External groups are visible only inside the external rule file that defines them. Rule execution order is still controlled by the referencing rule's `priority`.

Condition fragments are processed in `groups` array order, followed by the rule's own `when`. `merge_condition_as` accepts `and`, `or`, or `override` and defaults to `and`; each fragment's value controls how that fragment joins the previous accumulated condition. If `override` appears, it may appear only once across the referenced groups plus rule, and the effective condition is exactly that fragment's `when`.

Actions from referenced groups and the rule are collected, sorted by action `priority` with lower values first, and executed in stable declaration order for equal priorities. Action `priority` defaults to `0`. Terminal actions still stop later actions after sorting.

## Development Tools

OxiBelt includes local and Admin API OxiRule development tools for validating and exercising rules before writing or applying them.

Local CLI:

```sh
oxibelt --config source/config/oxibelt.toml oxirule check --rule rules/block.oxirule.toml
oxibelt --config source/config/oxibelt.toml oxirule test --rule rules/block.oxirule.toml --fixture '{"request":{"uri":"/admin"}}'
oxibelt --config source/config/oxibelt.toml oxirule explain --rule rules/block.oxirule.toml --fixture fixture.json
oxibelt --config source/config/oxibelt.toml oxirule cost --rule rules/block.oxirule.toml
oxibelt --config source/config/oxibelt.toml oxirule replay --rule rules/block.oxirule.toml --input captured.ndjson
oxibelt oxirule template list
oxibelt oxirule template render --name admin-path --var path_prefix=/admin --var admin_cidr=10.0.0.0/8
oxibelt oxirule false-positive --finding finding.json
```

The matching Admin API endpoints live under `/admin/v1/waf/oxirule/*` and are synchronous and stateless. They accept inline candidate OxiRule content plus optional inline OxiRule group content, compile it against the active configuration context, and return JSON fields such as `ok`, `diagnostics`, `matched_rules`, `actions`, `terminal`, `mutations`, `tags`, `stream_close`, `body_need`, `cost_warnings`, and `explain_steps`. The API does not write files or install rules; use `POST /admin/v1/files/sync` for deployment.

Fixtures can target request, response, or stream phase. Stream fixtures evaluate the rule engine's `WafStreamInput` shape for WebSocket/WebTransport metadata and payloads; they do not create live upgraded sessions. Replay accepts uploaded NDJSON fixture lines and does not read server-side log files.

Built-in templates are `vaultwarden`, `gitea`, `nextcloud`, `generic-login`, and `admin-path`. The false-positive planner returns suggested TOML for CRS allowlists/rule overrides or native OxiRule monitor/condition tuning without mutating configuration.

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

The CRS compatibility matrix is available at `GET /admin/v1/waf/crs/compatibility` for principals allowed to use `waf:GetCrsCompatibility`. It returns the targeted CRS release lines, currently including CRS `v4.25.0` and the `v4.25.x` LTS line as of 2026-05-10, plus supported directives, operators, transforms, variables, action syntax, accepted-but-ignored syntax, and known unsupported surfaces.

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
reason = "editor intentionally submits HTML"
```

Rule selectors match by `rule_ids`, `tags`, or `msg_contains`; at least one selector is required. Allowlists also require a traffic selector. Traffic selector categories are ANDed together, and values within one category are ORed. Scope allowlists with `methods`, `routes`, or `path_prefixes`; `header_equals` is rejected because inbound request headers are client-controlled before proxy forwarding. A matching allowlist suppresses CRS scoring/actions for that transaction, increments `tuned_hits`, and leaves the original hit visible for review. `rule_overrides` are for broader per-rule policy changes: `monitor` observes without contributing to blocking score, `enforcing` can enforce under global monitor mode, and `disabled` records hits without scoring/actions.

Recommended rollout is monitor first, review `/admin/v1/waf/rule-hits`, add scoped allowlists or per-rule overrides for confirmed false positives, then switch CRS mode to `enforcing`. This mirrors the CRS tuning model while keeping OxiBelt's supported tuning surface in TOML rather than implementing the full ModSecurity exclusion language. See the official CRS [v4.25.0 LTS announcement](https://coreruleset.org/20260321/announcing-crs-v4-25-lts/), [false positives and tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/), and [installation](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/) references.

Response body and native stream payload inspection are bounded by `waf.limits.max_body_inspection_bytes`, record whether the inspected prefix was truncated, and should be enabled only where the deployment needs response leak detection or upgraded-session payload policy. For WebSocket stream WAF, an individual frame payload larger than this limit is closed fail-closed instead of being buffered and forwarded. CRS compatibility mode does not inspect WebSocket frames/messages or WebTransport stream/datagram payloads.

## Execution Phases

Request rules run after OxiBelt parses the request and matches a route, but before upstream forwarding. They can reject the request, mutate request headers, set transaction tags, require Person proof, or override the upstream/pool selection.

Response rules run after OxiBelt receives an upstream response or creates a synthetic upstream-error response, but before returning data to the downstream client. They can continue, replace, or reject the response, mutate response headers, and emit access logs.

Stream rules run after a WebSocket upgrade or WebTransport CONNECT session is established. They inspect both directions, including WebSocket raw frames, reassembled WebSocket messages, WebTransport stream chunks, and WebTransport datagrams. They can close the active stream/session with `close_stream`; request/response mutation and routing actions are not valid in stream phase. Generic HTTP Upgrade and CONNECT tunnels remain byte tunnels in v1.

Rules that read request, response, or stream payload content trigger bounded prefix inspection before forwarding that side of the transaction. OxiBelt scans up to `waf.limits.max_body_inspection_bytes`, replays the captured prefix, and forwards data beyond the inspection window unchanged with `Body.IsTruncated = true` or `Stream.Payload.IsTruncated = true`, except that oversized WebSocket frames on stream-WAF routes are rejected before forwarding to keep proxy-owned frame buffers bounded.

Rules that read only `Request.Body.Size` or `Response.Body.Size` use a single valid positive `Content-Length` when it is available. When body size is unknown, including chunked HTTP/1.1 bodies and bodies without `Content-Length`, OxiBelt captures a bounded prefix up to `waf.limits.max_body_inspection_bytes` before evaluating the size. If that prefix is truncated, `Body.Size` evaluates to the captured byte count plus one as a conservative lower bound. Rules that read `Body.Text`, `Body.Bytes`, `Body.IsTruncated`, or body helper methods such as `contains`, `matches`, `scan`, and `isFormat` still trigger bounded prefix inspection. When prefix inspection is required but the HTTP metadata proves the body is empty, OxiBelt evaluates body text and bytes against an empty captured body without polling the stream.

Rules run by ascending `priority`, with rule name as a tie-breaker. Tags created by request rules are visible to later request rules and to response rules for the same transaction.

`Response` is not available in request-phase or stream-phase expressions. `Request.Body` is also unavailable in stream-phase expressions; use `Stream.Payload` for upgraded-session payload inspection.

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

Object properties use `PascalCase`, such as `Request.Http.Path`. Built-in methods use `lowerCamelCase`, such as `startsWith` and `inCidr`. User-defined functions are called directly, such as `is_bad_path(Request.Http.Path)`.

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
- Closures, callbacks, arrow functions, imperative function bodies, and imports. Declarative bounded user-defined functions are configured with `[[waf.functions]]` or `[[routes.waf.functions]]`.
- `await`, promises, external I/O, file access, environment access, network access, clock access, random access, or process execution.
- Unbounded loops, comprehensions, and map construction in v1.

Dynamic policy integration does not change this sandbox: OxiRule can only read `DynamicPolicy.*` values already computed from the current in-memory snapshot.

Nullable values must be checked before nested access:

```cel
Request.Transport.Tcp != null &&
Request.Transport.Tcp.Sni == 'blocked.example.com'
```

## Actions

Actions run only when the effective rule condition evaluates to `true`. Ungrouped actions run in declaration order because their default `priority` is `0`; grouped and rule-local actions are sorted together by action `priority`.

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
type = "weigh_person_proof"
weight = 25
```

```toml
[[waf.rules.actions]]
type = "allow_person_proof"
```

```toml
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

```toml
[waf.person_proof]
session_path = "/.oxibelt/person-proof/session"
verify_path = "/.oxibelt/person-proof/verify"
openapi_path = "/.oxibelt/person-proof/openapi.json"

[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "third_party_provider"
third_party_provider = "turnstile" # turnstile | hcaptcha | friendly_captcha_v2
custom_frontend_url = "/person-proof/index.html"
challenge_redirect_status = 303
site_key = "0x4AAAA..."
secret_env = "OXIBELT_TURNSTILE_SECRET"
provider_timeout_ms = 3000
provider_fail_policy = "closed" # closed | open
send_remote_ip = true
```

`rate_limit` is request-phase only. Supported keys are `global`, `route`, `client_ip`, `client_ip_route`, `client_ip_path`, `access_token`, `access_token_route`, and `access_token_path`; `client-ip` style aliases are accepted for the client-IP keys. `global` uses one bucket shared by all matching requests, and `route` uses one bucket per resolved route. Access-token limits read `Authorization: Bearer <token>` first and then optional `token_header`. Token values are hashed before storage, and requests without a token fall back to the client IP bucket. `max_buckets` defaults to `16384` and caps process-local buckets for a single WAF rate-limit action; in enforcing mode, new identities are rejected after the cap until a fully refilled bucket can be reclaimed. When shared state maps rate limits to a backend, WAF `rate_limit` actions use the same Redis-compatible or PostgreSQL token-bucket storage as route rate limits. Monitor-mode rules count matches without consuming rate-limit tokens.

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

Stream-phase terminal actions:

```toml
[[waf.rules.actions]]
type = "close_stream"
websocket_code = 1008
webtransport_code = 1
reason = "policy violation"
```

`close_stream` is valid only in stream-phase rules. If fields are omitted, WebSocket uses close code `1008`, WebTransport uses close/reset code `1`, and the reason is `policy violation`. WebSocket close reasons are limited to the protocol payload limit for a close frame.

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
policy = "weighted_least_conn"
```

Supported load-balancing policies are `power_of_two_choices`, `weighted_least_conn`, `rendezvous_hash`, `rendezvous_ip_hash`, `ewma`, and `least_time`. `sticky_cookie` is configured on the upstream pool itself, not through WAF policy overrides. Legacy policy names such as `round_robin`, `least_conn`, `least_connections`, `random`, `hash`, and `ip_hash` are rejected.

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

Tag keys and Person proof `success_tag` values must match `[A-Za-z0-9-]{1,32}`. `waf.limits.max_mutations` counts request/response header mutations, `set_tag`, routing overrides, `set_load_balancing_policy`, `rate_limit`, `weigh_person_proof`, `allow_person_proof`, and `emit_mitigation`. Terminal actions such as `reject`, `replace_response`, `reject_response`, `require_person_proof`, `continue_response`, and `close_stream` are validated separately and do not consume this mutation budget.

Mitigation emission action:

```toml
[[waf.rules.actions]]
type = "emit_mitigation"
intent = "rtbh" # dots | flowspec | rtbh | blackhole | vendor | observe
provider = "example-isp"
reason = "login flood"
target = "Request.Transport.RemoteIp"
ttl_seconds = 300
dedupe_window_ms = 60000
min_count = 3
failure_policy = "open" # open | closed

[[waf.rules.actions.fields]]
name = "path"
value = "Request.Http.Path"
```

`emit_mitigation` is valid in request, response, and stream phases. It writes an aggregate PostgreSQL row through `[database.mitigation]` for an external mitigation controller to translate into DOTS, BGP FlowSpec, RTBH/blackhole, or provider-specific REST/OpenAPI calls. OxiBelt does not call those external APIs directly.

The default target is `Request.Transport.RemoteIp`. `target` and `target_prefix` are OxiRule expressions and must evaluate to an IP address or CIDR string. Custom `fields` use the same expression shape as `emit_access_log`, but may not read `Request.Body`, `Response.Body`, or `Stream.Payload`, including through user-defined functions. Default records include safe request, transport, TLS, response, and stream metadata, including User-Agent, Host, path without query, route, rule identity, TCP/UDP metadata, TLS fingerprint, and stream direction/unit.

When `min_count` is greater than `1`, rows are written as `observing` until the deduplicated aggregate count reaches the threshold, then promoted to `pending`. Existing controller-owned statuses are preserved on later updates. `failure_policy = "open"` drops queue/write failures after logging and metrics; `closed` returns the configured fail-closed HTTP response or stream close.

## Person Proof

`require_person_proof` is a request-phase anti-automation challenge. It is not authentication, identity proof, proof of biological or legal status, bot reputation, or proof of benign intent.

Public Person proof behavior is selected with `person_proof_mode`:

- `built_in`: OxiBelt built-in proof-of-work plus the built-in challenge frontend. This is the default and does not use `custom_frontend_url`.
- `openapi`: OxiBelt built-in proof-of-work session/verify/OpenAPI endpoints plus a custom challenge frontend. This requires `custom_frontend_url`.
- `third_party_provider`: OxiBelt built-in adapters for `third_party_provider = "turnstile" | "hcaptcha" | "friendly_captcha_v2"`. This requires `custom_frontend_url`, `third_party_provider`, `site_key`, and `secret_env`.
- `custom_provider`: custom JSON HTTP provider verification. This preserves the former custom provider capability under the new mode name, requires `custom_frontend_url` and `provider_endpoint`, and keeps `provider` as the custom provider identifier.

The PoW modes compute a nonce such that `SHA-256(session || "." || nonce)` has the configured number of leading zero bits. Successful verification issues the same signed `clearance.v2` token through the configured clearance target. Later requests validate the configured clearance sources and, when `single_use = true`, rotate the signed clearance credential instead of recomputing proof.

`custom_frontend_url` is not a filesystem path. It is an origin-relative URL routed by the same OxiBelt instance as the protected request. It can point at a static route asset, such as a route whose `static_root` contains `/person-proof/index.html`, or at a separate challenge frontend backend proxied by OxiBelt. When set, OxiBelt redirects the protected request to that URL and exposes only the general Person proof API paths in the redirect query. Browser-visible challenge code should call OxiBelt's `session`, `verify`, and optional `openapi` endpoints, not provider-native server APIs.

Global API path defaults are configured under `[waf.person_proof]`:

```toml
[waf.person_proof]
session_path = "/.oxibelt/person-proof/session"
verify_path = "/.oxibelt/person-proof/verify"
openapi_path = "/.oxibelt/person-proof/openapi.json"
```

Each `require_person_proof` action may override `session_path`, `verify_path`, and `openapi_path`. API paths must be origin-relative paths without query strings or fragments. `custom_frontend_url` may include a query string but not a fragment. If the same runtime path is used for different API roles, configuration fails closed; explicitly duplicated per-policy API paths are also rejected.

`GET openapi_path` returns a static OpenAPI 3.1 JSON document with the configured paths reflected in `paths` and `Cache-Control: no-store`.

When a protected request needs a custom challenge, OxiBelt responds with `challenge_redirect_status` and a `Location` that includes signed `session`, `session_path`, `verify_path`, `openapi_path`, `return_path`, and `expires_unix_ms` query parameters. Provider details such as CAPTCHA site keys are intentionally returned by `GET session_path?session=...` instead of being placed on the redirect URL.

Clearance storage and lookup are configured under each `require_person_proof` action. `clearance.sources` is the ordered list OxiBelt checks on protected requests. Source `type = "cookie"` reads the named cookie key from the `Cookie` header, `type = "authorization_bearer"` reads `Authorization: Bearer <token>`, and `type = "header"` reads the configured header key as the raw token. `clearance.issue_to = "cookie"` sends `Set-Cookie` after verification, `issue_to = "local_storage"` returns the token and localStorage metadata in the verify JSON so the browser can store it, and `issue_to = "response_json"` only returns the token in JSON for custom clients. OxiBelt cannot read browser localStorage directly, so localStorage mode uses `clearance.local_storage.request_header` as the follow-up request bridge; clients should also update the stored token from that response header when `single_use = true` rotates the clearance.

```toml
[[waf.rules.actions]]
type = "require_person_proof"
clearance.issue_to = "cookie" # cookie | local_storage | response_json

[[waf.rules.actions.clearance.sources]]
type = "cookie"
key = "__oxibelt_person_proof"

[[waf.rules.actions.clearance.sources]]
type = "authorization_bearer"

[[waf.rules.actions.clearance.sources]]
type = "header"
key = "X-OxiBelt-Person-Proof"

[waf.rules.actions.clearance.cookie]
key = "__oxibelt_person_proof"
path = "/"
same_site = "lax"
secure = true
http_only = true

[waf.rules.actions.clearance.local_storage]
key = "oxibelt.personProof"
request_header = "X-OxiBelt-Person-Proof"
```

`GET session_path?session=<signed-session>` returns JSON describing the challenge:

```json
{
  "session": "session.v1...",
  "person_proof_mode": "third_party_provider",
  "provider": "cloudflare-turnstile",
  "expires_unix_ms": 1700000000000,
  "return_path": "/protected",
  "verify_path": "/.oxibelt/person-proof/verify",
  "clearance": {
    "issue_to": "cookie",
    "cookie": {
      "key": "__oxibelt_person_proof",
      "path": "/",
      "same_site": "Lax",
      "secure": true,
      "http_only": true
    },
    "local_storage": {
      "key": "oxibelt.personProof",
      "request_header": "X-OxiBelt-Person-Proof"
    },
    "sources": [
      { "type": "cookie", "key": "__oxibelt_person_proof" }
    ]
  },
  "challenge": {
    "kind": "third_party_provider",
    "third_party_provider": "turnstile",
    "site_key": "0x4AAAA...",
    "metadata": {}
  }
}
```

PoW sessions for `built_in` and `openapi` use `challenge.kind = "pow_sha256_v1"` and include `difficulty` and `token`. The `token` is the signed session string that the client hashes with the nonce and submits to `verify_path`. Clearance delivery metadata is top-level `clearance`, not a token-internal field. `third_party_provider` sessions use `challenge.kind = "third_party_provider"` and include `third_party_provider`, `site_key`, and configured `provider_metadata`. `custom_provider` sessions use `challenge.kind = "custom_provider"` and return configured `provider_metadata`.

`POST verify_path` accepts `application/json`:

```json
{
  "session": "session.v1...",
  "response": {
    "token": "browser-or-provider-token",
    "fields": {}
  }
}
```

Successful verification returns `200 application/json` with `{ "ok": true, "return_path": "...", "clearance": { ... } }`. Cookie mode also sends a `Set-Cookie` header with the configured cookie key and attributes. LocalStorage and response-JSON modes include the `clearance.token`; localStorage mode also includes `clearance.local_storage.key` and `clearance.local_storage.request_header`. The frontend should store the token when required, then navigate to the signed `return_path`. Invalid or missing sessions return `403`, expired sessions return `410`, invalid responses return `403`, provider transport/API failure returns `503` unless `provider_fail_policy = "open"`, non-POST verify requests return `405`, non-JSON verify requests return `415`, and oversized verify bodies return `413`.

Default provider endpoints are:

- `turnstile`: `https://challenges.cloudflare.com/turnstile/v0/siteverify`
- `hcaptcha`: `https://api.hcaptcha.com/siteverify`
- `friendly_captcha_v2`: `https://global.frcapi.com/api/v2/captcha/siteverify`

Use `provider_endpoint` to override the default endpoint for EU, private, or test deployments. OxiBelt sends the secret from `secret_env`, the browser token as `response`, the configured `site_key` where the provider supports it, and the direct remote IP when `send_remote_ip = true`. Provider transport errors, timeouts, invalid JSON, or non-success HTTP status codes fail closed with `503` by default; set `provider_fail_policy = "open"` only when availability is more important than this anti-automation control.

`custom_provider` sends a JSON verification request to `provider_endpoint` and expects `{ "success": true }` or `{ "success": false, "error_codes": [] }`. The request includes the OxiBelt session, `person_proof_mode`, provider name, response token/fields, optional remote IP, optional site key, and configured metadata. Built-in Turnstile, hCaptcha, and Friendly Captcha HTTP shapes are adapter-internal and are not exposed to the browser-facing API.

Tokens are signed with a startup-local secret by default, or a shared cluster secret when `[shared_state].person_proof_backend` is configured. Session and clearance tokens bind the original host, mode, selected third-party or custom provider identity, request method, route, policy key, return path, API paths, clearance signing id, and token-binding hash.

Supported token bindings:

- `user_agent`: the `User-Agent` request header.
- `tls_fingerprint`: OxiBelt's downstream TLS fingerprint.
- `route`: the matched OxiBelt route name.
- `direct_peer_ip_network_prefix`: the direct peer IP prefix, not a forwarded-header value.
- `tcp_max_hop`: the configured TCP max-hop policy.

Defaults are `["user_agent", "route", "direct_peer_ip_network_prefix"]`, `/24` for IPv4, and `/56` for IPv6. Use `/32` and `/128` to bind to exact direct peer IPs.

When any policy sets `tcp_max_hop`, OxiBelt applies the strictest configured value listener-wide at accept time using Linux `IP_MINTTL` for IPv4 and `IPV6_MINHOPCOUNT` for IPv6. This is not route-local because the route is not known until after TLS and request parsing.

`single_use` defaults to `true`. When enabled, OxiBelt tracks verification-attempt and clearance reuse in memory by default, or in the configured Person proof shared backend when shared state is enabled. Challenge issuance itself does not reserve replay state. For Person proof API verification, the signed session is consumed before provider verification so a failed CAPTCHA/provider response cannot replay the same session into another provider call. It rotates the configured clearance credential after each valid request. LocalStorage clients should persist the rotated token from the configured request-header name in the protected response. Local in-memory state is bounded by `waf.limits.max_person_proof_reuse_tokens`; exhaustion fails closed with `429 Too Many Requests`.

`weigh_person_proof` and `allow_person_proof` are request-phase policy helpers for Anubis-style explicit rule sets. `weigh_person_proof` adds its integer `weight` to `Request.Client.PersonProof.Weight` for later request rules in the same transaction. `allow_person_proof` sets `Request.Client.PersonProof.Allowed = true`; later `require_person_proof` actions no-op while other actions, including `reject`, still run normally. OxiBelt does not challenge generic browser traffic by default: define the weights and terminal challenge rules you want explicitly.

```toml
[[waf.rules]]
name = "weigh-suspicious-automation"
phase = "request"
priority = 100
when = "Request.Client.UserAgent.contains('Headless')"

[[waf.rules.actions]]
type = "weigh_person_proof"
weight = 50

[[waf.rules]]
name = "allow-static-health"
phase = "request"
priority = 110
when = "Request.Http.Path == '/healthz'"

[[waf.rules.actions]]
type = "allow_person_proof"

[[waf.rules]]
name = "challenge-high-person-proof-weight"
phase = "request"
priority = 120
when = "Request.Client.PersonProof.Weight >= 50 && Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 18
token_validity_seconds = 300
clearance.cookie.key = "__oxibelt_person_proof"
```

Validation constraints:

- `person_proof_mode` must be `built_in`, `openapi`, `third_party_provider`, or `custom_provider`.
- `method`, `algorithm`, and `challenge_url` are no longer supported; use `person_proof_mode` and `custom_frontend_url`.
- `difficulty` must be between `1` and `30` for `built_in` and `openapi`.
- `token_validity_seconds` must be between `1` and `86400`.
- `ttl_seconds` and `token_ttl_seconds` are compatibility aliases.
- Flat `cookie` is no longer supported; use `clearance.cookie.key` and `clearance.sources`.
- `clearance.cookie.key` and cookie sources may contain only ASCII letters, digits, `_`, `-`, or `.`.
- `clearance.cookie.path` must be an origin path without control characters or `;`.
- Header sources and `clearance.local_storage.request_header` must be valid HTTP header names.
- `clearance.local_storage.key` must not be empty or contain control characters.
- `clearance.sources` must not be empty when `clearance.issue_to = "response_json"`.
- `token_bindings` must not be empty and may not contain duplicates.
- IPv4 prefix bits must be `0..32`; IPv6 prefix bits must be `0..128`.
- `tcp_max_hop`, when set, must be `0..255`.
- `token_bindings` containing `tcp_max_hop` must also set `tcp_max_hop`.
- `status` must be a valid HTTP status code.
- `custom_frontend_url`, when set, must be origin-relative and may include a query string but not a fragment.
- `challenge_redirect_status` must be `301`, `302`, `303`, `307`, or `308`; the default is `303`.
- `built_in` forbids `custom_frontend_url` and `third_party_provider`.
- `openapi` requires `custom_frontend_url` and forbids `third_party_provider`.
- `third_party_provider` requires `custom_frontend_url`, `third_party_provider`, `site_key`, and `secret_env`, and forbids `provider`.
- `custom_provider` requires `custom_frontend_url` and `provider_endpoint`.
- `session_path`, `verify_path`, and `openapi_path` must be origin-relative paths without query strings or fragments.
- `provider_endpoint`, when set, must use `http://` or `https://`.
- `provider_timeout_ms` and `provider_max_response_body_bytes` must be greater than zero.
- `weigh_person_proof.weight` must be between `-1000000` and `1000000`.

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

Field `value` may also be written as `expression`. Field expressions may read response-phase `Request`, `Response`, and `Context` values and may call the same scoped user-defined functions available to the matching WAF rule. They may evaluate to scalar JSON values (`Bool`, `Int`, `String`, or `Null`) or bounded JSON collections/objects exposed by the OxiRule object model, such as `Request.Headers`, `Request.QueryParams`, `Request.Cookies`, `Request.Tags`, `Context.RuleTags`, or `Request.Headers.getAll(...)`. Field names must match `[A-Za-z0-9_.-]{1,64}` and may not be `event` or `timestamp_unix_ms`. Fields that read request body bytes are rejected. Request-wide system access-log fields under `[logging.access_log]` use the OxiRule expression language but do not receive WAF user-defined functions in v1.

If `fields` is omitted, OxiBelt emits the default access-log field set. In that default set, `user_agent` is a bounded collection from `Request.Headers.getAll('User-Agent')`, so duplicate `User-Agent` headers are preserved instead of failing the whole log record.

## Object Model

Top-level objects:

```text
Context.Phase: 'request' | 'response' | 'stream'
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

```text
Stream.Protocol: 'websocket' | 'webtransport'
Stream.Direction: 'downstream_to_upstream' | 'upstream_to_downstream'
Stream.Unit: 'websocket_frame' | 'websocket_message' | 'webtransport_stream_chunk' | 'webtransport_datagram'
Stream.Payload: BodyView
Stream.WebSocket: WebSocketStreamMetadata
Stream.WebTransport: WebTransportStreamMetadata
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
PersonProofMetadata.Mode: String | Null
PersonProofMetadata.Difficulty: Int | Null
PersonProofMetadata.IssuedAtUnixMs: Int | Null
PersonProofMetadata.ExpiresAtUnixMs: Int | Null
PersonProofMetadata.Weight: Int
PersonProofMetadata.Allowed: Bool

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

`TcpMetadata.Mss` is populated from the accepted TCP socket's maximum segment size where the platform exposes it. `TcpMetadata.RttMs` is populated from Linux `TCP_INFO` RTT in milliseconds; unsupported platforms or socket option failures evaluate to `null`. `UdpMetadata.ConnectionId` is an OxiBelt-local QUIC connection identifier in the form `quinn-stable:<id>` when available. It is not the wire QUIC connection ID. Request-level `UdpMetadata.DatagramSize` is reserved because a single HTTP/3 request does not map cleanly to one UDP datagram; WebTransport datagram payload size is exposed separately as `Stream.WebTransport.DatagramSize`.

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
UpstreamMetadata.Name: String | Null
UpstreamMetadata.Pool: String | Null
UpstreamMetadata.Scheme: String | Null
UpstreamMetadata.ConnectTimeMs: Int | Null
UpstreamMetadata.FirstByteTimeMs: Int | Null
UpstreamMetadata.Error: UpstreamError | Null

UpstreamError.Code: 'dns_error' | 'connect_timeout' | 'connect_error' | 'tls_error' | 'read_timeout' | 'protocol_error'
UpstreamError.Message: String

WebSocketStreamMetadata.Opcode: 'continuation' | 'text' | 'binary' | 'close' | 'ping' | 'pong' | 'message'
WebSocketStreamMetadata.Fin: Bool
WebSocketStreamMetadata.IsControl: Bool
WebSocketStreamMetadata.MessageOpcode: 'text' | 'binary' | Null
WebSocketStreamMetadata.FramePayloadSize: Int

WebTransportStreamMetadata.StreamKind: 'bidi' | 'uni' | Null
WebTransportStreamMetadata.StreamId: Int | Null
WebTransportStreamMetadata.DatagramSize: Int | Null
```

`UpstreamMetadata.Name` is `Null` when no upstream was selected or the upstream is unknown. `UpstreamMetadata.Pool` is `Null` when no upstream pool was used. `UpstreamMetadata.Scheme` is `Null` when the upstream scheme is unknown.

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
- Some local endpoint fields, byte counters, request-level UDP datagram sizes, TCP socket metadata, and unavailable connection identifiers are reserved and may evaluate to `null`.

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

The same shape is supported for `Response.Body` in response-phase rules and `Stream.Payload` in stream-phase rules. Body content helpers are bounded by `waf.limits.max_body_inspection_bytes`; bytes beyond that prefix are replayed or forwarded but not inspected.

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
- WebSocket request rules apply to the HTTP upgrade request. Stream-phase rules inspect raw frames before forwarding, reject individual frame payloads larger than `waf.limits.max_body_inspection_bytes`, and reassemble text/binary messages up to that limit before releasing queued fragments.
- WebRTC signaling HTTP requests can be inspected when they pass through OxiBelt; TURN media payloads are forwarded by WebRTC TURN listeners outside OxiRule/WAF inspection.
- WebTransport over HTTP/3 exposes the CONNECT request as `Request.Protocol == 'webtransport'` with UDP/QUIC transport metadata. Stream-phase rules inspect WebTransport stream chunks and datagrams before forwarding. Stream IDs are exposed as `null` where the underlying crate API does not provide them.

## Validation Summary

OxiRule validation rejects:

- External `path` entries combined with inline `when`, `groups`, or `actions`, or rules without an effective condition.
- Duplicate rule names in the same scope.
- Duplicate non-empty public rule IDs.
- Duplicate rule group names in one scope, duplicate group references from one rule, or references to unknown rule groups.
- Invalid rule IDs, rule tags, transaction tag keys, or Person proof `success_tag` values.
- Multiple `merge_condition_as = "override"` condition fragments in one rule expansion.
- Invalid function names or parameters, duplicate function names in one scope, duplicate parameters, unknown function calls, arity mismatches, or recursive function call graphs.
- Unsupported phases, negative rule or action priorities, unsupported operators, unknown properties, or unknown built-in functions.
- Forbidden imperative constructs, callbacks, imports, or external I/O.
- Request-phase access to `Response`.
- Stream-phase access to `Response` or `Request.Body`.
- Response mutation actions in request-phase rules.
- Request routing actions in response-phase rules.
- Request, response, routing, rate-limit, tag, Person proof, and access-log actions in stream-phase rules.
- `close_stream` outside stream phase.
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
