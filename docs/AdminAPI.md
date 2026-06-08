# Admin API

OxiBelt exposes its authenticated control-plane API on the configured
`[admin]` listener. The canonical machine-readable contract is
`docs/admin-openapi.json`, an OpenAPI 3.1 document for the current
`/admin/v1/*` surface.

The running Admin listener serves the same contract and metadata through:

- `GET /admin/v1/openapi.json`
- `GET /admin/v1/capabilities`
- `GET /admin/v1/version`
- `GET /admin/v1/audit`

The three metadata endpoints require normal Admin bearer authentication and
`admin:ReadMetadata` through IPM. The resource names are
`metadata/openapi`, `metadata/capabilities`, and `metadata/version`, which map
to resources such as `oxibelt:<namespace>:admin:metadata/openapi`.
`GET /admin/v1/audit` requires `admin:ReadAudit` on `audit/admin`.

`/admin/v1/capabilities` reports the API version, package version, compiled
or configured Admin features, and request-size limits used by the Admin API.
`/admin/v1/version` reports the API version, package name, and package version.
Admin listener responses include `X-OxiBelt-Request-Id` and
`X-OxiBelt-API-Version`. Non-2xx Admin errors use a JSON envelope:
`{ "error": { "code": "...", "message": "...", "details": { ... } },
"request_id": "..." }`. `details` is omitted when there is no safe
operation hint to expose. Permission denials may include the checked IPM
`action` and resolved `resource`; ETag failures may include the `If-Match`
header name and expected ETag. Generation ETags are concurrency diagnostics,
not bearer secrets.

An opt-in `[admin.http3]` UDP listener is available for Admin WebTransport
operation event subscriptions. It requires Admin TLS with TLS 1.3 support and
does not replace the existing HTTP/1 Admin API contract.

Operationally large list endpoints opt in to pagination when `limit`, `cursor`,
`sort`, `order`, or `filter[...]` is present. The first implementation covers
`/admin/v1/dynamic-policies` and the IPM principal, credential, policy, and
binding lists. Existing calls without these query parameters keep returning the
full legacy array. Paginated responses preserve the existing array field and add
`pagination` with `limit`, `has_more`, optional opaque `next_cursor`, `sort`,
and `order`; cursors are bound to the endpoint and normalized query.

When `[admin.audit]` is enabled, `/admin/v1/audit` returns unified Admin
request audit records as `{ "audit": [...] }`; otherwise it returns `409`.
Records include actor, peer, method, path, authorization action/resource,
outcome, status, and a redacted request summary. Request bodies are summarized
with byte count, top-level JSON keys, and selected safe scalar fields, not
stored as raw payloads.

## Long-Running Operations

Admin operations can run control-plane work asynchronously without changing
existing endpoint behavior by default. The v1 runtime is process-local,
in-memory, and lost on restart. Supplying `Prefer: respond-async` to supported
source endpoints returns `202 Accepted` with the operation snapshot plus
`Location`, `Operation-Location`, and `Preference-Applied: respond-async`.
Operation IDs are canonical UUIDv4 values prefixed with `op_`, for example
`op_550e8400-e29b-41d4-a716-446655440000`.

Supported async kinds are `cache_warm`, `oxirule_replay`,
`diagnostics_preflight`, `support_bundle`, `dynamic_policy_import`,
`webtransport_snapshot`, and `webtransport_drain`.
Explicit creation uses `POST /admin/v1/operations` with `{ "kind": "...",
"request": { ... } }`; the request payload is the same shape as the matching
source endpoint. `dynamic_policy_import` still enforces `If-Match` at execution
time, so a stale ETag fails the operation without applying changes.

Operations can be listed, polled, cancelled, and watched:

- `GET /admin/v1/operations`
- `POST /admin/v1/operations`
- `GET /admin/v1/operations/{id}`
- `DELETE /admin/v1/operations/{id}`
- `GET /admin/v1/operations/{id}/events`
- `GET /admin/v1/operations/{id}/events/ws`
- `CONNECT /admin/v1/operations/{id}/events/wt` over Admin HTTP/3 WebTransport

`GET /events` streams `text/event-stream` by default, or newline-delimited JSON
with `?format=ndjson`. The stream envelope is intentionally compatible with
MCP Streamable HTTP-style event consumption, but OxiBelt does not expose a full
MCP JSON-RPC server. `GET /events/ws` upgrades to WebSocket and sends the same
event envelope as JSON text frames.

`CONNECT /events/wt` accepts an HTTP/3 WebTransport session when
`[admin.http3]` and `admin.operations.webtransport` are enabled. OxiBelt
opens one server-initiated unidirectional stream, writes NDJSON operation
events, replays stored history, emits heartbeat records, and closes the stream
after a terminal operation event. Datagrams and client-created WebTransport
streams are ignored in v1.

The creator may read their own operation over any event transport. Other
callers need `admin:ReadOperation` on `operation/<kind>/<id>` or
`operation/*`.

`webtransport_snapshot` returns active data-plane WebTransport sessions from
the process-local registry. `webtransport_drain` installs a drain rule for a
scope, rejects new matching sessions with `503`, waits for `grace_ms` or
`runtime.drain.long_connection_close_delay_ms`, and closes remaining matching
sessions. Cancelling the drain removes the rule but does not restore sessions
already closed.

## Resource Scoping

Admin authorization uses `oxibelt:<namespace>:<service>:<resource>` resource
names. Resource components derived from operator input are normalized where the
domain requires it, such as cache hosts, and reserved characters are
percent-encoded before matching. Some mutating endpoints require more than one
resource grant before any state change or warm/probe-like work starts.

Resource-specific Admin/IPM resources include:

- cache: `policy/<policy>` and `host/<normalized-host>`
- operations: `operation/*` or `operation/<kind>/<id>`
- runtime WebTransport: `webtransport/session/*`,
  `webtransport/session/<id>`, `webtransport/route/<route>`,
  `webtransport/upstream/<upstream>`, or `webtransport/client-ip/<ip>`
- WAF Person proof: `person-proof/status`, `person-proof/clearance/*`,
  and `person-proof/clearance/<sha256>`
- dynamic policy: `status/current`, `source/<source>/name/<name>`, and
  `route/<route>`
- upstream pool: `status/current`, `<pool>`, and `<pool>/server/<server_id>`
- IPM: `status/current`, `principal/<id>`, `credential/<id>`,
  `policy/<name>`, `binding/<id>`, `group/<group>`, `audit/current`, and
  `simulation/current`

Cache purge, key-explain, and warm operations check the effective cache policy
and the normalized host. Cache warm derives that policy from the same
synthesized request context used for execution, including `Host`, trusted
Real-IP, and scheme-derived TLS metadata. Tag purge without a host checks
`host/*`. Dynamic policy create, apply, import, patch, and delete operations
check the `source/<source>/name/<name>` target and, when present, the
`route/<route>` target. Upstream server mutations check
`<pool>/server/<server_id>`. IPM
credential assignment checks both the credential and target principal; binding
create checks the binding, target principal or group, and policy.
Person proof status checks `person-proof/status`, clearance listing checks
`person-proof/clearance/*`, and exact revocation checks the normalized
`person-proof/clearance/<sha256>` resource before state lookup or mutation.
`POST /admin/v1/ipm/simulate` uses the same `simulation/current` resource.
Current-actor checks require `ipm:SimulateSelf`; target principal, credential,
subject, or group overrides require `ipm:SimulatePrincipal` plus the referenced
target resources; inline policy or binding overlays require `ipm:SimulatePolicy`
plus the touched policy, binding, principal, or group resources.

The legacy signed query purge endpoints under `/cache/purge*` are documented
in `docs/Configuration.md`; they are intentionally outside the first
`/admin/v1/*` OpenAPI contract.

`oxibelt-gateway-controller` uses the existing `GET /admin/v1/config/status`
and `POST /admin/v1/files/sync` endpoints. It fetches the active config ETag,
writes only its managed config-root include file, and sends `apply = "full"` so
OxiBelt validates and loads the replacement runtime view. The controller does
not build candidates from redacted effective config output.

## Person Proof Administration

`GET /admin/v1/waf/person-proof/status` returns aggregate Person proof policy
and replay-store state. `GET /admin/v1/waf/person-proof/clearances` lists only
hash-keyed active clearance identifiers in canonical `clearance:<sha256>` form
with expiry metadata. `POST /admin/v1/waf/person-proof/clearances/revoke`
accepts only a bare SHA-256 value or canonical `clearance:<sha256>` value and
creates an exact-match revocation tombstone.

These endpoints never return raw session material, raw clearance credentials,
provider responses, token-binding payloads, MACs, or the shared Person proof
HMAC secret. Legacy raw-keyed replay markers created by older versions remain
honored until expiry for replay protection, but Admin responses expose them
only as aggregate legacy counts. In process-local mode the operation affects
only the current snapshot; with a configured Person proof shared-state backend
it applies through that shared backend. Revocation targets one exact clearance
hash, not a browser, user, route, or future rotated clearance.

## IPM Administration

`GET /admin/v1/ipm/status` returns the active IPM `generation`, `etag`,
static/store object counts, and the last refresh result. Mutating IPM
endpoints require `If-Match` with this ETag; missing ETags return `428`, stale
ETags return `412`.

`GET /admin/v1/dynamic-policies/status` returns the dynamic-policy PostgreSQL
generation and ETag. Create, import, patch, and delete require matching
`If-Match`; `apply` keeps its panic-button behavior and enforces `If-Match`
only when the caller supplies it. `GET /admin/v1/upstream-pools/status`
returns the upstream-pool runtime generation and ETag required by server
mutations.
`GET /admin/v1/upstream-pools` and `GET /admin/v1/upstream-pools/{pool}`
remain protected by the existing upstream-pool IPM actions and include runtime
server details such as `health_reason`, `last_health_check_ms`,
`ejected_until_ms`, `ejection_count`, `slow_start_remaining_ms`, and
`effective_weight_percent`.
`GET /admin/v1/stream-pools/status` returns the stream-pool runtime generation
and ETag required by TCP/UDP stream server mutations. `GET
/admin/v1/stream-pools` and `GET /admin/v1/stream-pools/{pool}` are protected
by `stream-pool:List` and `stream-pool:Get`; `POST`, `PATCH`, and `DELETE`
under `/admin/v1/stream-pools/{pool}/servers...` require the matching
`stream-pool:AddServer`, `stream-pool:UpdateServer`, or
`stream-pool:RemoveServer` action on `<pool>/server/<server_id>` plus
`If-Match` with the current stream-pool ETag.

When `[ipm].backend` resolves to a PostgreSQL shared-state backend, OxiBelt
loads a strict hybrid IPM snapshot from TOML plus `oxibelt_ipm_*` tables. TOML
entries remain visible with `source = "config"` and are read-only. Store
entries use `source = "store"` and can be managed through:

- principals: `GET/POST /admin/v1/ipm/principals`,
  `GET/PATCH/DELETE /admin/v1/ipm/principals/{id}`
- credentials: `GET/POST /admin/v1/ipm/credentials`,
  `GET/PATCH/DELETE /admin/v1/ipm/credentials/{id}`,
  `POST /admin/v1/ipm/credentials/{id}/rotate`,
  `POST /admin/v1/ipm/credentials/{id}/revoke`
- policies: `GET/POST /admin/v1/ipm/policies`,
  `GET/PATCH/DELETE /admin/v1/ipm/policies/{id}`
- bindings: `GET/POST /admin/v1/ipm/bindings`,
  `DELETE /admin/v1/ipm/bindings/{id}`
- audit: `GET /admin/v1/ipm/audit`
- simulation: `POST /admin/v1/ipm/simulate`

If no PostgreSQL IPM store is configured, list/get endpoints keep serving the
static TOML snapshot and mutation endpoints return `409`. Store refresh is
generation-based and keeps the last-good snapshot if the DB rows fail strict
validation, including any ID conflict with TOML principals, credentials,
policies, or bindings.

Credential create and rotate responses return a new `obt_v1_<base64url>` token
exactly once. OxiBelt stores only a `sha256-v1` digest plus token prefix. Rotate
keeps the previous token valid until `previous_token_overlap_until`; revoke and
delete clear regular access subject to lockout prevention.

`/admin/v1/ipm/simulate` accepts `action` and `resource` for a self check, plus
optional `target`, `context`, and `overlay` objects. `target.principal` resolves
an active principal; `target.credential` resolves the credential's principal and
actor name only when the credential is active; `target.subject` and
`target.groups` override only the simulated actor. OxiBelt authorizes named
target and overlay resources before resolving them so scoped callers cannot use
validation errors to enumerate IPM objects. If `context` is omitted, OxiBelt
evaluates with the current Admin request context; if it is supplied, only the
supplied context fields participate. Simulation responses list context
`claim_keys` but do not echo claim values.
`overlay.policies` and `overlay.bindings` are applied to an in-memory snapshot
for the single request and are never persisted.
