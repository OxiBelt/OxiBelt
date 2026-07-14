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

The three metadata endpoints require normal Admin bearer authentication by
default and `admin:ReadMetadata` through IPM. When
`[admin.workload_identity].enabled = true`, verified Admin mTLS certificate
identity is mapped to one IPM principal and a supplied bearer credential must
map to that same principal; `bearer_mode = "optional"` also permits the mapped
certificate alone. The resource names are
`metadata/openapi`, `metadata/capabilities`, and `metadata/version`, which map
to resources such as `oxibelt:<namespace>:admin:metadata/openapi`.
`GET /admin/v1/audit` requires `admin:ReadAudit` on `audit/admin`.

`/admin/v1/capabilities` reports the API version, package version, compiled
or configured Admin features, active mTLS workload-identity binding mode, and
request-size limits used by the Admin API.
`features.admin_mutation_replay` is true when `[admin.mutations]` is in
`optional` or `required` mode.
`/admin/v1/version` reports the API version, package name, and package version.
Admin listener responses include `X-OxiBelt-Request-Id` and
`X-OxiBelt-API-Version`. Non-2xx Admin errors use a JSON envelope:
`{ "error": { "code": "...", "message": "...", "details": { ... } },
"request_id": "..." }`. `details` is omitted when there is no safe
operation hint to expose. Permission denials may include the checked IPM
`action` and resolved `resource`; ETag failures may include the `If-Match`
header name and expected ETag. Generation ETags are concurrency diagnostics,
not bearer secrets.

Successful protected mutation executions and terminal replay responses include
`X-OxiBelt-Mutation-Request-Id`, `X-OxiBelt-Mutation-Revision`, and
`X-OxiBelt-Idempotent-Replay`. The mutation request ID is supplied by the
caller and is distinct from the server-generated `X-OxiBelt-Request-Id` audit
correlation ID.

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

`/admin/v1/audit` returns unified Admin request audit records from the durable
Admin audit store as `{ "audit": [...] }`. The endpoint requires
`[admin.audit.store]` with a PostgreSQL backend; export-only stdout or OTLP
Admin audit configurations return `409` because exports are not query stores.
Records include actor, peer, method, path, authorization action/resource,
outcome, status, and a redacted request summary. With mTLS workload binding,
they also include the workload identity, mapped principal, leaf fingerprint,
credential identity, and fixed authentication reason. Request bodies are summarized
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
- protected mutations: `admin:ReadMutations` on `mutation/<request_id>` and
  `config:GetInstances` on `instances/current`
- typed mutation resources: `config:RotateKey` on
  `key/<target>/<name-or-default>` and `config:UpdateSecretReference` on
  `secret-reference/<encoded-field>`
- break glass: `ipm:GetBreakGlassActivation` and
  `ipm:ActivateBreakGlass` on `break-glass/principal/<principal>`, and
  `ipm:RevokeBreakGlass` on `break-glass/activation/<activation_id>`

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

`oxibelt-gateway-controller` does not use the Admin API as a cluster rollout
transport. It publishes a Kubernetes immutable ConfigMap, updates the selected
workload, and relies on per-Pod revision/digest proof. In
`kubernetes_immutable` deployment mode, `POST /admin/v1/config/load`,
`POST /admin/v1/config/rollback`, `POST /admin/v1/files/sync`, and
`POST /admin/v1/tls/downstream/reload` return `409` so one Pod cannot diverge
from its assigned revision. Read-only status, effective-config, validation, and
diff endpoints remain available to operators.

`[admin.mutations.rollout] mode = "admin_cluster"` is reserved for a future
fixed-member rollout authority. Configuration validation rejects selecting the
mode. A defense-in-depth request-path guard also returns `503` if such a runtime
is constructed; this release does not claim distributed validation, apply,
acknowledgement, or rollback. `single_instance` is the supported P1-13 runtime.
`GET /admin/v1/config/instances` exposes only the bounded configured-member and
live-heartbeat diagnostic view; it is not convergence proof.

## Protected Mutations

When `[admin.mutations].mode = "required"`, each high-risk request must carry
`X-OxiBelt-Mutation`. The header value is unpadded base64url containing a
strict JSON object with `version`, `signer_id`, canonical UUID `request_id`,
RFC 3339 UTC `issued_at` and `expires_at`, `expected_previous_revision`,
`new_revision`, exact-body `content_digest`, required `target`, and
`signature`. Single-instance mode uses its deterministic local target. The
supported signature suites are `ed25519` and, when the
post-quantum build feature is present, the fail-closed hybrid
`ed25519_ml_dsa_44`. A hybrid envelope must contain valid Ed25519 and ML-DSA-44
signatures over the same suite-bound transcript; it never downgrades to one
signature.

The signed transcript binds the signer, IPM namespace, authenticated principal,
HTTP method, exact path and query, normalized strong `If-Match`, timestamps,
logical revisions, target, and
`sha256:<lowercase-hex>` digest of the exact transmitted body bytes. Unknown or
duplicate envelope fields, an expired request, excessive validity, a signer
not bound to the authenticated principal, an invalid signature, or a digest
mismatch is rejected before mutation. The envelope does not replace ordinary
bearer/mTLS authentication, IPM authorization, request limits, or `If-Match`.

The protected families are configuration load and rollback, file sync,
downstream TLS reload, downstream TLS key reload, submitted secret-reference
update, every IPM principal/credential/policy/binding write, credential rotation
and revocation, and break-glass activation or revocation. The single strong
quoted `If-Match` value is normalized, required to equal the current operational
ETag, and included in the signed transcript. The distinct signed
`expected_previous_revision` is compared with the PostgreSQL mutation ledger's
logical head; a successful terminal receipt advances that head to the signed
`new_revision`. The first logical head is initialized from the active
operational revision. Missing mutation metadata or `If-Match` returns `428`;
invalid or expired metadata returns `400`; invalid
signer authentication returns `401`; stale revisions, conflicting request-ID
reuse, or an unresolved prior attempt return `409`; an unavailable replay,
audit, or rollout store returns `503`.

The PostgreSQL mutation ledger is the idempotency authority. An exact retry of
the same request ID, fingerprint, actor, and target returns a reduced, bounded
safe result with the retained HTTP status and
`X-OxiBelt-Idempotent-Replay: true`, without reapplying the change. This replay
body is intentionally not necessarily byte-for-byte equal to the first
response. Reusing the ID for any different request returns `409`. A request
whose commit outcome cannot be proved remains indeterminate and cannot be
automatically retried. `GET /admin/v1/mutations/{request_id}` exposes a bounded,
redacted receipt; it never returns raw bodies, credentials, signatures, private
keys, or secret values.

Credential creation and rotation return plaintext token material only from the
first successful execution. An exact replay returns only the reduced safe
result with `token_recoverable = false`; the mutation revision remains in the
response header. It neither rotates again nor stores or re-emits the token.

`POST /admin/v1/keys/rotate` supports only the configured default or SNI
downstream TLS key path. It verifies a digest-pinned, pre-provisioned file and
reloads downstream TLS; it does not accept private-key bytes. Admin TLS, QUIC
host-key, and remote-signer activation are not advertised by this release.
`POST /admin/v1/config/secret-references/update` validates its typed allowlist
and rejects raw secret values, but no atomic runtime activation slot exists, so
the current endpoint is fail-closed and returns `409` without changing state. In
`[ipm.break_glass] access_mode = "two_factor_activation"`, an inactive
break-glass credential can access only its self-status and activation route;
activation additionally requires a signer bound to that principal and creates
a bounded database-timed grant. Replaying an activation never extends it.

## Person Proof Administration

`GET /admin/v1/waf/person-proof/status` returns aggregate Person proof policy
and replay-store state. `GET /admin/v1/waf/person-proof/clearances` lists only
hash-keyed active clearance identifiers in canonical `clearance:<sha256>` form
with expiry metadata. Shared-backend clearance pagination returns an opaque,
versioned cursor bound to the shared-state namespace and scan position; invalid
or cross-namespace cursors return `400`, and clients should discard cursors
after a backend or deployment change. Authorization is checked before cursor
parsing or shared-state enumeration. A shared status operation that cannot
finish its complete scan inside its configured bound returns `503`, never a
partial aggregate count. Clearance listing always returns only its bounded page
plus a continuation cursor.
`POST /admin/v1/waf/person-proof/clearances/revoke` accepts only a bare SHA-256
value or canonical `clearance:<sha256>` value and creates an exact-match
revocation tombstone. It optionally accepts exactly one `Idempotency-Key`
header containing 1 through 128 visible ASCII characters. OxiBelt retains only
the SHA-256 digest of that key. While the revocation tombstone remains active
(at most 24 hours), repeating the same key with the same normalized clearance
hash and the same supplied `ttl_seconds` representation (omitted and explicit
values are distinct) returns the original response, including its original
expiry. Reusing the key with a different request returns `409`; malformed or
repeated headers return `400`; and a configured shared backend that cannot
commit the operation returns `503`. This retry contract is intentionally scoped
to this one Person proof mutation and does not make other Admin writes
idempotent. Process-local mode bounds live replay records; when that bound is
full, a new keyed mutation returns `503` rather than evicting a still-live
record.

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
ETags return `412`. When mutation protection is required, these endpoints also
require `X-OxiBelt-Mutation`; the PostgreSQL transaction rechecks the expected
generation after locking so two writers cannot both commit from one revision.

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
delete clear regular access subject to lockout prevention. An exact mutation
replay returns the reduced retained safe result with
`token_recoverable = false`; it never rotates again or re-emits the plaintext
token. The signed new logical revision remains available in the mutation
response header and receipt.

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
