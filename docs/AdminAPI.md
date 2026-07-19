# Admin API

OxiBelt exposes its authenticated control-plane API on the configured
`[admin]` listener. The canonical machine-readable contract is
`source/assets/admin-openapi.json`, an OpenAPI 3.1 document for the current
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
An unavailable PostgreSQL store, query failure, or invalid stored record
returns `503`; it never falls back to stdout/OTLP history.

New rows use `schema_version = "oxibelt.admin.audit/v1"`. Each returned v1
record contains its database `id` and namespace plus occurrence `timestamp`
and `timestamp_unix_ms`, event and instance IDs, `intent` or `terminal` phase,
server request ID and optional mutation request ID, actor/principal/workload and
credential identity, peer and canonical source address, method/path/service,
operation and durability action, authorization resource/target, optional
previous and desired revisions and content digest, HTTP status, result/outcome,
stable error code, redacted summary, integrity envelope, and database
`created_at`. `result` is `accepted`, `applied`, `rejected`, or
`indeterminate`. The integrity envelope identifies `sha256` or `hmac_sha256`,
chain ID, sequence, previous and current event hashes, and optional HMAC key ID
and tag.

Rows created before this schema remain visible as `legacy-v0`. They retain the
same response envelope and historical fields, while unavailable v1 fields are
`null` and no integrity proof is invented. Request bodies are summarized with
byte count, top-level JSON keys, and selected safe scalar fields; raw bodies,
tokens, certificates, signatures, keys, and arbitrary internal errors are not
stored. Query filters are `limit`, `outcome`, `actor`, `principal`, `service`,
`operation`, `request_id`, `path_prefix`, and `before_id`.

## Long-Running Operations

Admin operations can run control-plane work asynchronously without changing
existing endpoint behavior by default. With
`admin.operations.persistence = "postgres"`, or when `"auto"` can activate a
suitable PostgreSQL shared-state backend and enforcing Admin audit on that same
backend, long-running operation status is journaled and remains queryable across
process restarts. `"ephemeral"` keeps the bounded process-local behavior. An
`"auto"` activation failure is visible and falls back to ephemeral operation
status; an explicitly configured PostgreSQL mode fails closed at startup.
`GET /admin/v1/capabilities` reports the configured and effective operation
persistence modes plus a fixed-vocabulary fallback reason when automatic
activation selected ephemeral mode.

Supplying `Prefer: respond-async` to supported source endpoints returns `202
Accepted` with the operation snapshot plus
`Location`, `Operation-Location`, and `Preference-Applied: respond-async`.
Operation IDs are canonical UUIDv4 values prefixed with `op_`, for example
`op_550e8400-e29b-41d4-a716-446655440000`.

Every snapshot reports `durability` (`durable` or `ephemeral`), its recovery
class, schema version, and monotonic revision. Durable states are `accepted`,
`queued`, `claimed`, `running`, `cancellation_requested`, `compensating`,
`succeeded`, `failed`, `cancelled`, and `indeterminate`. Terminal durable
snapshots include a stable versioned receipt. A crash with ambiguous side
effects is recovered according to the operation's declared recovery class and
becomes `indeterminate` when success cannot be proved; it is never synthesized
as success.

Supported async kinds are `cache_warm`, `oxirule_replay`,
`diagnostics_preflight`, `support_bundle`, `dynamic_policy_import`,
`webtransport_snapshot`, and `webtransport_drain`.
Explicit creation uses `POST /admin/v1/operations` with `{ "kind": "...",
"request": { ... } }`; the request payload is the same shape as the matching
source endpoint. `dynamic_policy_import` still enforces `If-Match` at execution
time, so a stale ETag fails the operation without applying changes.
An optional `Idempotency-Key` contains 1 to 128 visible ASCII bytes. In durable
mode it is stored only as a domain-separated keyed digest and replays the
original operation and terminal receipt when the authenticated principal,
permission action, and canonical request fingerprint match. Reusing the same
key for a different request is rejected as a conflict.

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
the process-local registry and therefore remains explicitly ephemeral.
`webtransport_drain` installs a process-local drain rule for a
scope, rejects new matching sessions with `503`, waits for `grace_ms` or
`runtime.drain.long_connection_close_delay_ms`, and closes remaining matching
sessions; it also remains explicitly ephemeral. Cancelling the drain removes
the rule but does not restore sessions already closed.

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

`[admin.mutations.rollout] mode = "admin_cluster"` enables the PostgreSQL-backed
fixed-member rollout authority. It requires mutation mode `required`, matching
process rollout mode, disabled hot reload, two through 1,024 unique configured
members, a local instance ID in that set, and one shared 32-byte artifact key.
The configured membership is an all-member policy boundary; there is no
majority-quorum mode.

The winning request is durably claimed with its exact encrypted command and
target set. Every configured member validates the candidate, the deterministic
canary applies and remains ready for the observation interval, and only then do
the remaining members apply. The normal endpoint response cannot return a
successful status until PostgreSQL contains an exact revision-and-digest ACK
from every configured member. Ordinary requests wait up to 30 seconds for that
terminal proof; if the rollout remains active they return
`409 mutation_in_progress` with `Location` and `Retry-After`. Clients can inspect
the redacted receipt at that location, and a disconnect does not cancel an
ordinary durable rollout. Credential create/rotate is the bounded exception:
because its plaintext token is neither durable nor replayable, the winning
request remains open for a rollout-derived bound covering forward phases,
rollback, and lease loss. Its request-scoped response owner must remain live
through commit; disconnect, process restart, or owner loss forces failure before
effect or durable rollback instead of committing an unrecoverable credential.

A NACK, timeout, readiness loss, or revision/digest mismatch rolls back every
member that may have applied. If neither convergence nor restoration can be
proved, the receipt becomes `indeterminate` and further protected writes remain
blocked. Member and coordinator authority is fenced by cluster, membership,
instance, boot, database epoch/lease, logical revision, and artifact digest;
restart recovery uses the durable assignments rather than an in-memory queue.
Configuration, file, downstream-TLS, key, and secret-reference operations execute per member.
IPM and break-glass updates are staged once in PostgreSQL, published after every
member validates, observed by the deterministic canary before the remaining
members, and committed only after every exact member ACKs the published
revision and digest. Failure restores the encrypted before-image once; an
unprovable restoration is `indeterminate`. For secret references, every member
resolves and preflights the complete candidate set and durably reports the same
reference-set digest and assigned runtime revision before canary selection.

`GET /admin/v1/config/instances` reports the configured membership, membership
revision, durable authority state, a safe blocking reason, active rollout
summary, and bounded per-instance configured/live/ready/compatible evidence.
It is an operational diagnostic view; the mutation's guarded terminal
transaction, not this read response, is the convergence authority.

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

In `admin_cluster` mode, receipt phases and member summaries are durable and
bounded. `committed` means all exact configured targets ACKed the same signed
revision and digest under current fencing evidence. `rollback_failed` means a
member explicitly failed restoration; `indeterminate` means OxiBelt could not
prove either the candidate or previous revision cluster-wide. Neither state is
automatically retried or treated as success.

Credential creation and rotation return plaintext token material only from the
first successful execution. An exact replay returns only the reduced safe
result with `token_recoverable = false`; the mutation revision remains in the
response header. It neither rotates again nor stores or re-emits the token.

`POST /admin/v1/keys/rotate` supports only the configured default or SNI
downstream TLS key path. It verifies a digest-pinned, pre-provisioned file and
reloads downstream TLS; it does not accept private-key bytes. Admin TLS, QUIC
host-key, and remote-signer activation are not advertised by this release.
`POST /admin/v1/config/secret-references/update` accepts schema version `1`
(omission defaults to `1`), one typed allowlisted `field`, and an environment
variable name or contained file `reference`; file references also require a
lowercase SHA-256 pin. It rejects raw secret values. OxiBelt resolves the full
active reference set into protected candidate-owned buffers, validates size and
type, rebuilds dependent TLS and client runtimes, validates certificate lifetime,
SAN coverage, CA parsing, and key pairing, and performs a bounded TLS handshake
for an affected configured HTTPS provider. Only a complete candidate is installed
with one compare-and-swap operation. A failure or competing mutation leaves the
old snapshot active.

A successful response and replay-safe receipt contain only `request_id`,
`config_logical_revision`, `reference_set_digest`,
`runtime_snapshot_revision`, and `target_revision`; references, environment
values, file paths, and plaintext material are not returned or written to the
mutation ledger. Stable `secret_*` error codes identify the rejected phase
without provider details. The prior snapshot remains rollback-capable for a
bounded connection-drain grace period and is then dropped. In Kubernetes
immutable rollout mode the endpoint returns `409 immutable_rollout_conflict`. In
`[ipm.break_glass] access_mode = "two_factor_activation"`, an inactive
break-glass credential can access only its self-status and activation route;
activation additionally requires a signer bound to that principal and creates
a bounded database-timed grant. Replaying an activation never extends it.

Prometheus exposes fixed, unlabeled
`oxibelt_secret_reference_activation_applied_total`,
`oxibelt_secret_reference_activation_rejected_total`, and
`oxibelt_secret_reference_activation_rollback_total` counters. They contain no
field, provider, reference, path, or material labels.

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
