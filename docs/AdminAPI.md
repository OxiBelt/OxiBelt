# Admin API

This API is present in the compatibility `oxibelt` package and the standalone
and `dataplane` images. The optional `oxibelt-dataplane-strict` package and
image do not compile or embed the Admin listener, mutation/operation runtime,
or this OpenAPI asset. Deploy a compatibility artifact when any endpoint in
this document is required.

Admin API image roles: with Admin and its OpenAPI asset: `standalone`, `dataplane`; without Admin and its OpenAPI asset: `dataplane-strict`, `controller`, `tools`, `keysigner`.

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
`features.atomic_secret_reference_activation` is true in mutable
`single_instance` and fixed-member `admin_cluster` modes and false in
`kubernetes_immutable` mode.
`features.admin_audit_anchoring` is true when external audit anchoring is
configured. The top-level `audit_anchoring` object reports `enabled`, the
effective `policy` (`disabled`, `best_effort`, or `required`), runtime `state`
(`disabled`, `healthy`, `degraded`, or `failed`), optional
`last_anchored_sequence`, and bounded local `pending_checkpoints` and
`pending_bytes`. These values expose operational progress without returning
the authority URL, credentials, signer socket/token, event content, or key
material.
`/admin/v1/version` reports the API version, package name, effective build
version, exact source revision or `unknown`, full source ref or `unknown`,
tracked-tree state (`clean`, `dirty`, or `unknown`), and build kind
(`official_release`, `tagged_development`, `git_development`, or
`source_archive`). `package_version` is the effective OxiBelt version and is
never inferred from Cargo's private `0.0.0` workspace sentinel. Runtime
snapshot and runtime-introspection format version `2`, plus support-bundle
format version `3`, carry the same `package_version`, `source_revision`,
`source_ref`, `source_dirty`, and `build_kind` metadata together with the
resolved runtime topology and bounded hardening evidence. The
unauthenticated health endpoints intentionally omit build identity; use these
authenticated metadata surfaces for inventory.
Admin listener responses include `X-OxiBelt-Request-Id` and
`X-OxiBelt-API-Version`. Non-2xx Admin errors use a JSON envelope:
`{ "error": { "code": "...", "message": "...", "details": { ... } },
"request_id": "..." }`. `details` is omitted when there is no safe
operation hint to expose. Permission denials may include the checked IPM
`action` and resolved `resource`; ETag failures may include the `If-Match`
header name and expected ETag. Generation ETags are concurrency diagnostics,
not bearer secrets.

## Runtime topology and capability resolution

Authenticated runtime snapshot, runtime introspection, and redacted support
bundle responses expose a shared version-`2` `runtime_topology` object. It
reports the requested and resolved main-runtime presets, `topology_policy`,
resolution outcome and fixed reason, subsystem owners, worker allocations,
blocking strategy, compatibility boundaries, and requested, resolved, and
active direct-H1 state. A resolved `hybrid_compio` preset truthfully reports a
Compio bootstrap boundary and Tokio ownership of listener, general HTTP,
HTTP/3 and QUIC, DNS/discovery, timer, and background/control work; it reports
Compio direct-H1 ownership only when that experimental service is active.

- `GET /admin/v1/runtime/snapshot?redact=true` requires
  `runtime:ReadSnapshot` on `runtime:snapshot/current` and returns the active
  generation's redacted runtime snapshot.
- `GET /admin/v1/runtime/introspection?redact=true` requires
  `runtime:ReadIntrospection` on `runtime:introspection/current` and adds live
  connection, request, stream, tunnel, and flow counters.
- `GET /admin/v1/diagnostics/support-bundle?redact=true` requires
  `diagnostics:ReadSupportBundle` and embeds the same active-generation
  topology.
- `GET /admin/v1/config/explain` uses config-report format version `3` and
  reports the active topology with `basis = "active"`; offline config explain
  uses `basis = "preflight"` and does not claim activation.

The fixed outcome vocabulary is `exact`, `fallback`, `rejected`, and
`feature_disabled`. A `require_exact` candidate that cannot be activated is
rejected instead of publishing a degraded topology. These surfaces omit raw
capability-probe errors, paths, hostnames, routes, peers, configuration secret
values, and credentials.

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

## Independent audit-anchor verification

`oxibeltctl audit verify` is a local verification workflow; it does not call
the Admin listener and does not use an Admin bearer credential. It opens one
read-only connection to the local Admin audit PostgreSQL database and one to
the external checkpoint authority, verifies the local event hash chains,
validates every checkpoint's Ed25519 signature and predecessor/sequence
continuity, checks the authority head, and proves checkpoint chain heads exist
in the corresponding local chain. It also compares the result with a durable
verifier witness so rollback of checkpoints seen by a previous verification
run is detectable.

The expected-stream manifest is deployment-owned evidence. It must name every
replica/stream that should exist; do not derive this set from the authority
being verified. Its schema is:

```json
{
  "schema_version": "oxibelt.admin.audit.expected-streams/v1",
  "namespace": "oxibelt",
  "streams": [
    {
      "stream_id": "sha256:<64-lowercase-hex>",
      "instance_id": "edge-0",
      "cluster_id": "edge-admin",
      "accepted_epoch_history": [
        {
          "membership_epoch": "membership-41",
          "deployment_epoch": "deploy-2026-07-18"
        }
      ],
      "membership_epoch": "membership-42",
      "deployment_epoch": "deploy-2026-07-19",
      "signing_key_schedule": [
        {
          "key_id": "audit-anchor-2026-07",
          "first_checkpoint_ordinal": 1,
          "last_checkpoint_ordinal": 812
        },
        {
          "key_id": "audit-anchor-2026-08",
          "first_checkpoint_ordinal": 813
        }
      ]
    }
  ]
}
```

`accepted_epoch_history` is optional and contains at most 1024 unique
membership/deployment pairs ordered oldest to newest. The top-level
`membership_epoch` and `deployment_epoch` are the current pair and must not be
duplicated in the history. Checkpoints may remain in one stream across those
declared transitions, but their epoch position may only stay the same or move
forward; an undeclared or backward transition is invalid. Preserve every
historical pair still represented by retained checkpoints. For standalone
instances, omit `cluster_id` and use the literal `single_instance` membership
epoch. Supply every trusted checkpoint key during an overlap/rotation window.
Each key file must contain exactly 32 raw Ed25519 public-key bytes, and its
`KEY_ID` must match checkpoint metadata.

`signing_key_schedule` is required, deployment-owned policy. It contains at
most 1024 non-overlapping, ordinal-contiguous ranges beginning at checkpoint
ordinal 1. Every non-final range has an inclusive
`last_checkpoint_ordinal`; only the final range may remain open. A key ID may
appear once, so a retired key cannot be reactivated. Before rotation, record
the current witnessed authority ordinal as the old key's inclusive end and
activate the new key at the next ordinal in both the manifest and deployment.
Merely retaining an old public key for historical verification does not
authorize it for new checkpoints.

If the local audit chain uses `hmac_sha256`, also supply every retained local
integrity key as `--trusted-hmac-key KEY_ID=FILE`. Each file contains exactly
32 raw secret bytes, must not be accessible by group or other users, and is
used only to authenticate the local event tags; it is separate from the public
checkpoint-signing trust set. Missing historical HMAC material makes the
report `incomplete`, while a mismatched tag makes it `invalid`. Keep these
files on the verifier host or its secret provider, not on the checkpoint
authority.

```sh
export OXIBELT_AUDIT_VERIFY_LOCAL_POSTGRES_URL='postgresql://...'
export OXIBELT_AUDIT_VERIFY_ANCHOR_POSTGRES_URL='postgresql://...'

oxibeltctl --output json audit verify \
  --expected-streams /secure/audit/expected-streams.json \
  --trusted-key audit-anchor-2026-07=/secure/audit/audit-anchor-2026-07.pub \
  --trusted-hmac-key audit-local-2026-07=/secure/audit/audit-local-2026-07.hmac \
  --witness /independent-witness/oxibelt-audit-witness.json \
  --initialize-witness
```

The default URL environment names shown above can be replaced with
`--local-postgres-url-env ENV` and `--anchor-postgres-url-env ENV`. Connection
URLs should use independent least-privilege database roles and verified TLS;
avoid putting passwords in shell history. Store the witness on retained,
access-controlled storage outside both the OxiBelt host/local database and the
checkpoint authority's administration/backup boundary.

The verifier refuses to load more than 1,000,000 local events, 100,000 external
checkpoints, or 512 MiB of serialized evidence across the manifest by default.
It also defaults to rejecting a local event larger than 128 KiB or a checkpoint
larger than 64 KiB in SQL before transferring the oversized value. Query page
size is clamped by the remaining row and byte budgets and by a 64 MiB page
budget. `--max-events`, `--max-checkpoints`, and `--max-evidence-bytes` may
raise the global bounds for a larger retained history after sizing the
independent verifier. Set `--max-event-bytes` to at least the producing
deployment's `admin.audit.spool.max_event_bytes` when that value exceeds the
default; `--max-checkpoint-bytes` similarly adjusts the checkpoint row bound.
Anchored producers cap `admin.audit.spool.max_event_bytes` at the verifier's
64 MiB maximum. All five limits remain mandatory and bounded; SQL also caps
each transferred value by the remaining global budget and the 64 MiB page
budget before the verifier materializes it.

The first trusted run requires `--initialize-witness`. Initialization refuses
to replace an existing witness and occurs only after all other verification
succeeds. Later runs omit that flag and atomically advance the witness only for
a fully `valid` report. Reports use schema
`oxibelt.admin.audit.verification/v1` and status `valid`, `incomplete`, or
`invalid`; both `incomplete` and `invalid` exit with status `2` and leave the
witness unchanged. Missing streams/events/checkpoints are incomplete evidence,
while malformed content, identity/epoch mismatch, signature failure,
continuity failure, authority-head conflict, or witness rollback are invalid.
Run verification on a regular schedule and after incident, restore, membership,
deployment, or key-rotation events.

Adding a stream to the operator-owned manifest authorizes witness expansion
only after that stream's local genesis chain, scheduled signing key, checkpoint
continuity, current epoch, and authority head all verify. The existing witness
heads are preserved. Removing a stream that is still present in the witness is
invalid, which prevents a rollout from silently deleting historical coverage.

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

When external audit anchoring is required, a terminal journal update remains
internal until the exact lifecycle audit event is covered by an authority
receipt. Poll, list, replay, and event-stream views remain nonterminal and omit
the result, error, and terminal receipt during that interval. Restart recovery
promotes the visibility marker from durable local outbox evidence without
rerunning operation work.

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

## Configuration Activation Planning

`POST /admin/v1/config/diff` remains the authenticated, non-mutating
configuration comparison endpoint and now returns activation-plan schema
version `3`. The request body is unchanged: `format` is `"toml"` and `config`
contains the candidate. The response preserves the existing ordered
`changes[].path` and `changes[].op` fields and additively returns this root
shape:

```json
{
  "activation_plan_schema_version": 3,
  "native_schema_epoch": 1,
  "ok": true,
  "basis": "online_active",
  "changes": [],
  "activation_plan": {
    "minimum_required_operation": "none",
    "selected_operation": "none",
    "reason_codes": ["no_configuration_change"],
    "can_apply_in_process": true,
    "conditional": false,
    "prerequisites": [],
    "listener": {
      "unchanged": [],
      "additions": [],
      "removals": [],
      "rebinds": [],
      "bind_conflicts": [],
      "external_port_availability": "not_applicable"
    },
    "connections": {
      "http1_keepalive": "unaffected",
      "http2": "unaffected",
      "http3": "unaffected",
      "websocket": "unaffected",
      "connect_tunnel": "unaffected",
      "webtransport": "unaffected",
      "tcp_streams": "unaffected",
      "udp_flows": "unaffected",
      "configured_drain_timeout_ms": null,
      "effective_force_close_timeout_ms": null
    },
    "confinement": {
      "filesystem": "unknown",
      "landlock": "unknown",
      "seccomp": "unknown",
      "mount_policy": "unknown",
      "requires_policy_expansion": false,
      "restart_required": false,
      "digests_withheld": true,
      "differences": [],
      "differences_truncated": false,
      "missing_prerequisites": []
    },
    "deployment": {
      "mode": "standalone",
      "target_count": null,
      "target_identities": [],
      "identities_withheld": false,
      "membership_revision": null,
      "signed_artifact_required": false,
      "durable_artifact_required": false,
      "all_members_acknowledgement_required": false,
      "missing_prerequisites": []
    },
    "rollback": "not_applicable"
  }
}
```

Each change has `path`, `op`, `secret`, `native_activation`,
`metadata_provenance`, `resolved_operation`, `reason_code`, `conditional`,
`prerequisite_missing`, `missing_prerequisites`,
`long_connections_affected`, and `rollback`. `op` is `add`, `remove`, or
`change`; metadata provenance is `explicit`, `pattern`, or
`conservative_default`. Native activation is `none`, `oxi_rule_reload`,
`downstream_tls_reload`, `full_reload`, `restart_required`, or `conditional`.
Resolved operations use the fixed weakest-to-strongest vocabulary `none`,
`oxi_rule_reload`, `downstream_tls_reload`, `full_snapshot_reload`,
`listener_transition`, `graceful_drain`, `process_restart`,
`kubernetes_immutable_rollout`, `admin_cluster_rollout`,
`blocked_by_confinement`, and `invalid_or_unsupported`. Rollback is
`automatic`, `manual`, `conditional`, `unavailable`, or `not_applicable`.
`basis` is `offline_config` or `online_active`; the Admin endpoint always emits
`online_active`. `ok = false` means invalid, unsupported, overflowed, or
terminally blocked rather than an executable success.

`minimum_required_operation` is the intrinsic activation required by the
changed fields after available runtime facts are considered.
`selected_operation` is the operation the current online executor and
deployment mode must use; it may be stronger. For example, the Admin config
load executor selects `full_snapshot_reload` for an otherwise specialized
in-process reload, while immutable and fixed-member modes select their
orchestrated rollout. A stronger selected operation is not proof that it has
been authorized, scheduled, or executed. `conditional = true` and
`prerequisites[].availability` (`available`, `missing`, `unknown`, or
`not_applicable`) identify evidence that the planner cannot prove.

The fixed reason-code set is `no_configuration_change`, `oxi_rule_changed`,
`downstream_tls_material_changed`, `full_snapshot_reload`,
`startup_only_subsystem`, `runtime_capability_context_required`,
`runtime_not_resizable`, `listener_added`, `listener_removed`,
`listener_rebind_required`, `listener_bind_conflict`,
`graceful_drain_required`, `filesystem_access_expansion`,
`filesystem_access_unavailable`, `landlock_policy_expansion`,
`mount_policy_incompatible`, `confinement_evidence_unavailable`,
`external_seccomp_profile_required`, `seccomp_expectation_unsatisfied`,
`immutable_config_requires_rollout`, `deployment_target_unavailable`,
`admin_cluster_coordinated_rollout`, `admin_cluster_membership_epoch`,
`signed_artifact_required`, `durable_artifact_required`,
`all_members_acknowledgement_required`, `rollback_artifact_unavailable`,
`change_limit_exceeded`, `invalid_configuration`, and
`unsupported_activation`. The prerequisite vocabulary is
`runtime_capability_context`, `resolved_listener_inventory`,
`filesystem_manifest`, `active_landlock_policy`, `active_seccomp_profile`,
`mount_policy_evidence`, `deployment_target_identity`,
`prior_rollback_artifact`, `signed_mutation_artifact`,
`durable_mutation_artifact`, `protected_write_authorization`,
`cluster_membership_revision`, and `all_members_acknowledgement`. Reports
contain at most 4,096 changes and reject overflow rather than truncating it.

The listener subplan reports sorted unchanged listeners, additions, removals, rebinds, bind
conflicts, and external-port availability. The connection subplan reports the
effect on HTTP/1 keep-alive, HTTP/2, HTTP/3, WebSocket, CONNECT, WebTransport,
TCP streams, and UDP flows plus configured and effective close deadlines.
Connection effects are `unaffected`, `graceful_drain`, `force_close`, or
`process_restart`. Confinement fit is `fits`, `expansion_required`,
`impossible`, or `unknown`; deployment mode is `standalone`,
`kubernetes_immutable`, or `admin_cluster`.
Listener additions are planned before removal/drain where the live executor
supports overlap, but unknown external port ownership or an incompatible
same-bind replacement remains conditional; the plan does not claim zero
downtime. Snapshot publication can drain HTTP and long-lived protocol
generations even when their socket remains bound.

The endpoint requires `config:DiffSecrets` on `*`. The legacy `config:Diff`
action remains valid in policy documents for migration compatibility but does
not authorize this endpoint. Broad `config:*` and `*` grants continue to match
the new action. The endpoint accepts no `If-Match` or
`X-OxiBelt-Mutation`, and success does not satisfy `config:Load`,
`admin:UpdateConfig`, `ipm:UpdateConfig`, protected-write, signed-artifact, or
rollout authority. Planning does not bind a socket, publish a snapshot, update
an ETag/revision, create rollback state, or contact Kubernetes. In
`admin_cluster` mode, `config:DiffSecrets` reveals the bounded target count and
membership revision; exact member identities are returned only when the same
caller also has `config:GetInstances` on `instances/current`.

Secret-bearing leaves remain visible only as changed/unchanged facts. OxiBelt
compares process-local, domain-separated HMAC-SHA-256 equality tags before
redaction; raw values, equality tags, provider-reference values, secret URLs,
and absolute secret file paths are not returned, logged, or retained in the
plan. The changed/unchanged bit is nevertheless a secret-equality oracle:
grant `config:DiffSecrets` only to principals trusted to test candidate
secrets, use high-entropy secret material, and monitor repeated plan requests.
Redaction prevents direct value disclosure; it does not make low-entropy
guessing safe.

`oxibeltctl config plan --current CURRENT --candidate CANDIDATE --format
text|json` performs offline planning; `oxibeltctl config plan --online
--candidate CANDIDATE --format text|json` uses this endpoint. Exactly one of
`--current` and `--online` is required. Text is the default. Exit `0` covers
every valid supported plan, including restart or rollout; invalid,
unsupported, blocked, denied, or failed planning exits `1`. The pre-existing
`oxibeltctl config diff FILE` command remains available.

Online confinement enrichment compares the fully resolved candidate manifest
with the process-installed Landlock policy and captured mount/seccomp evidence.
It emits at most 64 subject-tagged differences. Filesystem differences use
report-local `path_id` values, optional source configuration paths, and precise
path, rights, scope, inode identity, type, access, parent, and mount kinds. Seccomp differences
use `assertion_id = "expectation" | "profile_identity" | "profile_digest"` and
never receive a fabricated filesystem path. Stable manifest and policy digests
are withheld from this redacted endpoint because they permit dictionary tests
of common paths; `digests_withheld` makes that omission explicit. Equal/subset
requirements fit; path, scope, or rights expansion requires restart/rollout;
incompatible required paths, mounts, or ABI rights block in-process activation.
Missing runtime evidence remains `unknown` and conditional. Seccomp uses
kernel-observed filter/NNP state plus a separately labeled external profile
assertion; requested configuration and checked-in profiles are never treated
as observation. Kubernetes immutable plans never
apply per Pod and report rollout target identity only when supplied by the
deployment. Fixed-member Admin plans report signed/durable artifact,
all-member acknowledgement, and rollback prerequisites; the planner never
creates or authorizes those artifacts. Membership or protected mutation,
audit, storage, and write-authority boundary changes carry
`admin_cluster_membership_epoch` and require an out-of-band coordinated
process restart; the active cluster cannot approve replacement of its own
trust boundary.

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
`POST /admin/v1/config/secret-references/update`, and
`POST /admin/v1/tls/downstream/reload` return
`409 immutable_rollout_conflict` so one Pod cannot diverge from its assigned
revision. Read-only status, effective-config, validation, and diff endpoints
remain available to operators.

`[admin.mutations.rollout] mode = "admin_cluster"` enables the PostgreSQL-backed
Admin-cluster rollout authority. It requires mutation mode `required`, matching
process rollout mode, disabled hot reload, two through 1,024 unique configured
members, and one shared 32-byte artifact key. The configured membership remains
the compatibility default and is an all-member policy boundary; there is no
majority-quorum mode.

`[admin.mutations.rollout.membership] mode = "staged"` opts into authenticated
membership epochs. `bootstrap_members` must exactly cover the initial configured
member IDs and supplies distinct canonical-base64 Ed25519 readiness and X25519
catch-up public keys. A local instance outside the active set starts as a
non-participating learner: it cannot heartbeat as an active member, validate or
acknowledge protected writes, acquire coordinator authority, or make the Admin
rollout ready. Merely adding that instance to local configuration never changes
the protected-write boundary.

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

`GET /admin/v1/membership` is the protected diagnostic view for the active
epoch document, exact required members, recent bounded transitions, learner
cursor/digest and blocking reason, and fenced maintenance/removal identities.
`POST /admin/v1/membership/transitions` proposes exactly one serialized
`initialize`, `join`, `maintenance`, `remove`, or `rejoin` transition. It is a
normal signed protected mutation authorized and acknowledged by every member of
the current boundary. Join and rejoin create an encrypted bounded catch-up
manifest at `GET .../{transition_id}/catchup`; its X25519/HKDF-SHA256/
AES-256-GCM binding includes the cluster, transition, learner, source epoch,
target epoch, and chunk index.

The learner submits `POST .../{transition_id}/readiness` with an Ed25519-signed
receipt binding the verified catch-up cursor/digest, exact build and capability,
target epoch, identity, and clock. This evidence changes only learner state; it
does not grant voting authority. A separate all-current-member protected
`POST .../{transition_id}/activate` authorizes promotion or fencing. The new
epoch becomes runtime authority only after that activation mutation is durably
`committed`; heartbeat reconciliation then releases the old member fence,
installs the new exact member set, and keeps removed members self-fenced.
`POST .../{transition_id}/cancel` can cancel only a non-terminal transition.
An unavailable active member is never silently omitted. Emergency boundary
reconstitution remains an out-of-band disaster-recovery procedure, not this
ordinary transition API.

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

When external audit anchoring is required, a durable terminal mutation remains
externally visible as `anchor_pending` with its HTTP status, result, and error
fields withheld until the exact terminal audit event is covered by a durable
authority receipt. Exact retries remain in progress during this interval and
never expose or replay a successful response early.

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

A first successful response contains `ok = true`, `request_id`,
`config_logical_revision`, `reference_set_digest`,
`runtime_snapshot_revision`, and `target_revision`. A protected replay-safe
result also contains `token_recoverable = false` and may include `state`; the
five binding fields are present only when the retained terminal evidence still
provides them. References, environment values, file paths, and plaintext
material are never returned or written to the mutation ledger. Stable
allowlisted `secret_*` error codes identify the rejected phase without provider
details. The endpoint returns `200` after an atomic activation; `400` for a
malformed, unsupported, non-allowlisted, or invalid reference; `401` for
invalid authentication or mutation-signer identity; `403` for failed IPM
authorization or a forbidden file; `409` for activation, preflight, snapshot,
mutation, or immutable-rollout conflicts; `412` for stale `If-Match`; `413`
above the 16 KiB request limit; `428` for missing `If-Match` or required
mutation metadata; and `503` for an unavailable provider, entropy source,
mutation store, audit authority, or cluster rollout dependency. A rejected
request leaves the active snapshot unchanged. The prior successful snapshot
remains rollback-capable for a bounded connection-drain grace period and is
then dropped. In Kubernetes immutable rollout mode the endpoint returns
`409 immutable_rollout_conflict`. In
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
