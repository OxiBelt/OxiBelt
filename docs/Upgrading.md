# Upgrading OxiBelt

This guide defines OxiBelt's supported upgrade and rollback contract. The
stable [changelog](../CHANGELOG.md) and
[beta changelog](../CHANGELOG-beta.md) provide the version-specific changes,
commands, known issues, and rollback constraints that supplement this guide.

## Supported upgrade policy

OxiBelt supports one stable step at a time:

- a stable release accepts the immediately preceding stable release;
- `X.Y.Z-beta.1` accepts the immediately preceding stable release;
- `X.Y.Z-beta.N`, for `N > 1`, accepts the preceding beta for the same
  `X.Y.Z` target and the immediately preceding stable release;
- the final `X.Y.Z` stable release may also accept the latest beta for that
  target when its stable changelog entry says so;
- skipped stable versions, arbitrary downgrade paths, and cross-version
  controller/data-plane skew are unsupported unless an exact release entry
  explicitly adds and validates that path.

Tags of the form `X.Y.Z-build.<sha8>` are development artifacts. They have no
upgrade compatibility promise, changelog entry, or GitHub Release and must not
be used as a supported production upgrade source or target.

## Compatibility matrix

| Source | Target | Status | Contract |
| --- | --- | --- | --- |
| `0.6.5` | `0.7.0-beta.1` | Unpublished failed cut | The immutable tag failed the exact-revision release-contract job before draft creation. It has no GitHub Release or official artifacts and is not a deployable beta target. |
| `0.6.5` | `0.7.0-beta.2` | Published failed cut | The immutable GitHub prerelease exists, but its `linux/riscv64` keysigner runtime smoke failed before official assets, manifests, attestations, or images were published. It is not a deployable beta target. |
| `0.7.0-beta.1` | `0.7.0-beta.2` | Recovery source only | The later entry admits the exact beta tag for source-build recovery, but neither failed cut has an official artifact that can be promoted or republished. |
| `0.6.5` | `0.7.0-beta.3` | Published, not qualified | The person-reviewed release and image publication completed, but the automatic independent rebuild stopped during hosted rootless Buildx setup before all 30 subject receipts existed. Do not use beta.3 as stable qualification evidence. |
| `0.7.0-beta.2` | `0.7.0-beta.3` | Recovery source only | The later entry admits the exact beta.2 source revision, but no beta.2 official image or release asset can be promoted. |
| `0.6.5` | `0.7.0-beta.4` | Published, not qualified | The prerelease exists, but its release-image workflow failed after publication and produced no official assets. Do not reuse its incomplete evidence for another cut. |
| `0.7.0-beta.3` | `0.7.0-beta.4` | Published, not qualified | Existing beta.3 configurations retain local native UDP and disabled generated `UDPRoute` defaults unless the operator performs the shared-flow transition, but beta.4 did not complete artifact publication or independent rebuild. |
| `0.6.5` | `0.7.0` | Unpublished failed cut | The immutable stable tag failed exact-revision release-contract validation before draft creation because `CHANGELOG.md` had no governed `0.7.0` entry. It has no GitHub Release or official artifacts. |
| `0.7.0-beta.3` | `0.7.0` | Not qualified | Beta.3 did not complete independent rebuild, and the later beta.4 and stable cuts also failed. None qualifies as a stable source or target. |
| `0.7.0-beta.4` | `0.7.0` | Unpublished failed cut | Beta.4 did not complete its release-image workflow, and the immutable stable tag was created without its governed entry. Neither cut qualifies as a stable source or target. |
| `0.6.5` | `0.7.1-beta.1` | Unpublished failed cut | The immutable tag failed exact-revision release-contract validation before draft creation because `CHANGELOG-beta.md` had no governed entry. It has no GitHub Release or official artifacts. |
| `0.6.5` | `0.7.1-beta.2` | Recovery candidate | Follow [Upgrade from 0.6.5 to the 0.7.1 line](#upgrade-from-065-to-the-071-line). Treat the target as available only after person review and every exact-revision artifact and evidence gate succeeds. |
| `0.7.1-beta.1` | `0.7.1-beta.2` | Recovery source only | The later entry admits the immutable beta.1 source revision, but beta.1 has no official image or release asset to promote. |
| `X.Y.Z-beta.N` | `X.Y.Z-beta.(N+1)` | Conditional | The later beta entry must name both the preceding beta and preceding stable release as supported sources. |

The release-specific changelog entry is authoritative when a row is marked
`Recovery candidate` or `Conditional`. A tag cannot prepare a GitHub draft
release until the matching entry and upgrade link pass the repository
release-contract checker.

### Recovery from the `0.7.0-beta.1` and `0.7.0-beta.2` failed cuts

The remote `0.7.0-beta.1` and `0.7.0-beta.2` tags are immutable: do not move,
delete, or recreate either tag. Do not publish a hand-written release for
beta.1 or repurpose the published beta.2 prerelease by attaching artifacts
after its exact release workflow failed. Preserve both cuts as attributable
release-history evidence and advance to the next beta.

If a local source build identifies itself as `0.7.0-beta.1` or
`0.7.0-beta.2`, stop it before release rollout and retain its configuration and
state only as a recovery source. Neither failed cut has an official image or
release asset to promote.

### Qualification recovery after `0.7.0-beta.3`

The published `0.7.0-beta.3` images are attributable to their immutable tag,
but the automatically triggered independent rebuild did not produce the
complete 30-subject evidence set. Substantial durable UDP and release-harness
changes also landed after that tag. Preserve beta.3 as release history; do not
rerun or reinterpret it as the stable candidate, and do not reuse its partial
evidence for beta.4.

The published `0.7.0-beta.4` prerelease subsequently failed its release-image
workflow and has no official release assets. The immutable `0.7.0` tag was
then rejected before draft creation because its exact revision had no governed
stable entry. Preserve both tags and the beta.4 prerelease as failed release
history; do not attach artifacts, synthesize a stable release, or reinterpret
their incomplete evidence as qualification for a later cut.

### Recovery from the `0.7.0` and `0.7.1-beta.1` failed cuts

The remote `0.7.0` and `0.7.1-beta.1` tags are signed immutable release
history. Do not move, delete, recreate, or repush either tag, and do not
prepare a hand-written GitHub Release for either failed cut. Their exact
revisions cannot acquire the missing governed entries after the fact.

Keep `0.6.5` as the immediately preceding stable release because `0.7.0`
never produced a GitHub Release or deployable official artifact. Preserve the
failed `0.7.1-beta.1` source revision in the governed beta ledger and advance
to `0.7.1-beta.2`. The recovery beta requires a fresh exact-revision draft,
complete 30-subject artifact matrix, vulnerability decision, attestations,
provenance, and independent-rebuild receipts; no evidence from
`0.7.0-beta.4` or `0.7.1-beta.1` may be promoted or reused.

Start the stable `0.7.1` qualification soak only after `0.7.1-beta.2` is
person-reviewed and published and every official evidence gate has succeeded.
Any source, configuration, schema, dependency, workflow, Helm, controller, or
packaging change during qualification requires a later beta and a restarted
soak. Record observed beta issues in the eventual stable entry before creating
the stable tag.

## General upgrade procedure

1. Read the complete entry for the target version and confirm that the
   deployed version appears under `Supported upgrade sources`.
2. Record the exact repository and immutable digest for every deployed image
   role. Retain the previous digests until rollback is no longer required.
3. Back up the active configuration, referenced policy/rule files, PostgreSQL
   databases, audit evidence, and any operator-owned external state required
   by the release entry.
4. Use the target release's `oxibeltctl` to validate the complete configuration
   before changing a running deployment:

   ```sh
   oxibeltctl config validate /etc/oxibelt/config/oxibelt.toml --local-only
   ```

5. When the release changes the native configuration schema epoch, generate a
   review tree first. For the epoch-0-to-1 transition:

   ```sh
   oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
     --from 0 --to 1 --dry-run
   oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
     --from 0 --to 1
   oxibeltctl config validate \
     /etc/oxibelt/config/oxibelt.toml.migrated-v1/oxibelt.toml \
     --local-only
   ```

   The sibling migration tree is a review overlay. Supply and verify referenced
   certificates, keys, rules, and other external files before activation.
6. Deploy exact target digests. The Gateway Controller and data-plane roles
   must use the same release version and source revision. Changing between
   `standalone`, `dataplane`, and `dataplane-strict` is a role/capability
   migration, not an equivalent image replacement.
7. Verify process health, readiness, effective build identity, active
   configuration revision, and a representative request before completing the
   rollout. Run any additional commands in the target release entry.

### Kubernetes controller and data-plane upgrade

The Kubernetes integration remains `experimental`; its objective compatibility
and graduation rules are in
[KubernetesSupport.md](KubernetesSupport.md). For a controlled adjacent-version
upgrade:

A feature-promotion check must validate every passed-gate evidence receipt
against the exact checked-out Git revision. CI supplies the trusted
`GITHUB_SHA`; local checks resolve `HEAD` when no expected revision is supplied.
Malformed, stale, or mismatched source revisions block the lifecycle change.

1. Verify that the source and target are explicitly admitted by the exact
   release entry and retain both immutable image digests.
2. Apply and establish the release-pinned operator-owned Gateway API standard
   CRD bundle. OxiBelt charts do not own CRD conversion or deletion.
3. Set the controller to `--compatibility-mode rolling_upgrade`, name an exact
   approved version from the immediately preceding minor with
   `--compatibility-previous-version`, and set `--compatibility-deadline` to an
   RFC3339 time no more than 24 hours ahead.
4. Upgrade the controller, verify `/supportz` and readiness, then upgrade the
   selected data-plane workload.
5. After every selected Pod carries the target
   `oxibelt.dev/effective-version`, restore
   `--compatibility-mode exact`.

Missing or mismatched Pod-template identity, newer-data-plane skew,
non-adjacent or unlisted versions, and expired transitions fail closed. For a
rollback inside the declared window, restore the prior data plane before the
prior controller, then return to `exact`. Never downgrade or delete
operator-owned Gateway API CRDs as an implicit Helm rollback.

### Durable UDP flow-state transition

Native UDP stream listeners retain `udp_flow_state = "local"` by default.
Generated `UDPRoute` is stricter: the new controller defaults
`l4.udp.flowState` to `disabled` and refuses to publish process-local generated
flow state. Treat migration from an older generated process-local `UDPRoute` as
a maintenance transition; there is no mixed-version zero-loss conversion of
live sockets or NAT state.

Use this staged sequence:

1. Stop new UDP admission and drain the existing generated listeners. Observe
   `oxibelt_stream_udp_flows_active` reach zero or wait through the longest
   configured idle timeout before assuming old process-local flows are gone.
2. Upgrade the controller and data plane using the version-skew procedure
   above while generated UDP remains disabled.
3. Provision one Redis-compatible or PostgreSQL backend and configure every
   selected data-plane Pod with the same `shared_state.namespace`, explicit
   `udp_flows_backend`, and `udp_flow_identity_key_env` name resolving to the
   same Secret-backed 32-byte base64 key. Configure the effective shared
   connection-limit backend to the same backend and preserve the required
   `idle_timeout_ms >= 6 * operation_timeout_ms` bound. When Redis is selected,
   its configured account must be able to run `INFO memory`, and the response
   must prove either `maxmemory = 0` or
   `maxmemory_policy = noeviction`; unsafe, missing, malformed, or
   access-denied policy evidence fails activation.
4. Roll all selected data-plane Pods and verify readiness and shared-state
   health before setting controller `l4.udp.flowState: shared_required`.
   Re-enable UDP admission only after the generated configuration is committed
   and all selected Pods report the intended build/configuration identity.
5. During the observation window, compare created/restored flows and alert on
   persistence errors, fence rejections, admission rejections, or dropped
   datagrams.

Do not run selected Pods with different UDP identity keys, namespaces, or
backend mappings. Key rotation deliberately creates a new opaque identity
domain: disable generated UDP, drain active flows, rotate the Secret on every
Pod, complete the data-plane rollout, and only then re-enable
`shared_required`. Follow the same disable/drain/all-Pod rollout for a Redis to
PostgreSQL migration or any backend-name change; OxiBelt does not mirror UDP
flow records between backends.

Do not change a selected Redis backend to an eviction-capable policy behind an
active listener. OxiBelt verifies the policy at activation and every
configuration reload, then relies on the trusted backend to preserve it for
that runtime snapshot. Stop new UDP admission before changing Redis memory
settings, keep the resulting policy non-evicting, and require every replica to
reload and pass policy verification before resuming admission. Restrictive
managed-service ACLs that cannot expose `INFO memory` are unsupported for
Redis-backed durable UDP; use a dedicated permitted account or PostgreSQL
instead.

Treat same-path Redis password, CA, client-certificate, or client-key rotation
as a drain boundary for each affected `shared_required` UDP listener. A
successful full reload builds and prewarms the replacement shared-state
runtime, then commits each prepared replacement while the retired listener
task drains. New `shared_required` UDP flows use the prepared runtime while
prior owned flows drain. Generation-unchanged TCP and `local` UDP listener
tasks retain their existing sockets; additions, removals, and other generation
changes start or drain only the affected entries. A local-only stream-listener
set does not restart for a shared-runtime identity change alone.

The Rust `1.97.1` lint-compatibility cleanup applied after this durable-flow
implementation does not change `udp_flow_state` or shared-state configuration
syntax, defaults, or validation; opaque flow-identity derivation;
Redis-compatible or PostgreSQL record formats; or lease, fencing, renewal, and
token-accounting behavior. Existing configurations and durable records require
no migration or additional drain beyond the transition and rollback procedures
in this section.

Durable listeners also retain one capacity, new-flow token, and monotonic-fence
scope while routing generations overlap during an ordinary configuration
rollout. Existing client tuples remain pinned to their stored generation and
target and fail closed if another generation tries to reuse them. Distinct new
client tuples may use the active routing generation while older records drain,
and every generation continues to count against the same listener-wide
admission bounds. This correction does not change Redis-compatible or
PostgreSQL record formats and requires no state migration or additional drain.

For rollback to a version without durable UDP support, first disable generated
UDP and drain new-version owners, then restore the prior data-plane
configuration and image before the prior controller. Keep the previous key and
backend available until the rollback decision is complete, but do not expect
an old binary to consume durable records. Records left behind are
idle-expiring operational state, not a backup of sockets or application
sessions. Rollback cannot restore the old upstream source port,
NAT/conntrack/exact Service endpoint selection, datagrams in flight, or
application/session state.

## Rollback contract

Rollback means restoring the previous version's exact image repositories,
digests, configuration, and compatible persisted state. Do not repoint a
mutable tag and do not switch image roles as a substitute for a digest
rollback.

Schema initialization for current PostgreSQL-backed Admin components is
additive and serialized, but old binaries do not understand operations or
state introduced by a newer release. Stop new-version writers before rollback.
If a release entry identifies an irreversible step or state incompatible with
the source release, restore the pre-upgrade backup or roll forward; OxiBelt
does not promise automatic down-migrations.

Fixed-member `admin_cluster` operation requires matching build and capability
identity across the configured membership. Do not submit protected mutations
while members run mixed versions. Follow the exact release entry for any
coordinated stop, replacement, or membership procedure.

For the Gateway Controller, retain the metadata-only Lease during a normal
rolling upgrade. Before downgrading to a version without Lease fencing, scale
the controller to one replica and wait for replacement to complete; multiple
unfenced writers are unsafe.
Retain controller-generated immutable ConfigMaps needed for the named rollback;
normal Helm uninstall removes release workloads/RBAC/Lease but not
operator-owned Gateway API CRDs or unrelated Gateway API objects.

## Upgrade from 0.6.5 to the 0.7.0 line

The `0.7.0` development line introduces native configuration schema epoch `1`,
local `oxibeltctl config schema`, `validate`, `explain`, and `migrate`
commands, durable Admin operations, fixed-member Admin cluster rollout,
atomic typed secret-reference activation, external audit anchoring, expanded
Gateway API support, and the optional `dataplane-strict` image role.

The immutable `0.7.0-beta.1` tag is an unpublished failed cut, and the immutable
published `0.7.0-beta.2` cut failed before official artifact publication. Do
not use either as an upgrade target. The published `0.7.0-beta.3` cut did not
complete independent rebuild, the published `0.7.0-beta.4` cut failed its
release-image workflow without official assets, and the immutable `0.7.0`
stable tag failed before draft creation. None is a qualified stable target.
Preserve every cut as release history and advance through the governed
`0.7.1` recovery instead of attaching, promoting, or reusing their artifacts
or evidence.

Before upgrading:

- review the epoch-1 replacements for
  `tls.key_exchange_groups`, `tls.session_tickets`,
  `tls.session_ticket_rotation_seconds`,
  `upstream_pools[].health_check.rise`, and
  `upstream_pools[].health_check.fall`;
- run the epoch-0-to-1 dry-run and validate the resulting review tree;
- back up PostgreSQL before enabling durable operations, fixed-member rollout,
  or external audit anchoring;
- decide whether the deployment requires the compatibility `dataplane` Admin
  surface or the Admin-free `dataplane-strict` role;
- audit downstream HTTP/1 clients before rollout: public, Admin, and operations
  listeners reject conflicting or malformed `Content-Length` and
  `Transfer-Encoding` framing before service dispatch, return `400 Bad Request`,
  and close the connection; request heads above the existing configured limit
  return `431 Request Header Fields Too Large`. Valid fixed-length and chunked
  requests, successful `101 Switching Protocols` upgrades, successful `2xx`
  `CONNECT` tunnels, and configuration syntax remain unchanged, so no
  configuration migration is required;
- keep controller and data-plane images on the same release revision.

The exact stable or beta changelog entry must complete the validation,
rollback, known-issue, and security details before its tag can prepare a draft
GitHub Release.

## Upgrade from 0.6.5 to the 0.7.1 line

The `0.7.1` line carries forward the epoch-1 configuration, Admin durability,
Gateway API, strict data-plane, release-image, and durable UDP behavior
described in [Upgrade from 0.6.5 to the 0.7.0 line](#upgrade-from-065-to-the-070-line).
The additional source change at the failed `0.7.1-beta.1` cut repairs
same-run vulnerability-evidence selection for a failed-jobs rerun; it does not
change runtime, configuration, schema, API, rulepack, or persisted-state
behavior.

Post-`0.7.1-beta.2` development keeps `compio-direct-h1-io` experimental.
The checked-in production example now explicitly recommends
`runtime.main_runtime = "tokio_hyper"` with
`runtime.direct_h1_io = "auto"`. The canonical omitted/default main-runtime
preset is now named `hybrid_compio`, which describes the existing execution
behavior: one Compio bootstrap driver surrounds a Tokio compatibility island,
and Tokio owns listeners, general HTTP, QUIC, DNS/discovery, timers, and
background/control work. This is a topology-name clarification rather than a
Tokio-to-Compio runtime rewrite.

Existing `runtime.main_runtime = "compio"` values remain valid and
behavior-identical. They resolve to `hybrid_compio` and emit
`CFG_RUNTIME_MAIN_RUNTIME_COMPATIBILITY_ALIAS`; no removal deadline is
assigned. Operators may adopt the canonical spelling immediately or retain
the alias while updating automation that previously interpreted `compio` as
proof that all server subsystems ran on Compio. `runtime.main_runtime =
"auto"` still prefers the hybrid preset. Add `runtime.topology_policy =
"require_exact"` when a startup or reload must reject rather than record a
Tokio fallback; omitted policy defaults to `allow_fallback`.

Worker ownership is additive. `[runtime.workers].tokio` sizes the Tokio
executor/island and `[runtime.workers].compio_direct_h1` sizes the experimental
Compio direct-H1 fleet, with matching owner-specific multipliers. Legacy
`runtime.worker_threads` and `runtime.worker_multipliers.runtime` remain valid
and supply each owner whose canonical field is omitted. A legacy-only
configuration therefore retains its previous resolved counts, while an
operator can migrate one owner at a time. Validate the effective configuration
and fixed migration diagnostics before removing the legacy keys.

Operators that deliberately select an active Compio runtime with
`runtime.direct_h1_io = "compio"` must continue to treat the Linux-only path
as experimental, not promoted. Its bounded response engine fails closed on
malformed, ambiguous, or unsupported HTTP/1 response framing. The selected
path now starts persistent workers, uses bounded admission, and can reuse only
cleanly framed generation-current HTTP/1.1 connections. This is an
internal resource-model change, not a configuration migration: worker, queue, waiter,
and connection limits derive from the resolved runtime and circuit-breaker
budgets, while upstream idle and absolute lifetimes retain their existing
configuration meaning.

Only guarded empty `GET` and `HEAD` operations can select the Compio service.
Bodyful, chunked, streaming, upgrade, CONNECT, or otherwise ineligible
operations continue through Hyper. An unhealthy or draining service, or a
resolution or connection failure, can fall back only before upstream bytes are
written. Queue saturation and connection-capacity rejection return the
configured admission response without rerouting through Hyper; a post-dispatch
failure closes the connection and does not implicitly replay the request.
Before opting in, validate representative upstream responses and monitor
`oxibelt_http_direct_h1_response_protocol_failures_total` together with the
`oxibelt_http_compio_direct_h1_*` queue, worker, connection, dispatch, wait,
connect, cancellation, buffer, and copied-byte metrics. Roll back by restoring
`runtime.direct_h1_io = "auto"` or `"tokio_hyper"` and restarting the process;
do not treat a main-topology or Tokio-worker change as an in-process resize.
Those changes require a process restart. A direct-H1 backend or worker-count
change may full-reload only after OxiBelt stages the replacement service; a
failure keeps the previous configuration, service, and reported topology
active.

Runtime snapshot, runtime introspection, support-bundle, and active config
explain consumers must accept format version `2` before this upgrade. Version
`2` adds the requested and resolved presets, fallback outcome/reason,
subsystem owners, worker allocations, compatibility boundaries, and active
direct-H1 state. Public readiness also adds the bounded
`X-OxiBelt-Runtime-Status` header. These surfaces do not expose raw capability
probe errors, paths, hostnames, routes, peers, or secrets.

Post-beta.2 development also adds experimental activation-plan schema version
`1` to `POST /admin/v1/config/diff`. Existing consumers may continue reading
the preserved `changes[].path` and `changes[].op` fields, but strict response
decoders must accept the new root `activation_plan_schema_version`,
`native_schema_epoch`, `ok`, `basis`, and nested `activation_plan` fields.
Array changes are now expanded into deterministic indexed leaf paths instead
of one aggregate array entry, so consumers that group paths must normalize
indices deliberately.
This is an additive Admin API and CLI change; the native configuration schema
remains epoch `1` and no TOML migration is required.

Post-beta.2 development also adds optional upstream HTTP/3 resolver controls
under `[quic.upstream.resolution]`. Existing TOML remains valid and uses the
documented defaults when these fields are omitted. The native configuration
schema remains epoch `1`; no TOML migration or compatibility alias is needed.
Changing any resolver field is classified as `full_reload`, which replaces the
resolver and pool snapshot for new work while already-draining connections keep
their normal bounded lifetime. Validate candidate TTL, endpoint, attempt,
address-family stagger, and cooldown limits before activation, then monitor the
fixed-cardinality upstream HTTP/3 resolver and pool metrics for negative-cache,
connect-failure, saturation, and wait changes. To roll back, restore or omit the
resolver fields and perform another full reload; this does not authorize
cross-origin connection reuse or post-dispatch request replay.

Before applying an upgrade candidate, operators can compare production-loaded
files without Admin authority:

```sh
oxibeltctl config plan \
  --current /etc/oxibelt/config/oxibelt.toml \
  --candidate ./review/oxibelt.toml \
  --format json
```

Use `--online` instead of `--current` to enrich the same fixed schema with the
active executor, resolved listener, confinement, and deployment context. The
online command needs `config:Diff`; exact fixed-member identities additionally
need `config:GetInstances`. Neither mode applies the candidate, satisfies a
mutation envelope, or proves zero downtime. Exit `0` means the candidate has a
valid, supported, non-blocked plan, including restart or rollout. Exit `1`
means invalid, unsupported, blocked, unauthorized, or failed planning.

Automation must inspect both `minimum_required_operation` and
`selected_operation`, every `conditional` and prerequisite availability,
listener bind conflicts, long-connection effects, and rollback class. Treat
`filesystem_manifest`, mount, and active-seccomp evidence as unresolved until
P1-05 is implemented; do not infer fit from a known-path subset or requested
profile. In Kubernetes immutable mode retain the previous immutable artifact
and let the workload controller perform rollout. In `admin_cluster` mode keep
the signed/durable artifact, exact membership, all-member acknowledgement, and
protected-write flow authoritative. Roll back this tooling change by ignoring
the additive fields or using the previous CLI; do not roll back an activated
configuration merely because its advisory plan format changed.

This post-beta.2 compatibility change requires a later governed beta and
fresh exact-revision evidence; it is not part of beta.2's immutable release
record.

Neither the immutable `0.7.0` tag nor `0.7.1-beta.1` is a deployable upgrade
target. Both failed exact-revision release-contract validation before draft
creation and have no GitHub Release or official artifact. Use
`0.7.1-beta.2` only after its person-reviewed release and its new
exact-revision artifact, vulnerability, attestation, provenance, and
independent-rebuild evidence all succeed.

When upgrading directly from `0.6.5`, follow the complete epoch-0-to-1
migration, backup, role-selection, HTTP/1 compatibility, fixed-member Admin,
Gateway Controller, and durable UDP preparation in the `0.7.0` guide above.
Create the review tree and validate every referenced file before activation:

```sh
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1 --dry-run
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1
oxibeltctl config validate \
  /etc/oxibelt/config/oxibelt.toml.migrated-v1/oxibelt.toml \
  --local-only
```

A local source build from `0.7.1-beta.1` may be retained only as recovery
history. Before replacing it with a person-reviewed later release, validate
the active epoch-1 configuration and referenced files, retain all prior
digests and backups, and confirm that controller and data-plane roles use the
same target revision:

```sh
oxibeltctl config validate /etc/oxibelt/config/oxibelt.toml --local-only
```

Do not reuse the failed beta.1 workflow run, its absent release artifacts, or
the incomplete beta.4 evidence. The `0.7.1-beta.2` release must produce its
own complete 30-subject image and evidence set before rollout.
