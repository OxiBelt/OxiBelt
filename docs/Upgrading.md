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
| `0.6.5` | `0.7.0-beta.4` | Release candidate | Follow [Upgrade from 0.6.5 to the 0.7.0 line](#upgrade-from-065-to-the-070-line). Treat the target as available only after a person reviews and publishes its draft and every official artifact gate passes. |
| `0.7.0-beta.3` | `0.7.0-beta.4` | Release candidate | Existing beta.3 configurations retain local native UDP and disabled generated `UDPRoute` defaults unless the operator performs the shared-flow transition. Beta.4 requires a new complete artifact and independent-rebuild evidence set. |
| `0.6.5` | `0.7.0` | Held for beta.4 evidence | The stable entry is intentionally absent until beta.4 publication, all 30 independent-rebuild receipts, and the evidence soak complete. |
| `0.7.0-beta.3` | `0.7.0` | Not qualified | Beta.3 did not complete independent rebuild and is not the planned beta-to-stable source. Advance through beta.4 rather than promoting beta.3 directly. |
| `0.7.0-beta.4` | `0.7.0` | Held for beta.4 evidence | Require at least 24 hours after successful beta.4 publication and complete independent-rebuild evidence, with no release-blocking issue, before preparing the stable entry or tag. |
| `X.Y.Z-beta.N` | `X.Y.Z-beta.(N+1)` | Conditional | The later beta entry must name both the preceding beta and preceding stable release as supported sources. |

The release-specific changelog entry is authoritative when a row is marked
`Release candidate` or `Conditional`, or is held for beta evidence. A tag
cannot prepare a GitHub draft release until the matching entry and upgrade
link pass the repository release-contract checker.

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

The stable `0.7.0` changelog entry remains intentionally deferred. Start its
minimum 24-hour evidence soak only after `0.7.0-beta.4` is person-reviewed and
published and all official artifacts, attestations, and 30 independent rebuild
receipts have succeeded. Any source, configuration, schema, dependency,
workflow, Helm, controller, or packaging change during qualification requires
a later beta and a restarted soak. Record any observed beta issue in the
eventual stable entry before creating the stable tag.

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
as a stream-listener drain boundary. A successful full reload builds and
prewarms the replacement shared-state runtime, then quiesces the old
stream-listener set and starts its replacement. New `shared_required` UDP
flows use the prepared runtime while prior owned flows drain. Because stream
listeners are replaced as one supervised set, a mixed set can also drain local
UDP or TCP listeners during this rotation; schedule the change accordingly. A
local-only stream-listener set does not restart for a shared-runtime identity
change alone.

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
complete independent rebuild and is not the stable candidate. Use
`0.7.0-beta.4` only after its person-reviewed release, complete artifact
publication, vulnerability admission, attestations, and all 30 independent
rebuild receipts succeed.

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
