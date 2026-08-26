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
| `0.6.5` | `0.6.6` | Published maintenance release | Follow [Upgrade from 0.6.5 to 0.6.6](#upgrade-from-065-to-066). The signed tag remains on its maintenance commit; the later ledger and lineage reconciliation preserve history but do not recreate exact-tag qualification evidence. |
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
| `0.6.5` | `0.7.1-beta.2` | Published, not qualified | The person-reviewed prerelease and release-image workflow completed, but its automatic independent rebuild failed before the complete 30-subject receipt set existed. Preserve it as release history; do not use it as stable qualification evidence. |
| `0.7.1-beta.1` | `0.7.1-beta.2` | Recovery source only | The later entry admits the immutable beta.1 source revision, but beta.1 has no official image or release asset to promote. |
| `0.6.5` | `0.7.1-beta.3` | Unpublished failed cut | The immutable tag failed exact-revision release-contract validation before draft creation because `CHANGELOG-beta.md` had no governed beta.3 entry. It has no GitHub Release or official artifacts. |
| `0.7.1-beta.2` | `0.7.1-beta.3` | Recovery source only | The beta.3 ledger records the adjacent source relationship, but beta.3 has no official artifact and beta.2 did not complete independent rebuild qualification. Neither cut can be promoted. |
| `0.6.5` | `0.7.1-beta.4` | Recovery candidate | Follow [Upgrade from 0.6.5 to the 0.7.1 line](#upgrade-from-065-to-the-071-line). Treat beta.4 as available only after person review and every fresh exact-revision artifact and evidence gate succeeds. |
| `0.7.1-beta.2` | `0.7.1-beta.4` | Recovery candidate | Direct configuration and state recovery is supported without a new native schema migration. Beta.2's incomplete rebuild evidence must not be reused; deploy only newly qualified beta.4 digests. |
| `0.7.1-beta.3` | `0.7.1-beta.4` | Recovery source only | Beta.3's source configuration and state are accepted by the recovery candidate, but beta.3 has no official artifact to promote and cannot contribute release evidence. |
| `0.6.6` | `0.8.0-beta.0` | Unpublished invalid cut | The immutable signed tag uses the forbidden beta.0 number, has no GitHub Release, and cannot be moved, repaired, published, or used as release evidence. |
| `0.6.6` | `0.8.0-beta.1` | Published, not qualified | The prerelease was published, but its release-image workflow failed and independent rebuilds were skipped. Preserve it as attributable release history; do not use it as a stable source or reuse its evidence. |
| `0.8.0-beta.1` | `0.8.0-beta.2` | Unpublished failed cut | The signed tag was created without a governed beta.2 entry, so exact-tag release-contract validation could not prepare a draft. Do not move, recreate, publish, attach artifacts to, or reuse evidence from this cut. |
| `0.6.6` | `0.8.1-beta.1` | Local, not qualified | The signed tag exists only locally at its original revision, whose canonical validation exposed release-harness flakes. It has no GitHub Release or official artifact and cannot provide qualification evidence. |
| `0.6.6` | `0.8.1-beta.2` | Unpublished failed cut | The immutable signed remote tag exists, but draft preparation failed and no GitHub Release or official artifact was created. Preserve the tag as history and do not reuse its workflow evidence. |
| `0.8.1-beta.1` | `0.8.1-beta.2` | Recovery source only | Direct configuration and state recovery is supported without a new migration, but beta.1 has no remote tag or official artifact and beta.2 has no release artifact to promote. |
| `0.6.6` | `0.8.1-beta.3` | Published failed cut | The prerelease exists, but its release-image workflow failed before canonical image publication. Preserve the immutable tag and release; do not reuse its incomplete evidence. |
| `0.8.1-beta.2` | `0.8.1-beta.3` | Recovery source only | Direct configuration and state recovery is supported without a new migration, but beta.2 has no official artifact or qualification evidence to promote. |
| `0.6.6` | `0.8.1-beta.4` | Published, not qualified | The exact-version images and charts were published, but the automatic independent verifier failed before producing its rebuild matrix or any independent receipt. Preserve the immutable release and artifacts as history; do not promote or reuse their evidence. |
| `0.8.1-beta.3` | `0.8.1-beta.4` | Recovery source only | Direct configuration and state recovery is supported without a new migration, but beta.3 has no qualified official image or evidence to promote. |
| `0.6.6` | `0.8.1-beta.5` | Published, not qualified | The exact-version images and charts were published, but independent image rebuilds exposed build-time APK log content and scanner serialization variance. Preserve the immutable release and artifacts as history; do not promote or reuse their evidence. |
| `0.8.1-beta.4` | `0.8.1-beta.5` | Recovery source only | Direct configuration and state recovery is supported without a new migration, but beta.4's published artifacts and incomplete verifier evidence cannot be promoted, relabeled, or reused. |
| `0.6.6` | `0.8.1-beta.7` | Published, superseded | Preserve the immutable prerelease and its exact-version evidence, but do not use it to qualify beta.8 or stable promotion after the later fuzz-harness and dependency refresh. |
| `0.8.1-beta.6` | `0.8.1-beta.7` | Recovery source only | Direct configuration and state recovery is supported without a new migration, but beta.6's published artifacts and exact-revision evidence cannot be promoted, relabeled, or reused. |
| `0.6.6` | `0.8.1-beta.9` | Published, qualified | Follow [Upgrade from 0.6.6 to the 0.8.1 line](#upgrade-from-066-to-the-081-line). Use only the fresh beta.9 exact-version artifacts and complete automatic qualification evidence; do not substitute an earlier beta subject or receipt. |
| `0.8.1-beta.8` | `0.8.1-beta.9` | Recovery source only | Direct configuration and state recovery is supported without a new migration, but beta.8's published artifacts and exact-revision evidence cannot be promoted, relabeled, or reused for beta.9. |
| `0.8.1-beta.9` | `0.8.1` | Stable candidate | The stable source is exactly one documentation-only commit after the qualified beta.9 revision. This exact transition has no additional calendar delay, but stable publication cannot predate beta publication or verifier completion and remains subject to every stable-only release and alias gate. |
| `0.8.1` | `0.9.0-beta.1` | Planned beta, not tagged | Follow [Upgrade from 0.8.1 to the 0.9.0 line](#upgrade-from-081-to-the-090-line). CT-disabled epoch-1 configurations need no native migration; enable CT only after fresh exact-candidate storage, signer, interoperability, load, and monitor evidence succeeds. |
| `X.Y.Z-beta.N` | `X.Y.Z-beta.(N+1)` | Conditional | The later beta entry must name both the preceding beta and preceding stable release as supported sources. |

The release-specific changelog entry is authoritative when a row is marked
`Recovery candidate` or `Conditional`. A tag cannot prepare a GitHub draft
release until the matching entry and upgrade link pass the repository
release-contract checker.

## Upgrade from 0.8.1 to the 0.9.0 line

`0.9.0-beta.1` is a development ledger target, not a tag, GitHub Release,
official artifact set, or qualified production release. It introduces native
Certificate Transparency (CT) runtime, tooling, signer, and experimental Helm
surfaces. CT remains disabled by default. An existing `0.8.1` epoch-1
configuration that does not add `[certificate_transparency]` or `ct_log`
routes needs no native schema migration and keeps its existing request
behavior.

Post-`0.8.1` development adds bounded lookahead and lookbehind support to
configuration-authored OxiRule, OxiRule Group, regex pattern-set, and CRS
regex literals. Existing patterns continue to prefer the linear Rust engine.
Operators may optionally set `max_advanced_regex_subject_bytes` and
`max_advanced_regex_backtracks` under `[waf.limits]`; omitted fields receive
backward-compatible defaults. Patterns requiring PCRE syntax that is not
accepted by `fancy-regex` remain invalid, and request-derived patterns do not
gain advanced-regex support. Rollback requires removing advanced syntax and
the two new optional keys from configurations consumed by an older binary.

Treat CT activation as a new service deployment. Use separate workloads for
each writable operator, read-only gateway, purpose-exclusive signer, and
independent monitor, and use separate writable operators for different
protocols or temporal shards. A process owns at most one writable log. CT
configuration and route changes require a full reload; do not introduce them
during an unrelated in-place reload.

The local POSIX storage profile and local schema version `1` are for
development and interoperability testing only. Before enabling a production
CT route, stop CT traffic, back up PostgreSQL, apply CT PostgreSQL schema
version `3`, and verify the storage contract:

```sh
oxibeltctl config validate /etc/oxibelt/oxibelt.toml --local-only
oxibeltctl ct postgres migrate --database-url-env OXIBELT_CT_DATABASE_URL
oxibeltctl ct postgres storage-check --database-url-env OXIBELT_CT_DATABASE_URL
```

Production CT also requires HTTPS S3-compatible versioned object storage,
create-only and conditional-write behavior, object lock and retention,
checksum readback, and an operator-supplied deletion-denial attestation. Pin
the canonical accepted-root bundle by SHA-256 digest and require at least two
independent Ed25519 signatures. Keep private log keys only in the
purpose-bound keysigner and mount database, object-storage, signer, root, and
public-identity secrets only into the workloads that own them.

The `oxibelt-ct` chart is an experimental deployment scaffold and development
version-inventory member. It is not one of the two official Helm charts in the
release packaging, independent-rebuild, or qualification contract. Its opaque
`log.config` remains the sole runtime configuration source, so the chart
cannot derive a readiness probe and leaves its Service disabled by default.
Render and review the selected profile without treating a successful template
as production qualification:

```sh
helm lint --strict deploy/helm/oxibelt-ct
helm template oxibelt-ct deploy/helm/oxibelt-ct \
  --values deploy/helm/oxibelt-ct/values-production.yaml
```

Before production support, the exact candidate must pass RFC 6962, Static CT,
and RFC 9162 interoperability; restart, signer-outage, PostgreSQL-failover,
object-conflict, and replica-fencing tests; and resource-based load tests that
hold the 60-second maximum merge delay without unbounded growth. An
independent monitor outside the operator trust boundary must then observe
seven continuous days without rollback, fork, invalid proof, or stale signed
tree heads. Archive the root quorum, shard schedule, retention, deletion
denial, immutable image, and monitor evidence for that exact revision.

To roll back to `0.8.1`, stop submissions, drain CT gateways and operators,
remove every `ct_log` and `ct_surface` route and the CT configuration, then
restore and validate the `0.8.1` binary and configuration together. Retain the
PostgreSQL backup, object-store versions, accepted-root snapshots, keys, and
monitor witnesses. There is no CT down-migration. Published checkpoints,
signed tree heads, receipts, and retained or object-locked objects are
externally visible or immutable and cannot be retracted by rollback; never
reuse a log identity to conceal a failed deployment.

## Upgrade from 0.6.6 to the 0.8.1 line

`0.8.1-beta.9` is the published and qualified source for stable promotion. The
signed beta.1 tag
remains at its original local revision and is absent from GitHub. The signed
beta.2 tag exists remotely at its immutable revision, but draft preparation
failed and no GitHub Release or official artifact was created. The immutable
beta.3 prerelease exists, but its release-image workflow failed before
canonical image publication because downloaded artifact data did not retain a
helper's executable mode. Beta.4 published its exact-version image and chart
set, but its automatic independent verifier failed before producing a rebuild
matrix or any independent receipt because package-manager setup ran outside
both sibling checkouts. Beta.5 also published its complete image and chart set;
its automatic verifier reproduced both charts but rejected the first image
rebuilds because APK wall-clock log content and scanner serialization metadata
differed. No complete beta.5 30-image receipt set or aggregate qualification
receipt exists. Beta.6 published its complete exact-version image and chart
set, but the dependency and toolchain refresh required a new beta.7 source
revision. Beta.7 was published at its immutable revision; later sustained-fuzz
artifact-path and HTTP/2 frame-budget fixes plus the dependency refresh
required beta.8 and fresh qualification. Beta.8 was then published at its
immutable revision; the `online-dsl-forge` and `syn` refresh plus the dated
fuzz-toolchain advance require beta.9 and another complete qualification. Do
not move or delete these tags, reinterpret an old rerun as beta.9
qualification, or reuse artifacts or evidence from an earlier cut.

The older `0.8.0-beta.0` tag is invalid, the published `0.8.0-beta.1` cut is
unqualified, and `0.8.0-beta.2` failed before a governed entry could prepare
its draft. Keep each as attributable release history; do not move a tag,
attach artifacts, publish a replacement, or reuse its evidence.

The `0.8.1` line carries epoch-1 configuration, bounded proxy engines,
activation planning, strict deployment hardening, durable Admin and shared
state, Gateway Controller and Gateway API surfaces, signed supply-chain
admission, reproducible image and Helm evidence, and expanded security testing.
All tracked general and Kubernetes features remain experimental and
unvalidated.

Create and inspect a sibling epoch-1 tree rather than editing the active
epoch-0 tree in place:

```sh
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1 --dry-run
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1
oxibeltctl config validate \
  /etc/oxibelt/config/oxibelt.toml.migrated-v1/oxibelt.toml \
  --local-only
helm version --short
```

Use `[proxy.upstream_resolution]` for the canonical resolver policy. Epoch-1
continues to accept `[quic.upstream.resolution]` as a deprecated compatibility
input; migrate every leaf and do not configure the same effective leaf in both
tables. Resolver-policy changes require `full_reload`.

The beta.9 runtime keeps the same circuit-breaker configuration surface, but
enforces `global.max_connections` and configured pool `max_connections` for
every physical Happy Eyeballs candidate before that candidate starts network
work.
The winning lease follows the pooled connection or tunnel; failed, losing,
canceled, and stale attempts release it. When a racing peer temporarily owns
the final slot, the rejected fallback is deferred and may retry after that peer
fails under the original absolute deadline. Confirm that intentional address-
family concurrency fits the configured global and pool limits, and monitor
capacity rejections during staged rollout.

HTTPS/SVCB discovery in beta.9 is also bound to the effective DNS query owner
that supplied the base addresses. Deployments using search domains should
verify that upstream DNS returns metadata for that accepted owner; hosts-pinned,
mixed-provenance, conflicting-owner, and mismatched metadata responses now stay
on their base addresses without SVCB expansion.

Use Helm `4.2.4` for canonical packaging and reproducibility; Helm `3.21.3`
or `4.2.4` may render and consume the charts. Inspect both exact-version chart
manifests and immutable admission references before staged rollout. On AMD64,
select the immutable `x86-64-v3` image only on compatible hosts; otherwise use
the explicit immutable `amd64v2` digest.

Retain `0.6.6` image digests, epoch-0 configuration, referenced assets,
compatible PostgreSQL backup, admission bundle, audit evidence, controller
rollback ConfigMaps, Gateway API CRDs and Lease, and shared UDP identity
material. To roll back, stop new-version writers, drain the data plane before
the controller, restore the old binaries, configuration, and database together,
and remove unknown epoch-1 tables before validating with `0.6.6`. External
audit, telemetry, network, and client-visible effects cannot be undone.

`0.8.1-beta.9` produced fresh exact-revision evidence for 30 immutable image
subjects, both official exact-version Helm OCI charts, their independent
rebuild receipts, and one complete automatic qualification receipt. Its
person-reviewed publication and verifier completion satisfy the exact
beta.9-to-`0.8.1` transition's prerequisites without an additional calendar
delay; stable publication still cannot predate either event. This one-release
exception does not apply to any other transition. Any tracked change outside
the documentation-only stable commit requires a later beta and restarts
qualification with the normal 24-hour gate.

## Upgrade from 0.6.5 to 0.6.6

`0.6.6` is a narrow maintenance release that restores legacy
`access_log.enable_system` runtime enablement for system records sent to
stdout or OTLP. The canonical setting remains
`access_log.system.enabled`; configurations using only that setting retain
their behavior. There is no native configuration schema, database, Admin API,
rulepack, or durable-state migration.

Before rollout, validate the complete configuration with the target binary and
confirm that the selected sink receives a probe record without exposing
sensitive fields:

```sh
oxibeltctl config validate /etc/oxibelt/config/oxibelt.toml --local-only
```

Keep the prior image digest and matching configuration until log volume,
redaction, transport authentication, and retention have been reviewed. To
roll back, drain the `0.6.6` instance and restore the prior image and
configuration together. Exported stdout or OTLP records cannot be retracted.

The immutable signed `0.6.6` tag was published from its maintenance branch
before the governed changelog entry existed. The later no-tree-change lineage
merge makes that release an ancestor of development without moving the tag or
claiming that post-publication documentation existed at the release revision.

## Upgrade from 0.6.6 to the 0.8.0 line

`0.8.0-beta.1` is the first valid qualification candidate for this line. The
immutable `0.8.0-beta.0` tag is invalid because release beta numbering begins
at beta.1. Keep beta.0 as attributable failed-cut history; do not move its tag,
create a release for it, attach artifacts, or reuse its workflow results.

The `0.8.0` line advances native configuration from epoch `0` to epoch `1` and
adds bounded proxy engines, activation planning, strict deployment hardening,
durable Admin and shared-state behavior, Gateway Controller and Gateway API
surfaces, signed supply-chain admission, reproducible image and Helm evidence,
and expanded security testing. Every tracked general and Kubernetes feature
remains experimental and unvalidated; this version target does not itself
graduate a feature.

Create and inspect a sibling epoch-1 tree rather than editing the active
epoch-0 tree in place:

```sh
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1 --dry-run
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1
oxibeltctl config validate \
  /etc/oxibelt/config/oxibelt.toml.migrated-v1/oxibelt.toml \
  --local-only
helm version --short
```

Use Helm `4.2.4` for canonical packaging and reproducibility. Helm `3.21.3` or
`4.2.4` may render and consume the charts. Inspect both exact-version chart
manifests and their admission references before a staged rollout; do not rely
on a mutable chart alias.

The canonical `linux/amd64` image requires `x86-64-v3`. Release builders now
apply that ISA consistently to Rust and bundled native C or C++ dependencies,
including AWS-LC, zstd, and vendored OpenSSL. Before rollout, run
`tests/scripts/select-amd64-docker-image-artifact.sh x86-64-v3` on each AMD64
node or use the equivalent `oxibeltctl doctor` deployment check. Hosts that do
not meet v3 must use the explicit `amd64v2` image by immutable digest; retain
that digest for rollback because OxiBelt does not negotiate an ISA variant at
runtime. Direct image builders should migrate from `OXIBELT_RUST_TARGET_CPU`
to `OXIBELT_AMD64_TARGET_CPU`; the old name remains an alias, and specifying
different values fails the build.

Retain the `0.6.6` image digests, complete epoch-0 configuration tree,
referenced assets, compatible PostgreSQL backup, admission bundle, audit
evidence, controller rollback ConfigMaps, Gateway API CRDs and Lease, and
shared UDP identity material. For rollback, stop new-version Admin,
membership, shared-state, and UDP writers, drain the data plane before the
controller, and restore the old binaries, configuration, and database
together. Remove every unknown epoch-1 table before validating with `0.6.6`;
there is no automatic down-migration, and external audit, telemetry, network,
or client-visible effects cannot be undone.

Beta.1 must produce fresh evidence for its exact revision: 30 immutable image
subjects, both official exact-version Helm OCI charts, their independent
rebuild receipts, and one complete automatic qualification receipt. Manual
diagnostics and earlier release evidence cannot qualify it. Begin the 24-hour
stable soak only after that evidence and person-reviewed publication are
complete. A tracked change outside the eventual documentation-only stable
commit requires beta.2 and restarts qualification.

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

### Recovery from the `0.7.0` and `0.7.1-beta.1` through `0.7.1-beta.3` failed cuts

The remote `0.7.0`, `0.7.1-beta.1`, and `0.7.1-beta.3` tags are signed
immutable release history. Do not move, delete, recreate, or repush those
tags, and do not prepare a hand-written GitHub Release for a cut rejected
before draft creation. Their exact revisions cannot acquire a missing
governed entry after the fact. Preserve the published `0.7.1-beta.2`
prerelease as history too; do not attach replacement evidence or reinterpret
its failed independent rebuild as a qualified release.

Keep `0.6.5` as the immediately preceding stable release because `0.7.0`
never produced a GitHub Release or deployable official artifact. Preserve all
three beta source revisions in the governed ledger and advance to
`0.7.1-beta.4`. The recovery beta requires a fresh exact-revision draft,
complete 30-subject artifact matrix, vulnerability decision, attestations,
provenance, and independent-rebuild receipts; no evidence from `0.7.0-beta.4`,
`0.7.1-beta.1`, `0.7.1-beta.2`, or `0.7.1-beta.3` may be promoted or reused.

Start the stable `0.7.1` qualification soak only after `0.7.1-beta.4` is
person-reviewed and published and every official evidence gate has succeeded.
Any source, configuration, schema, dependency, workflow, Helm, controller, or
packaging change during qualification requires another beta and a restarted
soak. Record observed beta issues in the eventual stable entry before creating
the stable tag.

### QUIC Initial reassembly in `0.7.1-beta.4`

`0.7.1-beta.4` retains native configuration schema epoch `1`. Existing
configuration remains valid because `[sni_forward.quic_initial_reassembly]` is
an optional, defaulted nested table. Before enabling split-Initial handling,
add the table deliberately, validate the complete configuration, and roll out
the target binary through the normal drain/restart procedure:

```sh
oxibeltctl config validate /etc/oxibelt/config/oxibelt.toml --local-only
```

The table creates no persisted state or migration. Its bounded pending state is
in-memory and is discarded at process stop. To roll back to an earlier strict
unknown-field binary, remove the complete
`[sni_forward.quic_initial_reassembly]` table first, validate with that binary,
then drain and restart. Do not roll back while relying on cross-datagram QUIC
Initial SNI classification: the older binary cannot interpret the nested table
or reproduce its bounded replay behavior.

### Dependency and Helm toolchain refresh

This source line refreshes the locked Rust and pnpm dependency graphs without
changing the native configuration schema epoch, persisted state, or public
configuration. Rebuild and redeploy each immutable image from the complete
target source revision; do not combine binaries or dependency evidence from
the old and new lockfiles.

The Helm 4 compatibility and release-evidence contract advances from `4.2.3`
to `4.2.4`, while the Helm 3 contract remains `3.21.3`. Operators using Helm 4
must upgrade the client to exactly `4.2.4` before rendering, installing, or
upgrading the chart. Evidence produced with Helm `4.2.3` does not satisfy the
new exact-version predicate and must not be reused. Existing deployed objects
need no state migration; render the chart again with the target client and
review the result before applying it.

Official image tooling now derives the pnpm version from the repository's
exact hash-pinned `packageManager` declaration. Rollback must use the previous
complete image, chart, lockfiles, and release evidence together rather than
mixing dependency generations.

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

### AWS-LC feature selection for mutation signing

Builds of `oxibeltctl` with `mutation-pqc` use the stable ML-DSA signature APIs
in `aws-lc-rs` 1.18.0 and no longer request the dependency's `unstable` feature
directly. This changes dependency feature bookkeeping only: command-line flags,
accepted PKCS#8 keys, mutation signatures, Admin wire format, and runtime
verification behavior are unchanged, and no configuration or state migration
is required.

The locked `quic-parser` 0.1.5 AWS-LC backend still requests
`aws-lc-rs/unstable` independently, so the full dependency graph continues to
include `unstable`; the first-party migration is not a graph-wide removal.
Rolling back to earlier source reintroduces the redundant direct `oxibeltctl`
request but does not change keys, protocols, or state.

### Supply-chain admission bundle v2

Admission bundle schema v2 adds a signed, bounded auxiliary-container policy.
New `oxibeltctl supply-chain admission-bundle` generation emits v2, including
an empty policy when `--workload-policy` is omitted. Older tools binaries reject
v2. The fixed admission server accepts a still-valid v1 bundle only as a strict
primary-`oxibelt` policy; every additional regular, init, native-sidecar, or
ephemeral container is denied.

For a primary-only deployment, upgrade the digest-pinned tools image while
retaining the current v1 bundle, wait for the new admission Deployment and
Service endpoints, and then rotate to a generated v2 bundle. For a deployment
that needs auxiliary images, generate and review the v2 policy first, then
roll out the v2-capable tools image, content-addressed bundle, Pod template,
and chart rules together. An old admission binary must never receive a v2
bundle. Confirm the rendered webhook contains exact `pods` CREATE/UPDATE and
`pods/ephemeralcontainers` UPDATE rules, not `pods/*`.

The chart derives the admission endpoint revision from both the bundle payload
digest and the exact tools-image repository/digest. Changing only the fixed
server image therefore creates a new Deployment/selector epoch and excludes
old permissive endpoints from the Service instead of mixing old and new
binaries. A short interval with no ready endpoint is intentionally fail-closed.

The chart serializes every `oxibelt.dev/supply-chain-bundle` revision label and
selector as a YAML string, including when the derived twelve-character epoch
contains only decimal digits. This corrects manifest typing without changing
the epoch derivation, chart values, or fail-closed endpoint selection; no
values migration is required.

Existing Pods continue running across the change. Pod recreation, ordinary
updates, and ephemeral-container updates fail closed when an executable is not
present in the active signed policy. Keep the previous valid bundle and fixed
tools-image digest until the new endpoints and data-plane rollout are healthy.
Supported rollback restores a previous valid v1 or v2 bundle under a fixed
server; remove auxiliary containers before restoring v1. Downgrading to a
server that permits unverified executables is not a supported security
rollback.

### Kubernetes controller and data-plane upgrade

The Kubernetes integration remains `experimental`; its objective compatibility
and graduation rules are in
[KubernetesSupport.md](KubernetesSupport.md). For a controlled adjacent-version
upgrade:

A feature-promotion verification must validate every detached feature receipt
against an explicitly supplied repository, ref, phase, and full checked-out Git
revision. The ordinary policy check validates only registry, schema, generated
documentation, and lifecycle agreement; it does not consume qualification
receipts. Authenticated CI supplies the trusted revision and rechecks workflow
and attestation identities. Missing, malformed, stale, or mismatched evidence
blocks the lifecycle change.

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

For an otherwise attachable `HTTPRoute`, `GRPCRoute`, `TCPRoute`, or
`UDPRoute`, a cross-namespace Service `backendRef` without an authorizing
`ReferenceGrant` reports `Accepted=True`, `ResolvedRefs=False` with reason
`RefNotPermitted`, and `Programmed=False`. The route still contributes no
listener or upstream, so this status correction does not weaken the
fail-closed data-plane result and requires no manifest migration.

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

Post-beta.2 shared-state initialization serializes its PostgreSQL schema work
with one transaction-scoped advisory lock. All base shared-state and durable
UDP table and index DDL runs in that same transaction, so
concurrent initializers wait instead of racing PostgreSQL catalog object
creation. A lock, DDL, or commit failure leaves the transaction uncommitted and
keeps backend initialization fail closed. This correction does not change
configuration, table or index layouts, stored records, or public APIs, and it
requires no state migration, additional drain, or database restoration solely
for this change.

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

Post-`0.7.1-beta.2` development also adds a machine-readable graduation
policy and detached-evidence verifier for the ten non-Kubernetes features that
remain experimental in this source revision. The checker binds any future
promotion to the intended status and stable target version, exact repository,
ref, and commit, qualified native platforms, the policy-definition digest, and
the declared workflow, job, artifact, report, and log identities. The checker
rejects missing, duplicate, mismatched, or incomplete receipt content. A
promotion gate additionally requires authenticated workflow and attestation
readback before treating those declared identities as qualification evidence.
The manual `Feature graduation qualification` workflow accepts only one full
lowercase revision on the live `main` ref. It rechecks that revision against
the checkout, `origin/main`, and the GitHub API before native AMD64 and ARM64
qualification work. Its evidence collector binds the exact run attempt,
successful producer jobs, report bytes, and downloaded job logs before an
isolated OIDC job attests the sealed subject and predicate. The OIDC job does
not check out or execute repository or artifact code; a separate read-only job
performs cryptographic and policy readback.

The canonical `Check OxiBelt` workflow always includes
`Feature graduation exact verification` in the non-benchmark summary. While
both registries have zero supported rows, that job validates the checked-in
policies and succeeds without external evidence. On pull requests it also
compares canonical expectations from the exact trusted base revision without
executing base code: zero-supported base and head revisions pass, as do
byte-identical supported expectations. A promotion, demotion, or supported
policy or expectation change fails until canonical `main` is qualified. Live
`main` requires exactly one successful manual qualification run for the same
SHA, exact attempt-qualified artifact, receipt set, predicate, signer workflow,
and attestation. The current manual matrix fails explicitly because no reviewed
gate producer is checked in; its topology is not qualification evidence and
cannot authorize a promotion. General comparative benchmarks remain outside
this prerequisite; only a future direct-H1 gate receipt may bind that feature's
dedicated evidence.
This tooling does not itself promote a feature or change runtime defaults,
native configuration syntax or schema, Admin API wire behavior, persisted
state, or rollback behavior. Roll back the tooling by restoring the previous
source revision; no runtime or data migration is required.

The Kubernetes graduation registry now uses the same detached, feature-scoped
receipt contract instead of storing mutable pass/fail state and receipt paths
on shared gate descriptors. All fifteen Kubernetes/controller/Helm rows remain
`experimental` and `unvalidated` in this revision. The supply-chain admission
target is bounded to native `linux/amd64` and `linux/arm64`; the other fourteen
rows retain their existing RISC-V qualification gates and blocker without a new
RISC-V support claim.

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

Runtime snapshot, support-bundle, and active config explain consumers must
accept format version `2` before this upgrade. Runtime-introspection consumers
must accept format version `3`; version `3` adds the aggregate redacted
`turn.udp_clients_active` and `turn.allocations_active` counters. Version `2`
adds the requested and resolved presets, fallback outcome/reason,
subsystem owners, worker allocations, compatibility boundaries, and active
direct-H1 state. Public readiness also adds the bounded
`X-OxiBelt-Runtime-Status` header. These surfaces do not expose raw capability
probe errors, paths, hostnames, routes, peers, or secrets.

Post-beta.2 development first added experimental activation-plan schema version
`1` to `POST /admin/v1/config/diff`; the runtime-confinement contract advances
that schema through version `2` and now to version `3`. Existing consumers may continue reading
the preserved `changes[].path` and `changes[].op` fields, but strict response
decoders must accept the new root `activation_plan_schema_version`,
`native_schema_epoch`, `ok`, `basis`, and nested `activation_plan` fields.
Version `2` adds active-policy/current/candidate manifest digests plus a bounded
redacted confinement-difference list; it never adds raw filesystem paths.
Version `3` removes those stable, unkeyed path-derived digests from the redacted
Admin response, adds `digests_withheld`, and changes each confinement difference
to a `subject = "filesystem" | "seccomp"` tagged value. Filesystem differences
retain report-local `path_id`; seccomp differences instead carry an
`assertion_id` and never synthesize a filesystem path. Consumers must branch on
`subject` before decoding subject-specific fields.
Array changes are now expanded into deterministic indexed leaf paths instead
of one aggregate array entry, so consumers that group paths must normalize
indices deliberately.
This is an additive Admin API and CLI change; the native configuration schema
remains epoch `1`.

Online activation planning now requires `config:DiffSecrets` on `*` because
the exact changed/unchanged classification for secret fields is
secret-equivalent information. Update explicit `config:Diff` grants used for
`POST /admin/v1/config/diff`, `oxibeltctl config diff`, or
`oxibeltctl config plan --online`; the legacy action remains policy-valid but
receives `403` from the endpoint. Broad `config:*` and `*` grants continue to
authorize planning. This authorization migration does not independently change
activation-plan or native configuration schema versions.

The runtime-confinement contract replaces canonical
`runtime.hardening.seccomp.mode` with `expectation = "off" | "optional" |
"required"`. Compatibility loading maps legacy `off` to `off`, `log` to
`optional`, and `enforce` to `required` and emits a fixed migration diagnostic;
mixing `mode` with `expectation` is invalid. Optional `profile_identity` and
`profile_digest` are expected external assertions, not kernel-observed facts.
Edit the field and run `oxibeltctl config validate`; the epoch migrator only
handles the explicit epoch `0` to `1` transform and does not rewrite this
same-epoch compatibility alias.
The alias remains accepted throughout native schema epoch `1`; removal is
reserved for a future incompatible schema epoch.

Landlock gains `mode = "manifest"`; existing `mode = "enforce"` remains the
manual allowlist and needs no migration. Before selecting manifest mode, run
`oxibeltctl config filesystem-access CONFIG --check`, review the redacted
requirements, mount every required writable parent narrowly, and use
`--show-paths` only in a trusted local terminal. A candidate requiring broader
active rules cannot hot reload; retain the previous process or immutable
workload until the restart/rollout plan succeeds.

Filesystem-access manifest/check JSON advances from schema version `1` to `2`.
The redacted default omits `manifest_digest` and sets
`manifest_digest_withheld = true`; `--show-paths` reveals both paths and the
stable comparison digest. Check reports add `total_findings` and
`findings_truncated` so bounded output cannot be mistaken for a complete list.

Post-beta.2 filesystem-access manifest/check JSON advances from schema version
`2` to `3`. Version 3 gives a fully verified Kubernetes AtomicWriter projection
the logical configured path as its digest identity while retaining the
canonical resolved target for checks and Landlock rules. This prevents a normal
ConfigMap or Secret timestamp-directory rotation from changing the digest, but
does not normalize incomplete, ambiguous, escaping, or lookalike symlink
layouts. Version 2 and version 3 digests are deliberately not interchangeable:
regenerate every `runtime.hardening.filesystem_manifest.expected_digest` and
Helm `runtimeHardening.filesystemManifest.expectedDigest` with the v3
`oxibeltctl config filesystem-access CONFIG --show-paths` output before rolling
out the v3 runtime and configuration together. Roll back the image and its
retained v2 expected digest as one immutable revision.

Support-bundle format advances from `2` to `3`, config-explain from `2` to `3`,
and runtime-check/hardening JSON advances to schema version `2` for bounded
effective-rule summaries and explicit digest-withholding metadata. The installed
authority used for reload admission remains internal and is never serialized.
Required seccomp now fails before listener startup unless Linux
reports filter mode `2` and `NoNewPrivs: 1`; ensure Docker/Kubernetes applies
the filter and no-new-privileges before changing from `off` or `optional`.
Rollback by restoring `expectation = "off"` or the retained prior config and
restarting with the prior immutable image. Landlock and seccomp are irreversible
inside a running process, so rollback always replaces the process rather than
attempting to weaken its current policy.

Post-beta.2 development also splits the public Rust startup API into explicit
owned and embedded modes. Existing library callers should migrate from the
deprecated `run`, `run_with_options`, and `configure_crypto_runtime` functions
to `OxiBelt::builder`; see [Embedding OxiBelt](Embedding.md). Use
`RuntimePolicy::FromConfig` with `ProcessPolicy::Standalone` when OxiBelt owns
runtime construction, signals, and configured hardening. Use
`RuntimePolicy::CurrentRuntime` with `ProcessPolicy::Embedded` when the caller
owns Tokio and select `ProcessGlobalHooks::CallerManaged`, `VerifyOnly`, or an
explicit `ApplySelected` grant.

The deprecated async run wrappers now use the caller's current runtime,
caller-managed process globals, and no implicit signals or Landlock. They
return a structured migration error when configuration requires process
ownership. Embedded runtime/topology and executor-worker settings are reported
as inapplicable rather than silently resized or falsely claimed. Prometheus
consumers that exactly match `oxibelt_runtime_worker_allocation` must accept its
bounded `applicability` label (`applied` or `inapplicable`) and update selectors
or parsers that assumed only `pool` and `owner`. New callers must retain
`ServerHandle` and await consuming `shutdown(deadline)` or `wait()` before
dropping their runtime when joined cleanup is required; dropping the handle
requests cancellation but does not prove a join. Sequential replacement should
wait for joined terminal completion and must retain compatible immutable
process-global choices; concurrent instances are not guaranteed. This changes
the Rust library compatibility surface but does not change TOML syntax, native
schema epoch, Admin wire schemas, or persisted state. Roll back by returning to
the prior library version and its startup wrapper; restart the host process
rather than attempting to reverse an installed process-global hook or Landlock
policy.

`edge-secure-medium` v2 is an explicit opt-in and never replaces an omitted or
explicit v1 selector. Before changing `profile_version = 1` to `2` in Helm or
native TOML:

1. switch to the official `dataplane-strict` repository and independently
   approve its exact lowercase SHA-256 digest;
2. inventory all ingress and egress dependencies, replace implicit reachability
   with typed peers/ports, and review each world-CIDR escape individually;
3. replace generic writable mounts with bounded `writableVolumes`, then run
   `oxibeltctl config filesystem-access CONFIG --check --show-paths` in a
   trusted environment and record the final expected manifest digest;
4. verify versioned TLS/rule/other Secret references, restricted Pod Security
   admission, projected-token audience/expiry when API access is required, and
   the Secret-free profile report; and
5. canary the immutable rollout while monitoring hardening status, readiness,
   DNS/upstream reachability, and CNI policy events.

V2 changes the Pod template for image identity, security, networking,
hardening, report, and safe reference checksums, so it is restart-required.
Runtime-check and hardening snapshots advance from schema version `2` to `3`;
consumers must accept the new bounded `filesystem_manifest` object and fixed
mismatch reasons without expecting raw digests or paths.
Roll back by restoring the retained v1 values and v1 image reference as one
immutable Helm revision. Do not weaken NetworkPolicy, seccomp, Landlock, Pod
Security admission, or a validating webhook in place to make a failed v2
rollout proceed. Existing v1 behavior, omission semantics, and tag-based image
compatibility remain available through the explicit rollback revision.

The protocol-neutral canonical resolver policy is now `[proxy.upstream_resolution]`.
Epoch `1` still accepts `[quic.upstream.resolution]` as a deprecated compatibility
input; move every leaf to the canonical table and do not configure the same
effective leaf in both locations. Resolver-policy changes require `full_reload`;
existing draining connections retain their bounded lifetime. Roll back by restoring
the retained epoch-1 legacy table or the prior canonical values and reloading.

Post-beta.2 development also refreshes the pinned RISC-V `cross-rs` builder
source and image together with the rootless Docker input used for independent
release rebuilds. The compiler version, target, linker, compiler-file hash,
`/x-tools`-only copy boundary, executable and image roles, repositories,
packaging layout, runtime capabilities, configuration, and persisted state are
unchanged, so this maintenance update requires no configuration or state
migration.

A later release candidate must rebuild every official artifact and produce
fresh exact-revision vulnerability, attestation, provenance, and independent-
rebuild evidence with the refreshed inputs; evidence produced with earlier
pins must not be reused. Roll back a deployed candidate by restoring the
retained prior immutable image digests rather than by changing configuration or
persisted state.

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
online command needs `config:DiffSecrets`; exact fixed-member identities
additionally need `config:GetInstances`. Neither mode applies the candidate,
satisfies a mutation envelope, or proves zero downtime. Exit `0` means the
candidate has a valid, supported, non-blocked plan, including restart or
rollout. Exit `1` means invalid, unsupported, blocked, unauthorized, or failed
planning.

Automation must inspect both `minimum_required_operation` and
`selected_operation`, every `conditional` and prerequisite availability,
listener bind conflicts, long-connection effects, rollback class, confinement
digests, and bounded differences. Offline mount/kernel evidence can remain
unresolved; do not infer it from requested configuration or a checked-in
profile. In Kubernetes immutable mode retain the previous immutable artifact
and let the workload controller perform rollout. In `admin_cluster` mode keep
the signed/durable artifact, exact membership, all-member acknowledgement, and
protected-write flow authoritative. Roll back this tooling change by ignoring
the additive fields or using the previous CLI; do not roll back an activated
configuration merely because its advisory plan format changed.

This post-beta.2 compatibility change requires a later governed beta and
fresh exact-revision evidence; it is not part of beta.2's immutable release
record.

Post-beta.2 development also adds stable discovery-instance identity and
aggregate weight composition to HTTP upstream pools. Existing pools with one
instance of each discovery provider remain valid: an omitted `id` derives the
legacy provider identity and an omitted `weight_multiplier` remains `1`.
Configure explicit unique IDs when one pool contains the same provider more
than once. Generated weighted multi-Service EndpointSlice pools require an
exact-version controller/data-plane pairing and are blocked while
`compatibility.mode = "rolling_upgrade"`, because a previous-minor data plane
cannot parse or preserve the new ownership fields. Roll back by returning the
route to one nonzero discovered Service, or by selecting `cluster_dns` before
entering rolling-upgrade mode; never remove identity fields from an already
active multi-instance pool in place. The data plane now scopes its internal
server IDs to provider-plus-instance ownership, so dashboards or Admin clients
must treat discovered server IDs as opaque and should key operator meaning from
the discovery instance. Configuration admission is capped at 64 instances per
pool and 256 total; split configurations above those limits before upgrade.

Post-beta.2 development also adds an optional static replicated data-plane
target set for the Gateway controller. An empty Helm `rollout.targets` array
preserves the existing single `rollout.target` behavior. Enabling the new mode
creates operator-owned
`OxiBeltDataPlaneTarget.gateway.oxibelt.dev/v1alpha1` resources and changes
artifact identity so it additionally binds target identity, GatewayClass,
policy version, capability set, rollout policy, and the target-specific source
snapshot. A target policy or capability change also changes the persisted
target-context digest; automatic rollback refuses an artifact from the earlier
context. Restore the earlier typed target policy before requesting that prior
artifact explicitly. Treat
this as a controller rollout boundary: apply the operator-owned CRD from
`deploy/kubernetes/oxibelt-gateway-controller/crds/` before the Helm upgrade,
let the chart install exact-name target RBAC, validate every target workload's immutable-rollout opt-in and
effective version, then add all replicated targets for the one managed
GatewayClass. `Programmed=True` is withheld until every assigned target has an
independent active proof, including a final proof pass after the controller
re-reads the complete source and target policy. Target snapshots include only
their selected Gateways/routes and reference-reachable Services, grants, TLS
policies, and CA ConfigMaps; unrelated namespaces can no longer block or churn
another target's artifact. To roll back the topology, retain every target's last
committed immutable ConfigMap, remove the typed target resources, restore the
legacy target values, and wait for that target's own proof; never copy a
revision from one target workload to another.

Post-beta.2 development also corrects Gateway HTTP `ExternalAuth` request-header
projection for `HTTPRoute` and `GRPCRoute`. Generated `forward_headers` now
contains only the route-authored `externalAuth.http.allowedHeaders` values that
the operator admits. Omitting the route list produces `forward_headers = []`
even when the operator allowlist contains `authorization`; operator admission
alone no longer forwards a downstream bearer credential.

Before upgrading, audit routes whose authorization service depends on that
formerly implicit header. Forwarding `Authorization` now requires all three
explicit opt-ins: `authorization` in the route's
`externalAuth.http.allowedHeaders`,
`--external-auth-allowed-request-header=authorization` (or `authorization` in
Helm `filters.externalAuth.allowedRequestHeaders`), and
`--external-auth-allow-credentials` (or Helm
`filters.externalAuth.allowCredentials = true`). A route that requests a
header outside the operator allowlist remains blocked with a diagnostic. This
correction changes no Gateway API or native configuration schema and requires
no persisted-state migration.

Rolling back to an earlier controller can resume implicit `Authorization`
forwarding when a route omits it. Roll back only after confirming every
selected authorization Service may receive that credential, or first stop the
affected `ExternalAuth` routes from carrying downstream bearer credentials.
Do not treat omission from `externalAuth.http.allowedHeaders` as a credential
deny boundary while an older controller is active.

Post-beta.2 development also aligns the opt-in staged Admin-cluster membership
writes with the Admin audit durability boundary. The exact proposal endpoint,
`POST /admin/v1/membership/transitions`, uses `membership.propose`; exact
one-segment `POST /admin/v1/membership/transitions/{transition_id}/activate`
and `/cancel` requests use `membership.activate` and `membership.cancel`.
Learner readiness, catch-up and status reads, wrong methods, and malformed
nested paths remain outside those action identities. When one of these actions
requires durable audit acknowledgement, an acknowledgement failure rejects the
request before the membership effect is published.

Deployments with active `[admin.mutations]` and
`admin.audit.mode = "durable_required_for_actions"` must add all three
`membership.*` identifiers to `admin.audit.required_actions`, for twelve
protected action IDs in total.
`durable_required` already covers them without an action list. Earlier binaries
reject the new identifiers, while this version rejects the former nine-action
selective list when Admin mutations are active. Either stop protected writes
and replace the binary and configuration together, or first switch to
`durable_required` and remove `required_actions`, validate that bridge with the
old binary, upgrade every member, and only then restore selective mode with all
twelve identifiers. Use the same `durable_required` bridge before rolling back
to an earlier binary; never bridge through `best_effort`. Fixed membership
remains the default.

The initial post-beta.2 staged-membership implementation advertised the three
protected transition writes above but rejected them during cluster operation
reconstruction before admission. Corrected binaries route the exact proposal,
one-segment activation, and one-segment cancellation `POST` requests through
shared-staged validation; readiness, catch-up and status reads, wrong methods,
arbitrary membership paths, mismatched transition IDs, and malformed nested
paths remain rejected. Keep protected membership writes quiesced until every
active Admin-cluster member runs a corrected binary because an older member
cannot validate or acknowledge the command. Complete or cancel any pending
transition before rolling a member back; restoring an affected binary restores
the fail-closed rejection. These audit and route-classification corrections
change no Admin wire shape, native configuration schema epoch, or persisted-state
format.

The Rust `1.97.1` lint-compatibility cleanup applied after the staged-membership
v2 implementation changes only internal sealed-result and heartbeat-bootstrap
plumbing. It does not change Admin HTTP or mutation wire shapes, native
configuration syntax, defaults, or schema epoch; stored membership or epoch
state; key derivation, encryption, or zeroization; membership admission,
fencing, readiness, or activation; heartbeat scheduling or metrics; or the
upgrade and rollback sequence above. Existing clusters require no migration or
additional coordinated rollout for this cleanup.

The subsequent dependency-maintenance refresh updates patch-level Rust crates,
pnpm development tooling, CodeQL and image-build/scan tooling, the sustained
fuzz nightly, and the immutable Node 24 Alpine builder-stage digest. The final
runtime Alpine base, published image roles, executable inventories, users,
ports, native configuration and Admin wire shapes, schema epoch, and persisted
state formats are unchanged. No configuration or state migration is required;
roll out and roll back through the normal exact-revision, immutable-image-digest
procedure, and keep each rebuild bound to the target revision's complete
lockfiles and pinned builder inputs rather than mixing inputs across revisions.

The subsequent fuzzing-harness maintenance keeps the `oxibeltctl` CLI in
default and image builds through its explicit default `cli` feature. A
`--no-default-features` build must request `--features cli` to build the
executable, while fuzzing intentionally uses the library-only
`--no-default-features --features fuzzing` configuration. Moving fingerprint
normalization into reusable code does not change accepted rulepack
fingerprints, signature verification, or trust decisions. The Admin canonical
JSON helper and the WAF normalization, CRS parsing, and configuration-policy
additions are fuzz-only entry points or behavior-preserving refactors; the fuzz
targets do not by themselves establish live network, filesystem, or storage
behavior or universal idempotence.

This maintenance changes no Admin wire or audit schema, rulepack format or
signature contract, native configuration schema or defaults, or persisted
state. It requires no coordinated rollout or data migration. Roll back through
the normal exact-revision, immutable-image procedure; an older binary need not
build or run the new fuzz targets.

A later staged-membership correction lets an instance outside an active legacy
version-`1` epoch remain online as a non-participating learner when the legacy
shared artifact key is not provisioned. The learner still cannot send an
active-member heartbeat, acquire coordinator or fencing authority, validate or
acknowledge protected writes, serve privileged mutation decisions, or make a
rollout ready. Active version-`1` members still require the shared key, and
version-`2` fingerprint, key-wrap, readiness, and activation behavior is
unchanged. The correction changes no Admin wire shape, native configuration,
schema epoch, persisted state, or cryptographic format and requires no migration
or coordinated active-member rollout. Before rolling a keyless learner back to
an affected binary while a version-`1` epoch remains active, stop that learner or
provision the legacy key through the protected external secret channel; the
older binary can otherwise fail heartbeat initialization.

Existing signed v1 and v2 supply-chain bundle wire shapes remain readable.
Admission now stops accepting either schema when the earliest signed
provenance, SBOM, rebuild-recipe, or independent-rebuild timestamp exceeds
`maxEvidenceAgeSeconds`, even if `expiresAt` is later. New generation rejects
such a later expiry and requires canonical rebuild metadata plus
attempt-bound, stable GitHub run evidence. Fresh independent-rebuild receipts
also bind the approved verifier commit and exact platform-recipe hash and must
satisfy the complete fixed comparison contract. `exact` now requires both the
OCI manifest and image archive SHA-256 to match; a matching manifest in a
different archive is only normalized-equivalent. Regenerate bundles from fresh
evidence before rollout. The v2 extension fields remain backward readable only
when all are absent; new bundles carry a positive run attempt and all three
platform-recipe hashes, and partial forms are invalid.

Neither the immutable `0.7.0`, `0.7.1-beta.1`, nor `0.7.1-beta.3` tag is a
deployable upgrade target. All three failed exact-revision release-contract
validation before draft creation and have no GitHub Release or official
artifact. The published `0.7.1-beta.2` prerelease completed its release-image
workflow but not its automatic independent rebuild, so it remains a source
and configuration recovery point rather than qualified stable-release
evidence.

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

A local source build from `0.7.1-beta.1` or `0.7.1-beta.3`, or a deployment
that used beta.2 under an operator's prerelease policy, may be retained only as
recovery history. Before replacing it with a person-reviewed later release,
validate the active epoch-1 configuration and referenced files, retain all
prior digests and backups, and confirm that controller and data-plane roles
use the same target revision:

```sh
oxibeltctl config validate /etc/oxibelt/config/oxibelt.toml --local-only
```

Do not reuse the failed beta.1 or beta.3 workflow runs, their absent release
artifacts, the incomplete `0.7.0-beta.4` evidence, or beta.2's incomplete
independent-rebuild set. `0.7.1-beta.4` must produce its own complete
30-subject image and evidence set before rollout. Its direct beta.2 recovery
path admits the active epoch-1 configuration and compatible state, not any
prior artifact or qualification result.
