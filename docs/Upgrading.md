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
| `0.6.5` | `0.7.0-beta.1` | Planned | The exact beta entry must be added to `CHANGELOG-beta.md` before the tag is pushed. |
| `0.6.5` | `0.7.0` | Planned | Follow [Upgrade from 0.6.5 to the 0.7.0 line](#upgrade-from-065-to-the-070-line); the exact stable entry must be added to `CHANGELOG.md` before the tag is pushed. |
| `X.Y.Z-beta.N` | `X.Y.Z-beta.(N+1)` | Conditional | The later beta entry must name both the preceding beta and preceding stable release as supported sources. |
| latest `X.Y.Z-beta.N` | `X.Y.Z` | Conditional | The stable entry must name that exact beta as a supported source. |

The release-specific changelog entry is authoritative when a row is marked
`Planned` or `Conditional`. A tag cannot prepare a GitHub draft release until
the matching entry and upgrade link pass the repository release-contract
checker.

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
