# Cache Groups

Cache groups implement the [RFC 9875](https://www.rfc-editor.org/rfc/rfc9875)
response membership and invalidation fields. They are enabled by default with `[cache.groups] enabled = true` and
can be disabled for an individual `[cache.policies]` entry with its nested
`groups.enabled` setting. The switch changes cache identity, so enabling it on
an existing cache starts with cold misses in the group namespace.

Origins attach membership with the `Cache-Groups` Structured Fields List. The
list accepts only strings; unknown item parameters are ignored. OxiBelt joins
all field lines and accepts at most 64 raw members, 256 decoded bytes per
member, and 16 KiB of combined field data. Membership values are opaque,
case-sensitive strings, with first-occurrence de-duplication. A malformed or
over-bound field rejects that response from group-aware caching. Empty strings
and an empty list are valid memberships.

## Invalidation

After response rules have run, OxiBelt preserves both `Cache-Groups` and
`Cache-Group-Invalidation` response fields in a cached response. Invalidation
executes only from a live final origin response, never a synthetic,
informational, trailer, or cached response. A non-safe request whose final
response is a 2xx or 3xx invalidates its exact target. Any other final status
invalidates only when its `Cache-Group-Invalidation` field supplies valid
members. GET, HEAD, OPTIONS, TRACE, and exact-uppercase QUERY do not trigger
this response-driven invalidation. Directly selected memberships are applied
once; they do not cascade through another member. On a 304 revalidation, an
absent membership field preserves the old membership, a valid field replaces
it, an empty list clears it, and an invalid field permits no reuse. An
invalidated old owner cannot be resurrected by the replacement fill.

No-Vary-Search aliases participate only when their validated owner path is
recorded in the group stamp. An exact invalidation also selects such aliases
with the same path, including old and new query representations. Ordinary
entries have no path marker and remain exact-target entries.

The Admin cache purge endpoint supports `type: "group"`, a canonical absolute
`origin`, an opaque decoded JSON string in `group`, and an optional cache
partition. It requires `cache:PurgeGroup` for the selected policy and origin
host. Exact, prefix, and tag purges on a group-aware policy require their
existing specific grant as well as `cache:PurgeGroup`; `oxibeltctl` plans
surface the same requirement.

```sh
oxibeltctl cache purge group \
  --origin https://example.test \
  --group release-1 \
  --partition tenant-a
```

## State, tiers, and recovery

Group stamps are scoped by canonical HTTP/HTTPS origin, policy, and cache
partition. The local cache is L1. Shared cache authorities use one atomic
compare-and-exchange transition for L2 state. An external L3 participates only
after it advertises the cache-groups capability; a handler without that
capability is not trusted for group-aware reuse. The persisted authority is
bounded to 16 MiB, 1024 scopes, 4096 names per map, and 4096 indexed entries
per scope. An Admin invalidation also preflights a 4096-entry enumeration
budget before it changes state.

The index retains membership metadata through the longest permitted freshness
or stale lifetime, including after a local body is evicted; eviction itself
does not propagate invalidation. Purge counts describe these indexed logical
representations across tiers. Failed writes conditionally withdraw their
publication without removing a concurrent replacement. Capacity exhaustion
bypasses further admission rather than dropping generation history.

Activation establishes enabled and disabled remote generations before the new
runtime snapshot is published. An ordinary cache hit does not reactivate a
disabled authority generation.

There is no pre-request barrier across disconnected nodes. The node that
receives an invalidating origin response preserves that origin response but
fences later group-aware reuse when the authority operation fails. Other nodes
that did not receive that invalidation can reuse their local entries until
recovery or expiry. Recovery creates a new complete policy generation instead
of replaying an unbounded unsafe-response queue. Monitor
`oxibelt_cache_group_invalidations_total`,
`oxibelt_cache_group_errors_total`, and
`oxibelt_cache_group_recoveries_total` with ordinary cache hit/miss metrics.

## External authority protocol

A capable external handler implements `POST cache-group-state` beneath its
configured endpoint. Requests use `protocol_version: "oxibelt-external-cache-v1"`,
`cache_key_version: "oxibelt-cache-groups-key-v1"`, a policy-derived `key`, and
`required_capabilities: ["cache-groups-v1"]`. Every successful JSON response
must advertise `capabilities: ["cache-groups-v1"]`.

| Request mode | Request fields | Response fields |
| --- | --- | --- |
| `read` | `key` | `value_base64`, omitted or null when absent |
| `compare_exchange` | `key`, optional `expected_base64`, required `replacement_base64` | `exchanged` boolean |

State values are opaque standard Base64-encoded bytes. An absent expectation
means the key must be absent; it is distinct from an empty byte value. The
handler must compare and replace atomically across all clients and preserve
authority state independently of cached-body eviction. A successful exchange
must be visible to subsequent reads. The decoded state limit is 16 MiB; the
configured `max_metadata_bytes` also bounds each complete JSON request and
response, including Base64 expansion.

An initial 404, 501, or response without the capability identifies an
unsupported handler. Once support has been established, losing it is an
authority failure and cannot silently switch the policy to local authority.
See the [protocol types](../source/src/cache/external_handler/group_protocol.rs)
and [test handler](../tests/docker/mock_external_cache/server.py) for the wire
shapes, alongside the ordinary external cache entry protocol.

## Rollout and rollback

Enabled policies validate group generations on cache hits, including responses
without a `Cache-Groups` field. Shared or capable external authorities require
remote validation, so their latency affects local hits too. These checks add
work compared with the disabled legacy namespace; assess cache-hit throughput
and origin load under invalidation before enabling a production policy.
When invalidation prevents a fill from publishing, the existing one-second
failed-fill suppression window still applies. Frequent invalidations can
therefore produce substantial origin traffic even when cached reuse resumes
normally after the invalidations stop.

The configuration and native-schema epochs are unchanged. During a
mixed-version rollout, explicitly set `[cache.groups] enabled = false` on
upgraded nodes, complete the binary upgrade across every cache participant,
then enable it. The new namespace produces cold misses for legacy entries, so
an ordinary upgrade does not require a manual cache clear; clear failed
authority state when recovery requires it. Before returning to an older binary,
remove `[cache.groups]` and every policy `groups` value, remove group-only
Admin/API values from automation, and cold-clear all cache tiers and group
authority state before starting the old binary.
