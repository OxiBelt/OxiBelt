# No-Vary-Search cache semantics

OxiBelt implements the [No-Vary-Search draft-09 response field](https://www.ietf.org/archive/id/draft-ietf-httpbis-no-vary-search-09.html) for
cacheable `GET`, `HEAD`, and opt-in `QUERY` requests. The top-level
`cache.no_vary_search` setting defaults to `true`; there is no per-route
opt-in. A request always tries its established exact cache key first. An
equivalent-query lookup is a bounded second step and never changes an exact
key, an explicit `{query:name}` token, or a raw `partition_key` value.

## Response field

All `No-Vary-Search` field lines form one RFC 9651 dictionary. OxiBelt accepts
the draft-09 members below and ignores unknown members:

- `params=("name" ...)` says the listed decoded form parameter names do not
  vary the response.
- `except=("name" ...)` says only the listed decoded form parameter names vary
  the response.
- `key-order` or `key-order=?1` permits parameter-name reordering. The order
  of duplicate pairs with the same name remains significant.

`params` and `except` are mutually exclusive. Their values must be inner lists
of strings; standalone values are invalid. RFC 9651 duplicate dictionary
members use the final member. A declaration with default behavior (such as
`params=()` alone or `key-order=?0` alone), an absent field, a malformed field,
an over-limit field, or both parameter members retain exact matching.
Configured names use form decoding without treating an encoded `&`
as a list separator. With `key-order`, names are compared in UTF-16 code-unit
order and serialization retains received order for equal names.

The field is capped at 4 KiB across combined lines, with at most 128 configured
parameter names. Query comparison admits at most 1024 pairs. Any bound or
parse failure is an exact-only result.

## Alias authorization and ownership

For an alias, the response rule must make both pairs equivalent: the received
downstream target and stored owner target, and the effective upstream target
after request rewrites and the owner's effective target. Non-query URI parts
stay exact. The scope also binds policy, route/upstream request context,
raw/effective target form, cache-key dimensions other than ordinary query
expansion, partition, verified-certificate and PROXY-TLS partitions, and
QUERY representation identity.

QUERY aliases preserve the original and effective request representations,
including method namespace, body digest, content headers, and trailers. A
candidate never supplies response bytes: OxiBelt reloads its exact owner and
requires the stored No-Vary-Search metadata and original field bytes to match
before reuse.

Alias indexes store at most the configured `max_vary_variants_per_key` limit,
capped at 1024. L1 retains bounded owner keys, L2 has fixed per-scope candidate
slots, and L3 responses are capped to the same bound. Missing, expired,
malformed, or displaced index records are cache misses. Shared and external
indexes expire no later than their owner retention.

Administrative exact purge advances a path fence and removes same-path owners
conservatively. Prefix and tag purge advance a policy-wide fence. Unsafe origin
responses advance path fences for every cache policy. These fences prevent an
in-flight old fill from being selected after a purge.

## Revalidation and refresh

An alias revalidates the stored owner's effective upstream target while keeping
the caller's target for downstream processing. A changed declaration retires the
old policy even when the replacement cannot be stored. A valid replacement is
stored under the owner's exact key. If a `304` or replacement response no longer
authorizes the current alias, OxiBelt fetches that alias unconditionally within
the original upstream deadline; an unexpected `304` from that fetch is an error.
Background refresh updates the owner and its policy so future alias lookups use
the refreshed declaration. Owner retries retain the original effective target
and do not transfer its validators to another pool origin.

Disk records persist only validated bounded metadata. If the durable epoch
vector is unavailable during recovery, recovered No-Vary-Search metadata is
discarded so aliases cannot be rebuilt from it. Exact response metadata remains
subject to normal cache validation and purge behavior.

Turning `cache.no_vary_search` off stops new alias storage and equivalent
lookup. Existing entries carrying No-Vary-Search metadata still honor their
stored invalidation fences, so disabling the switch cannot resurrect a response
that an earlier unsafe response or purge invalidated.

## External cache handlers

The existing external-cache protocol remains exact-key compatible. A handler
opts into aliases by returning the `no-vary-search-v1` capability. OxiBelt uses
two bounded JSON control endpoints relative to the configured handler URL:

- `POST nvs-epoch` accepts `protocol_version`, `cache_key_version`, `policy`,
  `scheme`, `host`, `uri`, `advance`, `epoch_bucket`, and
  `required_capabilities: ["no-vary-search-v1"]`. It returns `target_epoch`
  and a `capabilities` array containing `no-vary-search-v1`.
- `POST nvs-candidates` accepts `protocol_version`, `cache_key_version`,
  `policy`, `scope`, `limit` (`1..=1024`), and the same required capability.
  It returns `capabilities` plus at most `limit` candidates. Each candidate has
  `metadata` (`version`, `scope`, `owner_uri`, `effective_uri`, `epoch`,
  `policy_epoch`, `candidate_limit`), response-field `fields` as JSON byte
  arrays, and `date_ms`.

Both epoch target kinds use the existing fixed query-epoch bucket calculation:
the first two SHA-256 bytes of UTF-8 `policy + "\n" + scheme + "\n" + host +
"\n" + uri`, interpreted as a big-endian unsigned integer modulo 256. A path
fence uses `scheme = "nvs-v1:{downstream_scheme}"`, the downstream host, and
the raw path. A broad prefix or tag fence uses `scheme = "nvs-policy-v1"`, an
empty host, and `uri = "/"`. The capability is required on both requests and
responses; absent capability, malformed JSON, an oversized response, or an
unsupported handler is an alias miss.

During mixed-version rollout, old L3 handlers continue serving ordinary exact
entries that do not carry No-Vary-Search metadata. They do not participate in
alias discovery or epoch authority. A tagged record from a handler that no
longer advertises `no-vary-search-v1` is a safe miss rather than an unfenced
exact or alias hit.
