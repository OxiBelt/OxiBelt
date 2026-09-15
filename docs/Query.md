# HTTP QUERY

OxiBelt forwards the exact uppercase `QUERY` method defined by
[RFC 10008](https://www.rfc-editor.org/rfc/rfc10008.html) through HTTP/1.1,
HTTP/2, and HTTP/3. The origin interprets the query language and chooses the
response. `Accept-Query`, origin redirects, and response metadata pass through
normal header and response processing.

## Admission and forwarding

Every QUERY must contain exactly one syntactically valid `Content-Type` field,
including an empty QUERY. Missing, malformed, and duplicate fields receive
`400`. Normal framing, routing, TLS, and early-data checks retain their order;
Content-Type is checked again after request header transformations. OxiBelt
does not synthesize a query language or decode application query content.

QUERY is safe and idempotent. Transport-verified early data is accepted when
`ssl_early_data = "safe_methods"` permits it; early data remains disabled by
default. Safety does not imply an empty body: DATA and trailers follow normal
body limits, WAF inspection, transformations, and timeouts. Lowercase `query`
is an extension method and does not receive QUERY-specific safety or caching.
Static-file routes continue to support GET and HEAD.

## Opt-in response caching

Default cache methods remain `GET` and `HEAD`. Opt in on the selected policy:

```toml
[cache]
enabled = true
cache_methods = ["GET", "HEAD", "QUERY"]
```

QUERY cache keys use a separate versioned namespace. In addition to the
configured cache key, partition, certificate identity, and PROXY identity,
they bind both the received and effective upstream representations:

- Scheme, authority, path, and query string.
- Complete content length and SHA-256 digest.
- Content metadata and ordered duplicate trailer values.

The effective headers supply key-template and `Vary` values. Credential and
no-store bypass rules apply to both received and effective headers. No QUERY
entry is eligible without complete, bounded identity. GET and HEAD keys keep
their existing format; neither can reuse a QUERY entry.

With streaming buffering, capture stops at `max_memory_body_bytes`. Overflow
restores the captured prefix and the live upload, then bypasses caching. It
does not add an upload rejection. Explicit memory/spool limits retain their
existing rejection behavior. Spool files are private and removed after the
last request or refresh consumer releases them. Incremental uploads bypass
QUERY cache capture.

Conditional and range requests first select the exact body-bound cached
representation. `If-None-Match` uses weak entity-tag comparison and takes
precedence over `If-Modified-Since`; malformed entity-tag lists go to the
origin. `If-Match` and `If-Unmodified-Since` always bypass QUERY caching.
Single and multipart ranges use the existing cached-range rules.

Eligible stale-while-revalidate QUERY requests can refresh using the captured
effective content and trailers, including over an HTTP/3 upstream. Refresh
retains existing concurrency, response-size, WAF, and PROXY-egress restrictions
and performs one attempt. Request content is held by that refresh task and is
not stored as part of the response-cache entry.

Successful unsafe or unknown-method origin responses invalidate QUERY variants
of the target across policies and partitions. Pending fills are fenced against
publishing the old representation. Failed backend invalidation disables QUERY
reuse for the affected policy and epoch bucket. Administrative exact, prefix, and tag purges retain
their existing broader scope.

## Durable invalidation and external handlers

QUERY invalidation uses 256 bounded epoch buckets per cache policy. The bucket
is the first two bytes of SHA-256 of `policy\nscheme\nhost\nuri`, interpreted
as an unsigned big-endian integer modulo 256. Collisions conservatively expire
other QUERY entries in that policy. GET and HEAD entries are unaffected.
Local disk caches atomically persist a versioned epoch vector. Invalid vectors
disable QUERY reuse; a missing vector discards recovered QUERY entries before
initializing fresh state. Shared caches read the authoritative epoch before
local hits, so a late shared-store write cannot resurrect an invalidated entry.

External handlers retain protocol `oxibelt-external-cache-v1`. QUERY entries
use key version `oxibelt-cache-query-key-v1` and require capability
`query-target-epoch-v1`. An external-only cache calls `POST query-epoch` before
reuse, with `protocol_version`, `cache_key_version`, `policy`, `scheme`, `host`,
`uri`, `epoch_bucket`, `advance`, and `required_capabilities`. Its JSON response
must include `target_epoch` and a `capabilities` array containing the required
capability. The handler must durably maintain a nondecreasing counter per
policy and bucket, atomically incrementing it when `advance` is true. Reads
must observe completed increments. QUERY lookup and entry metadata bind
`query_target_epoch`; purge requests carry it as well. When shared cache is
configured, its epoch counter is authoritative for the external tier too.
Legacy handlers without the capability bypass QUERY caching. Legacy GET/HEAD
messages omit these optional fields and keep their existing keys.

## Retries

HTTP/3 uses the configured HTTP retry conditions, attempt counts, deadlines,
backoff, overload limits, and pool reselection. This applies to all eligible
methods; non-idempotent methods such as POST still require explicit retry
opt-in. Replay preserves DATA and trailers. A transport failure after a
nonempty request was handed to the upstream cannot prove that content was
unsent, so that ambiguous attempt is not replayed. A completed retryable
status response remains eligible for a policy-controlled retry. Pool reselection
conservatively skips QUERY cache publication because the final effective
target may have changed.

## Admin and Gateway

See [Admin cache operations](AdminAPI.md) for QUERY warming and exact key
explanation. QUERY explain requires explicit received and effective content;
it does not predict origin-side query evaluation.

Gateway API routes without a method match can forward QUERY. The pinned
Gateway API method enum does not contain QUERY; no custom method-match or CORS
extension is introduced. Native OxiBelt method matching can use `QUERY`.

## Validation

```sh
cargo test -p oxibelt --lib query
cargo test -p oxibelt --lib proxy::http::retry
```

The handler tests cover request-version admission, H1/H2 upstream forwarding,
body-separated hits, conditionals, ranges, overflow, and invalidation. Retry
tests include a real QUIC/H3 origin. These checks are distinct from Docker
protocol-matrix and PostgreSQL recovery validation.
