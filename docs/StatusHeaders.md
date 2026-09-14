# Status-header contract

OxiBelt can emit [RFC 9209 `Proxy-Status`](https://www.rfc-editor.org/rfc/rfc9209.html)
and [RFC 9211 `Cache-Status`](https://www.rfc-editor.org/rfc/rfc9211.html) response fields. The
global `[proxy.status_headers]` policy defaults to `proxy_status = true`,
`cache_status = true`, and `upstream = "preserve"`; `[routes.status_headers]`
overrides each field independently. These defaults add diagnostic response
headers. They do not alter request routing, cache decisions, WAF phases,
response processing, or legacy `X-OxiBelt-Cache` fields. No new trailers are generated.

## Local members

OxiBelt generates a local member only for proxied responses. Local origin-role
responses are excluded. The configured `identifier` is a trusted local alias;
it is never copied or inferred from an upstream field. It must be one through
128 printable ASCII characters and cannot be whitespace-only.

When no identifier is configured, OxiBelt generates an opaque identifier once
per process. It remains stable across configuration reloads in that process and
rotates after a restart. It is not an instance identity or a request
correlation value.

`Proxy-Status` reports only bounded local facts such as a classified error,
received response status, and upstream protocol. `Cache-Status` reports local
cache facts only for cache-enabled routes. A complete cache fill can report its
forward reason, received upstream status, and successful storage; a cache hit
reports `hit` and its remaining TTL when known. Facts are sparse: stale and collapsed
responses include only facts OxiBelt established, missing source status does
not create `fwd-status`, and a streaming fill omits `stored` because storage is
not complete when its response head is sent.

## Received chains

Received status fields are untrusted Structured Fields. OxiBelt accepts at
most 4 KiB across repeated field lines, 16 members, and 16 parameters per
member. It drops a received family entirely when parsing or bounds checks fail,
or a hop-by-hop `Connection` declaration nominates it; it never exposes raw parse
diagnostics. A preserved valid chain precedes the local member. A local member
replaces a received chain when appending it would exceed those bounds.

`upstream = "strip"` removes received chains. Disabling `proxy_status` or
`cache_status` removes both received and local fields in that family. The sole
exception is `Proxy-Status: oxibelt; error=incremental_refused`, which remains
the required Incremental protocol refusal signal. OxiBelt does not generate
new trailers; it only retains a valid received status field in trailers when
the selected policy permits it.
