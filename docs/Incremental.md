# Incremental HTTP forwarding

OxiBelt supports [RFC 10036](https://www.rfc-editor.org/rfc/rfc10036.html)
`Incremental` on HTTP/1.1, HTTP/2, and HTTP/3, including cross-version
forwarding. It is built in; there is no new configuration switch or default.

## Signal and forwarding

A single valid Structured Field Boolean `Incremental: ?1` asks the recipient
to forward that message incrementally. Request and response signals are
independent: marking an upload does not mark the response. Valid unknown
parameters are ignored. False, non-Boolean, malformed, comma-list and duplicate
field values do not activate the feature. Ordinary header forwarding and
configured header mutations still apply. Once OxiBelt has recognized a true
signal, later header removal does not undo its internal forwarding decision.

Accepted marked uploads are streamed without replay buffering or request
mirroring. They are not retried after dispatch; existing safe pre-dispatch
selection and admission failures can still choose another upstream. Upstream
response headers and data can arrive before request EOF. A clean response EOF
does not cancel an unfinished upload, and exchange resources remain accounted
for until both directions terminate. Abandonment, transport failure and the
existing timeouts cancel unfinished work. Existing connection, stream, body-size,
bandwidth and overload limits still apply; there is no extra incremental quota.
When HTTP/3 upstream pooling is disabled, a cleanly completed one-shot connection
keeps its transport and connection admission alive for a bounded drain so queued
final upload bytes are not discarded by an immediate connection close. Existing
send timeouts and explicit request deadlines cap that drain.

Marked responses skip optional compression, new cache fills, background cache
collection and small-response coalescing. Existing complete cache entries can
still be served under the normal cache policy. An incremental upload does not
wait for a collapsed cache fill. HTTP framing, flow control and transport
backpressure still apply: this is not a packet-boundary or fixed-latency promise.

## Required buffering and inspection

The signal never bypasses required inspection or silently changes a configured
buffering policy. OxiBelt returns `501 Not Implemented` with
`Proxy-Status: oxibelt; error=incremental_refused` when forwarding a marked
nonempty message would require any of the following:

- Explicit `memory`, `spool` or `reject_if_too_large` buffering.
- WAF prefix or complete-body capture, including a required decompression
  transform. Prefix capture waits for its prefix or EOF and is not incremental.
- External authorization that requires request-body capture.

Refusal occurs before the incompatible capture consumes the body. HTTP/1.x
request refusal closes the connection rather than reusing an unread upload.
Known-empty messages and body-size checks satisfied from trusted framing
metadata do not require payload capture. The existing `text/event-stream`
automatic streaming exception is preserved. CONNECT, Upgrade, WebSocket and
WebTransport retain their existing tunnel/session behavior. Local origin
endpoints, such as static-file serving and the certificate-transparency API,
retain their application semantics; this feature governs proxy forwarding.

A configured mutation that adds a true signal only after incompatible capture
or conversion cannot retroactively make that work incremental; forwarding is
refused. Prefer signaling on the original message and selecting a route whose
required policy can operate without body capture.

## Temporary capacity rejection

When a marked request is rejected because admission reaches an active limit,
a pending queue is full, or a pending queue times out, OxiBelt returns
`429 Too Many Requests` as described in [RFC 10036 Section 4.2](https://www.rfc-editor.org/rfc/rfc10036.html#section-4.2).
The response includes `Retry-After`, `Cache-Control: no-store`, and
`Proxy-Status: oxibelt; error=connection_limit_reached`. The retry delay uses
existing admission timing, rounded up to whole seconds with a minimum of one.
The protocol status field remains present even when global or route
`proxy_status` emission is disabled, independently of the configured identifier
and upstream status-header policy.

These marked capacity rejections always close HTTP/1.0 and HTTP/1.1 connections,
including known-empty requests, so an unread upload cannot be reused as another
request. HTTP/2 and HTTP/3 responses do not include `Connection: close`.
Circuit-open, retry-budget and internal-state-unavailable failures retain their
configured admission response, as do all unmarked requests. Limits, queues,
retry selection, readiness and admission-resource lifetimes are unchanged.

## gRPC-Web text

For a marked gRPC-Web text upload, the decoder forwards each complete Base64
quartet as it arrives, retaining at most three encoded bytes between frames.
Independently padded chunks are accepted; malformed alphabet, padding or a
truncated final quartet fails the stream. For a marked upstream response, each
DATA frame is encoded as an independently padded Base64 chunk, and the final
gRPC-Web trailer frame is emitted separately and last. Clients must accept
concatenated padded chunks as required by the
[gRPC-Web wire protocol](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md#text-encoded-response-streams).
The ordinary, unmarked codec behavior is unchanged.

## Validation

The Docker matrix case exercises all nine downstream/upstream version pairs
with causal body markers: the next upload fragment depends on the previous
response fragment, and the final upload fragment is sent after clean response
EOF. A separate upstream receipt confirms consumption of that final fragment
and request EOF before the client closes its connection. This detects buffering
deadlocks without treating chunk boundaries as transport guarantees.

```sh
cargo test -p oxibelt incremental --lib
tests/scripts/run-proxy-integration-matrix.sh http-semantics incremental-rfc10036
tests/scripts/run-proxy-integration-matrix.sh http-semantics incremental-rfc10036-unpooled
```

Parser, policy-refusal, lifecycle, fast-response and codec tests complement the
wire checks. These are functional checks, not sustained-load qualification or
a throughput/latency benchmark.
