# WebTransport

OxiBelt supports H2→H2, H2→H3, H3→H2, and H3→H3 WebTransport forwarding.
Routes use the existing `webtransport` protocol and upstream capability controls.
The selected upstream HTTP version is exact; session establishment does not retry
on another transport. Upstream establishment precedes downstream acceptance.

HTTP/2 legs implement
[draft-ietf-webtrans-http2-15](https://www.ietf.org/archive/id/draft-ietf-webtrans-http2-15.html)
and require TLS 1.3 with ALPN `h2`. Ordinary HTTP TLS policy is unaffected. HTTP/3
defaults to the existing draft02 dialect. Draft02 requests send
`Sec-WebTransport-HTTP3-Draft02: 1`, and successful responses send
`Sec-WebTransport-HTTP3-Draft: draft02`. The H3 upstream may explicitly select
`draft16`; downstream draft16 advertisement requires
`proxy.http3.webtransport_draft16 = true`. Transport
negotiation fields are regenerated for each leg rather than forwarded as
application metadata. H3 ingress and egress dialects must match; H2 ingress or
egress can translate to the selected H3 dialect. This is a pinned draft
implementation, not a claim that every browser or third-party WebTransport
implementation supports HTTP/2.
The [W3C WebTransport Candidate Recommendation](https://www.w3.org/TR/2026/CR-webtransport-20260730/)
provides the browser interoperability target. The H3 draft16 wire contract is
[draft-ietf-webtrans-http3-16](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16)
with [reliable stream reset](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-09).

## Handshake and flow control

The H2 server must advertise extended CONNECT and enabled WebTransport SETTINGS
before the client opens a session. Clients advertise receive limits without
needing to send SETTINGS_WT_ENABLED. Requests use `CONNECT`, `:protocol = webtransport`, an `https`
scheme, authority, and path. A supplied Origin is checked against the route's
allowed-origin policy; Admin operation subscriptions accept the same origin.
Non-browser clients may omit Origin. Invalid `WebTransport-Init` fields are
rejected before acceptance. Their `u`, `bl`, and `br` integer credits are combined
with the corresponding acknowledged SETTINGS using the greater value. Unknown
dictionary keys and parameters are ignored.

Each session captures the SETTINGS that apply at its CONNECT boundary. Later
connection SETTINGS changes affect new sessions only. Public downstream H2
SETTINGS grant zero initial application credit, so new sessions on an older connection can use lowered reload limits. Session-data and
stream-count capsules grant credit after capacity is reserved; opening a virtual
stream triggers its stream-data grant. Wire MAX_STREAMS values are cumulative; closing and releasing a stream replenishes a
concurrent slot. Reads replenish data credit as buffered bytes are consumed.

Capsule parsing is incremental, including fragmented variable-length integers
and stream payloads. The reader remains active while an independently driven
writer waits for transport capacity. Unknown capsules are skipped at the local
endpoint, and unsupported extension capsules are not translated between H2 and
H3. Oversized datagrams are discarded without allocating their declared length.
Datagram queues are bounded and drop newest under backpressure. Configuration
defaults and validation are documented in [Configuration](Configuration.md#http2-webtransport).

## Session failures and cleanup

The draft leaves WebTransport-specific HTTP/2 reset codepoints unassigned.
OxiBelt therefore uses standard HTTP/2 RST_STREAM reasons on the CONNECT stream:

| Failure | HTTP/2 reason |
| --- | --- |
| Malformed capsule or illegal stream state | `PROTOCOL_ERROR` |
| WebTransport flow-control violation | `FLOW_CONTROL_ERROR` |
| Local bounded-resource abuse | `ENHANCE_YOUR_CALM` |
| Cancellation or silent close | `CANCEL` |
| Internal transport failure | `INTERNAL_ERROR` |

Application close codes and UTF-8 close reasons remain application data. H3
transport errors are mapped separately from these H2 fallback reasons. H2 forwarding
preserves buffered stream bytes before sending a RESET capsule and its reliable
size. H3 draft02 retains ordinary QUIC reset semantics: resetting a stream may
discard unread or unacknowledged bytes, including its association header. H3
draft16 sends `RESET_STREAM_AT` with a reliable prefix that covers the
WebTransport data-stream header. Cross-transport resets preserve application
error codes. For draft02, an unassociated unidirectional reset is relayed only
when its code is a valid WebTransport error, exactly one downstream session has
ever been established on the connection and is still active, its upstream is H3,
and the configured stream limit is not exhausted;
ambiguous resets are discarded. Such cancellation does not close
unrelated streams or the connection. A malformed session is reset independently
of unrelated H2 requests or sessions. Cancellation
can interrupt a writer even when the peer grants no H2 send credit. Session and
identity permits remain held through transport cleanup; reload budgets count
sessions from older snapshots until they release their reservations.

For strict browser close-event parity, set
`proxy.http3.webtransport_only_connections = true` on a dedicated H3 endpoint.
Each downstream QUIC connection then admits at most one WebTransport session;
ordinary H3 requests and later CONNECTs on that connection are rejected. A
WebTransport session may close its dedicated QUIC connection without terminating
unrelated H3 traffic on another endpoint. The default `false` retains shared H3
connections, where a session close does not terminate the whole connection.

## Admin and Gateway

TLS Admin listeners support ordinary H1 and H2 APIs. The operation-event endpoint
uses the existing authentication, IPM, break-glass, audit, and session-limit
rules for either WebTransport transport. H2 events use a server-originated
unidirectional NDJSON stream. Client application-stream credit is zero;
valid control capsules are processed and datagrams are discarded with bounded
storage. Plaintext Admin does not enable h2c.

When `[admin.operations.event_compression].enabled = true`, Admin WebTransport
clients can select the event stream coding with
`OxiBelt-Event-Stream: ndjson-v1; coding=<br|zstd|gzip|deflate|identity>`.
An absent header preserves raw NDJSON. A malformed value returns `400`, a
valid coding that is disabled or unavailable returns `406`, and exhausted
compression capacity returns `503`. `identity` selects raw NDJSON. The same
contract applies to Admin H2 and H3 WebTransport; it does not change public
WebTransport forwarding. See [Admin API](AdminAPI.md) for the other event
transports and [Configuration](Configuration.md) for the full settings.

Gateway's `webTransport.upstreamHttpVersion` policy creates a higher-priority
WebTransport-only sibling route and a separate pool while keeping the ordinary
route. Optional native pool `max_http_version` makes that transport selection
explicit; H3 pool members must use HTTPS. The optional
`webTransport.upstreamHttp3Draft` sets the pool member dialect (`draft02` by
default). Native upstreams and discovery sources use
`webtransport_http3_draft`. See [Gateway API](GatewayAPI.md).

## Interoperability gate

The required CI gate runs every WebTransport test from pinned web-platform-tests
revision `ece2d7fdc436d4b9a3856877163b07ec15c05354` in Chrome for Testing
`154.0.8037.57` and Firefox `156.0`. It compares direct WPT-server results
with OxiBelt-proxied results using the same browser URL and certificate. Each
path must pass session, bidirectional stream, unidirectional stream, datagram,
and close controls. The gate fails if any test or subtest is missing, or if a
direct and proxied test or subtest status differs. Run it with a prebuilt OxiBelt
image and `tests/scripts/run-webtransport-wpt-gate.sh`; see the
[test harness README](../tests/docker/webtransport_wpt/README.md) for the exact
command and artifact path.

The pinned WPT server uses draft02. The Docker
`tests/scripts/run-webtransport-h2-integration.sh` matrix separately exercises
draft16 H3 SETTINGS and CONNECT, H2↔H3 forwarding, streams, datagrams, and
reliable reset delivery against a draft16 upstream probe.
