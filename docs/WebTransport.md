# WebTransport

OxiBelt supports H2→H2, H2→H3, H3→H2, and H3→H3 WebTransport forwarding.
Routes use the existing `webtransport` protocol and upstream capability controls.
The selected upstream HTTP version is exact; session establishment does not retry
on another transport. Upstream establishment precedes downstream acceptance.

HTTP/2 legs implement
[draft-ietf-webtrans-http2-15](https://www.ietf.org/archive/id/draft-ietf-webtrans-http2-15.html)
and require TLS 1.3 with ALPN `h2`. Ordinary HTTP TLS policy is unaffected. HTTP/3
retains the existing `sec-webtransport-http3-draft: draft02` contract. Transport
negotiation fields are regenerated for each leg rather than forwarded as
application metadata. This is a pinned draft implementation, not a claim that
every browser or third-party WebTransport implementation supports HTTP/2.

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
size. HTTP/3 retains ordinary QUIC reset semantics: resetting a stream may discard
unread or unacknowledged bytes. Cross-transport resets preserve application error
codes, but do not add reliable-prefix delivery to HTTP/3. A stream that is reset
before its HTTP/3 WebTransport association header reaches the peer might never
become visible as an application stream. Such cancellation does not close
unrelated streams or the connection. A malformed session is reset independently
of unrelated H2 requests or sessions. Cancellation
can interrupt a writer even when the peer grants no H2 send credit. Session and
identity permits remain held through transport cleanup; reload budgets count
sessions from older snapshots until they release their reservations.

## Admin and Gateway

TLS Admin listeners support ordinary H1 and H2 APIs. The operation-event endpoint
uses the existing authentication, IPM, break-glass, audit, and session-limit
rules for either WebTransport transport. H2 events use a server-originated
unidirectional NDJSON stream. Client application-stream credit is zero;
valid control capsules are processed and datagrams are discarded with bounded
storage. Plaintext Admin does not enable h2c.

Gateway's `webTransport.upstreamHttpVersion` policy creates a higher-priority
WebTransport-only sibling route and a separate pool while keeping the ordinary
route. Optional native pool `max_http_version` makes that transport selection
explicit; H3 pool members must use HTTPS. See [Gateway API](GatewayAPI.md).
