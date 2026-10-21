# OxiBelt quinn-proto patch

This directory starts from the crates.io `quinn-proto` 0.11.19 source archive
(`0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe`).
It remains licensed under MIT OR Apache-2.0.

The local change implements draft-ietf-quic-reliable-stream-reset-09:
`reset_stream_at` transport parameter 0x1d, `RESET_STREAM_AT` frame 0x24,
peer capability checks, reliable prefix retransmission, final-size and flow
control validation, reset metadata with the full final size, reliable-prefix
reads before the terminal reset error, and 0-RTT resumption and Retry
compatibility.
Ordinary `RESET_STREAM` remains supported.

The root `Cargo.toml` patches crates.io quinn-proto to this source. Review
this delta against every future upstream quinn-proto release and rerun the
protocol tests before removing the patch.
Track upstream replacement in OxiBelt/OxiBelt#220.

The 0.11.19 rebase preserves the complete reliable-reset patch. Upstream
Initial and loss-probe padding now honors the configured minimum MTU, bounded
by the peer's maximum UDP payload size; the default minimum remains 1200.
The shipped upstream `Cargo.lock` is copied unchanged from the checksum-verified
0.11.19 archive; the root lock owns production.

The local DATAGRAM frame-limit extension separates the advertised complete-frame
limit from the aggregate receive-buffer budget. `datagram_max_frame_size(None)`
retains the upstream limit derived from that buffer; an explicit cap also leaves
room for one buffered datagram's existing bookkeeping and never increases the
queue. Received frame accounting includes the actual encoded type and length,
including a legal nonminimal length varint. Frames exceeding the advertised
limit fail with `PROTOCOL_VIOLATION` before being queued. Queue accounting and
per-send payload checks remain in force.

OxiBelt uses a downstream cap of at most 1144 bytes, reserving the conservative
1200-byte QUIC path floor, maximum CID and packet-number widths, AEAD tag,
DATAGRAM header, and upstream WebTransport association ID. The upstream leg
keeps its independent limit. A caller lowering a frame limit while accepting
0-RTT must isolate its resumption context; OxiBelt binds the effective limit
into both its stateful-cache and stateless-ticket registry keys. Review this
extension and its wire-width, queue, and path-fallback tests on every rebase.
