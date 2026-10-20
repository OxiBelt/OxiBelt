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
