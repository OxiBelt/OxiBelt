# OxiBelt quinn-proto patch

This directory starts from the crates.io `quinn-proto` 0.11.18 source archive
(`a9746dbde176634f4f2f1faf2404e30a31b2bc1e9cafb5329c95d8177a18c9fc`).
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
