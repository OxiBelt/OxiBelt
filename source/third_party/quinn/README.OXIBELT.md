# OxiBelt Quinn patch

This directory starts from the crates.io `quinn` 0.11.12 source archive
(`4051e23e9185c255a7e33ef59cdbca87a22d359052eecd22fc6b901fb37d9d11`).
It remains licensed under MIT OR Apache-2.0.

The local change exposes `SendStream::reset_at`,
`Connection::peer_supports_reset_stream_at`, and receive-side reset metadata
with the full final size for the draft-09 QUIC `RESET_STREAM_AT` extension
implemented by the adjacent `quinn-proto` patch.
The ordinary `reset` API is unchanged.

The root `Cargo.toml` patches crates.io Quinn to this source. Review this
delta against every future upstream Quinn release before removing the patch.
Track upstream replacement in OxiBelt/OxiBelt#220.
