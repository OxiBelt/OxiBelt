# OxiBelt h3 fork

This is the `h3` 0.0.8 crate from the crates.io source archive, licensed under MIT.
OxiBelt carries a local patch for WebTransport over HTTP/3 draft 16 alongside
the existing draft 02 support. The patch recognizes `webtransport-h3`, records
the draft 16 SETTINGS and initial flow-control values, validates the enabling
setting, and exposes receipt of peer SETTINGS to the proxy runtime.

Keep changes limited to the protocol boundary. Review the local delta against
the crates.io `h3` 0.0.8 archive when updating this fork.
Track future upstream consolidation in OxiBelt/OxiBelt#220.
