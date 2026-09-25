# OxiBelt web-transport-quinn fork

This is the `web-transport-quinn` 0.12.1 crate from the crates.io source archive,
licensed under MIT OR Apache-2.0. OxiBelt carries a local patch for WebTransport over HTTP/3
draft 16 negotiation and stream handling while preserving draft 02 support.
The fork also accepts successful non-200 CONNECT responses, ignores an unoffered
selected subprotocol, distinguishes clean CONNECT FIN from capsule read errors,
and enforces close-capsule reason and trailing-data limits.

Review the local delta against the crates.io 0.12.1 archive when updating this fork.
Track future upstream consolidation in OxiBelt/OxiBelt#220.
