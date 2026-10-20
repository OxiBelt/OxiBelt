# OxiBelt web-transport-proto fork

This is the `web-transport-proto` 0.6.2 crate from the crates.io source archive,
licensed under MIT OR Apache-2.0. OxiBelt carries a local patch for WebTransport over HTTP/3
draft 16 protocol constants and handshake encoding.
Malformed selected-subprotocol response fields are ignored when the CONNECT
status and draft marker are valid, matching browser WebTransport negotiation.

Review the local delta against the crates.io 0.6.2 archive when updating this fork.
Track future upstream consolidation in OxiBelt/OxiBelt#220.

The local dependency manifest also selects `sfv` 0.16, matching the first-party
structured-field parser. The parser retains RFC 8941/9651 acceptance and canonical
serialization; draft 16 constants, handshake encoding, and subprotocol handling
remain unchanged. This dependency-only delta is tracked by OxiBelt/OxiBelt#304.
