# OxiBelt web-transport-quinn fork

This is the `web-transport-quinn` 0.13.4 crate from the crates.io source archive,
licensed under MIT OR Apache-2.0. OxiBelt carries a local patch for WebTransport over HTTP/3
draft 16 negotiation and stream handling while preserving draft 02 support.
The fork also accepts successful non-200 CONNECT responses, ignores an unoffered
selected subprotocol, distinguishes clean CONNECT FIN from capsule read errors,
and enforces close-capsule reason and trailing-data limits.

Review the local delta against the crates.io 0.13.4 archive when updating this fork.
Track future upstream consolidation in OxiBelt/OxiBelt#220.

The 0.13.3 rebase retains the draft 16 receive-credit ledger, association-header
wire widths, reliable reset prefix, drain/close handling, and credit-writer lifetime.
It combines upstream raw-QUIC close-code handling with those local paths; HTTP/3
continues to use the WebTransport application-code mapping. The upstream stream
header reader retains its underlying QUIC error while also returning the encoded
width needed by local final-size accounting.

OxiBelt's application receive boundary remains the selected Tokio AsyncRead
adapter into initialized storage. Updating this fork does not authorize generic,
raw, or poll receive APIs in application callers or certify their trait defaults.

The 0.13.4 upstream refresh changes package metadata and the example harness;
its production source and dependency requirements are identical to 0.13.3.
OxiBelt retains the local transport patches and initialized receive adapter.
