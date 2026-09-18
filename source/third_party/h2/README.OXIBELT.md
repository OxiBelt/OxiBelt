# OxiBelt HTTP/2 WebTransport patch

This directory carries the production sources of `h2` 0.4.19 from the
crates.io archive with SHA-256
`ef8e5e5a340588f4452631496976cf8636d4a7ecf600239fdc27615d2530bc16`.
The upstream MIT license is retained. The owner is `piquark6046`; maintenance
and removal are tracked in [issue #195](https://github.com/OxiBelt/OxiBelt/issues/195).

The patch implements the WebTransport SETTINGS identifiers from
`draft-ietf-webtrans-http2-15`, validates their values, and captures acknowledged
settings when inbound CONNECT request/response HEADERS are processed and when
outbound HEADERS are buffered in wire order. Queued requests are canceled
locally if the peer withdraws support before emission. Existing sessions
retain their snapshots when connection settings change. Terminal-aware,
per-waiter settings futures wake every pending request when settings change or
the connection can no longer open streams. Capsule parsing and virtual streams
are implemented in OxiBelt, outside this HTTP/2 dependency.

There is no new build script, native dependency, or unsafe capability. The
review compares changes with the checksum-matched archive and covers frame
decoding, settings acknowledgement, concurrency, and existing stream lifetime
ownership. Source checksums in `supply-chain/h2-source.sha256` and the shared
dependency policy lock the shipped source. The root `Cargo.lock` owns the
production graph; an independent upstream test lockfile is not shipped.

Review this patch with each upstream update and at least every 30 days.
Replace it with upstream APIs once acknowledged settings snapshots and the
OxiBelt protocol matrix have equivalent coverage. Using an opaque CONNECT byte
tunnel does not implement WebTransport stream or flow-control semantics;
introducing another HTTP/2 implementation would duplicate transport ownership.
