# OxiBelt Hyper transport patch

This directory vendors the production sources of `hyper` 1.11.1 from the
crates.io artifact with SHA-256
`27b501faa50e7a26c3d3560ca625132f4078a17771f4810baf70475ae48cbe43`.

OxiBelt carries a deliberately narrow patch, owned by `piquark6046` and
tracked in [issue #194](https://github.com/OxiBelt/OxiBelt/issues/194):

- a request-scoped, bounded server informational-response sender for HTTP/1.1
  and HTTP/2; and
- HTTP/2 client support for Hyper's existing `on_informational` callback.

The patch keeps protocol writers inside Hyper, accepts only non-switching 1xx
heads with bounded headers/FIFO capacity, and does not expose raw HTTP/2
senders. Upstream repository metadata, VCS state, build caches, generated
artifacts, and tests are intentionally not vendored.

## Source and maintenance review

The production graph uses the root `Cargo.lock`. The separate empty workspace
allows upstream inline unit tests to run without making Hyper a first-party
OxiBelt workspace member; its generated test lockfile is not shipped.
`supply-chain/hyper-source.sha256` locks every shipped file, including this
notice, and `supply-chain/dependency-policy.json` locks that manifest.

The source review on 2026-09-17 compared the patch against the checksum-matched
crates.io artifact. All 64 upstream source files remain present. The informational-response
changes are confined to `ext/informational{,_sender}.rs`, `ext/mod.rs`,
`proto/h1/{conn,dispatch,mod,role}.rs`, and `proto/h2/{client,server}.rs`.
The patch adds no unsafe code and changes no existing unsafe block or unsafe
policy. The upstream MIT license is retained byte-for-byte. No build script,
network acquisition, or native capability is added.

An independent transport review exercises the HTTP/1 encoder's final-response
state, cross-protocol interim-version conversion, interim/final ordering,
bounded queues, duplicate `100` suppression, and HTTP/2 client/server delivery.
The informational-response baseline passed its inline full-feature library
suite (127 tests; six upstream tests ignored). OxiBelt's cross-protocol probe
is the integration boundary; unit results are not performance qualification.

Alternatives considered were waiting for upstream server informational APIs,
dropping `104`, or bypassing Hyper's HTTP encoders. The first two do not provide
the required live negotiated upload support; bypassing the encoder would split
framing ownership. Keep this patch narrow, review each Hyper update and at
least every 30 days, and remove it when an upstream release satisfies the
tracked feature and integration tests.

## HTTP/2 WebTransport extension

[Issue #195](https://github.com/OxiBelt/OxiBelt/issues/195), with the same owner,
tracks the additional draft-15 WebTransport patch. It adds typed CONNECT session
handoff after response HEADERS enter wire order, immutable directional SETTINGS
receipts supplied by the paired `h2` patch, and
independent receive/send halves. The writer remains owned by Hyper, uses a
bounded payload channel, and accepts an out-of-band reset so exhausted peer
send credit cannot prevent session cancellation. Pending WebTransport CONNECT
requests return Hyper's closed-connection error when the paired HTTP/2 driver
terminates before the required settings arrive. Existing ordinary CONNECT,
HTTP/1, and informational-response behavior must retain their regression tests.

The additional source review covers `ext/webtransport.rs`, HTTP/2 connection
builders, `proto/h2/{client,server,upgrade}.rs`, and their ownership boundaries.
It adds no unsafe block or native capability. WebTransport capsule and stream
flow control live in OxiBelt's common transport module. Keep both tracked patch
requirements in the removal criteria when adopting a future upstream release.
