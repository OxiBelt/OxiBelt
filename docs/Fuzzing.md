# Fuzzing

OxiBelt uses [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) for
coverage-guided fuzz testing of byte-oriented protocol surfaces. The fuzz
workspace lives in `fuzz/` and is excluded from normal stable commands by the
root workspace `default-members`.

## Setup

`cargo-fuzz` uses libFuzzer and requires a nightly Rust toolchain. It is
intended for Unix-like environments with LLVM sanitizer support.

```sh
cargo install cargo-fuzz
rustup toolchain install nightly --profile minimal
```

## Fuzz Targets

The fuzz crate depends on `oxibelt` with the `fuzzing` feature enabled. That
feature exposes only small deterministic wrappers under `oxibelt::fuzzing`;
the underlying proxy, TLS, HTTP, WebSocket, WebTransport, and TURN helpers stay
private to the main crate.

- `turn_protocol`: raw STUN parsing, TURN ChannelData parsing, helper
  validation paths, and bounded round-trips through protocol encoders.
- `tls_client_hello`: TLS record/raw ClientHello parsing, SNI extraction, and
  downstream SNI normalization.
- `http_semantics`: HTTPS request metadata semantics including host/authority
  handling, URI rewrite, hop-by-hop header stripping, forwarded headers, and
  upgrade detection.
- `http3_webtransport`: HTTP/3 request classification, 0-RTT policy checks,
  and WebTransport extended CONNECT/protocol header parsing.
- `websocket_frame`: bounded WebSocket frame ownership, parsing, and stream
  WAF prefix inspection behavior.
- `webrtc_turn`: TURN/STUN auth validation, nonce handling, and
  ChannelData/STUN edge cases for the WebRTC TURN listener surface.
- `syscall_boundaries`: bounded UDP socket-address conversion, batched-message
  planning, Landlock access-mask selection, minimum-hop option selection, and
  file-offset conversion. It exercises safe marshalling and validation without
  repeatedly applying irreversible process-wide syscalls.

Run a target locally:

```sh
cargo +nightly fuzz run tls_client_hello
```

Run the same short smoke pass used by CI for all targets:

```sh
for target in \
  turn_protocol \
  tls_client_hello \
  http_semantics \
  http3_webtransport \
  websocket_frame \
  webrtc_turn \
  syscall_boundaries
do
  cargo +nightly fuzz run "${target}" -- -runs=256
done
```

If `cargo-fuzz` finds a crash, keep the generated reproducer and minimize it
with `cargo +nightly fuzz tmin <target> <path-to-crash>` before turning it
into a regression test.
