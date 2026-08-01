# Fuzzing

OxiBelt uses [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) and
libFuzzer to continuously exercise attacker-controlled parsers, decoders, and
state transitions. Pull requests run two bounded smoke passes over every
target: one uses stable Rust without a sanitizer and one uses AddressSanitizer
on the pinned fuzz nightly. The default branch also runs a longer nightly
campaign that accumulates a bounded corpus and publishes coverage and failure
evidence.

The fuzz crate is excluded from the stable workspace `default-members`. Normal
OxiBelt builds do not enable the `fuzzing` feature or expose its internal
harness facades.

## Program catalog and ownership

[`fuzz/targets.toml`](../fuzz/targets.toml) is the source of truth for the
program. Every target records its subsystem owner, input contract, hard input
limit, invariants, deliberately unsupported states, reviewed seed directory,
optional dictionary, coverage landmarks, regression destination, and leak
policy. `tests/rust/fuzz_program_contract.rs` prevents the Cargo bins, both CI
matrices, and this metadata from drifting apart.

| Target | Input contract and important invariant | Deliberately excluded |
| --- | --- | --- |
| `turn_protocol` | Bounded STUN, ChannelData, attributes, and authentication material; malformed lengths fail closed | Live sockets, relay allocation, credential lookup |
| `tls_client_hello` | Raw and TLS-record-framed ClientHello parsing and SNI normalization | Live handshakes, keys, remote signers |
| `http_semantics` | Methods, URIs, authority, versions, and headers; ambiguous framing and forwarding state fail closed | Network I/O, connections, streaming bodies |
| `compio_h1_response` | At most 128 KiB of response bytes, bounded fragmentation, and validated small protocol limits; framing and metadata remain deterministic and bounded | Live sockets, transport cancellation, and changes to Hyper |
| `http3_webtransport` | HTTP/3 metadata, early-data state, and extended CONNECT protocols | Live QUIC/H3 sessions and datagrams |
| `upstream_dns_resolution` | Bounded DNS response parsing, query identity, names, TTLs, and endpoint records | Live DNS sockets, cache tasks, and QUIC dialing |
| `websocket_frame` | At most eight bounded data/control frames and WAF prefix inspection | Upgraded sockets and unbounded reassembly |
| `webrtc_turn` | TURN/STUN integrity, nonce, fingerprint, padding, and address cases | Relay listeners, databases, network allocation |
| `syscall_boundaries` | Reversible ABI and marshalling decisions only | Applying Landlock, socket options, or other process-wide syscalls |
| `native_config` | An in-memory graph of up to eight TOML documents, including includes and merges | Host filesystem, environment, runtime publication |
| `oxirule_expression` | Parsing and analysis against fixed Request, Response, and Stream schemas | Rule execution, body access, side-effectful functions |
| `admin_json_mutations` | Deserialization and pure validation for protected Admin mutation request types | Routing, storage, mutation execution |
| `admin_mutation_envelope` | Canonical header parsing, encoding, and transcript binding | Signing keys, signature verification, handlers |
| `cluster_rollout_state` | Framed commands and at most sixteen synthetic rollout members | PostgreSQL, snapshot replacement, member communication |
| `http_body_coding` | Bounded gzip, deflate, Brotli, and Zstandard operations | Streaming bodies, spawned work, network I/O |
| `cache_metadata_key` | Metadata text, external-cache JSON, key templates, and variants | Cache file access, backend clients, fill coordination |
| `gateway_api_translation` | At most sixteen in-memory Kubernetes objects and pure translation | Kubernetes clients, watches, leader election, filesystem rendering |
| `tls_certificate_metadata` | At most four in-memory DER candidates and bounded metadata extraction | Certificate files, private keys, live TLS servers |

The protocol targets intentionally stop at deterministic parse and policy
boundaries. Live HTTP/3, WebTransport, WebSocket, TURN, Gateway Controller, and
storage behavior remains the responsibility of the repository's integration
matrices.

## Setup and local runs

CI uses moving `stable` for sanitizer-free smoke coverage and pins the
AddressSanitizer and sustained profiles to `nightly-2026-08-01`. Both use
`cargo-fuzz 0.13.2`. Stable Rust cannot enable cargo-fuzz's nightly-only
sanitizer instrumentation, so the stable lane supplements rather than replaces
the pinned sanitizer lane. Install the same tools so local reproduction does
not silently use a different compiler or driver:

```sh
rustup toolchain install stable --profile minimal
rustup toolchain install nightly-2026-08-01 --profile minimal --component llvm-tools-preview
cargo +stable install cargo-fuzz --version 0.13.2 --locked
```

Run the stable, sanitizer-free 256-iteration pass used by pull requests:

```sh
OXIBELT_FUZZ_PROFILE=stable tests/scripts/run-fuzz-target.sh smoke tls_client_hello
```

Run the matching AddressSanitizer pass. The `asan` profile is the default for
backward-compatible local reproduction:

```sh
tests/scripts/run-fuzz-target.sh smoke tls_client_hello
```

For example, exercise the Compio HTTP/1 response protocol engine under both
pull-request profiles:

```sh
OXIBELT_FUZZ_PROFILE=stable tests/scripts/run-fuzz-target.sh smoke compio_h1_response
tests/scripts/run-fuzz-target.sh smoke compio_h1_response
```

Run the fifteen-minute campaign profile locally:

```sh
tests/scripts/run-fuzz-target.sh campaign tls_client_hello
```

The runner accepts only target names present in the catalog, reads the target's
maximum length there, and confines mutable corpora and crash data to validated
runner-temporary directories; `cargo fuzz coverage` uses its ignored `fuzz/`
report directory. The profiles enforce a ten-second input
timeout, 3,072-MiB RSS limit, 512-MiB allocation limit, and final libFuzzer
statistics. Stable smoke runs use `--sanitizer none`; they do not provide
AddressSanitizer or LeakSanitizer evidence. AddressSanitizer smoke runs disable
leak detection for reliability, while campaigns enable AddressSanitizer and
leak detection for every target. The stable profile is accepted only for
`smoke`; campaign, minimization, coverage, and reporting remain pinned to the
nightly sanitizer profile. A sanitizer exception requires an owner, a written
rationale, an expiry, and a tracking issue in `fuzz/targets.toml`.

The runner enforces those AddressSanitizer and LeakSanitizer settings itself,
so local invocations retain the selected tier's leak policy even when the
caller has not preconfigured sanitizer environment variables.

## Seeds, dictionaries, and corpus promotion

Only small, reviewed inputs under `fuzz/seeds/<target>/` are committed. Their
origin, license, classification, and SHA-256 digest are recorded in
[`fuzz/seeds/manifest.toml`](../fuzz/seeds/manifest.toml). Seed inputs must be
repository-authored or otherwise license-compatible, contain no secrets or
production data, use no symlinks, and stay within the per-target and aggregate
limits in the catalog. Dictionaries under `fuzz/dictionaries/` follow
libFuzzer's dictionary syntax and contain only public syntax or protocol
vocabulary.

Generated local inputs under `fuzz/corpus/`, direct `cargo-fuzz` crashes under
`fuzz/artifacts/`, and reports under `fuzz/coverage/` are ignored. The guarded
runner places CI crash artifacts under
`$RUNNER_TEMP/oxibelt-fuzz-artifacts/<target>` so automation never writes crash
data into the checkout. Nightly jobs may restore a bounded,
default-branch-only corpus cache and publish a minimized corpus candidate as an
artifact. Automation never commits a generated corpus or opens a public issue.
Corpus minimization uses a short-lived ignored staging directory under `fuzz/`
because `cargo-fuzz` requires its input and temporary directories to share a
filesystem. The runner validates the minimized result and atomically installs
a runner-temporary replacement while retaining the original until that swap
succeeds.
To promote a useful input:

1. Reproduce it with the pinned toolchain and inspect it for credentials,
   private identifiers, copyrighted material, and unexpected size.
2. Verify that it reaches new behavior or protects a confirmed regression.
3. Minimize a corpus with `tests/scripts/run-fuzz-target.sh cmin <target>` or a
   crash with `cargo +nightly-2026-08-01 fuzz tmin <target> <reproducer>`.
4. Add it under the target's reviewed seed or regression directory and record
   its provenance and digest. Never replace a reviewed seed silently.

## Coverage evidence

The nightly workflow replays each minimized corpus with `cargo fuzz coverage`
and publishes `coverage.profdata`, JSON/LCOV summaries, and HTML output for 30
days. Catalogued parser, compiler, and state-machine landmarks must have
nonzero coverage. The program initially gates landmark reachability rather
than a repository-wide percentage, which would be unstable as targets and
generated code evolve.

Generate equivalent evidence locally with the same catalog and corpus bounds:

```sh
tests/scripts/run-fuzz-target.sh coverage tls_client_hello
```

Coverage is evidence that inputs reach a boundary, not evidence that the
boundary is correct. Semantic invariants still require assertions and ordinary
regression tests.

## Crash triage and regressions

The sustained workflow preserves raw crash, timeout, and OOM inputs and makes
a bounded attempt to minimize at most eight inputs for five minutes each. A
failure bundle is retained for 90 days and records the source commit, target,
tool versions, sanitizer settings, exact reproduction command, corpus digest,
and input hashes. Post-processing preserves the original fuzz exit status.

Treat every reproducer as untrusted and potentially security-sensitive:

1. Download it only into a temporary directory and verify the recorded digest.
2. Reproduce with
   `cargo +nightly-2026-08-01 fuzz run <target> <reproducer>`.
3. Minimize with
   `cargo +nightly-2026-08-01 fuzz tmin <target> <reproducer>`.
4. Classify security-sensitive crashes through the private process in
   [`SECURITY.md`](../SECURITY.md); do not paste them into a public issue.
5. Add the minimized input under
   `tests/fixtures/fuzz-regressions/<target>/` and replay it from
   `tests/rust/fuzz_regressions.rs` or a narrower owner-local unit test.
6. Merge the fix only after the deterministic regression and the target pass.

Fuzz targets and their feature-gated facades must not use network or database
clients, spawn commands, mutate the process environment, read or write outside
validated temporary paths, apply raw syscalls, or rely on unbounded allocation.
The repository contract test rejects these side-effect APIs in target wrappers;
normal unit and integration tests retain responsibility for all unsupported
runtime states.
