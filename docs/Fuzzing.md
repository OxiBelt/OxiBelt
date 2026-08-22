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

The pull-request and sustained matrices do not set `max-parallel`, so every
profile/target child is independently schedulable. GitHub runner and account
capacity may still queue children, while each job retains its explicit
wall-clock timeout.

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
| `tls_client_hello` | Raw and TLS-record-framed ClientHello parsing, bounded QUIC Initial CRYPTO range merging, and SNI normalization | Live handshakes, keys, remote signers |
| `http_semantics` | Methods, URIs, authority, versions, and headers; ambiguous framing and forwarding state fail closed | Network I/O, connections, streaming bodies |
| `compio_h1_response` | At most 128 KiB of response bytes, bounded fragmentation, and validated small protocol limits; framing and metadata remain deterministic and bounded | Live sockets, transport cancellation, and changes to Hyper |
| `http3_webtransport` | HTTP/3 metadata, early-data state, and extended CONNECT protocols | Live QUIC/H3 sessions and datagrams |
| `upstream_dns_resolution` | Bounded DNS response parsing, query identity, names, TTLs, and endpoint records | Live DNS sockets, cache tasks, and QUIC dialing |
| `websocket_frame` | At most eight bounded data/control frames and WAF prefix inspection | Upgraded sockets and unbounded reassembly |
| `webrtc_turn` | TURN/STUN integrity, nonce, fingerprint, padding, and address cases | Relay listeners, databases, network allocation |
| `syscall_boundaries` | Reversible ABI and marshalling decisions only | Applying Landlock, socket options, or other process-wide syscalls |
| `native_config` | An in-memory graph of up to eight TOML documents, including includes and merges | Host filesystem, environment, runtime publication |
| `config_policy_normalization` | Bounded in-memory config, policy, identity, Admin, canonical JSON, and operator-tool normalization | Filesystem, environment, runtime, storage, network, and live secrets |
| `oxirule_expression` | Parsing and analysis against fixed Request, Response, and Stream schemas | Rule execution, body access, side-effectful functions |
| `waf_request_normalization` | Bounded HTTP metadata and in-memory CRS syntax, transforms, and normalized request views | Filesystem-backed rules, request execution, network, storage, and external functions |
| `admin_json_mutations` | Deserialization and pure validation for protected Admin mutation request types | Routing, storage, mutation execution |
| `admin_mutation_envelope` | Canonical header parsing, encoding, and transcript binding | Signing keys, signature verification, handlers |
| `cluster_rollout_state` | Framed commands and at most sixteen synthetic rollout members | PostgreSQL, snapshot replacement, member communication |
| `http_body_coding` | Bounded gzip, deflate, Brotli, and Zstandard operations | Streaming bodies, spawned work, network I/O |
| `cache_metadata_key` | Metadata text, external-cache JSON, key templates, and variants | Cache file access, backend clients, fill coordination |
| `gateway_api_translation` | At most sixteen in-memory Kubernetes objects and pure translation | Kubernetes clients, watches, leader election, filesystem rendering |
| `tls_certificate_metadata` | At most four in-memory DER candidates and bounded metadata extraction | Certificate files, private keys, live TLS servers |
| `path_security_semantics` | Structured URI forms, route prefixes, rewrites, static lexical resolution, and WAF path views; rejected paths cannot become accepted at a later modeled stage | Filesystem access, static-file opening, network I/O |
| `waf_request_evaluation` | Bounded request metadata and bodies against a fixed in-memory security ruleset; decoder or policy failure cannot silently become allow | Filesystem-backed rules, external functions, network and storage |
| `auth_request_semantics` | Bounded headers, bearer parsing, route scope, backend outcome, fail policy, trusted identity replacement, and trailer sanitization; explicit denial never opens | External-auth network calls, credentials, live upstream forwarding |

Normalization targets assert deterministic parsing, bounded output, canonical
forms where the owning API defines one, and non-mutation of source inputs.
They do not impose universal idempotence: WAF percent and Unicode decoding is
intentionally one pass, so a nested encoding may produce a different but still
bounded value when the result is normalized again. Filesystem-backed path
canonicalization, environment lookup, live secret material, runtime state,
storage, and network access remain outside these pure fuzz facades.

The protocol targets intentionally stop at deterministic parse and policy
boundaries. Live HTTP/3, WebTransport, WebSocket, TURN, Gateway Controller, and
storage behavior remains the responsibility of the repository's integration
matrices.

## Docker security-property fuzzing

Pure fuzzing is complemented by a Docker program for properties that
require real listeners, the release-like Alpine image, protocol state, or
observable runtime cleanup. Its canonical target and bound catalog is
[`tests/docker/security_fuzz/targets.toml`](../tests/docker/security_fuzz/targets.toml).
The generated pull-request matrix runs these eight families independently:

| Target | Catalog protocols | Boundary | Primary oracle |
| --- | --- | --- | --- |
| `path_security` | `h1`, `h2`, `h3` | Paths and static routing | A unique outside-root canary is never returned |
| `tls_quic_sni` | `tls`, `quic` | TLS records, fragmented SNI handshakes, and QUIC Initial inputs | Malformed input fails closed and a later valid connection succeeds |
| `http_framing` | `h1`, `h2`, `h3` | Request framing | The protected upstream observes no extra or desynchronized request |
| `waf_bypass` | `h1`, `h2`, `h3` | WAF path, header, and bounded body representations | A must-block request never reaches the protected upstream |
| `auth_bypass` | `h1`, `h2`, `h3` | External-auth results and identity headers | Invalid or explicit-deny auth never reaches the upstream; only a catalogued fail-open transport error may open |
| `websocket_webtransport` | `ws`, `h3`, `webtransport` | WebSocket frame validity and WebTransport extended CONNECT/session behavior | Malformed session input stays isolated and active counts recover |
| `turn_runtime` | `udp`, `tcp`, `tls` | TURN authentication and lifecycle | Invalid authentication and malformed STUN fail closed, documented upstream nonce challenges remain authoritative, and active runtime counts return to baseline |
| `admin_authz` | `h1` | Admin authorization and mutation-state containment | Unauthorized requests leave the canonical redacted state projection unchanged |

Each target derives structured selectors and bounded fields from its input,
then applies only that protocol's semantic, wire, fragmentation, or raw
mutations. An equality or no-downgrade oracle is applied only to transforms
explicitly catalogued as meaning-preserving; arbitrary malformed input is
instead required to fail closed without losing later valid service. Every
case has a deterministic seed derived from the source revision, target,
schema, run seed, and case index.

Pull requests run at most 1,024 cases or 120 seconds per target, whichever is
reached first. The default-branch sustained workflow runs each target for 900
seconds. Its target jobs are independently schedulable subject to GitHub runner
and account capacity. Per-case, recovery, payload, concurrency, per-session
case-count, and 32-MiB evidence limits are enforced by the catalog and runner.

Run the same bounded smoke tier locally with the standard `docker` command:

```sh
tests/scripts/run-docker-security-fuzz.sh smoke path_security --seed 42
```

Replay one exact case without regenerating earlier cases:

```sh
tests/scripts/run-docker-security-fuzz.sh replay path_security --seed 42 --case 17
```

Run a locally bounded campaign (the sustained job passes `900`):

```sh
tests/scripts/run-docker-security-fuzz.sh campaign path_security 120 --seed 42
```

The runner uses run-unique, label-scoped Docker resources and removes only
those resources. On failure it writes a bounded private evidence bundle before
cleanup: catalog and source versions, seed and case, case mutation metadata,
bounded input and digest, structured probe observations, selected container
state, logs, and the exact replay command. It does not capture container
environments or test tokens. Generated evidence and corpora are never
committed or opened as a public issue automatically; security-sensitive
failures follow
[`SECURITY.md`](../SECURITY.md).

## Setup and local runs

CI uses moving `stable` for sanitizer-free smoke coverage and pins the
AddressSanitizer and sustained profiles to `nightly-2026-08-04`. Both use
`cargo-fuzz 0.13.2`. Stable Rust cannot enable cargo-fuzz's nightly-only
sanitizer instrumentation, so the stable lane supplements rather than replaces
the pinned sanitizer lane. Install the same tools so local reproduction does
not silently use a different compiler or driver:

```sh
rustup toolchain install stable --profile minimal
rustup toolchain install nightly-2026-08-04 --profile minimal --component llvm-tools-preview
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

CVE-inspired seeds are vulnerability-class regression inputs only. Their
presence records a parser, normalization, framing, or policy pattern worth
preserving; it does not claim that OxiBelt contained the historical
third-party vulnerability associated with that CVE.

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
   crash with `cargo +nightly-2026-08-04 fuzz tmin <target> <reproducer>`.
4. Add it under the target's reviewed seed or regression directory and record
   its provenance and digest. Never replace a reviewed seed silently.

## Coverage evidence

The nightly workflow replays each minimized corpus with `cargo fuzz coverage`
and publishes `coverage.profdata`, JSON/LCOV summaries, and HTML output for 30
days. Catalogued parser, compiler, and state-machine landmarks must have
nonzero coverage. The program initially gates landmark reachability rather
than a repository-wide percentage, which would be unstable as targets and
generated code evolve.

For every run, the runner supplies `cargo-fuzz` an isolated target directory
and the pinned nightly host triple. It accepts only that target's exact
instrumented release binary; missing, off-triple, or multiple matching
binaries fail closed rather than selecting a stale build artifact.

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
   `cargo +nightly-2026-08-04 fuzz run <target> <reproducer>`.
3. Minimize with
   `cargo +nightly-2026-08-04 fuzz tmin <target> <reproducer>`.
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
