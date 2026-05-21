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

## TURN/STUN Protocol Target

The initial fuzz target covers `oxibelt::turn::protocol`, including raw STUN
parsing, TURN ChannelData parsing, helper validation paths, and bounded
round-trips through the protocol encoders.

Run the target locally:

```sh
cargo +nightly fuzz run turn_protocol
```

Run the same short smoke pass used by CI:

```sh
cargo +nightly fuzz run turn_protocol -- -runs=256
```

If `cargo-fuzz` finds a crash, keep the generated reproducer and minimize it
with `cargo +nightly fuzz tmin turn_protocol <path-to-crash>` before turning it
into a regression test.
