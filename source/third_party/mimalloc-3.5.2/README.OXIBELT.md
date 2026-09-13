# OxiBelt-governed mimalloc source

This directory contains the 70-file native payload selected directly from
Microsoft mimalloc 3.5.2 at commit
`636510a36ab743f76a582067142f29d15b024c90`. The upstream annotated tag
`v3.5.2` has object ID `4e3a61669be12515da74a0208d4f58bd920931ab`; it was
retrieved over HTTPS but has no cryptographic signature. That provenance limit
requires independent source review before production qualification.

Neither `libmimalloc-sys` nor the `mimalloc` Rust crate is an OxiBelt
dependency. The prior payload's locally reviewed fixes are present in 3.5.2,
so no downstream backports remain:

- `_mi_strnlen` checks its length bound before dereferencing input.
- Linux transparent-huge-page parsing uses the count returned by `read`.
- Secure level 3 and higher can enable allocation padding without an
  unconditional `MI_PADDING=0` override.

`UPSTREAM-MANIFEST.sha256` and `NATIVE-MANIFEST.sha256` each bind the selected
unmodified 70-file source payload. `SOURCE-PROVENANCE.json` records its source
and the selected `MI_SECURE=4`, `MI_DEBUG=0`, `MI_PADDING=1`, `MI_STATS=1`, and
`MI_PROFILE=1` build contract. Any source refresh, target expansion, build-mode
change, or modified file requires a new source review, updated hashes, and
allocator qualification.

The native source is licensed under the MIT License in `LICENSE`. The private
Rust `GlobalAlloc` bridge in `source/crates/oxibelt-allocator/src/lib.rs` is
adapted from the MIT-licensed
[`purpleprotocol/mimalloc_rust`](https://github.com/purpleprotocol/mimalloc_rust)
bindings, Copyright 2019 Octavian Oncescu; its complete notice is retained in
that source file. See `THIRD-PARTY-NOTICES.md` at the repository root.

Tracking: [OxiBelt/OxiBelt#183](https://github.com/OxiBelt/OxiBelt/issues/183).
