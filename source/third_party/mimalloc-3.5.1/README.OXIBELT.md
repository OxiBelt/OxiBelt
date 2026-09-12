# OxiBelt-governed mimalloc source

This directory contains the 67-file native payload selected directly from
Microsoft mimalloc 3.5.1 at commit
`34fbd7e7cd4627424490afe19b20f8066bfc537d`. The upstream annotated tag
`v3.5.1` has object ID `8e05dab9b9e38aa92ab6a6e137baefeaa9e45e40`; it was
retrieved over HTTPS but has no cryptographic signature. That provenance limit
requires independent source review before production qualification.

Neither `libmimalloc-sys` nor the `mimalloc` Rust crate is an OxiBelt
dependency. The prior payload's two locally carried upstream fixes are present
in 3.5.1, so no downstream backports remain:

- `_mi_strnlen` checks its length bound before dereferencing input.
- Linux transparent-huge-page parsing uses the count returned by `read`.

`UPSTREAM-MANIFEST.sha256` and `NATIVE-MANIFEST.sha256` each bind the selected
unmodified 67-file source payload. `SOURCE-PROVENANCE.json` records its source
and selected build contract. Any source refresh, target expansion, build-mode
change, or modified file requires a new source review, updated hashes, and
allocator qualification.

The native source is licensed under the MIT License in `LICENSE`. The private
Rust `GlobalAlloc` bridge in `source/crates/oxibelt-allocator/src/lib.rs` is
adapted from the MIT-licensed
[`purpleprotocol/mimalloc_rust`](https://github.com/purpleprotocol/mimalloc_rust)
bindings, Copyright 2019 Octavian Oncescu; its complete notice is retained in
that source file. See `THIRD-PARTY-NOTICES.md` at the repository root.

Tracking: [OxiBelt/OxiBelt#183](https://github.com/OxiBelt/OxiBelt/issues/183).
