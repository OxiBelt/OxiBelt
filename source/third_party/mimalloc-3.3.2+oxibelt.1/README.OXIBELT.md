# OxiBelt-governed mimalloc source

This directory contains the 65-file mimalloc v3 native source payload from
Microsoft mimalloc 3.3.2 at commit
`30b2d9d89099bee08e9f67a1ffb3e12e7ba45227`. OxiBelt acquired the payload
from the checksum-pinned `libmimalloc-sys 0.1.49` crate for mechanical source
comparison; neither `libmimalloc-sys` nor the `mimalloc` Rust crate is an
OxiBelt dependency.

The native payload carries two later upstream fixes:

- `acea8bcb71d3f35666e32b3b3d78544496200d7c` bounds `_mi_strnlen` before
  dereferencing its input.
- `f2dc730bad28899a675672846bfe551e91a23493` bounds transparent-huge-page
  parsing to the bytes actually read.

`UPSTREAM-MANIFEST.sha256` records the original 65 files.
`NATIVE-MANIFEST.sha256` records the selected files after applying those two
fixes. `SOURCE-PROVENANCE.json` binds their origin, build boundary, and patch
identity. Any source refresh, target expansion, build-mode change, or modified
file requires a new source review, updated hashes, and allocator qualification.

The native source is licensed under the MIT License in `LICENSE`. The private
Rust `GlobalAlloc` bridge in
`source/crates/oxibelt-allocator/src/lib.rs` is adapted from the MIT-licensed
[`purpleprotocol/mimalloc_rust`](https://github.com/purpleprotocol/mimalloc_rust)
bindings, Copyright 2019 Octavian Oncescu; its complete notice is retained in
that source file. See `THIRD-PARTY-NOTICES.md` at the repository root.

Tracking: [OxiBelt/OxiBelt#183](https://github.com/OxiBelt/OxiBelt/issues/183).
