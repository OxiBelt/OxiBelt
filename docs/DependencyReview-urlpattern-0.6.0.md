# Dependency review: `urlpattern` 0.6.0

Date: 2026-09-19  
Owner: [@piquark6046](https://github.com/piquark6046)  
Tracking issue: [#208](https://github.com/OxiBelt/OxiBelt/issues/208)

`urlpattern` implements the [URLPattern web API](https://wicg.github.io/urlpattern/)
in Rust. OxiBelt uses the exact `0.6.0` release only for RFC 9842
`Use-As-Dictionary` match validation and dictionary selection. It is not a
network client and it does not select an upstream or rewrite a request.

## Artifact and source

- Registry archive SHA-256:
  `df16f50ef4cc145211879a3867ba757076b25dfee812040dcb0658bd9ae7904b`.
  This equals the checked-in `Cargo.lock` checksum.
- The packaged source declares upstream commit
  `e29804d15bdc60797c1c7f715d90480ace0bb451` in `.cargo_vcs_info.json` and
  repository [`denoland/rust-urlpattern`](https://github.com/denoland/rust-urlpattern).
- The complete packaged source and manifest were reviewed. It is MIT licensed,
  declares `build = false`, contains no `unsafe` code, and has no FFI,
  filesystem, network, process, or ambient-environment access.
- Its direct dependencies (`icu_properties`, `regex`, `serde`, and `url`) were
  already present in the locked graph and receive their own admission review.

## Runtime boundary and failure behavior

The wrapper accepts only HTTPS same-origin dictionary URLs. Structured-field
parsing limits `match` to 4 KiB, rejects invalid patterns, and rejects every
user-provided regexp group through `has_regexp_groups()` before use. The only
remaining expressions are generated literal and wildcard patterns compiled by
Rust `regex`, whose matching engine is linear time. Stored matches repeat the
same construction and group rejection, while all parse or match errors deny
dictionary use. Request URL and dictionary/profile quotas bound the remaining
input and allocation work.

The crate internally tokenizes, canonicalizes URL components through `url`,
builds a matcher, and returns errors for invalid construction. Its assertions
guard parser invariants; the reviewed OxiBelt boundary supplies validated,
length-bounded UTF-8 and maps construction or matching failure to rejection.

## Alternatives and maintenance

Using `url` alone cannot implement RFC 9842 URL Pattern semantics. A local
parser or direct regular-expression construction would duplicate URL
canonicalization and introduce a larger first-party security boundary.
`urlpattern` is the focused implementation maintained in the Deno organization
and declares the standard it follows. Its small maintainer surface remains a
maintenance risk, so review every selected release and remove the dependency
if an update cannot preserve the bounded wrapper and this audit criteria.

## Admission evidence

`cargo vet --locked` initially reported only `urlpattern:0.6.0` as missing
`safe-to-deploy`. The local audit in `supply-chain/audits.toml` certifies this
exact version. The dependency-policy entry records it as an untrusted-input
parsing dependency and binds the current lockfile digest.
