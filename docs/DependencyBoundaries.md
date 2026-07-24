# Dependency Boundaries

OxiBelt enforces dependency direction at Rust module, Cargo package, feature,
and public API boundaries. These contracts keep policy and representation code
usable without pulling deployment control, Admin routing, or runtime ownership
into lower-level code. They are stronger than a source-file line count: the
750-line report is advisory, while forbidden dependency edges fail CI.

The main `oxibelt` crate is an internal integration crate (`publish = false`).
Its Rust visibility is not, by itself, a promise of ecosystem stability.
Stable contracts are the documented configuration format, command-line
interfaces, external-control wire types, Admin API, and other explicitly
documented behavior.

## Boundary map

Dependencies flow from orchestration and adapters toward policy,
representations, and narrow mechanics. Lower layers do not reach back into
their callers.

1. **Cargo roles and feature isolation.** The integrated runtime, strict data
   plane, controller, CLI, keysigner, netport switcher, and deployment
   diagnostics are separate roles. A role may depend only on the first-party
   packages and `oxibelt` features assigned to it. The strict data plane must
   not acquire Admin, configuration tooling, fuzzing, mutation, controller,
   CLI, diagnostics, or Kubernetes dependencies. The controller's production
   graph must not depend on the integrated `oxibelt` runtime.
2. **Proxy and data-plane isolation.** Production code under
   `source/src/proxy/` owns request and transport handling and must not import
   `server` orchestration or Admin roots. Server code may call the proxy, not
   the reverse. QUIC TLS metadata therefore belongs to HTTP/3 proxy code rather
   than server dispatch.
3. **Configuration isolation.** Production configuration modules parse,
   normalize, resolve, and validate typed configuration. They must not depend
   on proxy handling, server orchestration, application state, or runtime
   ownership. Runtime and proxy layers consume validated configuration.
4. **Pure WAF isolation.** OxiRule expressions, compilation, plans, and
   evaluators operate on supplied representations. They must not load
   configuration or files and must not reach into databases, runtime/server
   orchestration, shared state, application state, proxy handling, or Admin
   routing.
5. **TLS and remote-signer isolation.** TLS and remote-signer modules may
   consume typed configuration and cryptographic representations, but they
   must not depend on server/proxy orchestration, shared-state ownership, or
   Admin routing. Remote signing also remains independent of WAF policy.
6. **Storage mechanics versus policy.** Storage adapters expose narrow,
   atomic persistence mechanics. Cache policy, retry budgets, failure policy,
   rate policy, and admission decisions stay with their owning callers instead
   of being embedded in storage implementations.
7. **Diagnostics and controller isolation.** Deployment diagnostics may
   inspect deployment systems through its own package, but core runtime
   diagnostics must not contain Kubernetes or controller implementations. The
   controller uses shared external-control protocol and HTTP packages rather
   than the integrated runtime.
8. **Public API ownership.** The crate-root public module set and wildcard
   facade re-exports are reviewed snapshots. New implementation modules are
   private or `pub(crate)` by default. Adding a root `pub mod` or a wildcard
   re-export requires an explicit contract review and a corresponding policy
   test update.

## Role feature matrix

The workspace dependency on `oxibelt` disables default features. Every role
that needs an integrated-runtime capability opts into it explicitly.

| Role | Allowed `oxibelt` relationship | Required or allowed features | Forbidden leakage |
| --- | --- | --- | --- |
| Integrated `oxibelt` runtime | Package root | Default build uses `admin-runtime`; the all-features lane exercises the declared feature set | Controller, CLI, deployment-diagnostics, Kubernetes, or Sequoia role packages in the runtime graph |
| `oxibelt-dataplane-strict` | Direct dependency | No `oxibelt` features | `default`, `admin-runtime`, `config-tooling`, `fuzzing`, `mutation-pqc`, controller, CLI, diagnostics, Kubernetes, or unknown first-party packages |
| `oxibelt-gateway-controller` | No production dependency | Shared build-identity, control HTTP, and control-protocol packages | Integrated `oxibelt` runtime in normal/build dependencies |
| `oxibelt-keysigner` | Direct dependency | No default/Admin/config/fuzz/mutation features; role-local `crypto-ring` remains allowed | Integrated default features and mutation pass-through features |
| `oxibelt-netport-switcher` | Direct dependency | No default/Admin/config/fuzz/mutation features; role-local `crypto-ring` remains allowed | Integrated default features and mutation pass-through features |
| `oxibeltctl` | Direct dependency | Explicit `admin-runtime` and `config-tooling` | Implicit acquisition through workspace defaults |
| `oxibelt-deployment-diagnostics` | Direct dependency | No default/Admin/config/fuzz/mutation features; Kubernetes dependencies are role-owned | Integrated default features outside the diagnostics role |

Dev-only dependencies are assessed separately from normal/build role graphs.
The controller's tests may use `oxibelt::config::Config` in
`source/apps/oxibelt-gateway-controller/src/translate/tests.rs`; that test-only
bridge does not authorize a production dependency.

## Reviewed bridges and exceptions

Exceptions are exact paths or symbols, not permission for a directory-wide
reverse dependency.

- The cfg-gated WebTransport Admin adapter is limited to
  `source/src/proxy/http3/webtransport_bridge/session.rs`,
  `source/src/proxy/http3/webtransport_bridge/session/state.rs`, and
  `source/src/proxy/http3/webtransport_bridge/session/admin_commands.rs`.
  Their Admin-facing imports and module wiring must remain guarded by
  `admin-runtime`.
- TLS certificate projection may use exactly
  `crate::waf::metadata::WafClientCertificateMetadata` from
  `source/src/tls/cert_metadata.rs`. This narrow representation bridge does not
  allow TLS modules to call WAF evaluation or Admin behavior.
- The controller configuration bridge described above is test-only.
- The strict package reuses `source/src/main.rs` with `server/strict_runtime.rs`;
  keysigner is limited to `remote_signer` and TLS provider setup; netport
  switcher is limited to configuration and `netport_switcher`; `oxibeltctl`
  owns its explicit Admin, configuration-tooling, and WAF tooling access; and
  deployment diagnostics consumes only the bounded core diagnostics model.
  These role bridges do not authorize unrelated runtime modules or features.

Person Proof core validation, challenge assets, and revocation consumption
remain data-plane capabilities. Person Proof status, listing, revocation
administration, and idempotency orchestration are `admin-runtime` capabilities.
The strict role continues to parse and reject invalid Person Proof
configuration without embedding Admin APIs or routes.

## Enforcement

`tests/rust/module_decomposition_contract.rs` parses Rust syntax and enforces
module dependency and public-surface policy. Its negative fixtures under
`tests/fixtures/rust-dependency-boundaries/` demonstrate rejected edges and
accidental public modules.

`tests/scripts/check-cargo-package-boundaries.sh` is the stable entrypoint for
the Cargo role analyzer. The analyzer uses package-scoped `cargo tree` output
for the resolved normal/build package and feature graph; `cargo metadata`
supplies workspace package identity only. The structured
`package_boundaries` Rust contract parses direct manifest and target facts.
The checks fail closed on Cargo errors, malformed or empty graphs, missing
roots, unknown local packages, and forbidden packages or features. Their unit
tests include valid and deliberately invalid graph fixtures.

Run the boundary checks from the repository root:

```sh
python3 -m unittest tests/scripts/test-check-rust-module-size.py
python3 -m unittest tests/scripts/test-check-cargo-package-boundaries.py
cargo test -p oxibelt --test module_decomposition_contract --locked
bash tests/scripts/check-cargo-package-boundaries.sh
tests/scripts/check-rust-module-size.sh --warn
```

The module-size advisory still fails for an invalid invocation, missing or
unreadable source roots, or a scan that checks no Rust files. It does not turn
an over-threshold file into a CI failure. `--enforce` retains the explicit hard
mode for callers that require it.

## Changing a boundary

A boundary exception is a security-sensitive architecture change. Keep it as
narrow as possible and include:

1. the concrete path, symbol, package, dependency kind, or feature being
   allowed;
2. why the dependency cannot point in the normal direction;
3. confirmation that runtime, configuration, CLI, wire, Admin, and image-role
   behavior remain unchanged, or documentation of the intended contract
   change;
4. positive coverage for the permitted edge and negative coverage proving
   adjacent edges remain forbidden; and
5. updates to this document and the relevant policy snapshot.

Prefer moving ownership to the consuming layer or extracting a side-effect-free
representation over adding an exception. Broad prefixes, undocumented feature
inheritance, wildcard allowances, and silently ignored missing policy targets
are not acceptable exceptions.
