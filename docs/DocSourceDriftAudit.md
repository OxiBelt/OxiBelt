# OxiBelt Doc/Spec Source Drift Audit

This audit records doc/spec claims checked against `git HEAD` on 2026-06-08.
Each item uses case-by-case truth selection: source/runtime behavior is
preserved when it is already intentional and tested, while explicit public
contracts drive code fixes when runtime behavior is behind the documented
contract.

| ID | Doc/spec claim | Source/runtime evidence | Existing test guard | Verdict | Priority | Recommended fix | Validation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CFG-001 | `docs/Configuration.md` said each route must set exactly one of `upstream`, `upstream_pool`, or `static_root`. | `source/src/config.rs` also treats terminal `actions.redirect` as a route target and emits an error naming all four targets. | `tests/rust/config_and_routes.rs` already covers redirect target compatibility and the four-target error text. | Doc-only drift. | P1 | Document `actions.redirect` in the top-level routing requirements and validation summary. | `cargo test --test config_and_routes --locked` |
| FTR-001 | `docs/FeatureStatus.md` is the canonical lifecycle matrix for major features. | Current matrix includes `tls-upstream-revocation`, `client-identity-asn`, `sybil-rate-limit-identities`, and `gateway-api-grpcroute`. | `tests/rust/feature_status_contract.rs` required many IDs but did not require those current rows. | Guard gap. | P1 | Add the missing current feature IDs to the required lifecycle assertions. | `cargo test --test feature_status_contract --locked` |
| ADM-001 | `docs/AdminAPI.md` says mutating IPM endpoints require `If-Match`; missing ETags return `428`, stale ETags return `412`. | `source/src/server/admin_ipm.rs` calls `check_if_match` for IPM create, patch, delete, rotate, and revoke operations; `docs/admin-openapi.json` already declares `If-Match`, `412`, and `428` for those operations. | `tests/rust/admin_openapi_contract.rs` guarded dynamic-policy, upstream-pool, and stream-pool mutations, but not IPM mutations. | Guard gap. | P1 | Add an Admin OpenAPI contract test for all mutating IPM operations. | `cargo test --test admin_openapi_contract --locked` |
| WAF-001 | `docs/OxiRule.md` says non-JSON Person proof verify requests return `415`. | `source/src/proxy/http/person_proof.rs` rejected non-JSON payloads but mapped all payload parse errors to `400`. | Existing parser tests rejected form/legacy payloads but did not distinguish media-type errors. | Runtime drift from explicit public contract. | P2 | Split unsupported media type from malformed JSON and map it to `415 Unsupported Media Type`. | `cargo test --manifest-path source/Cargo.toml --locked person_proof` |
| WAF-002 | `docs/OxiRule.md` described custom provider failure as `{ "success": false, "error_codes": [] }`. | `source/src/proxy/http/person_proof.rs` requires only boolean `success`; tests accept `{ "success": false }`. `docs/Configuration.md` already documents `{ "success": true\|false }`. | Unit tests pin the lenient response contract. | Doc ambiguity. | P3 | Clarify that `error_codes` is optional provider diagnostics, not a required field. | `cargo test --manifest-path source/Cargo.toml --locked person_proof` |
| OPS-001 | `AGENTS.md` and `CONTRIBUTING.md` oriented DevOps/CI-related automation under `devops/`. | Current deployable assets live under `deploy/observability` and `deploy/helm/oxibelt-gateway-controller`; `docs/Observability.md`, `docs/GatewayAPI.md`, and contract tests already use `deploy/`. | `tests/rust/observability_assets.rs` guards `deploy/observability`; feature matrix names `deploy/helm/oxibelt-gateway-controller`. | Orientation doc drift. | P2 | Document `deploy/` as the home for deployable Helm/observability assets and keep `devops/` for TypeScript DevOps/CI support tooling when present. | `cargo test --test observability_assets --locked` |

## Follow-Up Audit Areas

- Extract or derive more config documentation guards around `allowed_config_keys`
  and shipped `source/config/oxibelt.toml` examples.
- Consider a runbook-to-metric contract for `docs/Observability.md` if metric
  names become a stable operator-facing contract.
- Keep `docs/admin-openapi.json`, Admin handlers, and IPM action/resource
  semantics aligned; the current path/method coverage test remains static.
- Use `docs/FeatureStatus.md` as the lifecycle source of truth when README or
  `docs/Specification.md` summarize non-goals.
