# OxiBelt Feature Status

Status: Draft
Target project: OxiBelt Rust-based reverse proxy

This document is the canonical lifecycle matrix for major OxiBelt runtime,
configuration, Admin API, and controller features. Configuration syntax is
covered in [Configuration.md](Configuration.md), behavior details are covered in
[Specification.md](Specification.md), and Admin API wire shapes are covered in
[AdminAPI.md](AdminAPI.md) plus [admin-openapi.json](admin-openapi.json).

Lifecycle states are intentionally limited:

- `supported`: implemented, documented, and expected to remain compatible.
- `experimental`: implemented but narrow, early, or still being hardened.
- `reserved`: intentionally out of scope or deferred; configs should reject or
  avoid this surface unless a later release moves it.
- `removed`: previously documented or legacy behavior that is rejected rather
  than supported.

## Feature Matrix

| Feature ID | Status | Surface | Contract notes |
| --- | --- | --- | --- |
| `downstream-http-protocols` | `supported` | Data plane | Downstream HTTP/1.1, HTTP/2, and HTTP/3 are implemented. |
| `upstream-http-protocols` | `supported` | Data plane | Upstream HTTP/1.1, HTTPS HTTP/2, h2c, HTTP/3, WebSocket, and WebTransport forwarding are implemented. |
| `route-matchers` | `supported` | Config/data plane | Routes support host, path prefix, `match.methods`, `match.headers`, `match.queries`, `match.path.exact`, `match.path.prefix`, `match.path.regex`, `match.source_cidrs`, `match.protocols`, and TLS client-certificate matchers. Protocol values: `http`, `http1`, `http2`, `http3`, `websocket`, `webtransport`. |
| `route-actions` | `supported` | Config/data plane | `replace_prefix_with`, `actions.rewrite`, and terminal `actions.redirect` are implemented with bounded templates. |
| `upstream-pool-algorithms` | `supported` | Config/data plane | HTTP pool algorithms: `power_of_two_choices`, `weighted_least_conn`, `rendezvous_hash`, `rendezvous_ip_hash`, `ewma`, `least_time`, `sticky_cookie`. Sticky-cookie fallback algorithms: `power_of_two_choices`, `weighted_least_conn`, `rendezvous_hash`, `rendezvous_ip_hash`, `ewma`, `least_time`. |
| `upstream-discovery` | `supported` | Config/runtime | Discovery providers: `dns`, `file`, `kubernetes`, `consul`, `etcd`, `nomad`. |
| `upstream-pool-runtime-state` | `supported` | Config/Admin API | Server states: `ready`, `drain`, `down`, `maintenance`; passive and active HTTP/gRPC health checks support configurable HTTP request options, status/body matching, jitter, and health-check-only TLS policy. |
| `tls-ocsp` | `supported` | Config/TLS/Admin API | Downstream OCSP modes: `disabled`, `static_file`, `live_fetch`. Static file staples and live fetch/refresh are supported. |
| `crlite` | `experimental` | TLS/revocation | Downstream and outbound upstream CRLite filter enforcement is implemented for operator-supplied local filters and managed Mozilla CRLite cache downloads. Modes: `disabled`, `enforce`, `managed`; failure policies: `fail_closed`, `degraded_allow`; coverage policies: `allow_unknown`, `require_good`. |
| `tls-upstream-revocation` | `experimental` | Config/TLS/Admin API | Runtime outbound TLS revocation is opt-in under `[proxy.upstream_revocation]` with direct-upstream overrides under `[upstreams.tls.upstream_revocation]`. Upstream OCSP modes: `disabled`, `live_fetch`; CRLite modes: `disabled`, `enforce`, `managed`. Admin endpoints: `GET /admin/v1/tls/upstream`, `POST /admin/v1/tls/upstream/refresh`. |
| `tls-remote-signer` | `supported` | Config/TLS | Downstream certificate signing can use the `oxibelt-keysigner` Unix-socket sidecar. |
| `tls-mtls-client-auth` | `supported` | Config/TLS/routing | Optional and required downstream client certificate authentication are supported for TCP TLS, with route matchers for available certificate metadata. |
| `upstream-ech` | `supported` | Config/upstream TLS | Upstream ECH supports `disabled`, GREASE, and configured `ECHConfigList` modes. |
| `stream-listener-tcp` | `supported` | Config/data plane | `[[stream_listeners]]` proxy raw TCP to a single configured `host:port` target. |
| `sni-forward` | `supported` | Config/data plane | TCP TLS and same-port QUIC SNI forwarding are implemented. Protocol values: `tcp_tls`, `quic`. |
| `oxirule-request-response` | `supported` | WAF/data plane/Admin API | OxiRule request, response, and native stream-phase policy are implemented with bounded evaluation. |
| `crs-request-response` | `supported` | WAF/data plane/Admin API | CRS-compatible request/response phases 1 through 4 are implemented for bounded body-prefix inspection. |
| `person-proof` | `supported` | WAF/data plane | Built-in PoW, OpenAPI custom frontend mode, third-party provider adapters, and custom JSON provider mode are implemented. |
| `client-identity-asn` | `experimental` | Config/runtime/WAF | Optional prefix-to-ASN lookup supports operator-supplied local or managed HTTPS `prefix_asn_csv` databases. IANA AS Numbers CSV is metadata only, not the origin-ASN lookup source. |
| `sybil-rate-limit-identities` | `experimental` | Config/WAF/data plane/Admin API | Rate-limit buckets and DynamicPolicy subjects support client IP prefixes, TLS fingerprints, ASN, composite client identities, WAF token-binding hashes, and verified Person proof clearance hashes. |
| `cache` | `supported` | Config/data plane/Admin API | Response caching, purge, key explain, warming, Vary guard, stale behavior, and disk streaming fills are implemented. |
| `admin-api-runtime-control` | `supported` | Admin API | Admin capabilities: `config_load`, `file_sync`, `dynamic_policy`, `ipm_store`, `waf_devtools`, `runtime_introspection`, `cache_admin`, `person_proof_admin`, `upstream_pool_runtime_control`, `admin_operations`, `admin_http3`, `admin_operation_webtransport`, `admin_audit`. Operation kinds: `cache_warm`, `oxirule_replay`, `diagnostics_preflight`, `support_bundle`, `dynamic_policy_import`, `webtransport_snapshot`, `webtransport_drain`. Operation states: `queued`, `running`, `succeeded`, `failed`, `cancelled`, `expired`. |
| `observability` | `supported` | Metrics/tracing/logging | Prometheus metrics, OTLP tracing, runtime snapshots, support bundles, and system/WAF access-log surfaces are implemented. |
| `gateway-controller` | `experimental` | Kubernetes/controller | `oxibelt-gateway-controller` renders a controller-owned TOML include and applies it through Admin file sync. |
| `gateway-api-httproute` | `experimental` | Kubernetes/controller | Gateway API `HTTPRoute` translation supports host intersection, path prefix/exact, method, exact header/query matches, weighted Service backends, bounded URL rewrite, origin-relative redirects, header modifiers, CORS, RequestMirror, and HTTP ExternalAuth. |
| `gateway-api-grpcroute` | `experimental` | Kubernetes/controller | Gateway API `GRPCRoute` translation supports HTTP/HTTPS listener attachment, exact service+method and service-only matches, exact headers, weighted Service backends, header modifiers, RequestMirror, and HTTP ExternalAuth. |
| `gateway-api-tlsroute` | `experimental` | Kubernetes/controller | Gateway API `TLSRoute` passthrough translation emits `[[sni_forward.rules]]` for `tls.mode = "Passthrough"`. |
| `helm-gateway-controller` | `experimental` | Deploy | The minimal Helm chart under `deploy/helm/oxibelt-gateway-controller` installs the controller deployment, service account, RBAC, Admin token secret reference, health probes, and examples. |
| `acme` | `reserved` | TLS/certificate lifecycle | ACME issuance and HTTP-01/DNS-01 challenge handling stay outside OxiBelt. |
| `downstream-ech` | `reserved` | Downstream TLS | Downstream ECH configuration is reserved until server-side TLS provider support is available. |
| `stream-proxy-udp` | `reserved` | L4 data plane | General-purpose UDP stream proxying outside same-port QUIC SNI forwarding and TURN-specific behavior is reserved. |
| `crs-stream-payload` | `reserved` | WAF/data plane | CRS inspection for WebSocket and WebTransport stream payloads is reserved. |
| `general-scripting` | `reserved` | WAF/config extension | General-purpose scripting, imports, loops, callbacks, and unbounded comprehensions are reserved by design. |
| `legacy-admin-rbac` | `removed` | Config/Admin API | Legacy Admin RBAC `roles`, `permissions`, and `deny_permissions` are rejected in favor of IPM. |
| `legacy-pool-algorithm-aliases` | `removed` | Config | Legacy pool algorithm aliases such as `round_robin`, `least_conn`, `least_connections`, `random`, `hash`, and `ip_hash` are rejected rather than treated as aliases. |
