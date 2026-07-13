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
| `static-files` | `supported` | Config/data plane | Static routes serve verified files under `static_root`, with directory indexes, `try_files`, SPA fallback, precompressed `br`/`zstd`/`gzip` variants, MIME overrides, cache-control policy, range/validator handling, hot-object cache isolation, plain HTTP sendfile support, and custom `404`/`50x` pages. |
| `tls-ocsp` | `supported` | Config/TLS/Admin API | Downstream OCSP modes: `disabled`, `static_file`, `live_fetch`. Static file staples and live fetch/refresh are supported. |
| `crlite` | `experimental` | TLS/revocation | Downstream and outbound upstream CRLite filter enforcement is implemented for operator-supplied local filters and managed Mozilla CRLite cache downloads. Modes: `disabled`, `enforce`, `managed`; failure policies: `fail_closed`, `degraded_allow`; coverage policies: `allow_unknown`, `require_good`. |
| `tls-upstream-revocation` | `experimental` | Config/TLS/Admin API | Runtime outbound TLS revocation is opt-in under `[proxy.upstream_revocation]` with direct-upstream overrides under `[upstreams.tls.upstream_revocation]`. Upstream OCSP modes: `disabled`, `live_fetch`; CRLite modes: `disabled`, `enforce`, `managed`. Admin endpoints: `GET /admin/v1/tls/upstream`, `POST /admin/v1/tls/upstream/refresh`. |
| `tls-remote-signer` | `supported` | Config/TLS | Downstream certificate signing can use the `oxibelt-keysigner` Unix-socket sidecar. |
| `tls-early-data` | `supported` | Config/TLS/data plane | Downstream TLS early data supports global `tls.ssl_early_data` and per-route `routes.tls.ssl_early_data` modes: `off`, `safe_methods`, and `on`. Verified early-data requests get upstream `Early-Data: 1`; untrusted client headers are stripped. |
| `root-netport-switcher` | `experimental` | Config/data plane/Docker | The `oxibelt-netport-switcher` wrapper can run as root with narrow bind and setuid/setgid capabilities, broker startup-allowed privileged data-plane TCP/UDP binds over Unix IPC, and launch the main `oxibelt` process as UID/GID `10001:10001`. Admin, metrics, and health listeners are intentionally excluded. |
| `tls-mtls-client-auth` | `supported` | Config/TLS/routing | Optional and required downstream client certificate authentication are supported for TCP TLS, with route matchers for available certificate metadata. |
| `upstream-ech` | `supported` | Config/upstream TLS | Upstream ECH supports `disabled`, GREASE, and configured `ECHConfigList` modes. |
| `stream-listener-tcp` | `supported` | Config/data plane/Admin API | `[[stream_listeners]]` proxy raw TCP to a direct `host:port` target or `[[stream_upstream_pools]]`, with optional visible TLS ClientHello SNI rules. |
| `sni-forward` | `supported` | Config/data plane | TCP TLS and same-port QUIC SNI forwarding are implemented. Protocol values: `tcp_tls`, `quic`. TCP ClientHello parse methods: `single_record`, `tls_record_reassembly`. |
| `oxirule-request-response` | `supported` | WAF/data plane/Admin API | OxiRule request, response, and native stream-phase policy are implemented with bounded evaluation. |
| `crs-request-response` | `supported` | WAF/data plane/Admin API | CRS-compatible request/response phases 1 through 4 are implemented for bounded body-prefix inspection. |
| `person-proof` | `supported` | WAF/data plane | Built-in PoW, OpenAPI custom frontend mode, third-party provider adapters, and custom JSON provider mode are implemented. |
| `client-identity-asn` | `experimental` | Config/runtime/WAF | Optional prefix-to-ASN lookup supports operator-supplied local or managed HTTPS `prefix_asn_csv` databases. IANA AS Numbers CSV is metadata only, not the origin-ASN lookup source. |
| `sybil-rate-limit-identities` | `experimental` | Config/WAF/data plane/Admin API | Rate-limit buckets and DynamicPolicy subjects support client IP prefixes, TLS fingerprints, ASN, composite client identities, WAF token-binding hashes, and verified Person proof clearance hashes. |
| `cache` | `supported` | Config/data plane/Admin API | Response caching, purge, key explain, warming, Vary guard, stale behavior, and disk streaming fills are implemented. |
| `global-overload-manager` | `supported` | Config/runtime/data plane | Opt-in global pressure sampling, hysteretic soft/hard state, public admission shedding, cache/compression/retry/WAF controls, graceful lifecycle drain, reserved control-plane slots, and fixed-vocabulary Prometheus metrics are implemented. |
| `request-queue-retry-circuit-breakers` | `supported` | Config/runtime/data plane/metrics | Enabled-by-default process-local global and route/pool bounded admission, FIFO queue limits, proportional retry budget, visible Hyper retry control, and upstream failure circuits with open/half-open recovery are implemented. |
| `priority-classes-reserved-capacity` | `supported` | Config/runtime/data plane/metrics | Fixed route priority classes have low-priority share caps, bounded per-class queues and rejection policies, strict authenticated request reservations, dedicated always-bounded Admin/health/metrics listener slots, and fixed-vocabulary Prometheus metrics. |
| `edge-secure-medium-profile` | `supported` | Config/runtime/Admin API/Deploy | The compiled-in `edge-secure-medium` v1 baseline expands before validation, materializes its fixed version in redacted effective configuration, and reports the resolved selector in config status. It has no profile URL/file/remote-catalog surface; only v1 is shipped, while future profiles require separately documented catalog entries. |
| `redis-shared-state-tls` | `supported` | Config/shared state/TLS | Redis-compatible shared-state backends support verified `rediss://`, explicit WebPKI/native/custom trust selection, hostname verification, optional mTLS, additive SPKI pins, ACL username/password or password-only secret files, secure plaintext policy, and activation-time connection validation. |
| `admin-api-runtime-control` | `supported` | Admin API | Admin capabilities: `config_load`, `file_sync`, `dynamic_policy`, `ipm_store`, `waf_devtools`, `runtime_introspection`, `cache_admin`, `person_proof_admin`, `upstream_pool_runtime_control`, `stream_pool_runtime_control`, `admin_operations`, `admin_http3`, `admin_operation_webtransport`, `admin_audit`. Operation kinds: `cache_warm`, `oxirule_replay`, `diagnostics_preflight`, `support_bundle`, `dynamic_policy_import`, `webtransport_snapshot`, `webtransport_drain`. Operation states: `queued`, `running`, `succeeded`, `failed`, `cancelled`, `expired`. |
| `observability` | `supported` | Metrics/tracing/logging | Prometheus metrics, OTLP tracing, runtime snapshots, support bundles, and system/WAF access-log surfaces are implemented. |
| `gateway-controller` | `experimental` | Kubernetes/controller | `oxibelt-gateway-controller` renders and validates a deterministic TOML include, publishes an immutable ConfigMap, rolls an opt-in workload, verifies every Ready Pod's assigned raw digest, and rolls back on failure; it does not use Admin file sync as a cluster rollout protocol. |
| `gateway-api-httproute` | `experimental` | Kubernetes/controller | Gateway API `HTTPRoute` translation supports host intersection, path prefix/exact, method, exact header/query matches, weighted Service backends, bounded URL rewrite, origin-relative redirects, header modifiers, CORS, RequestMirror, and HTTP ExternalAuth. |
| `gateway-api-grpcroute` | `experimental` | Kubernetes/controller | Gateway API `GRPCRoute` translation supports HTTP/HTTPS listener attachment, exact service+method and service-only matches, exact headers, weighted Service backends, header modifiers, RequestMirror, and HTTP ExternalAuth. |
| `gateway-api-tlsroute` | `experimental` | Kubernetes/controller | Gateway API `TLSRoute` passthrough translation emits `[[sni_forward.rules]]` for `tls.mode = "Passthrough"`. |
| `helm-data-plane` | `experimental` | Deploy | The Helm chart under `deploy/helm/oxibelt` installs the OxiBelt data plane as a Deployment or DaemonSet with immutable content-addressed base ConfigMaps, safe rollout defaults, read-only mounts, probes, pod security defaults, metrics service wiring, PDB, optional HPA, an opt-in Kubernetes immutable rollout mode, validated TLS 1.3/mTLS Admin listener values, safe Redis TLS/ACL Secret projection paths, an opt-in portable NetworkPolicy baseline, and the optional `examples/edge-secure-medium-v1-values.yaml` companion. That companion selects the built-in profile, narrowly projects the named QUIC host-key Secret entry, enables the NetworkPolicy baseline, scopes metrics to a Prometheus identity, and leaves non-DNS egress explicit; optional Cilium exact-FQDN egress requires its installed CRD. It does not imply default ServiceAccount-token hardening or complete Kubernetes lifecycle/topology guarantees. |
| `helm-gateway-controller` | `experimental` | Deploy | The Helm chart under `deploy/helm/oxibelt-gateway-controller` installs a single-replica immutable-rollout controller, service account, read-only Gateway API RBAC, and a namespace-scoped target Role with ConfigMap `get`/`create`, Pod list, Deployment-only ReplicaSet list, and named workload `get`/`patch` (no target watch/delete); it also provides status-service and backend-resolution options, health probes, pod security defaults, and examples, with no Admin credential coupling. |
| `acme` | `reserved` | TLS/certificate lifecycle | ACME issuance and HTTP-01/DNS-01 challenge handling stay outside OxiBelt. |
| `downstream-ech` | `reserved` | Downstream TLS | Downstream ECH configuration is reserved until server-side TLS provider support is available. |
| `stream-proxy-udp` | `supported` | Config/data plane/Admin API | `[[stream_listeners]] network = "udp"` proxies UDP datagram flows to direct targets or UDP stream pools, pins each downstream flow to its selected upstream, and can route QUIC Initial SNI with per-listener SNI rules. |
| `crs-stream-payload` | `reserved` | WAF/data plane | CRS inspection for WebSocket and WebTransport stream payloads is reserved. |
| `general-scripting` | `reserved` | WAF/config extension | General-purpose scripting, imports, loops, callbacks, and unbounded comprehensions are reserved by design. |
| `legacy-admin-rbac` | `removed` | Config/Admin API | Legacy Admin RBAC `roles`, `permissions`, and `deny_permissions` are rejected in favor of IPM. |
| `legacy-pool-algorithm-aliases` | `removed` | Config | Legacy pool algorithm aliases such as `round_robin`, `least_conn`, `least_connections`, `random`, `hash`, and `ip_hash` are rejected by default rather than treated as aliases. Explicit migration UX is available through `[config] lb_policy_compat_profile = "nginx"` or `"caddy"` and `oxibeltctl config lb-policy-compat`; only `least_conn`/`least_connections` and `ip_hash` are converted. |
