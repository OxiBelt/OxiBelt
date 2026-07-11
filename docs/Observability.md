# OxiBelt Observability Runbook

Status: Draft
Target project: OxiBelt Rust-based reverse proxy

This runbook turns OxiBelt's existing operational surfaces into a small,
operator-facing bundle. It does not introduce a new configuration section.
Use `[metrics]`, `[health]`, `[telemetry.tracing]`, and
`[access_log]` directly.

The supporting Prometheus, OpenTelemetry Collector, and Grafana assets live in:

```text
deploy/observability/
```

## Secure Starter Configuration

Keep observability opt-in and private by default. Loopback binds are the safe
local baseline:

```toml
[metrics]
enabled = true
bind = "127.0.0.1:9090"
format = "prometheus"
detail = "detailed"

[health]
enabled = true
bind = "127.0.0.1:9091"
ready_path = "/ready"
live_path = "/live"

[logging.access_log]
enabled = true
stdout = true

[access_log.system]
enabled = true

[access_log.waf]
enabled = true

[access_log.admin]
enabled = true

[access_log.stdout]
enabled = true
schema = "ocsf"

[access_log.otlp]
enabled = false
endpoint = "http://127.0.0.1:4318/v1/logs"
trusted_ca_certs = []
schema = "ocsf"
queue_capacity = 1024
batch_size = 64
export_timeout_ms = 3000
service_name = "oxibelt"

[telemetry.tracing]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/traces"
service_name = "oxibelt"
sample_ratio = 1.0
export_timeout_ms = 3000
propagate_trace_context = true
```

Use wider binds, such as `0.0.0.0:9090`, only on a private Docker or
orchestrator network where the metrics and health listeners are not reachable
from the public internet. If trace context crosses an untrusted upstream or
tenant boundary, set `propagate_trace_context = false`.

Do not add credential-bearing request headers, session cookies, or response
cookies to access-log fields. Keep custom access-log expressions focused on
request IDs, route names, status, client network metadata, and upstream timing.
Access logs export OCSF or ECS JSON on stdout, and can also export the selected
projection as OpenTelemetry Logs over OTLP HTTP/protobuf with `[access_log.otlp]`.
Use `https://` for non-loopback collectors; `http://` is only accepted for
loopback collectors such as local sidecars. Add private collector CAs with
`access_log.otlp.trusted_ca_certs`.
Trace OTLP export remains configured separately under `[telemetry.tracing]`.

## Bundle Assets

The bundle is intentionally small:

- `deploy/observability/prometheus.yml`: scrapes OxiBelt's `/metrics`
  endpoint at `oxibelt:9090`.
- `deploy/observability/otel-collector.yaml`: accepts OTLP traces on
  `4318` for OxiBelt's HTTP exporter and `4317` for tools that use OTLP gRPC.
- `deploy/observability/grafana/provisioning/datasources/oxibelt.yml`:
  provisions a Prometheus data source.
- `deploy/observability/grafana/provisioning/dashboards/oxibelt.yml`:
  provisions the dashboard directory.
- `deploy/observability/grafana/dashboards/oxibelt-overview.json`: a starter
  dashboard based only on public-safe `oxibelt_*` metrics.

When using the assets in Compose or another orchestrator, mount the Grafana
dashboard file into `/etc/grafana/provisioning/dashboards/oxibelt/` and mount
the provisioning directories under `/etc/grafana/provisioning/`.

## Operator Questions

The dashboard and existing endpoints are organized around seven first-response
questions.

| Question | Primary signal | Notes |
| --- | --- | --- |
| Is the proxy up? | `/ready`, `/live`, `oxibelt_requests_total`, `oxibelt_responses_total` | Readiness returns `503 draining` while lifecycle drain is active. |
| Are certificates healthy? | `GET /admin/v1/tls/downstream`, `GET /admin/v1/tls/upstream`, `oxibelt_tls_ocsp_*`, `oxibelt_tls_crlite_*`, `oxibelt_tls_upstream_*`, TLS session storage metrics | Certificate inventory, including bounded SNI-selected downstream certificate entries, downstream OCSP/CRLite state, and upstream revocation state stay on the authenticated Admin API. Public TLS revocation metrics use fixed series only and omit responder URLs, SNI, issuers, certificate fingerprints, serial numbers, and filter identifiers. |
| Are upstreams healthy? | `oxibelt_upstream_requests_total`, `oxibelt_upstream_errors_total`, `oxibelt_upstream_pool_servers`, `oxibelt_upstream_pool_health_reports_total`, `oxibelt_upstream_pool_outlier_ejections_total`, upstream latency histograms | Public pool metrics use pool/source/state/outcome/reason labels and omit origins, discovery endpoints, tokens, raw errors, and response bodies. Use Admin upstream-pool APIs for per-server health reason, slow-start, ejection, active control, and Admin upstream TLS status for outbound revocation health. |
| Are stream listeners healthy? | `oxibelt_stream_tcp_sessions_total`, `oxibelt_stream_udp_sessions_total`, `oxibelt_stream_session_errors_total`, `oxibelt_stream_tcp_bytes_total`, `oxibelt_stream_udp_bytes_total`, `oxibelt_stream_udp_rate_limited_total`, Admin stream-pool snapshots | Public stream metrics are aggregate by transport and omit listener names, SNI values, targets, and origins. Use authenticated stream-pool APIs and runtime introspection for per-pool state and active TCP/UDP flow counts. |
| Is shared state saturated? | `oxibelt_shared_state_queue_duration_ms`, `oxibelt_shared_state_operation_duration_ms`, `oxibelt_shared_state_queued_operations`, `oxibelt_shared_state_in_flight_operations`, `oxibelt_shared_state_operations_total`, `oxibelt_shared_state_deferred_cleanup_dropped_total` | Alert on sustained queue growth or rising queue latency before operation timeouts. A nonzero deferred-cleanup drop counter means cancellation exhausted its bounded fallback queue. Labels are bounded to backend, kind, operation, and outcome; they never contain backend keys, request identity, tokens, URLs, or raw errors. |
| Is security automation active? | dynamic-policy, external-auth, and mitigation counters | Public metrics expose aggregate behavior, not sensitive WAF metadata. |
| Is HTTP/3 working? | detailed HTTP protocol labels and `oxibelt_quic_retries_total` | Detailed metrics must be enabled for per-protocol request panels. |
| Are reloads and drains safe? | `/ready`, Admin lifecycle state, runtime snapshot endpoints | Use `redact=true` on runtime and support-bundle endpoints. |

## WAF Telemetry Boundary

Downstream live OCSP fetch status is split by audience. Authenticated Admin TLS status, runtime snapshots, and support bundles include bounded fields for `status`, `staple_present`, `this_update`, `next_update`, `last_fetch_at`, `last_success_at`, `last_error_code`, `next_refresh_at`, and `failure_policy = "drop_stale"`. Public Prometheus output exposes only aggregate `oxibelt_tls_ocsp_fetch_success_total`, `oxibelt_tls_ocsp_fetch_errors_total`, `oxibelt_tls_ocsp_staple_present`, `oxibelt_tls_ocsp_next_update_timestamp_seconds`, and `oxibelt_tls_ocsp_stale_drops_total`.

OCSP fetch failures degrade serving without a staple instead of making TLS handshakes perform network I/O. Expired OCSP responses are dropped before they can be stapled.

CRLite enforcement status follows the same audience split. Authenticated Admin TLS status, runtime snapshots, and support bundles include bounded fields for `status`, `enabled`, `filter_present`, `filter_loaded`, `filter_stale`, `last_checked_at`, `last_error_code`, `result`, `failure_policy`, `coverage_policy`, `managed`, `storage`, `cache_present`, `cache_fresh`, `last_refresh_at`, `next_refresh_at`, `last_success_at`, and `last_error_kind`. Public Prometheus output exposes only aggregate `oxibelt_tls_crlite_checks_total`, `oxibelt_tls_crlite_revoked_total`, `oxibelt_tls_crlite_errors_total`, `oxibelt_tls_crlite_enabled`, `oxibelt_tls_crlite_filter_stale`, `oxibelt_tls_crlite_managed_enabled`, `oxibelt_tls_crlite_managed_refresh_success_total`, `oxibelt_tls_crlite_managed_refresh_errors_total`, `oxibelt_tls_crlite_managed_cache_bytes`, and `oxibelt_tls_crlite_managed_last_success_timestamp_seconds`.

CRLite checks run during startup or downstream TLS reload, and managed mode also runs bounded background refreshes. TLS handshakes never perform CRLite network I/O. Public metrics do not expose SNI, issuer names, certificate fingerprints, serial numbers, filter filenames, cache paths, Remote Settings URLs, or raw filter identifiers.

Outbound upstream revocation status follows the same audience split. Authenticated Admin TLS status, runtime snapshots, and support bundles include bounded fields for `enabled`, `ocsp_mode`, `crlite_mode`, `ocsp_cache_entries`, `ocsp_fetch_in_flight`, `last_ocsp_error_code`, `crlite_managed_filters`, and `last_crlite_error_code`. Public Prometheus output exposes only aggregate `oxibelt_tls_upstream_ocsp_success_total`, `oxibelt_tls_upstream_ocsp_errors_total`, `oxibelt_tls_upstream_crlite_checks_total`, `oxibelt_tls_upstream_crlite_revoked_total`, and `oxibelt_tls_upstream_crlite_errors_total`.

Upstream OCSP fetches are scheduled outside the TLS handshake verifier and use dedicated bootstrap HTTP clients so OCSP responder requests and managed CRLite Remote Settings downloads do not recursively depend on outbound revocation. Public and support surfaces do not expose responder URLs, upstream SNI, issuer names, certificate serial numbers, fingerprints, filter filenames, cache paths, Remote Settings URLs, or raw filter identifiers.

The public metrics listener is intentionally unauthenticated and therefore
omits WAF rule names, IDs, tags, per-rule hit counts, and cost details. Use the
authenticated Admin WAF telemetry endpoints when an operator needs that detail:

```text
GET /admin/v1/waf/rule-hits
GET /admin/v1/waf/rule-costs
GET /admin/v1/waf/crs/compatibility
```

Keep the Grafana dashboard on aggregate public-safe metrics. Do not copy
Admin-only WAF metadata into Prometheus labels, dashboard variables, or public
logs.

## Validation

Local static checks for this bundle:

```sh
cargo test --test observability_assets
```

Runtime verification with the existing Docker matrix:

```sh
tests/scripts/run-proxy-integration-matrix.sh ops observability-detail
```

The Docker matrix case verifies detailed Prometheus labels, trace-context
propagation, and the separation between public metrics and authenticated WAF
telemetry.
