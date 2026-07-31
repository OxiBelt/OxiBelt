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
- `deploy/observability/prometheus-adapter-oxibelt-values.yaml`: a narrowly
  scoped values overlay for a separately operated Prometheus Adapter. It maps
  only the fixed per-Pod active-request gauge to
  `oxibelt_active_http_requests` under `custom.metrics.k8s.io`.

When using the assets in Compose or another orchestrator, mount the Grafana
dashboard file into `/etc/grafana/provisioning/dashboards/oxibelt/` and mount
the provisioning directories under `/etc/grafana/provisioning/`.

## Kubernetes Active-Request Autoscaling

OxiBelt exposes the low-cardinality raw gauge
`oxibelt_overload_active_work{kind="active_http_requests"}`. The `kind` value
is a fixed vocabulary, so this metric does not put routes, client identities,
URLs, or upstream names into Prometheus labels. The companion adapter overlay
requires Kubernetes-provided `namespace` and `pod` scrape labels and exposes
only the fixed alias `oxibelt_active_http_requests` for per-Pod HPA use.
The chart accepts this HPA mode only with `edge-secure-medium`, whose overload
sampler maintains the active-work gauge.

The overlay sets a 30-second adapter relist interval and disables the adapter
chart's broad default rules. It is a values file, not an adapter installation:
the cluster monitoring owner remains responsible for the adapter chart version,
image provenance, `APIService`, and cluster-scoped RBAC. See
[KubernetesDeployment.md](KubernetesDeployment.md#health-and-metrics) for the
HPA values, rollout command, and diagnostics. Merge the overlay with the
adapter's existing values that define the actual Prometheus endpoint and its
TLS/authentication; this OxiBelt-specific file deliberately does not guess a
cluster service name.

Autoscaling observes the metric after the Prometheus scrape, adapter relist and
query, and HPA controller sync loops. Treat that combined lag as part of the
control loop when choosing targets and alerts. If the adapter cannot return the
custom metric, investigate the scrape labels, adapter discovery, and HPA events
before lowering thresholds; CPU may still scale up while the unavailable custom
metric blocks scale-down.

## Operator Questions

### Which exact build is running?

Use authenticated `GET /admin/v1/version`, runtime introspection, or a redacted
support bundle. Their effective version, revision, source ref, tracked-tree
state, and build kind come from the same compile-time identity used by CLI
`--version` and OCI labels. Build identity is deliberately absent from public
health responses and from Prometheus label sets to avoid unauthenticated
fingerprinting and unbounded time-series churn.

The dashboard and existing endpoints are organized around first-response
questions.

| Question | Primary signal | Notes |
| --- | --- | --- |
| Is the proxy up? | `/ready`, `/live`, `oxibelt_requests_total`, `oxibelt_responses_total` | Readiness returns `503 draining` while lifecycle drain is active and `503 overloaded` for configured hard overload. Health responses include `X-OxiBelt-Backend-Status`, `X-OxiBelt-Overload-State`, and fixed-vocabulary `X-OxiBelt-Runtime-Status` without exposing request data. |
| Which runtime topology is active? | `oxibelt_runtime_topology_info`, `oxibelt_runtime_subsystem_owner`, `oxibelt_runtime_worker_allocation`, `oxibelt_runtime_compatibility_boundary`, authenticated runtime introspection | Compare requested and resolved presets, fallback outcome/reason, every subsystem owner, final worker allocations, compatibility islands, and active direct-H1 state. `hybrid_compio` means a Compio bootstrap around Tokio-owned server work, not an all-Compio server. |
| Is overload protection active? | `oxibelt_overload_state`, `oxibelt_overload_resource_ratio`, `oxibelt_overload_active_work`, `oxibelt_overload_rejections_total`, `oxibelt_overload_transitions_total`, `oxibelt_overload_control_plane_active` | Alert when `state="hard"` persists, resource ratios approach hard thresholds, or rejections rise. Signal, work-kind, action, boundary, and control-plane labels are fixed vocabularies; no labels contain routes, client identities, URLs, or raw errors. |
| Are request queues or upstream circuits limiting traffic? | `oxibelt_circuit_breaker_active`, `oxibelt_circuit_breaker_queued`, `oxibelt_circuit_breaker_rejections_total`, `oxibelt_circuit_breaker_state`, `oxibelt_circuit_breaker_transitions_total`, `oxibelt_circuit_breaker_priority_active`, `oxibelt_circuit_breaker_priority_capacity`, `oxibelt_circuit_breaker_priority_queued`, `oxibelt_circuit_breaker_priority_rejections_total`, `oxibelt_circuit_breaker_priority_queue_wait_milliseconds_total` | Alert on sustained queued work, rising `queue_timeout`/`retry_budget` or per-priority `share_limit` rejections, or a route/pool `state="open"`. Scope labels are configuration-derived and capped; priority, capacity, and reason labels use fixed vocabularies only and never include paths, host headers, client identities, origins, or raw errors. |
| Is the persistent Compio direct-H1 service healthy? | `oxibelt_http_compio_direct_h1_submissions_total`, `oxibelt_http_compio_direct_h1_queue_occupancy`, `oxibelt_http_compio_direct_h1_workers`, `oxibelt_http_compio_direct_h1_connections`, `oxibelt_http_compio_direct_h1_connection_events_total`, `oxibelt_http_compio_direct_h1_dispatch_total`, wait/connect/cancellation duration counters, buffer events, and copied bytes | This Linux-only experimental service is present only when Compio direct-H1 is selected. Alert on nonzero `full`, `unhealthy`, or `draining` submissions; sustained queue occupancy; an unhealthy worker; post-dispatch failures; retirement churn; or active connections that do not return to zero after load. These series use fixed state/outcome/event vocabularies and never label an origin, host, route, path, peer, request, or raw error. |
| Are certificates healthy? | `GET /admin/v1/tls/downstream`, `GET /admin/v1/tls/upstream`, `oxibelt_tls_ocsp_*`, `oxibelt_tls_crlite_*`, `oxibelt_tls_upstream_*`, TLS session storage metrics | Certificate inventory, including bounded SNI-selected downstream certificate entries, downstream OCSP/CRLite state, and upstream revocation state stay on the authenticated Admin API. Public TLS revocation metrics use fixed series only and omit responder URLs, SNI, issuers, certificate fingerprints, serial numbers, and filter identifiers. |
| Are upstreams healthy? | `oxibelt_upstream_requests_total`, `oxibelt_upstream_errors_total`, `oxibelt_upstream_pool_servers`, `oxibelt_upstream_pool_health_reports_total`, `oxibelt_upstream_pool_outlier_ejections_total`, upstream latency histograms | Public pool metrics use pool/source/state/outcome/reason labels and omit origins, discovery endpoints, tokens, raw errors, and response bodies. Use Admin upstream-pool APIs for per-server health reason, slow-start, ejection, active control, and Admin upstream TLS status for outbound revocation health. |
| Are stream listeners healthy? | `oxibelt_stream_tcp_sessions_total`, `oxibelt_stream_udp_sessions_total`, `oxibelt_stream_session_errors_total`, `oxibelt_stream_tcp_bytes_total`, `oxibelt_stream_udp_bytes_total`, `oxibelt_stream_udp_rate_limited_total`, `oxibelt_stream_udp_flows_active`, `oxibelt_stream_udp_flows_created_total`, `oxibelt_stream_udp_flows_restored_total`, `oxibelt_stream_udp_flow_persistence_errors_total`, `oxibelt_stream_udp_flow_fence_rejections_total`, `oxibelt_stream_udp_flows_expired_total`, `oxibelt_stream_udp_flows_evicted_total`, `oxibelt_stream_udp_flow_admission_rejections_total`, `oxibelt_stream_udp_flows_forced_shutdown_total`, `oxibelt_stream_udp_datagrams_dropped_total`, Admin stream-pool snapshots | Public stream metrics are aggregate and omit listener names, peers, SNI values, targets, origins, and shared-state keys. `udp_flows_active` is current process-local socket/session state, not the global number of durable records. Compare created with restored flows, and alert on persistence errors, fence rejections, admission rejections, or dropped datagrams. Use authenticated stream-pool APIs and runtime introspection for per-pool state. |
| Is shared state saturated or degraded? | `oxibelt_shared_state_queue_duration_ms`, `oxibelt_shared_state_operation_duration_ms`, `oxibelt_shared_state_queued_operations`, `oxibelt_shared_state_in_flight_operations`, `oxibelt_shared_state_operations_total`, `oxibelt_shared_state_enumeration_total`, `oxibelt_shared_state_deferred_cleanup_dropped_total`, `oxibelt_shared_state_pool_connections`, `oxibelt_shared_state_pool_waiters`, `oxibelt_shared_state_pool_max_connections`, `oxibelt_shared_state_pool_circuit_state`, `oxibelt_shared_state_pool_acquisitions_total`, `oxibelt_shared_state_pool_connection_events_total`, `oxibelt_backend_feature_degraded`, `oxibelt_backend_failure_policy_applied_total`, `oxibelt_backend_feature_recoveries_total`, `oxibelt_backend_local_fallback_entries`, `oxibelt_backend_stale_snapshot_age_seconds` | Alert on sustained queue growth, pool wait/create timeouts, a nonzero enumeration `cap_exhausted` event, a non-closed Redis reconnect circuit, or a nonzero feature-degraded gauge before security-sensitive operations fail. Failure-policy labels are fixed to configured backend/kind plus the finite feature, mode, and failure-kind vocabulary; no labels contain backend keys, request identity, tokens, URLs, or raw errors. |
| Is security automation active? | dynamic-policy, external-auth, and mitigation counters | Public metrics expose aggregate behavior, not sensitive WAF metadata. |
| Is durable Admin audit healthy? | `oxibelt_admin_audit_events_total`, `oxibelt_admin_audit_required_rejections_total`, `oxibelt_admin_audit_replay_total`, `oxibelt_admin_audit_integrity_failures_total`, `oxibelt_admin_audit_spool_events`, `oxibelt_admin_audit_spool_bytes` | Alert on required rejections, integrity failures, sustained replay failures, or spool use approaching its configured byte/event bounds. Outcome, store, reason, and replay labels are fixed vocabularies and never contain actors, credentials, request IDs, paths, or raw errors. |
| Is Admin audit evidence externally anchored? | `GET /admin/v1/capabilities`, `oxibelt_admin_audit_anchor_submissions_total`, `oxibelt_admin_audit_anchor_submission_failures_total`, `oxibelt_admin_audit_anchor_verification_failures_total`, `oxibelt_admin_audit_anchor_last_sequence`, `oxibelt_admin_audit_anchor_lag_sequences`, `oxibelt_admin_audit_anchor_pending_checkpoints`, `oxibelt_admin_audit_anchor_pending_bytes`, `oxibelt_runtime_subsystem_state{subsystem="admin_audit"}`, `oxibelt_runtime_task_state{task="admin_audit_anchor"}` | Alert on any signature/continuity verification failure, rising submission failures, sustained nonzero lag, or pending evidence approaching configured checkpoint/byte bounds. Failure reasons are the fixed values `capacity_exhausted`, `signer_unavailable`, `authority_unavailable`, `continuity_failure`, and `worker_failure`; verification reasons are `local_chain`, `checkpoint_signature`, and `checkpoint_continuity`. Required anchoring makes the Admin audit subsystem/task readiness-critical and `/ready` returns `503` while it is unavailable; best-effort anchoring reports `degraded` without failing readiness. Metrics and capability status omit authority URLs, stream/instance IDs, event content, key IDs, and raw errors. Independently schedule `oxibeltctl audit verify`; runtime health is not a substitute for witness-based historical verification. |
| Is HTTP/3 working? | detailed HTTP protocol labels and `oxibelt_quic_retries_total` | Detailed metrics must be enabled for per-protocol request panels. |
| Are reloads and drains safe? | `/ready`, Admin lifecycle state, runtime snapshot endpoints | Use `redact=true` on runtime and support-bundle endpoints. |

### Runtime topology and readiness signals

Startup and successful full-reload events report the version-`2` topology
using fixed enum values and counts. The active Admin config explain, runtime
snapshot, runtime introspection, and redacted support bundle report the same
active-generation topology. Offline config explain reports
`basis = "preflight"` and must not be used as proof that a listener or worker
fleet was activated.

The public metrics surface exports:

- `oxibelt_runtime_topology_info{requested_preset,resolved_preset,outcome,reason}`;
- `oxibelt_runtime_subsystem_owner{subsystem,owner}`;
- `oxibelt_runtime_worker_allocation{pool,owner}`;
- `oxibelt_runtime_compatibility_boundary{boundary}`.

These labels come from bounded preset, outcome, reason, subsystem, owner,
pool, and boundary vocabularies. Worker counts are gauge values, not label
values. Logs, metrics, and support surfaces omit raw capability errors,
hostnames, paths, routes, peers, request data, and secrets.

`X-OxiBelt-Runtime-Status` is `ready`,
`required_acceleration_degraded`, or `runtime_unavailable`. A
`require_exact` activation failure is rejected and never published as a
degraded active topology. Readiness returns `503` when required acceleration
or another readiness-critical runtime subsystem is unavailable; authenticated
runtime output carries the fixed subsystem and reason while the public body
remains generic.

### Persistent Compio direct-H1 metrics

The service exports the following public-safe metric families:

- `oxibelt_http_compio_direct_h1_submissions_total{outcome}` with `outcome="immediate|waited|full|unhealthy|draining"`;
- `oxibelt_http_compio_direct_h1_queue_occupancy`;
- `oxibelt_http_compio_direct_h1_workers{state}` with `state="starting|healthy|unhealthy|draining|stopped"`;
- `oxibelt_http_compio_direct_h1_connections{state}` with `state="active|idle"`;
- `oxibelt_http_compio_direct_h1_connection_events_total{event}` with `event="created|reused|retired_idle_timeout|retired_absolute_lifetime|retired_stale_generation|retired_peer_close|retired_eof|retired_upgrade|retired_protocol|retired_timeout|retired_cancellation|retired_residual_bytes|retired_pool_full|retired_io_error|retired_worker_failure|closed_shutdown"`;
- `oxibelt_http_compio_direct_h1_dispatch_total{outcome}` with `outcome="predispatch_fallback|predispatch_rejection|postdispatch_failure"`;
- `oxibelt_http_compio_direct_h1_buffer_events_total{event}` with `event="allocate|reuse|discard"`;
- `oxibelt_http_compio_direct_h1_operation_wait_observations_total` and `oxibelt_http_compio_direct_h1_operation_wait_duration_ns_total`;
- `oxibelt_http_compio_direct_h1_connect_observations_total` and `oxibelt_http_compio_direct_h1_connect_duration_ns_total`;
- `oxibelt_http_compio_direct_h1_cancellation_observations_total` and `oxibelt_http_compio_direct_h1_cancellation_duration_ns_total`;
- `oxibelt_http_compio_direct_h1_copied_bytes_total` (bytes materialized into
  the owned upstream request wire buffer; response reads append directly into
  the owned parser buffer).

Compute mean wait, connect, or cancellation completion time only when its matching observation delta is positive. A `predispatch_fallback` is safe to replay through the established path because no upstream request byte was written. A `predispatch_rejection` means policy suppressed fallback before dispatch, including capacity exhaustion or cancellation. A `postdispatch_failure` is not fallback evidence and must not be retried outside the existing replay-safety policy. Connection `reused` should rise during eligible keep-alive traffic. Any retirement reason means that connection was not returned to the idle pool.

The version-`2` redacted support bundle includes the resolved runtime topology,
the resolved shared-state feature/backend mapping, and bounded failure-policy
state (`mode`, backend name, backend kind, degraded flag, and stale-snapshot
age). It omits connection URLs, credentials, request keys, raw capability
errors, and raw backend errors.

For `udp_flow_state = "shared_required"`, correlate stream lifecycle counters
with `oxibelt_shared_state_operations_total`,
`oxibelt_shared_state_operation_duration_ms`, queue/pool saturation, and
`oxibelt_backend_feature_degraded{feature="udp_flows"}`. A rising restored
counter after a rollout is expected; a rising persistence-error or
fence-rejection counter is not proof of data loss, but it means the requested
logical recovery or ownership transition did not complete. The fixed
`reject_new_only` outage policy lets an already-local owned flow remain usable
while rejecting packets that require a shared lookup, claim, recovery, or token
decision. None of these metrics proves preservation of a socket, upstream
source port, NAT/conntrack entry, exact Service endpoint, datagrams in flight,
or application/session state.

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
