# OxiBelt Observability Runbook

Status: Draft
Target project: OxiBelt Rust-based reverse proxy

This runbook turns OxiBelt's existing operational surfaces into a small,
operator-facing bundle. It does not introduce a new configuration section.
Use `[metrics]`, `[health]`, `[telemetry.tracing]`, and
`[logging.access_log]` directly.

The supporting Prometheus, OpenTelemetry Collector, and Grafana assets live in:

```text
devops/observability/
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

## Bundle Assets

The bundle is intentionally small:

- `devops/observability/prometheus.yml`: scrapes OxiBelt's `/metrics`
  endpoint at `oxibelt:9090`.
- `devops/observability/otel-collector.yaml`: accepts OTLP traces on
  `4318` for OxiBelt's HTTP exporter and `4317` for tools that use OTLP gRPC.
- `devops/observability/grafana/provisioning/datasources/oxibelt.yml`:
  provisions a Prometheus data source.
- `devops/observability/grafana/provisioning/dashboards/oxibelt.yml`:
  provisions the dashboard directory.
- `devops/observability/grafana/dashboards/oxibelt-overview.json`: a starter
  dashboard based only on public-safe `oxibelt_*` metrics.

When using the assets in Compose or another orchestrator, mount the Grafana
dashboard file into `/etc/grafana/provisioning/dashboards/oxibelt/` and mount
the provisioning directories under `/etc/grafana/provisioning/`.

## Operator Questions

The dashboard and existing endpoints are organized around six first-response
questions.

| Question | Primary signal | Notes |
| --- | --- | --- |
| Is the proxy up? | `/ready`, `/live`, `oxibelt_requests_total`, `oxibelt_responses_total` | Readiness returns `503 draining` while lifecycle drain is active. |
| Are certificates healthy? | `GET /admin/v1/tls/downstream`, TLS session storage metrics | Certificate inventory and reload state stay on the authenticated Admin API. |
| Are upstreams healthy? | `oxibelt_upstream_requests_total`, `oxibelt_upstream_errors_total`, upstream latency histograms | Use Admin upstream-pool APIs for server-level state and active control. |
| Is security automation active? | dynamic-policy, external-auth, and mitigation counters | Public metrics expose aggregate behavior, not sensitive WAF metadata. |
| Is HTTP/3 working? | detailed HTTP protocol labels and `oxibelt_quic_retries_total` | Detailed metrics must be enabled for per-protocol request panels. |
| Are reloads and drains safe? | `/ready`, Admin lifecycle state, runtime snapshot endpoints | Use `redact=true` on runtime and support-bundle endpoints. |

## WAF Telemetry Boundary

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
