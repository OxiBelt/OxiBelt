# OxiBelt Configuration Reference

Status: Draft
Target project: OxiBelt Rust-based reverse proxy

This document describes the OxiBelt TOML configuration format. For
behavior-level context, see [Specification.md](Specification.md). For canonical
feature lifecycle status, see [FeatureStatus.md](FeatureStatus.md). For OxiRule
rule syntax, see [OxiRule.md](OxiRule.md). For metrics, tracing, access-log, and
dashboard guidance, see [Observability.md](Observability.md).

The repository example configuration is:

```sh
source/config/oxibelt.toml
```

The release container entrypoint expects:

```sh
/etc/oxibelt/config/oxibelt.toml
```

Validate a configuration without starting listeners:

```sh
oxibelt --config source/config/oxibelt.toml --check
```

For editor completion and automation, the build-validated JSON Schema for the
current native configuration epoch is
[`source/assets/oxibelt-config-v1.schema.json`](../source/assets/oxibelt-config-v1.schema.json).
The repository [`.taplo.toml`](../.taplo.toml) associates that schema with the
example and native TOML configuration directories. Print the exact embedded
schema with:

```sh
oxibeltctl config schema --epoch 1
```

Run local production parsing, include expansion, structural checks, and the
authoritative Rust semantic validator with stable JSON diagnostics:

```sh
oxibeltctl config validate /etc/oxibelt/config/oxibelt.toml --local-only
```

Without `--local-only`, validation remains local-first and then sends the
merged, include-free TOML to the authenticated Admin
`POST /admin/v1/config/validate` endpoint. A local fatal result is never sent.
Diagnostics carry `report_schema_version`, `native_schema_epoch`, severity,
stage, source file, canonical field path, and bounded spelling suggestions.
Warnings and deprecations do not fail validation; `unsupported` and `fatal`
diagnostics do.

Explain one local field, including its effective source and schema/lifecycle
metadata, with:

```sh
oxibeltctl config explain tls.private_key \
  --file /etc/oxibelt/config/oxibelt.toml
```

Omit `--file` to explain the active redacted Admin configuration through
`GET /admin/v1/config/explain`. Literal secrets, secret references, and values
already redacted by the effective-config boundary are never returned.

Native schema epochs are monotonic. Epoch 1 is the current public contract;
its artifact is immutable for incompatible shape changes. Additive optional
fields and metadata corrections may be published within an epoch, while a
field removal, incompatible type change, or incompatible required-field change
requires a new epoch and an explicit migration. The diagnostics report schema
is versioned independently. JSON Schema provides structural/editor guidance;
`Config::load` plus `Config::validate` remains authoritative for cross-field,
path, security, and runtime semantics.

The only automatic migration currently supported is the explicit legacy epoch
0 to epoch 1 transform:

```sh
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1 --dry-run
oxibeltctl config migrate /etc/oxibelt/config/oxibelt.toml \
  --from 0 --to 1
```

Migration preserves comments and formatting through `toml_edit`, rejects
ambiguous or conflicting transformations, emits a deterministic report, and
validates an in-memory overlay with production path semantics before writing.
The default output is a new sibling directory named
`<config-directory>.migrated-v1`; existing output is never overwritten. Only
TOML documents in the include graph are copied. Certificates, keys, and rule
assets remain at the original roots, so the result is a review/overlay tree,
not a self-contained runnable layout until the operator supplies the referenced
assets. Re-running the transform on canonical input is idempotent.

Run the ordered startup runtime diagnostic without serving traffic:

```sh
oxibelt runtime-check --config source/config/oxibelt.toml
```

`runtime-check` separately reports configuration load and validation, tracing,
crypto provider setup, hardening, Compio probe and main runtime construction,
the Tokio compatibility island, TLS certificate/key loading, and listener bind
dry-runs. Use `--format json` for automation. When Compio crashes during the
probe, the parent process reports a normal failed stage instead of terminating
with the probe signal.

Run the production preflight doctor without starting listeners:

```sh
oxibeltctl doctor --config source/config/oxibelt.toml
```

`oxibeltctl doctor` emits a natural-language report by default (`--format
natural-language`) and exits non-zero for `error` or `critical` findings. The
former `--format text` spelling is not accepted. Use `--format json` or
`--format sarif` for automation, `--fail-on critical|error|warning` to tune
deploy gates, and repeat
`--external-probe shared_state|ipm_store|remote_signer|upstream|all` to run
explicit dependency probes. Without `--external-probe`, doctor only
loads and validates configuration plus local files, directories, and Unix
socket permissions; it does not connect to upstreams, databases, Redis, or the
remote signer. Local `oxibeltctl doctor` permits its explicit probes to read
secret-backed endpoint inputs, including Redis ACL files; Admin candidate
diagnostics keep those probes disabled unless an authorized workflow opts in.

Every JSON finding has a stable short `code`, such as `ADM-001`, plus its
long-standing dotted `id` compatibility alias. Reports include
`schema_version = 1`; automation should key policy on `code` and retain `id`
for operator context. SARIF 2.1.0 output uses the code as `ruleId`, preserves
the dotted ID, target, and remediation in result properties, and does not
pretend config-key targets are source-file locations.

Doctor has three optional read-only deployment sources. `--config FILE` may be
combined with exactly one of them, while `--candidate FILE` remains an Admin
preflight input and cannot be combined with local sources:

```sh
# Rendered YAML directory; YAML/YML files are bounded and symlinks are rejected.
oxibeltctl doctor --helm-rendered deploy/rendered --format sarif

# Local chart only. Rendering is argv-only Helm client dry-run with no hooks,
# no DNS enablement, no dependency updates, and a bounded timeout/output size.
oxibeltctl doctor --helm-chart deploy/helm/oxibelt \
  --helm-values values-production.yaml \
  --helm-release oxibelt --helm-namespace production

# Live cluster: list-only Deployments, DaemonSets, and HorizontalPodAutoscalers.
oxibeltctl doctor --kubernetes --kube-context production \
  --kube-namespace edge --kube-selector app.kubernetes.io/name=oxibelt
```

`--kubernetes` defaults to the selected context namespace; use
`--all-namespaces` only when an explicit cluster-wide inventory is intended.
It never reads Secrets or issues mutations. For safety, doctor refuses
kubeconfigs containing `exec` or `auth-provider` credentials rather than
running credential helper commands. In-cluster service-account configuration is
supported when no kubeconfig is present.

The deployment checks identify unpinned OxiBelt and Gateway Controller images,
immutable Gateway Controller target wiring, and configuration-revision
acknowledgement before multi-instance rollout. A read-only base ConfigMap mount
is valid for the immutable controller protocol; the controller replaces it with
its own projected revision volume during rollout. Doctor does not treat that
safe initial mount as a writable-configuration failure.

Print the merged, redacted effective configuration:

```sh
oxibelt --config source/config/oxibelt.toml --dump-effective-config
```

## Path Model

Container deployments use three purpose-specific directories:

```text
/etc/oxibelt/config   TOML configuration and included TOML modules
/etc/oxibelt/cert     TLS certificates, keys, CA roots, OCSP, and ECH files
/etc/oxibelt/oxirule  External .oxirule.toml, .oxirule-group.toml, and .oxirule-rulepack.toml files
```

Relative paths are resolved by purpose:

- `include`: relative to the TOML file that declares it.
- TLS, CA, OCSP, PostgreSQL TLS, and ECH files: under the cert directory.
- External OxiRule rule, group, CRS, and rulepack files: under the oxirule directory.

Runtime file paths must be relative, normalized paths without `.` or `..` components. They must resolve to existing regular files under the correct purpose-specific directory before startup continues.

## Top-Level Shape

A typical configuration may contain:

```toml
include = ["conf.d/*.toml"]
profile = "edge-secure-medium"
profile_version = 1

[config]
[access_log]
[access_log.system]
[access_log.waf]
[access_log.admin]
[access_log.stdout]
[access_log.otlp]
[logging]
[logging.access_log]
[[logging.access_log.fields]]
[runtime]
[runtime.worker_multipliers]
[runtime.accept]
[runtime.drain]
[runtime.hot_reload]
[runtime.hardening]
[runtime.hardening.seccomp]
[runtime.hardening.landlock]
[runtime.netport_switcher]
[crypto]
[crypto.primitives]
[listeners]
[listeners.proxy_protocol]
[sni_forward]
[[sni_forward.rules]]
[tls]
[[tls.certificates]]
[tls.client_auth]
[tls.ocsp]
[proxy]
[proxy.forwarded_headers]
[proxy.real_ip]
[proxy.auto_upgrade]
[proxy.upgrades]
[proxy.retry]
[proxy.buffering]
[proxy.http]
[client_identity]
[client_identity.asn]
[client_identity.asn.managed]
[client_identity.asn.iana_registry]
[limits]
[shared_state]
[[shared_state.backends]]
[shared_state.backends.redis_pool]
[shared_state.backends.tls]
[compression]
[[compression.policies]]
[cache]
[admin]
[admin.tls]
[[admin.tls.certificates]]
[admin.tls.client_auth]
[metrics]
[telemetry]
[telemetry.tracing]
[health]
[overload]
[overload.thresholds]
[overload.actions.soft]
[overload.actions.hard]
[overload.reserved_capacity]
[circuit_breakers]
[circuit_breakers.global]
[circuit_breakers.route_defaults]
[circuit_breakers.pool_defaults]
[circuit_breakers.retry_budget]
[circuit_breakers.failure]
[security.headers]
[[security.header_policies]]
[waf]
[waf.limits]

[[waf.pattern_sets]]
[[waf.rules]]
[[rate_limits]]
[[connection_limits]]
[[upstreams]]
[[upstream_pools]]
[[routes]]
```

Required routing inputs:

- At least one `[[routes]]`, `[sni_forward]` rule/default target, `[[stream_listeners]]`, or `[[webrtc_turn_listeners]]`.
- Each route must set exactly one of `upstream`, `upstream_pool`, `static_root`, `ct_log`, or terminal `actions.redirect`.

## Operational Profiles

Operational profiles are compiled-in, versioned configuration baselines. They
reduce omission and configuration drift, but do not replace the operator's
deployment-specific policy, certificate, identity, or Secret management.
OxiBelt ships immutable `edge-secure-medium` versions `1` and `2`:

```toml
profile = "edge-secure-medium"
# Optional in source. Omission permanently selects version 1, never latest.
profile_version = 1

[tls]
server_names = ["edge.example.com"]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"

[waf]
# This must be explicitly present and true in the source TOML or an include.
enabled = true
```

`profile = "edge-secure-medium"` always selects v1 when
`profile_version` is omitted; it does not mean "latest." The redacted
effective configuration materializes `profile_version = 1`, so saved output
is an explicit compatibility pin. `profile_version` without `profile`, an
unknown or malformed name/version pair, or more than one effective selector is
rejected even when `[config] strict_unknown_fields = false`.

Profile definitions are built into the OxiBelt binary. There are no profile
files, URLs, remote catalogs, or operator-supplied profile definitions. New
catalog entries require a separately documented version; v1 will not change
silently. This operational-profile
feature is separate from the `oxibeltctl mitigate <profile>` local/remote
dynamic-policy rendering feature described later in this document.

Profile expansion happens before typed configuration validation. Precedence is
compiled-in profile defaults, then explicit merged TOML (including all
`include` files), then supported runtime/CLI configuration overrides. An
explicit scalar or table leaf replaces the profile leaf; an explicit array
replaces the profile array rather than appending to it. A profile-protected
value is accepted only when the result preserves the selected version's
security boundary; unsafe weakening is rejected rather than silently clamped.
V1 and v2 use separate validators so selecting v2 does not retroactively
change v1. Configurations
without `profile` keep their existing defaults and behavior.

### `edge-secure-medium` v1 contract

The profile supplies these baseline values and validates the resulting
configuration. Required credentials and deployment-specific names deliberately
remain explicit rather than being synthesized by the profile.

| Area | v1 baseline and required operator inputs |
| --- | --- |
| Public TLS and QUIC | TLS is TLS 1.3 only; SNI is required and unknown SNI is rejected. Configure explicit public `tls.server_names` (the literal `*` is rejected) plus a certificate/key pair or the existing remote signer. HTTP/3 enables QUIC Retry, disables QUIC 0-RTT and TCP early data, and requires an explicit stable `quic.host_key_file`; do not use generated restart-local key material for a public HTTP/3 listener. |
| Resource bounds | The fixed public ceilings are `65,536` connections, `128` connections per IP, `65,536` WebTransport sessions, `128` WebTransport sessions per IP, `256` WebTransport sessions per connection, `1,000` requests per connection, `128` headers, `128` bytes per header name, `8,192` bytes per header value and URI, `65,536` aggregate header bytes, and `10 MiB` request and decoded-body caps. The decoded-body expansion ratio is `20`; downstream HTTP/2 and QUIC bidirectional/unidirectional stream caps are `1,024` and `512` respectively. The QUIC ceiling applies to the base, downstream, and upstream transport override blocks. Explicit profile overrides may tighten these caps but may not raise them. |
| Framing and client identity | Ambiguous HTTP framing and unsafe trailers remain rejected/sanitized; ordinary request trailers default to `drop` while native gRPC trailers remain available. Forwarding metadata is overwritten. Real-IP is disabled by default. Enabling Real-IP or PROXY protocol requires a nonempty, concrete trusted-source CIDR allowlist; all-address CIDRs are rejected. |
| WAF and rulepacks | `[waf] enabled = true` must be explicit in source TOML or an include. The profile defaults to `mode = "enforcing"`, fail-closed WAF evaluation, fail-closed duplicate metadata handling, and bounded body transform, regex, and evaluation budgets. A deliberate `mode = "monitor"` override is allowed for a staged rollout, but disabling the WAF is not. Rulepack selection must use exact paths and required manifest versions; wildcard rulepack files are rejected and remotely installed rulepacks must retain SHA-256 provenance. |
| Shared state, overload, and telemetry | Existing overload and circuit-breaker admission controls are enabled with their bounded control-plane capacity. Detailed metrics, health endpoints, and the existing system/WAF/Admin access-log sources are enabled by default; operators still choose their log-delivery policy. Remote Redis/Valkey backends may not use plaintext `redis://`; configure verified `rediss://` and any required trust or client-auth material explicitly. |
| Admin | Admin is disabled by default. If enabled, it must use a dedicated non-data-plane bind, TLS 1.3, required client certificates, IPM authorization, and enforcing durable PostgreSQL audit storage. Certificates, trust roots, principals, policies, and audit connection material remain operator inputs. |
| Lifecycle | Shutdown readiness delay is `10` seconds, ordinary graceful drain is at least `30` seconds, and long-lived connection close delay is at least `300` seconds. Overrides may lengthen these values but may not shorten the v1 guarantees. |

Use the regular validation and effective-config surfaces to inspect the exact
expanded result before deployment:

```sh
oxibelt --config source/config/oxibelt.toml --check
oxibelt --config source/config/oxibelt.toml --dump-effective-config
```

When Admin is enabled, `GET /admin/v1/config/status` reports the resolved
profile name/version and `GET /admin/v1/config/effective` returns the same
redacted, expanded TOML. Support bundles include this profile metadata and the
redacted effective configuration. Treat a selected profile or version change
as a full configuration change, not an OxiRule-only reload.

### `edge-secure-medium` v2 runtime contract

V2 keeps the v1 public-edge limits and requires the runtime confinement
contract to gate readiness. Select it explicitly and bind the expected
path-disclosing manifest digest and writable-path set:

```toml
profile = "edge-secure-medium"
profile_version = 2

[runtime.hardening.filesystem_manifest]
expected_digest = "sha256:FULL_64_CHARACTER_LOWERCASE_DIGEST"
expected_writable_paths = []
```

V2 requires `runtime.hardening.close_range = "required"`,
`runtime.hardening.seccomp.expectation = "required"`, and
`runtime.hardening.landlock.mode = "manifest"`. Generate the expected digest
only after resolving the final configuration and mounts:

```sh
oxibeltctl config filesystem-access CONFIG --check
oxibeltctl config filesystem-access CONFIG --show-paths
```

`--show-paths` deliberately discloses paths and the stable comparison digest;
run it only in a trusted local terminal. Startup compares both the digest and
the normalized read-write path set before building application state. Missing
expectation fields fail configuration validation. Mismatched runtime evidence
produces a blocked hardening snapshot and keeps readiness closed; the process
and liveness endpoint remain available so an operator can inspect the fixed
failure reason without creating a probe-driven restart loop. Ordinary redacted
config, logs, diagnostics, and support bundles report only whether an
expectation was present and matched; they never serialize the raw path-derived
digest. Runtime hardening snapshots use schema version `3` and add the bounded
`filesystem_manifest` expectation-present, digest-match, and writable-path-match
states. Fixed blocking reasons distinguish unavailable manifest evidence,
digest mismatch, and writable-path mismatch.

### Helm companion presets

The compatibility Helm companion preset is
`deploy/helm/oxibelt/examples/edge-secure-medium-v1-values.yaml`. It is not
selected by the chart's default values, preserving existing chart upgrade
behavior. Its public interface is:

```yaml
operationalProfile:
  name: edge-secure-medium
  version: 1
tls:
  serverNames:
    - edge.example.com
quic:
  hostKeySecretName: oxibelt-quic-host-key
  hostKeySecretKey: quic-host-key.b64
lifecycle:
  preStop:
    enabled: true
    drainSeconds: 300
  terminationGracePeriodSeconds: 360
podDistribution:
  enabled: true
podDisruptionBudget:
  minAvailable: null
  maxUnavailable: 1
  unhealthyPodEvictionPolicy: AlwaysAllow
networkPolicy:
  enabled: true
  ingress:
    public:
      allowAll: true
```

The preset renders the top-level selector, public TLS SNI enforcement, and a
read-only projection of just the named QUIC host-key Secret entry at the path
used by `quic.host_key_file`. It contains no certificate, private key, or host
key material. Operators must supply their own TLS Secret/configuration and a
stable base64-text QUIC host key in the named Secret, then replace the example
server name and Secret references before installation. Generate the mounted
text with `openssl rand -base64 64 > quic-host-key.b64`, then use
`kubectl create secret generic oxibelt-quic-host-key --from-file=quic-host-key.b64`.
The file projection must contain that base64 text (which decodes to exactly 64
random bytes); a Kubernetes `data:` field therefore requires one additional
base64 encoding, while `stringData:` may contain the text directly. The preset keeps
the Admin Service absent and enables the chart's portable NetworkPolicy
baseline. It permits only the public named ports plus the configured Prometheus
identity, permits DNS to the configured resolver peers, and deliberately leaves
Admin peers and non-DNS egress empty. Add explicit destinations before enabling
runtime features that need upstream, shared-state, revocation, Kubernetes API,
or external-dependency traffic; policy enforcement also requires a compatible
cluster CNI. The preset inherits the chart's default data-plane behavior: it
does not mount a Kubernetes API token or grant discovery RBAC. Token projection
and API access remain an explicit chart-level discovery choice. The preset does
select a three-replica minimum, managed hostname/zone distribution, preferred
same-release anti-affinity, a one-Pod PDB disruption budget, and the fixed
300-second `SIGUSR1` pre-stop drain inside a 360-second grace period. It
requires Kubernetes 1.31 or later. It does not turn release-image trust policy
into a property of the runtime profile. Release CI creates and verifies GitHub
API-hosted keyless SLSA provenance and CycloneDX SBOM attestations for canonical
image digests, but those bundles are not GHCR OCI referrers or an
OxiBelt-managed Kubernetes admission policy. Operators still verify, approve,
and pin immutable image digests and own freshness, rollback, vulnerability, and
admission policy. See [Release Image Trust and
Attestations](SupplyChain.md), especially before upgrading a cluster whose
fail-closed policy expects registry-resident historical referrers.

The opt-in v2 deployment envelope is
`deploy/helm/oxibelt/examples/edge-secure-medium-v2-values.yaml`. In addition
to selecting the native v2 profile, it requires the official
`dataplane-strict` repository at a lowercase SHA-256 digest, explicit default
deny networking, the v2 filesystem-manifest expectation, typed writable
`emptyDir` or PVC declarations, and the fixed Pod-security boundary. Replace
the example image and filesystem digests before installation; the placeholders
are intentionally not deployable evidence. The chart emits a Secret-free
profile report for review, but that report is a deterministic description of
rendered intent, not proof of CNI enforcement, kernel confinement, image
provenance, or admission-policy success.

## Includes

The main entry file can include modular TOML files:

```toml
include = [
  "conf.d/upstreams.toml",
  "conf.d/routes/*.toml",
]
```

The default example config also allows controller-owned modules with:

```toml
include = ["conf.d/*.toml"]
```

This is the expected immutable rollout target for
`oxibelt-gateway-controller`. The controller publishes
`conf.d/gateway-api.generated.toml` plus any digest-bound public CA assets from
an immutable Kubernetes ConfigMap; it does not write the config root through
Admin `POST /admin/v1/files/sync`. The controller-generated file can contain
HTTP/gRPC route and pool arrays, raw TCP/UDP stream listener and pool arrays,
Gateway HTTP external auth, and SNI forwarding rules. Operator-owned base
HTTP/HTTPS listeners, downstream TLS, Admin/IPM, public Service ports, and
scalar `[sni_forward]` settings stay in the base config.
For controller-generated L4 listeners, expose operator-approved sockets with
data-chart `service.additionalPorts[]` (`name`, `TCP|UDP`, Service `port`, and
numeric unprivileged `targetPort`) and configure controller-chart `l4` bounds.
The controller chart also accepts at most 16 unique `statusAddresses`; each is
passed as one `--status-address`. See [Gateway API](GatewayAPI.md) and
[Kubernetes Deployment](KubernetesDeployment.md) for attachment, RBAC, and
NetworkPolicy requirements.
The managed file path must be a safe nested relative `.toml` path so its parent
is present beneath the read-only config root; a root-level generated filename,
path traversal, or an unsafe path segment is rejected by the paired Helm
charts and controller.

`include` may be a single string or an array of strings. Include entries support exact file paths and glob patterns using `*`, `?`, and `[...]`.

Include behavior:

- Entries must be relative paths under the declaring file's directory.
- Absolute paths, `.` components, and `..` components are rejected.
- Exact include paths must exist.
- Glob matches are sorted before loading for deterministic startup.
- Glob entries that match no files are allowed.
- Included files may contain their own `include` entries.
- Include cycles are rejected.
- Include symlinks or glob matches that resolve outside the declaring file's directory are rejected.

TOML merge behavior:

- Included files are merged before the declaring file.
- Tables are merged recursively.
- Arrays are appended in include expansion order, then the declaring file's own array entries are appended.
- Duplicate scalar keys and incompatible value types are rejected.

Example split:

```toml
# source/config/oxibelt.toml
include = ["conf.d/*.toml"]

[listeners]
https_binds = ["0.0.0.0:8443", "[::]:8443"]
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"
```

```toml
# source/config/conf.d/10-upstreams.toml
[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2"
```

```toml
# source/config/conf.d/20-routes.toml
[[routes]]
name = "app-root"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
```

## Core Sections

```toml
[config]
strict_unknown_fields = true
warn_on_deprecated_fields = true
lb_policy_compat_profile = "strict" # strict | nginx | caddy

[logging]
level = "info"

[logging.access_log]
enabled = false
stdout = true

[access_log.system]
enabled = false

[access_log.waf]
enabled = true

[access_log.admin]
enabled = false

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
```

`strict_unknown_fields` defaults to `true`; unknown keys fail startup after includes are merged. `lb_policy_compat_profile` defaults to `strict`, which accepts only canonical OxiBelt load-balancing policy names. Set it to `nginx` or `caddy` only while migrating legacy pool-policy names; the profile converts exact safe aliases and rejects names that do not have an exact OxiBelt equivalent. `level` is passed to the tracing filter and defaults to `info`.

`access_log` controls the supported access-log sources and sinks. `system`, `waf`, and `admin` independently enable request-wide, OxiRule, and Admin API records. `[access_log.stdout]` writes newline-delimited JSON and defaults to `schema = "ocsf"`. Set `schema = "ecs"` to emit Elastic Common Schema JSON instead. `[access_log.otlp]` exports OpenTelemetry Logs over OTLP HTTP/protobuf to `/v1/logs` style collector endpoints and has an independent `schema = "ocsf"` or `schema = "ecs"` projection choice. Remote OTLP access-log collectors must use `https://`; `http://` is accepted only for loopback collectors. `trusted_ca_certs` adds private collector CA roots from the cert directory.

`logging.access_log` keeps the request-wide field-expression list and legacy `enabled` compatibility flag. When enabled through either `[access_log.system]` or `logging.access_log.enabled`, OxiBelt emits one access-log record for each finalized HTTP response with `event = "oxibelt.access"` and `scope = "system"` before schema projection. The default fields include request/response IDs, transaction ID, method, URI, client IP, route, status, upstream name, upstream timing fields, and a duplicate-safe `user_agent` collection from `Request.Headers.getAll('User-Agent')`.

Custom fields use the same expression syntax as OxiRule access-log fields:

```toml
[logging.access_log]
enabled = true
stdout = true

[[logging.access_log.fields]]
name = "method"
value = "Request.Http.Method"

[[logging.access_log.fields]]
name = "status"
expression = "Response.Http.Status"
```

PostgreSQL access-log sinks are removed. `database.access_log` and `logging.access_log.database` fail configuration loading; use `[access_log.stdout]` or `[access_log.otlp]` with `schema = "ocsf"` or `schema = "ecs"`.

```toml
[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
main_runtime = "tokio_hyper" # hybrid_compio | tokio_hyper | auto; legacy: compio
topology_policy = "allow_fallback" # allow_fallback | require_exact
direct_h1_io = "auto" # auto | tokio_hyper | compio

[runtime.workers]
tokio = "auto"
compio_direct_h1 = "auto"

[runtime.worker_multipliers]
tokio = 1.0
compio_direct_h1 = 1.0
accept = 0.5
quic_socket = 1.0

[runtime.accept]
workers = "auto"
reuse_port = true
backlog = 8192
accept_error_backoff_ms = 10

[runtime.drain]
graceful_timeout_ms = 30000
long_connection_close_delay_ms = 300000
shutdown_delay_ms = 0

[runtime.hot_reload]
mode = "off" # off | oxirule | downstream_tls | full
poll_interval_ms = 2000

[runtime.netport_switcher]
enabled = false
socket_dir = "/run/oxibelt-netport-switcher"
main_uid = 10001
main_gid = 10001
io_timeout_ms = 5000
pidfd_supervision = true

[runtime.hardening]
close_range = "auto" # auto | off | required

[runtime.hardening.seccomp]
expectation = "off" # off | optional | required
# profile_identity = "oxibelt-tokio-v1"
# profile_digest = "sha256:<64 lower-case hex>"

[runtime.hardening.landlock]
mode = "off" # off | enforce (manual) | manifest
read_paths = []
read_write_paths = []
```

`unprivileged_mode = true` rejects listener ports `1..1023` unless `[runtime.netport_switcher] enabled = true` is set for data-plane listeners and OxiBelt is started through `/usr/local/bin/oxibelt-netport-switcher`. While the Compio direct-H1 response engine remains experimental, the checked-in example and conservative production recommendation explicitly select `main_runtime = "tokio_hyper"` and `direct_h1_io = "auto"`.

### Library runtime ownership

The Rust library has separate owned and embedded entry points; see
[Embedding OxiBelt](Embedding.md). `RuntimePolicy::FromConfig` applies
`runtime.main_runtime`, `runtime.topology_policy`, and the configured Tokio and
Compio worker ownership in a runtime created and owned by OxiBelt.
`RuntimePolicy::CurrentRuntime` instead uses the caller's current Tokio
runtime. In that mode the main-runtime, topology-policy, Tokio-worker, and
Compio-worker fields remain valid TOML but are reported as `Inapplicable`; the
library never resizes the caller executor or claims a different executor.
Accept and QUIC socket workers remain OxiBelt-owned and their configuration is
still applied.

`ProcessPolicy::Embedded` separately selects
`ProcessGlobalHooks::CallerManaged`, `VerifyOnly`, or `ApplySelected`. These
policies control process-global crypto defaults, tracing, signals/reload,
`close_range`, and hardening rather than changing TOML precedence. Embedded
Landlock application is rejected because confinement cannot be made truthful
after a caller-owned runtime has created threads. Select
`ProcessPolicy::Standalone` and the owned API when configured Landlock or
OxiBelt-owned process signals are required.

`main_runtime = "hybrid_compio"` is the canonical default. It owns one Compio bootstrap driver around a Tokio compatibility island; TCP accept, general HTTP, HTTP/3 and QUIC, DNS and discovery, timers, background/control work, and Tokio-managed blocking work execute on Tokio. Only an activated Compio direct-H1 worker fleet owns direct-H1 transport work. The legacy value `main_runtime = "compio"` remains behavior-identical, resolves to `hybrid_compio`, and emits `CFG_RUNTIME_MAIN_RUNTIME_COMPATIBILITY_ALIAS`; no removal deadline is assigned. `main_runtime = "tokio_hyper"` runs the same server subsystems directly on Tokio/Hyper. `main_runtime = "auto"` prefers a safe hybrid topology and records a fallback to Tokio/Hyper when Compio is unavailable or unsafe.

`topology_policy = "allow_fallback"` preserves the compatibility fallback behavior. `require_exact` rejects startup or reload when `auto` cannot retain the preferred hybrid topology or an explicitly requested Compio direct-H1 transport would require a compatibility fallback. Capability resolution is deterministic and reports `exact`, `fallback`, `rejected`, or `feature_disabled` together with a fixed reason; it accounts for the OS, architecture, compiled support, Compio driver safety and preflight, required socket/protocol capabilities, hardening, and worker/resource budgets. Raw probe errors are not exposed in logs, metrics, config explain, runtime snapshots, or support bundles.

`[runtime.workers].tokio` and `compio_direct_h1` accept a positive integer or `"auto"`. Auto sizing uses Rust `std::thread::available_parallelism()`, falls back to `1` when detection fails, applies the matching `[runtime.worker_multipliers]` value, and rounds up. Multiplier defaults are `tokio = 1.0`, `compio_direct_h1 = 1.0`, `accept = 0.5`, and `quic_socket = 1.0`. Legacy `runtime.worker_threads` and `runtime.worker_multipliers.runtime` remain accepted: each supplies a canonical owner only when that owner's new field is omitted, so an explicit owner-specific value takes precedence. Legacy use emits a fixed migration diagnostic, and a legacy-only configuration preserves its previous resolved counts. Existing configurations that set `runtime.worker_multipliers.accept = 1.0` keep the previous CPU-count accept-worker behavior.

`direct_h1_io = "auto"` and `direct_h1_io = "tokio_hyper"` use the established Hyper direct-H1 transport. `direct_h1_io = "compio"` is an explicit Linux-only experimental selection and applies only after the normal direct-H1 route, upstream, body, retry, transform, upgrade, and CONNECT guards pass. It requires the hybrid Compio compatibility boundary. With `topology_policy = "allow_fallback"`, an incompatible resolved main topology records a Tokio/Hyper compatibility fallback; with `require_exact`, startup or reload rejects the candidate instead.

The Compio selection starts a persistent service at subsystem startup. Its worker count is the resolved `[runtime.workers].compio_direct_h1` allocation, and each worker owns one long-lived Compio execution context plus a bounded submission queue. Queue capacity, per-origin idle connections, total idle connections, retained buffer count, idle lifetime, and absolute connection lifetime derive from existing runtime and upstream-pool limits; worker count is the only independent public Compio allocation in this release. Shutdown stops admission, waits only within the configured process drain deadline, cancels remaining operations, closes idle connections, and joins workers. OxiBelt reserves the final bounded portion of that same configured window for terminal worker cleanup (up to 5 seconds, using the whole window when it is shorter than 100 ms; there is no new public knob), so native thread joining cannot extend shutdown beyond the operator's deadline. If a native worker still owns driver I/O at that hard deadline, OxiBelt aborts the process so a supervisor can replace it instead of detaching the worker into a continuing server.

When Compio direct-H1 is selected, automatic circuit-breaker connection and pending capacities are also bounded by the transport's worker memory, queue memory, file-descriptor, and active-plus-staged reload reservations. OxiBelt reduces only automatic values to find a safe transport budget; an operator-provided fixed value that cannot fit remains an unavailable Compio capability. `topology_policy = "allow_fallback"` then selects Tokio/Hyper direct-H1, while `require_exact` rejects the candidate. A finite cgroup memory limit is the hard sizing ceiling. When the cgroup reports unlimited memory, an optional Kubernetes request is capped by detected host memory when both are available, followed by host-memory discovery and a conservative fallback if no finite observation succeeds.

Only guarded empty `GET` or `HEAD` requests can enter this service, including prevalidated downstream H2/H3 requests, and only when the upstream hop is direct plaintext HTTP/1.1. Bodyful, chunked, streaming, upgrade, CONNECT, retry-unsafe, transformed, or otherwise ineligible requests remain on the Hyper direct-H1 transport and record a pre-dispatch Compio fallback. An unhealthy or draining service, or a resolution or connection failure, may fall back only before an upstream request byte is written. Queue saturation and connection-capacity rejection instead return the configured admission response and never reroute through Hyper. Once dispatch is externally observable, a Compio failure closes the connection and returns the established upstream failure; it never implicitly replays the operation through Hyper.

Reusable Compio connections are returned to the bounded idle pool only after complete unambiguous response framing with no residual bytes, no peer `Connection: close`, and a matching configuration generation. Parser failure, EOF, timeout, cancellation in uncertain framing, upgrade, stale generation, worker failure, pool overflow, and I/O failure retire the connection. The response engine bounds response heads, interim-response chains, chunk metadata, and trailers internally and fails closed on unsupported or ambiguous framing.

Full hot reload rejects a different resolved main topology or `[runtime.workers].tokio` count with a restart-required diagnostic. A direct-H1 backend or worker-count change can activate in-process only after the replacement fleet is staged successfully; otherwise the prior configuration, service, and reported topology remain active. Accept and QUIC worker changes retain listener-rebind behavior. A `topology_policy` change is accepted in-process only when re-resolution validates the active topology and is rejected otherwise.

`[runtime.accept]` controls data-plane TCP accept loops for HTTPS, plain HTTP, and TCP stream listeners. `workers` accepts a positive integer or `"auto"`; omitted values default to `"auto"` and use `[runtime.worker_multipliers].accept`. Set `reuse_port = true` whenever the resolved worker count can be greater than one; OxiBelt fails startup instead of silently enabling `SO_REUSEPORT`. `backlog` is passed to `listen(2)`. `accept_error_backoff_ms` throttles repeated accept errors.

`[runtime.drain]` controls reload and shutdown draining. `graceful_timeout_ms` is the maximum time a stopped listener generation waits for active HTTP/1.1, HTTP/2, and HTTP/3 request work (including an HTTP/3 graceful-shutdown control write) before force-closing remaining connection tasks. Successful reloads also drain existing HTTP connections that captured the previous data-plane snapshot, even when listener binds do not change, so new requests use the replacement snapshot on new connections. `long_connection_close_delay_ms` protects upgraded WebSocket/generic Upgrade, CONNECT, WebTransport, and TCP stream bridges after a drain signal before they are closed; drained WebTransport bridges keep existing sessions for that grace window but reject new request streams immediately. `shutdown_delay_ms` marks the instance draining and waits before listener drain begins; `0` is allowed. `graceful_timeout_ms` and `long_connection_close_delay_ms` must be greater than zero.

On Unix, `SIGUSR1` starts the same irreversible drain-only state without
requesting process exit. The first signal records lifecycle reason `shutdown`,
makes readiness return `503 draining`, immediately quiesces public admission,
asks HTTP/2 to send GOAWAY, and starts HTTP/3 graceful connection drain while
existing work uses the configured ordinary and long-connection windows. TCP
acceptors stop; QUIC accept loops retain only enough work to discard newly
queued handshakes while established connections drain. UDP stream, TURN, and
SNI-QUIC paths retain known flows/CIDs while refusing new ones. Control and
health tasks stay available.
Repeated `SIGUSR1` is idempotent and does not reset a drain deadline.
`SIGTERM` or Ctrl-C then performs final shutdown without clearing that drain
state. This process-local signal is intended for a trusted local supervisor
such as the chart-owned Kubernetes pre-stop hook; it is not a network control
API and does not bypass Admin/IPM authorization.

`poll_interval_ms` must be greater than zero. CLI flags `--hot-reload-mode` and `--hot-reload-poll-interval-ms` override TOML values and emit warnings when they differ.

`[runtime.netport_switcher]` is an opt-in Linux root wrapper for privileged data-plane ports. When enabled, the wrapper creates a Unix control socket under `socket_dir`, starts the main OxiBelt process as `main_uid:main_gid`, and brokers only startup-allowed privileged binds for HTTPS TCP, HTTP/3 UDP, plain HTTP, stream TCP/UDP, and WebRTC TURN UDP/TCP/TLS. The wrapper needs `CAP_NET_BIND_SERVICE` to bind low ports and `CAP_SETUID`/`CAP_SETGID` to launch the child as `main_uid:main_gid`. The broker validates protocol, bind address, purpose, worker count, `SO_REUSEPORT`, TCP backlog, and UDP buffer options before passing a socket FD over `SCM_RIGHTS`. Admin, metrics, and health listeners are control/ops surfaces and are never brokered. `pidfd_supervision = true` uses Linux pidfds for child signal forwarding when available and falls back to PID signaling if pidfd setup fails; it forwards the drain-only `SIGUSR1` signal as well as normal shutdown/reload signals. `--check` and `--dump-effective-config` remain offline validation commands and do not require the wrapper socket.

`[runtime.hardening]` contains Linux hardening hooks. `close_range = "auto"` marks file descriptors `3..` close-on-exec with `close_range(CLOSE_RANGE_CLOEXEC)` when the kernel supports it; `required` fails startup on error. `seccomp.expectation` verifies an externally installed filter: `required` requires the startup process to report Linux filter mode `2` and `NoNewPrivs: 1` before OxiBelt mutates either state, `optional` records a bounded degradation when that contract is absent, and `off` makes no enforcement claim. Optional `profile_identity` and `profile_digest` values are expectations for the reserved orchestrator environment assertion; OxiBelt compares them but always labels them `kernel_verified = false`. Legacy `seccomp.mode` maps `off` to `off`, `log` to `optional`, and `enforce` to `required` with a migration diagnostic; mixing old and new fields is invalid. The alias remains accepted for native schema epoch `1` and is reserved for removal only in a future incompatible schema epoch.

`landlock.mode = "enforce"` preserves the operator-owned manual allowlist in `read_paths` and `read_write_paths`. `landlock.mode = "manifest"` derives the minimum filesystem rules from the fully resolved configuration and unions those explicit lists as exceptional additions. OxiBelt installs the rules before telemetry exporters, async runtimes, workers, and listeners, reports requested and effective ABI rights plus policy/manifest digests, and rejects a required operation that the active ABI cannot represent. The existing embedded API rejects Landlock activation when it cannot prove single-thread process ownership instead of claiming whole-process confinement.

Generate and inspect the same access contract locally with:

```sh
oxibeltctl config filesystem-access ./source/config/oxibelt.toml --format text
oxibeltctl config filesystem-access ./source/config/oxibelt.toml --format json --check
oxibeltctl config filesystem-access ./source/config/oxibelt.toml --show-paths
```

Text and JSON schema version `3` redact paths to deterministic report-local identifiers by default and withhold the stable manifest digest, because an unkeyed digest would permit dictionary tests of common paths. `--show-paths` is an explicit local disclosure mode that also reveals the comparison digest. Digest identity uses configured logical paths for a verified Kubernetes AtomicWriter projection, so rotating a ConfigMap or Secret does not replace the expected digest merely because Kubernetes selected a new timestamped backing directory. OxiBelt retains the canonical resolved target for access checks and Landlock installation. Incomplete, ambiguous, escaping, or lookalike symlink layouts are not normalized as AtomicWriter projections and therefore fail an unchanged expected-digest comparison closed. `--check` adds non-mutating existence, type, access, parent, mount, and read-only-rootfs evidence; observations do not affect that digest. Its bounded findings include `total_findings` and `findings_truncated`, so automation can detect omitted explanations. Certificate/key rotation records replacement-parent read scope but not parent write, while cache, audit, spool, state, and generated artifacts receive parent write only where OxiBelt itself performs create, rename, truncate, or removal.

Example Docker activation for container port `443`:

```sh
docker run --rm \
  --user 0:0 \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --cap-add=SETUID \
  --cap-add=SETGID \
  --security-opt no-new-privileges \
  -p 443:443/tcp \
  -p 443:443/udp \
  --entrypoint /usr/local/bin/oxibelt-netport-switcher \
  oxibelt --config /etc/oxibelt/config/oxibelt.toml
```

Reload modes:

- `off`: no reload.
- `oxirule`: reload only WAF-owned configuration and external rule files.
- `downstream_tls`: reload the current downstream certificate, key, static OCSP response, or live OCSP runtime.
- `full`: reload OxiRule policy, TOML configuration, upstream clients, access-log sinks, downstream TLS material, downstream listener bind/protocol settings, and admin listener enable/bind settings.

Reload failures keep the previous active state.

Successful full reloads start replacement listeners before draining old listener generations. Successful OxiRule, downstream TLS, full, and runtime pool snapshot replacements drain previous HTTP connection generations as well. Local readiness stays OK for a successful reload because the active replacement snapshot is serving; existing requests on the old generation finish within `graceful_timeout_ms`, and long-lived upgraded or stream connections keep their drain grace from `long_connection_close_delay_ms`. Full reload and admin config load rebuild telemetry tracing from the replacement configuration, though old-generation connections may keep the previous telemetry runtime until their captured snapshot drains. During that grace period, new WebTransport CONNECT or ordinary HTTP/3 request streams on a drained WebTransport connection are rejected with `503` instead of using the previous snapshot.

## Crypto Providers

```toml
[crypto]
tls_provider = "aws_lc_rs" # aws_lc_rs | ring
primitive_provider = "rustcrypto" # rustcrypto | aws_lc_rs
primitive_backend = "auto" # auto | hardware | software | soft | exact backend

[crypto.primitives]
aes_gcm = "rustcrypto"
chacha20poly1305 = "rustcrypto"
hkdf = "rustcrypto"
hmac_sha256 = "rustcrypto"
sha2 = "rustcrypto"

[crypto.primitive_backends]
aes_gcm = "auto"
chacha20poly1305 = "auto"
hkdf = "auto"
hmac_sha256 = "auto"
sha2 = "auto"
```

`tls_provider` selects the rustls crypto provider used by downstream TLS, upstream TLS, HTTP/3, Admin QUIC, TURN TLS, ticket encryption, certificate verification, and QUIC client/server configuration. The default is `aws_lc_rs`. `ring` requires an OxiBelt build with the `crypto-ring` Cargo feature. The `ring` provider does not support the default post-quantum hybrid `x25519mlkem768` TLS 1.3 key exchange group, so configurations that set `tls_provider = "ring"` must omit that group from global and route-specific TLS 1.3 negotiation policies. Upstream ECH requires `aws_lc_rs`.

`primitive_provider` selects the default provider for OxiBelt's direct primitive helpers outside rustls. `rustcrypto` is the default. `aws_lc_rs` is available for SHA-256, HKDF-SHA256, HMAC-SHA256, AES-256-GCM, and ChaCha20-Poly1305 call sites. `[crypto.primitives]` can override `aes_gcm`, `chacha20poly1305`, `hkdf`, `hmac_sha256`, and `sha2` individually; omitted overrides inherit `primitive_provider`.

`primitive_backend` selects the default RustCrypto backend contract for direct primitive helpers. `[crypto.primitive_backends]` can override the same primitive keys individually; omitted overrides inherit `primitive_backend`. Backend forcing applies only when the effective primitive provider is `rustcrypto`. With `aws_lc_rs`, use `auto` because AWS-LC backend dispatch is provider-owned.

`auto` preserves the binary's normal provider behavior. Forced values are fail-closed: OxiBelt accepts them only when the running binary was built with matching dependency cfgs and, for hardware variants, when startup CPU detection confirms the required feature. `software` maps to the exact `soft` backend for that primitive. `hardware` maps to the hardware backend compiled into the binary for that primitive. Exact backend values are primitive-specific:

- `sha2`, `hkdf`, and `hmac_sha256`: `soft`, `x86-sha`, `aarch64-sha2`, or `riscv-zknh`. These direct helpers use SHA-256; SHA-512-only cfgs such as `x86-avx2` are not accepted for OxiBelt's direct SHA-256 paths.
- `aes_gcm`: `soft`, `aes-avx256`, or `aes-avx512`.
- `chacha20poly1305`: `soft`, `chacha20-sse2`, `chacha20-avx2`, or `chacha20-avx512`.

Use `tests/scripts/build-crypto-backend-variant.sh` to run Cargo with the matching `RUSTFLAGS` cfgs for default, all-software, and x86 hardware variants. Build scripts advertise the accepted cfg names for linting, but the build command must set cfgs before Cargo compiles dependencies.

## Listeners and TLS

```toml
[listeners]
https_binds = ["0.0.0.0:8443", "[::]:8443"]
http_binds = ["0.0.0.0:8080", "[::]:8080"]
http_mode = "redirect_to_https" # off | redirect_to_https | proxy
http1 = true
http2 = true
http3 = false

[listeners.proxy_protocol]
enabled = false
version = "any" # v1 | v2 | any
trusted_sources = []
```

At least one downstream HTTP version must be enabled. HTTP/1.1 and HTTP/2 listen on TCP for every `https_binds` address. HTTP/3 listens on UDP for every `https_binds` address. `http_binds` controls the optional plain HTTP listener when `http_mode` is not `off`. Legacy scalar `https_bind` and `http_bind` remain accepted as one-address compatibility aliases, but they must not be mixed with `https_binds` or `http_binds` respectively. IPv6 listener sockets are IPv6-only; configure both `0.0.0.0:443` and `[::]:443` when you want explicit IPv4 and IPv6 exposure. Adding wildcard binds such as `0.0.0.0` or `[::]` exposes all interfaces for that IP family. PROXY protocol is accepted only from configured trusted sources. When HTTP/3 Alt-Svc is enabled without `quic.alt_svc.port_overrides`, all HTTPS bind entries must use the same port because OxiBelt advertises one inferred Alt-Svc port.

```toml
[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"
server_names = []
require_sni = false
reject_unknown_sni = false
min_version = "tls1.3"
max_version = "tls1.3"
ssl_early_data = "off" # off | safe_methods | on
session_tickets = true
session_ticket_rotation_seconds = 86400

[tls.1_3]
key_exchange_groups = ["x25519mlkem768", "x25519", "secp256r1", "secp384r1"]
ciphers = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"]

[tls.1_2]
groups = [
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
]

[tls.resumption]
mode = "stateful" # off | stateful | stateless
multi_certificate = "off" # off | partition_by_sni
session_cache_size = 4096
tls13_ticket_count = 2
rotation_seconds = 86400

[[tls.certificates]]
server_names = ["iam.example.me"]
cert_chain = "iam-fullchain.pem"
private_key = "iam-privkey.pem"

[[tls.certificates]]
server_names = ["admin.example.me"]
cert_chain = "admin-fullchain.pem"
private_key = "admin-privkey.pem"

[tls.certificates.ocsp]
mode = "disabled"

[tls.remote_signer]
enabled = false
# socket_path = "/run/oxibelt-keysigner/sign.sock"
# key_id = "edge-default"
token_env = "OXIBELT_KEYSIGNER_TOKEN"
token_file = "keysigner-token.b64"
token_reload_interval_ms = 1000
connect_timeout_ms = 250
sign_timeout_ms = 1000
pool_max_idle_connections = 64
allow_tls12_unstructured_signing = false

[tls.client_auth]
mode = "off" # off | optional | require
ca_certs = []
# Maximum presented client certificate chain length: leaf + intermediates,
# excluding the configured trust anchor.
verify_depth = 4

[tls.ocsp]
mode = "disabled" # disabled | static_file | live_fetch
# response_file = "ocsp.der"
# responder_url = "https://ocsp.example.test/status"
# request_timeout_ms = 3000
# max_response_bytes = 16384
# refresh_jitter_pct = 10
# clock_skew_seconds = 300

[tls.crlite]
mode = "disabled" # disabled | enforce | managed
# filter_file = "crlite.filter"
# filter_sha256 = ""
# max_filter_bytes = 33554432
# max_filter_age_seconds = 86400
# failure_policy = "fail_closed" # fail_closed | degraded_allow
# coverage_policy = "allow_unknown" # allow_unknown | require_good

[tls.crlite.managed]
# storage = "disk" # memory | tmpfs | disk
# cache_dir = "/var/lib/oxibelt/crlite"
# tmpfs_dir = "/dev/shm/oxibelt-crlite"
# max_cache_bytes = 67108864
# refresh_interval_seconds = 21600
# request_timeout_ms = 3000

[tls.ct]
mode = "disabled" # disabled | audit | enforce
policy = "chrome" # chrome | firefox
failure_policy = "reject_handshake"

[tls.ct.log_list]
mode = "managed" # managed | static_file
cache_dir = "/var/lib/oxibelt/ct-log-list"
max_download_bytes = 4194304
request_timeout_ms = 5000
refresh_interval_seconds = 86400
# file = "ct/log_list.json"
# signature_file = "ct/log_list.sig"

[proxy.upstream_revocation.ocsp]
mode = "disabled" # disabled | live_fetch
# failure_policy = "fail_closed" # fail_closed | degraded_allow
# request_timeout_ms = 3000
# max_response_bytes = 16384
# refresh_jitter_pct = 10
# clock_skew_seconds = 300

[proxy.upstream_revocation.crlite]
mode = "disabled" # disabled | enforce | managed
# filter_file = "upstream-crlite.filter"
# filter_sha256 = ""
# max_filter_bytes = 33554432
# max_filter_age_seconds = 86400
# failure_policy = "fail_closed" # fail_closed | degraded_allow
# coverage_policy = "allow_unknown" # allow_unknown | require_good

[proxy.upstream_revocation.crlite.managed]
# storage = "disk" # memory | tmpfs | disk
# cache_dir = "/var/lib/oxibelt/upstream-crlite"
# tmpfs_dir = "/dev/shm/oxibelt-upstream-crlite"
# max_cache_bytes = 67108864
# refresh_interval_seconds = 21600
# request_timeout_ms = 3000
```

`cert_chain` is always required and is the default downstream certificate. `private_key` is required unless `tls.remote_signer.enabled = true`; when remote signing is enabled, `private_key` must not be set. `server_names` can name SNI values owned by the default certificate. Additional `[[tls.certificates]]` entries select certificate material by SNI before HTTP routing; exact names match before leftmost wildcards. Missing or unknown SNI uses the default certificate unless `require_sni = true` or `reject_unknown_sni = true`. In local-key mode each extra certificate requires `private_key`; in remote-signer mode each extra certificate requires `remote_signer_key_id` and uses the global signer socket/token settings. Multi-certificate downstream TLS keeps resumption, QUIC 0-RTT, and TCP early data rejected by default; set `tls.resumption.multi_certificate = "partition_by_sni"` with `tls.require_sni = true` and `tls.reject_unknown_sni = true` to allow resumption/early-data transports with per-certificate SNI partitions.

`tls.ssl_early_data` controls accepted downstream TLS early data. The default is `off`. `safe_methods` permits only transport-verified `GET` and `HEAD` requests, while `on` permits all methods and should be used only for routes that tolerate replay. TCP TLS early data requires TLS 1.3 and `tls.resumption.mode = "stateful"`; with `[[tls.certificates]]`, it also requires `tls.resumption.multi_certificate = "partition_by_sni"` plus strict SNI. HTTP/3 0-RTT transport admission remains controlled by `quic.zero_rtt`; `zero_rtt = "safe_methods"` is the recommended mode. When QUIC admits early data, the effective `ssl_early_data` mode controls route and method policy after route matching. Client-supplied `Early-Data` headers are stripped; OxiBelt adds `Early-Data: 1` upstream only for transport-verified early-data requests.

`tls.1_3.key_exchange_groups` controls the downstream TCP TLS, HTTP/3, and TURN TLS named groups exposed through the aws-lc-rs provider. The TLS 1.3 default keeps rustls' post-quantum hybrid first: `["x25519mlkem768", "x25519", "secp256r1", "secp384r1"]`. The legacy flat `tls.key_exchange_groups` key remains accepted as a compatibility alias for `tls.1_3.key_exchange_groups` only; it no longer changes TLS 1.2 behavior.

`tls.1_3.ciphers` controls TLS 1.3 cipher suites. Supported values are `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, and `TLS_CHACHA20_POLY1305_SHA256`. `tls.1_2.groups` controls TLS 1.2 cipher suites; the key name is intentionally `groups` for compatibility with TLS 1.2 cipher-suite group selection and replaces the old `tls.1_2.key_exchange_groups` key, which is rejected. Supported TLS 1.2 values are `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, and `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`. Cipher names may have surrounding whitespace but otherwise must use exact uppercase IANA spelling; empty, duplicate, unknown, or wrong-version suites fail config validation.

For handshake-heavy deployments that prefer lower cold-handshake CPU cost over post-quantum hybrid negotiation, omit `x25519mlkem768` from `tls.1_3.key_exchange_groups`, for example `["x25519", "secp256r1", "secp384r1"]`. In TLS 1.3 server mode, rustls chooses from the client supported-group order, so moving `x25519mlkem768` later does not force classical ECDHE when clients offer the hybrid group first. Per-route overrides can be set under `routes.tls.min_version`, `routes.tls.max_version`, `routes.tls.1_3.key_exchange_groups`, `routes.tls.1_3.ciphers`, and `routes.tls.1_2.groups`, but only on exact-host, path-root routes with no additional match conditions. Omitted route TLS version fields inherit from `[tls]`. They are selected by TLS SNI before HTTP routing, so wildcard hosts or path/header/method-specific routes cannot carry TLS negotiation overrides. After HTTP routing, OxiBelt rejects requests whose resolved route policy differs from the SNI-selected TLS policy with `421 Misdirected Request`; same-policy hosts can still share a TLS connection. When HTTP/3 is enabled, an SNI whose effective route TLS policy excludes TLS 1.3 is rejected for QUIC while TCP TLS can still use the configured TLS 1.2 policy.

The remote signer uses a Unix domain socket and a base64 32-byte token. Prefer `token_file = "keysigner-token.b64"` for short rotation; it is resolved under the certificate directory, must contain exactly 32 random bytes in base64, is tracked as a downstream TLS reload input, and takes precedence over `token_env`. `token_env` remains supported for existing deployments. `token_reload_interval_ms` controls how often OxiBelt refreshes the file-backed token cache before requests; an `unauthorized` signer response forces one immediate token reload and retry. `socket_path` must be absolute, and `key_id` selects the signer-held default key. `pool_max_idle_connections` caps reusable idle signer sockets per remote signing key and defaults to `64`; set it to `0` to open a fresh Unix socket for each signing request. Idle pooled sockets older than `sign_timeout_ms` are discarded before reuse. By default, remote signing is limited to TLS 1.3 server CertificateVerify inputs. Set `allow_tls12_unstructured_signing = true` only when a global or route-level downstream TLS policy allows TLS 1.2 and the signer sidecar is started with the same opt-in.

Run the sidecar as a separate UID that can read private key files. OxiBelt should be able to read certificate chains and connect to the socket, but should not be able to read private keys. The sidecar command is:

```sh
oxibelt-keysigner \
  --socket /run/oxibelt-keysigner/sign.sock \
  --key edge-default=/etc/oxibelt/cert/privkey.pem \
  --token-file /etc/oxibelt/cert/keysigner-token.b64 \
  --token-reload-interval-ms 1000 \
  --socket-mode 0660 \
  --max-connections 256 \
  --io-timeout-ms 5000 \
  --allow-peer-uid 10001
```

The signer enforces its own IPC availability controls before token validation: `--max-connections` caps concurrently handled Unix-socket clients, and `--io-timeout-ms` bounds request-frame reads and response writes so idle or trickled local peers cannot hold signer tasks indefinitely. `--socket-mode` accepts only `0600` or `0660`; `0660` is the default for sidecar socket sharing. Keep the socket directory and mode restrictive, and prefer `--allow-peer-uid` or `--allow-peer-gid` in sidecar deployments. If both peer allowlists are omitted, the signer logs a startup warning and allows any local peer that can connect to the socket for compatibility.

For token rotation, write a new 32-byte base64 token to a temporary file in the same directory and atomically replace the live file, for example `openssl rand -base64 32 > /etc/oxibelt/cert/keysigner-token.b64.tmp && mv /etc/oxibelt/cert/keysigner-token.b64.tmp /etc/oxibelt/cert/keysigner-token.b64`. Rotation-capable container deployments should mount the containing certificate/token directory or a projected secret volume so the replacement path is visible inside both OxiBelt and signer containers; a single-file bind mount can keep the container pinned to the old inode. The signer and OxiBelt both preserve the last good token if a later file read or parse fails. A newly started signer requires a valid token file at startup.

Remote signing is compatible with read-only root filesystems, but the socket directory itself must be writable. The signer creates the Unix socket file at `socket_path`, so a container started with `--read-only` should provide a tmpfs or shared volume for the parent directory, for example `--tmpfs /run/oxibelt-keysigner:rw,noexec,nosuid,nodev,mode=0770`. In a sidecar deployment, mount that same socket directory into both containers, run OxiBelt and the signer as different numeric identities such as `10001:10001` and `10002:10002`, and give OxiBelt only the supplemental signer socket group needed to connect. Mount private keys and `keysigner-token.b64` read-only into the signer container; OxiBelt should receive certificate chains, the signer socket, and its own readable copy of `keysigner-token.b64`, not private key files. For rotating tokens, prefer a read-only directory or projected secret mount over a single-file bind mount. If the signer cannot create the socket, OxiBelt cannot describe the remote key: startup fails for initial config load, and hot reload rejects the new TLS config while preserving the active one.

`tls.resumption.mode = "stateful"` uses a bounded in-memory server session cache and preserves QUIC 0-RTT compatibility. `stateless` uses the rustls/aws-lc-rs ticket producer with provider-managed key rotation; it cannot be combined with `quic.zero_rtt = "safe_methods"`. `off` disables server-side resumption. `tls.resumption.multi_certificate = "off"` is the safe default for `[[tls.certificates]]`; `partition_by_sni` builds separate downstream TCP TLS and QUIC server configs per selected certificate identity so session tickets and stateful cache entries are not shared across unrelated certificates. `session_tickets` and `session_ticket_rotation_seconds` are legacy aliases for the nested resumption table and must not conflict with it. `tls.client_auth.ca_certs` is required when client authentication mode is not `off`, and `tls.client_auth.verify_depth` must be greater than `0` when enabled. `verify_depth` limits the presented client certificate chain length, counting the leaf certificate and any intermediates while excluding the configured trust anchor. `tls.ocsp.mode = "static_file"` requires `response_file`; `tls.ocsp.mode = "live_fetch"` rejects `response_file` and uses `responder_url` or the first HTTP/HTTPS OCSP AIA URL from the leaf certificate. HTTP/3 requires `tls.min_version = "tls1.3"`.

With `tls.ocsp.mode = "live_fetch"`, OxiBelt builds and verifies an OCSP request for the configured downstream leaf certificate and issuer certificate. The certificate chain must include the issuing certificate. Successful responses are stapled only when they contain exactly one matching `CertID`, a `good` status, a valid issuer or delegated OCSP responder signature, and valid `thisUpdate`/`nextUpdate` freshness. `failure_policy` is fixed to `drop_stale`: OxiBelt never staples an expired OCSP response. If startup or refresh cannot reach the responder, receives an invalid response, or drops an expired staple, serving continues without a staple and `GET /admin/v1/tls/downstream`, runtime snapshots, support bundles, and metrics report degraded OCSP status.

Live OCSP fetches run at snapshot startup/reload and in a bounded background refresh worker. TLS handshakes, including TCP TLS and HTTP/3, never perform network OCSP I/O; both transports share the refreshed staple through snapshot runtime state. `request_timeout_ms` and `max_response_bytes` bound each fetch, redirects are not followed, and responder URLs may only use `http` or `https` without credentials or fragments. When `responder_url` is omitted, the responder source is certificate-provided AIA, so operators should treat certificate issuance policy as part of the egress trust boundary. Public Prometheus OCSP metrics use fixed series names only and do not expose responder URLs, SNI, issuer names, or certificate fingerprints.

`tls.crlite.mode = "enforce"` enables experimental local CRLite enforcement for the configured downstream TLS leaf certificate using an operator-supplied filter. `tls.crlite.mode = "managed"` enables experimental Mozilla CRLite Remote Settings download, integrity checking, and local cache management for the same downstream certificate check. Downstream CRLite is separate from `tls.ocsp`: OCSP controls stapling for clients, while CRLite controls whether OxiBelt accepts its own configured serving certificate during startup, downstream TLS reload, and managed refresh. Managed Remote Settings downloads use public WebPKI roots only and do not inherit `proxy.trusted_ca_certs`. `enforce` requires `filter_file`, resolves it under the cert directory, and can pin `filter_sha256`. `managed` rejects `filter_file` and `filter_sha256` so manual and managed sources cannot be mixed. `max_filter_bytes` bounds filter reads/downloads, and `max_filter_age_seconds` treats older local or cached filters as stale.

With `failure_policy = "fail_closed"`, missing, oversized, stale, hash-mismatched, unparseable, or unavailable CRLite filters reject startup or reload. With `failure_policy = "degraded_allow"`, those filter health failures are reported through Admin TLS status, support bundles, and public aggregate metrics while the existing TLS snapshot can continue. A `revoked` CRLite result always rejects the configured downstream certificate, even under `degraded_allow`. `coverage_policy = "allow_unknown"` permits CRLite `not_covered` and `not_enrolled` results; `require_good` rejects anything other than `good`.

Managed CRLite storage defaults to `disk` at `/var/lib/oxibelt/crlite`, which should be a writable persistent volume in production. Use `tmpfs` with `tmpfs_dir = "/dev/shm/oxibelt-crlite"` for read-only root filesystems that still provide writable tmpfs. Use `memory` only for ephemeral deployments that accept refetching on every restart and possible fail-closed startup if the managed filter cannot be fetched. The cache contains public revocation data, but it is integrity-sensitive; keep the directory owned by the OxiBelt runtime user and avoid sharing write access with unrelated processes.

`tls.ct` is a downstream certificate-health gate that verifies RFC 6962 v1 SCTs embedded in each configured leaf certificate. It is separate from the top-level `certificate_transparency` log-operator service and from CRLite metadata parsing. `audit` verifies and reports without rejecting a certificate. `enforce` rejects initial activation or reload when a certificate is non-compliant, and its resolver stops selecting a certificate for new TCP TLS or QUIC handshakes if a later Log-list refresh makes it non-compliant. Existing connections are not terminated. The default is `disabled`, so existing configurations and handshakes do not require a Log list.

The versioned `chrome` and `firefox` profiles implement the embedded-SCT thresholds used by the current Chrome policy and Mozilla's CT policy enforcer: two distinct Logs for certificates with a lifetime of at most 180 days, otherwise three; at least two distinct Log operators; and at least one SCT from a currently acceptable Log. Retired-Log and previous-operator timestamps are evaluated at SCT issuance time. These are operator-selected health policies over the authenticated Chromium v3 Log list, not a claim that OxiBelt performs a browser's full public-WebPKI validation or update behavior.

Managed Log-list mode downloads the fixed Chromium v3 JSON list and detached signature with a WebPKI-only client, verifies the build-pinned official list-signing key, bounds both responses, rejects an update older than the available cached or in-memory LKG, and atomically stores a signed bundle under an inter-process lock in `cache_dir`. A complete cache-volume restore also restores that local rollback baseline, so protect snapshot and restore authority separately. No CT network I/O, DER parsing, or SCT signature verification occurs during a handshake; the enforce path compares the resolver's selected chain with the evaluated chain and checks the absolute stale deadline. Use a private, persistent, writable directory in production. When the authenticated Log-list timestamp reaches 70 days of age, audit mode reports degradation and enforce mode rejects new handshakes; OxiBelt deliberately fails closed rather than copying Chrome's browser-side enforcement-disable fallback.

`static_file` mode requires both `file` and `signature_file`; the paths are resolved under the certificate directory and participate in downstream TLS reload. The JSON must be an official Chromium v3 Log list and the signature must verify with the same pinned signing key. Per-certificate `[tls.certificates.ct] mode = "disabled" | "audit" | "enforce"` can override only the mode. OxiBelt does not fetch or staple TLS-delivered SCTs, does not submit certificate chains to public Logs, and does not modify or re-sign certificates.

`proxy.upstream_revocation` enables opt-in revocation checks for runtime outbound TLS clients. It applies to HTTPS upstream clients, upstream-pool generated HTTPS clients, HTTP/3 and WebTransport upstream QUIC clients, external auth and discovery HTTP clients, `turns://` TURN upstreams, and diagnostics probes. The default is disabled for compatibility. When enabled globally, each direct `[[upstreams]]` entry can override the policy under `[upstreams.tls.upstream_revocation]`; upstream-pool forwarding, upstream-pool discovery, external auth, discovery, TURN, and diagnostics clients use the global policy. Active upstream-pool health checks can override only their health-check HTTPS client policy under `[upstream_pools.health_check.tls.upstream_revocation]`; that override does not affect forwarding clients. Standalone helper clients such as `oxibeltctl` fetches are outside this runtime policy.

`proxy.upstream_revocation.ocsp.mode = "live_fetch"` verifies a stapled upstream OCSP response when the server provides one. Without a staple, OxiBelt builds a request from the upstream certificate AIA, uses a bounded background fetch/cache, and applies `failure_policy` to the current handshake when the cache is missing, stale, or invalid. The TLS handshake verifier never performs network I/O; it only validates the WebPKI chain/hostname, checks the supplied staple or local cache, and schedules a bounded fetch on the runtime. `fail_closed` rejects missing or invalid revocation state; `degraded_allow` permits rollout while reporting the bounded error code. Revoked responses always reject.

`proxy.upstream_revocation.crlite.mode = "enforce"` checks the verified upstream server leaf plus issuer certificate against an operator-supplied local filter. `managed` uses the same Mozilla CRLite Remote Settings machinery as downstream CRLite but stores and reports upstream status separately. Managed Remote Settings downloads use public WebPKI roots only and do not inherit `proxy.trusted_ca_certs`, even when upstream TLS or OCSP responder bootstrap clients use those operator roots. Local `filter_file` paths are resolved under the cert directory and tracked as runtime reload files, not downstream TLS reload files. Managed CRLite and OCSP responder bootstrap downloads use dedicated non-revocation HTTP clients so revocation refreshes cannot recursively depend on themselves.

Authenticated `GET /admin/v1/tls/upstream`, `POST /admin/v1/tls/upstream/refresh`, runtime snapshots, and support bundles expose only bounded upstream revocation status: enabled flag, default modes, cache counts, fetch counts, managed-filter counts, and compact error codes. They do not expose responder URLs, SNI, issuer names, certificate serial numbers, fingerprints, filter paths, cache paths, or Remote Settings URLs. Public Prometheus metrics use fixed aggregate names: `oxibelt_tls_upstream_ocsp_success_total`, `oxibelt_tls_upstream_ocsp_errors_total`, `oxibelt_tls_upstream_crlite_checks_total`, `oxibelt_tls_upstream_crlite_revoked_total`, and `oxibelt_tls_upstream_crlite_errors_total`.

OxiBelt does not perform ACME issuance, HTTP-01 or DNS-01 challenge handling, certificate renewal, or private key rotation itself. OCSP live fetch is revocation-status stapling for already provisioned downstream certificates or outbound revocation checking for already provisioned upstream certificates; CRLite enforcement is a local or managed filter check for already provisioned downstream and upstream certificates. Neither changes private key handling, remote signer isolation, or certificate renewal. Provision and renew TLS files with external automation such as Certbot/Lego or the `certbot/certbot`/`goacme/lego` Docker image, then point `cert_chain` and `private_key` at the generated files under the cert directory. Use `runtime.hot_reload.mode = "downstream_tls"` or `full` when renewed TLS material should be picked up without a process restart.

Keep ACME credentials, DNS-01 provider tokens, renewal state, and private signing keys out of the OxiBelt process/container when possible. This limits blast radius if a proxy vulnerability ever exposes process memory or permits remote code execution: the running proxy may have access to certificate chains and remote signing capability, but it should not also contain private keys or the DNS/ACME credentials needed to mint arbitrary new certificates. A compromised OxiBelt process that still has signer socket and token access may request signatures while that access remains valid, so socket permissions, peer UID/GID allowlists, token rotation, and process isolation remain important.

When `tls.remote_signer.token_file` is selected through the atomic secret-reference
Admin endpoint, OxiBelt pins the resolved token to that immutable runtime snapshot.
That instance changes tokens only through another activation, rollback, full config
load, or restart. Startup configurations that were not atomically activated retain
their configured file-reload behavior.

## QUIC Sections

```toml
[quic]
retry = true
zero_rtt = "off" # off | safe_methods
# host_key_file = "quic-host-key.b64"

[quic.alt_svc]
enabled = true
max_age_seconds = 86400
persist = false

# [[quic.alt_svc.port_overrides]]
# bind = "0.0.0.0:8443"
# advertised_port = 443

[quic.transport]
max_concurrent_bidi_streams = 512
max_concurrent_uni_streams = 512
idle_timeout_ms = 30000
keep_alive_interval_ms = 0
stream_receive_window_bytes = 1250000
receive_window_bytes = 8388608
send_window_bytes = 10000000
send_fairness = true
datagram_receive_buffer_bytes = 1048576
datagram_send_buffer_bytes = 1048576
max_udp_payload_size = 1472
gso = true
initial_mtu = 1200
min_mtu = 1200

[quic.transport.mtu_discovery]
enabled = true
upper_bound = 1452
interval_ms = 600000
black_hole_cooldown_ms = 60000
minimum_change = 20

[quic.downstream.transport]
# inherits from [quic.transport]
keep_alive_interval_ms = 10000

[quic.upstream.transport]
# inherits from [quic.transport]
stream_receive_window_bytes = 2097152

[quic.upstream.transport.mtu_discovery]
upper_bound = 1472

[proxy.upstream_resolution]
max_endpoint_count = 16
min_ttl_ms = 1000
max_ttl_ms = 30000
negative_ttl_ms = 1000
cooldown_base_ms = 1000
cooldown_max_ms = 30000

[proxy.upstream_resolution.happy_eyeballs]
mode = "v3"
resolution_delay_ms = 50
connection_attempt_delay_ms = 250
minimum_connection_attempt_delay_ms = 100
maximum_connection_attempt_delay_ms = 2000
max_connect_attempts = 4
max_concurrent_attempts = 2
preferred_address_family_count = 1
last_resort_local_synthesis_delay_ms = 2000
svcb = "auto"
pref64 = "auto"

[quic.socket]
receive_buffer_bytes = 16777216
send_buffer_bytes = 16777216
workers = "auto"
reuse_port = true

[quic.upstream_pool]
enabled = true
max_connections_per_upstream = 1
max_lifetime_ms = 600000
```

`retry = true` enables QUIC Retry/address validation for unvalidated downstream HTTP/3 connection attempts. `zero_rtt = "safe_methods"` enables QUIC TLS early data and rejects unsafe requests that the QUIC transport reports as early data with `425 Too Early`; only early-data `GET` and `HEAD` are accepted.

`host_key_file` is optional and is resolved under the cert directory. It must contain base64 for exactly 64 random bytes. OxiBelt derives QUIC stateless reset and Retry/validation token keys from this material. The file is included in runtime reload fingerprints and in downstream TLS reload inputs. Do not reuse a key baked into an image; generate deployment-local material, for example `openssl rand -base64 64 > /etc/oxibelt/cert/quic-host-key.b64`, then mount it with the rest of the certificate material.

When downstream HTTP/3 is enabled and `quic.alt_svc.enabled = true`, HTTPS HTTP/1.1 and HTTP/2 responses advertise `Alt-Svc: h3=":<https port>"; ma=<max_age_seconds>`. `persist = true` appends `; persist=1`. `[[quic.alt_svc.port_overrides]]` entries map a configured HTTPS listener `bind` to a client-visible `advertised_port`, for example when Docker publishes `443:8443/udp`; unlisted binds still advertise their bind port. Each override bind must match a `listeners.https_binds` entry and `advertised_port` must be greater than zero. OxiBelt does not add `Alt-Svc` to downstream HTTP/3 responses, plain HTTP responses, or `101 Switching Protocols`.

`[quic.transport]` is the shared QUIC transport baseline for both downstream HTTP/3 clients and upstream HTTP/3 forwarding. `[quic.downstream.transport]` and `[quic.upstream.transport]` are partial endpoint-specific overrides; unset values inherit from `[quic.transport]`, including nested `mtu_discovery` values. Existing configurations that only use `[quic.transport]` keep the same behavior for both endpoints.

`keep_alive_interval_ms = 0` disables QUIC keep-alive packets. Nonzero keep-alive intervals must be lower than `idle_timeout_ms`. `stream_receive_window_bytes`, `receive_window_bytes`, and `send_window_bytes` tune QUIC flow-control and send buffering. Larger windows can improve high-bandwidth or high-RTT HTTP/3 throughput, but they also raise worst-case per-connection memory exposure when many peers consume the full window. `receive_window_bytes` must be no larger than `stream_receive_window_bytes * max(max_concurrent_bidi_streams, max_concurrent_uni_streams)` so one connection cannot advertise more aggregate receive credit than its configured stream concurrency can justify.

`initial_mtu`, `min_mtu`, `max_udp_payload_size`, and `mtu_discovery.upper_bound` must be in the QUIC UDP payload range `1200..=65527`; `min_mtu` must not exceed `initial_mtu`, and enabled MTU discovery requires `upper_bound >= initial_mtu`. Keep `min_mtu = 1200` for public internet deployments unless the network path is fully controlled. MTU discovery is enabled by default and periodically probes up to `upper_bound`; disabling it keeps the configured initial/minimum MTU behavior.

`quic.socket.receive_buffer_bytes = 0` and `send_buffer_bytes = 0` keep the OS defaults. Nonzero socket buffer values are applied to UDP sockets, and startup fails if the OS rejects an explicitly configured buffer size. `quic.socket.workers` accepts a positive integer or `"auto"`; omitted values default to `"auto"` and use `[runtime.worker_multipliers].quic_socket`. When HTTP/3 is enabled, set `reuse_port = true` whenever the resolved worker count can be greater than one, which creates one `SO_REUSEPORT` UDP socket per downstream HTTP/3 worker. QUIC transport and pool numeric values must be greater than zero, except `keep_alive_interval_ms = 0`; socket receive/send buffer `0` is the explicit OS-default sentinel.

`[proxy.upstream_resolution]` is the protocol-neutral upstream resolver policy. Successful A and AAAA answers are bounded by `max_endpoint_count` and the TTL clamps; negative answers use `negative_ttl_ms`; address cooldown uses the bounded base and maximum values. Current HTTP/3 use remains compatible with the legacy `[quic.upstream.resolution]` input.

`happy_eyeballs.mode = "v3"` is the default implementation of the current Happy Eyeballs v3 Internet-Draft scheduling model; global `legacy` and per-upstream `happy_eyeballs_mode = "legacy"` are compatibility escapes. The delay fields are bounded and every candidate launch remains pre-dispatch and deadline-bounded. `svcb` and `pref64` accept only `auto` or `disabled`; they are security/compatibility escape hatches, not a way to supply arbitrary DNS targets, ports, or trust policy. Automatic SVCB discovery is not queried or admitted for literal-IP origins or origins resolved through `/etc/hosts`; those configured endpoints remain authoritative. Per-upstream `svcb_allowed_ports` is an explicit unique nonzero allowlist. `upstream_http_version_mode = "ceiling"` requires that route to explicitly set `upstream_http_version`; `exact` is the default.

During native schema epoch `1`, `[quic.upstream.resolution]` is deprecated compatibility input. Its leaves map to the canonical policy, including `address_family_stagger_ms` to `happy_eyeballs.connection_attempt_delay_ms`. Disjoint canonical and legacy leaves may be combined; the same effective leaf in both locations is rejected even when values agree, so configuration never relies on precedence. Migrate to `[proxy.upstream_resolution]`; the alias is reserved for removal only in a future incompatible epoch.

The upstream HTTP/3 pool multiplexes ordinary request forwarding over reusable QUIC connections when `quic.upstream_pool.enabled = true`. When disabled, ordinary requests use one-shot QUIC connections. One-shot HTTP/3 and WebTransport retain their dedicated connection lifetimes, but use the same bounded resolver component. Resolution, connection coalescing, and slot waits are bounded by the effective request deadline. Candidate failover is allowed only before request dispatch; a post-dispatch failure does not implicitly replay the request.

Reusable connections are keyed by logical security and routing identity: protocol mode, normalized authority and TLS server name, verification/trust policy, client identity, configuration generation, and discovery identity. The selected IP address is connection state, not pool identity. OxiBelt does not coalesce across origins merely because their addresses or certificates overlap. Changing any canonical `[proxy.upstream_resolution]` field, or its deprecated legacy alias, requires a full reload. These additive canonical fields keep native configuration schema epoch `1`; omitted fields use the defaults above. Configurations that still use the legacy alias should migrate as described above.

## SNI Forwarding

`[sni_forward]` enables opt-in L4 forwarding before OxiBelt terminates downstream TLS. It inspects only the visible TLS ClientHello SNI value. ECH-hidden inner names are not available to this matcher.

```toml
[sni_forward]
enabled = true
client_hello_max_bytes = 65536
client_hello_parse_methods = ["single_record"]
idle_timeout_ms = 75000
quic_max_sessions = 8192
quic_local_queue_capacity = 1024
# default_target = "10.0.10.20:443"

[sni_forward.quic_initial_reassembly]
max_pending_sessions = 64
max_fragments_per_session = 64
max_datagrams_per_session = 64
max_buffered_datagram_bytes_per_session = 131072
max_total_buffered_bytes = 4194304
timeout_ms = 10000

[[sni_forward.rules]]
name = "legacy-tls"
server_names = ["legacy.example.com", "*.legacy.example.com"]
target = "10.0.10.10:443"
protocols = ["tcp_tls", "quic"]
connect_timeout_ms = 3000
idle_timeout_ms = 75000
tcp_proxy_protocol_egress = "off"
```

Matching order is explicit `[[sni_forward.rules]]` first, then local `[[routes]].hosts`, then `sni_forward.default_target` when configured. A route host of `"*"` is not treated as a defined SNI name. Missing, malformed, or unparseable SNI fails closed when SNI forwarding is enabled. Exact SNI patterns and leftmost wildcard patterns such as `"*.example.com"` are accepted; duplicate rule names or duplicate SNI patterns across forwarding rules are rejected.

For TCP TLS, OxiBelt peeks at a bounded ClientHello before `rustls` accepts the connection. Forwarded sessions are raw TCP tunnels, and the original ClientHello remains unread by OxiBelt because `peek` does not consume bytes. Local SNI matches continue through the normal HTTP/1.1 and HTTP/2 TLS termination path. Forwarded TCP sessions count against the same global connection limit as local TLS; when `limits.connection_limit_identity` uses a Real-IP mode, they also acquire the normal per-IP and named connection leases for the post-PROXY-protocol peer address because no HTTP request headers are available before forwarding.

`client_hello_parse_methods` controls TCP TLS SNI inspection. The default is `["single_record"]`, which parses only a complete ClientHello contained in one TLS handshake record. Add `tls_record_reassembly` to accept a ClientHello split across consecutive TLS handshake records, for example `["single_record", "tls_record_reassembly"]`, when compatibility with DPI-bypass client fragmentation tools is required.

For QUIC, `protocols = ["quic"]` uses the same UDP address as downstream HTTP/3 and therefore requires `listeners.http3 = true`. OxiBelt decrypts QUIC Initial packets, reassembles visible CRYPTO frames across datagrams, extracts ClientHello SNI, and replays contributing datagrams in arrival order: matched sessions go to UDP passthrough and local sessions are queued into Quinn. Forwarded QUIC sessions acquire the same total, per-IP, and named downstream connection leases as local HTTP/3 connections. QUIC forwarding tracks connection IDs and expires idle sessions using the rule or global idle timeout.

`quic_max_sessions` caps SNI-forwarding QUIC pre-classification state across local and forwarded clients; when the cap is exceeded, the oldest tracked client is evicted and forwarded sessions are ended with a `capacity` outcome. `quic_local_queue_capacity` caps queued local QUIC datagrams waiting for Quinn; excess local datagrams are dropped instead of growing memory without bound. Both values must be greater than zero.

`[sni_forward.quic_initial_reassembly]` bounds only pending QUIC Initial reconstruction and is shared by all `SO_REUSEPORT` workers for a logical bind. Every value must be positive, and `max_buffered_datagram_bytes_per_session` must not exceed `max_total_buffered_bytes`. Its total budget counts retained raw datagrams plus unique decrypted CRYPTO bytes; `client_hello_max_bytes` remains the bound on ClientHello/CRYPTO data. The effective absolute deadline is `min(timeout_ms, limits.tls_handshake_timeout_ms)` and retransmissions do not extend it. Identical overlap/retransmit data is deduplicated, while conflicting overlap, expiry, capacity admission, and every fragment/datagram/byte limit fail closed. Pending state is separate from established local or forwarded sessions, so incomplete unauthenticated Initials cannot evict an established session.

Prometheus metrics include aggregate SNI-forward decision, parse-failure, session, active-QUIC-session, TCP-byte, UDP-byte, and `oxibelt_sni_forward_quic_initial_reassembly_total{outcome}` counters. The latter has only the fixed outcomes `pending`, `completed`, `expired`, `capacity_rejected`, `limit_rejected`, `overlap_conflict`, `local_replay_queue_full`, and `forward_replay_send_failed`; it never labels peer, connection ID, SNI, or error text. With `metrics.detail = "detailed"`, bounded labels add protocol, decision, rule, target, and outcome.

QUIC Initial inspection diagnostics are sampled per logical listener. DEBUG records a sampled `peer`, `classification_mode`, `stage`, static `reason`, `datagram_bytes`, and `suppressed_since_last`; TRACE adds bounded version/header/decryption/CRYPTO/reassembly lengths and counts. Neither level records raw packets, decrypted content, connection IDs or their hashes, partially parsed SNI, TLS transcript fields, or dependency error strings. These diagnostics follow `[logging].level` and `RUST_LOG`; environment filtering takes precedence when configured, and changing either level requires a process restart.

## Proxy Sections

```toml
[proxy]
trusted_ca_certs = []

[proxy.forwarded_headers]
mode = "overwrite" # overwrite | append
client_ip_source = "resolved" # resolved | direct_peer

[proxy.real_ip]
enabled = false
trusted_proxies = []
header = "x-forwarded-for" # x-forwarded-for | x-real-ip | forwarded | cf-connecting-ip
recursive = true
fail_on_untrusted_forwarded_headers = false

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2" # h1 | h2 | h3

[proxy.upgrades]
websocket = true
generic_http_upgrade = false
connect_tunneling = false

[proxy.grpc_web]
enabled = false

[proxy.retry]
enabled = false
tries = 2
timeout_ms = 5000
total_budget_ms = 5000
per_attempt_timeout_ms = 1000
on = ["connect_error", "read_timeout", "502", "503", "504"]
retry_non_idempotent = false
backoff_base_ms = 0
backoff_max_ms = 0
jitter = false
reselect_pool_on_retry = true
exclude_failed_pool_upstreams = true
report_passive_health = true

[proxy.buffering]
request = "streaming"  # streaming | memory | spool | reject_if_too_large
response = "streaming" # streaming | memory | spool | reject_if_too_large
max_memory_body_bytes = 1048576
max_temp_file_bytes = 0
# temp_dir = "/var/cache/oxibelt"

[proxy.static_files]
sendfile = "auto" # off | auto
sendfile_write_strategy = "auto" # auto | split | msg_more | tcp_cork
sendfile_chunk_bytes = 1048576
inline_max_bytes = 16384
open_file_cache_max_entries = 0
open_file_cache_ttl_ms = 0
hot_object_cache_max_bytes = 0
hot_object_cache_max_file_bytes = 65536

[proxy.http]
early_hints = "drop" # drop | pass
trailers = "pass"    # pass | drop
expect_continue = "auto" # auto | reject
priority = "pass"    # pass | ignore
sse_auto_streaming = true
direct_h1_small_request_body_max_bytes = 16384

[proxy.http2]
adaptive_window = true
# initial_stream_window_bytes = 1048576
# initial_connection_window_bytes = 16777216
# max_frame_size_bytes = 65535
max_concurrent_streams = 1024
max_send_buf_size = 1048576
keep_alive_interval_ms = 0
keep_alive_timeout_ms = 20000
keep_alive_while_idle = false

[proxy.http3]
inline_bodyless_fast_path = false

[proxy.http.grpc]
enabled = true
respect_grpc_timeout = true
retry = "off"        # off | safe_unary

[proxy.http.errors]
mode = "legacy_plain" # legacy_plain | plain | json
```

`trusted_ca_certs` adds upstream TLS trust roots from the cert directory. `forwarded_headers.mode = "overwrite"` replaces inbound forwarding metadata; `append` preserves and extends the inbound `X-Forwarded-For` chain. `forwarded_headers.client_ip_source = "resolved"` emits the same trusted client IP used by WAF, rate limiting, external auth, and Real-IP-aware connection limits; set it to `"direct_peer"` only for legacy upstreams that expect the immediate peer address. `X-Forwarded-Port` is derived from the downstream request authority, or the scheme default when no port is present. `real_ip` resolves the client IP only when the direct peer is trusted; that identity is used by rate limiting and WAF evaluation, by forwarded headers when `client_ip_source = "resolved"`, and by connection limits when `limits.connection_limit_identity` selects a Real-IP mode.

`generic_http_upgrade` and `connect_tunneling` enable the global capability only. Individual routes must also opt in with `generic_http_upgrade = true` or `connect_tunneling = true`. CONNECT tunnels are not open-proxy tunnels; OxiBelt connects only to the selected route upstream origin. `proxy.grpc_web.enabled` enables the global gRPC-Web transformer, and each route must also set `grpc_web = true`.

`proxy.buffering` controls ordinary HTTP request and response body buffering. `streaming` keeps the previous streaming behavior. `memory` reads the full body into memory up to `max_memory_body_bytes`. `spool` keeps up to `max_memory_body_bytes` in memory and spills the remainder to `temp_dir`, capped by `max_temp_file_bytes` per body. `reject_if_too_large` is memory-only and rejects bodies that exceed `max_memory_body_bytes`. `spool` requires `max_temp_file_bytes > 0` and a writable `temp_dir`; OxiBelt removes `oxibelt-buffer-*` temp files when the buffered body is dropped, when spooled buffering fails before ownership is transferred, and when cleaning stale matching files on initial startup.

`proxy.retry` controls ordinary HTTP retry behavior. `tries` is the maximum number of attempts including the first attempt. `timeout_ms` remains supported as the legacy total retry-loop budget; `total_budget_ms` is preferred and takes precedence when both are set. `per_attempt_timeout_ms` caps the first-byte wait for each upstream attempt. `on` accepts `connect_error`, `read_timeout`, and retryable response statuses such as `502`, `503`, and `504`. Backoff is disabled when `backoff_base_ms` or `backoff_max_ms` is `0`; otherwise OxiBelt sleeps between retryable failures up to the configured maximum, optionally applying jitter. For upstream pools, `reselect_pool_on_retry` picks a fresh backend on each retry, `exclude_failed_pool_upstreams` avoids retrying an upstream that already failed in the same request, and `report_passive_health` records retryable failures in passive health. Set `retry_non_idempotent = true` only when the upstream can tolerate duplicate write-side effects from retried POST, PATCH, or other non-idempotent requests.

`proxy.static_files` controls built-in static file transfer behavior. Convenience behavior such as directory indexes, SPA fallback, precompressed variants, MIME overrides, cache-control headers, and custom error pages is configured per static route under `[routes.static_files]`. `inline_max_bytes` reads static response bodies at or below the configured size into a single response frame; `0` disables this small-file inline path. `sendfile = "auto"` enables a guarded Linux `sendfile(2)` fast path only for plaintext HTTP/1.1 `GET` and `HEAD` requests that can be proven equivalent to the normal static route path. `sendfile_chunk_bytes` controls each kernel sendfile attempt size, and `sendfile_write_strategy` selects ordinary split header/body writes, Linux `MSG_MORE`, or Linux `TCP_CORK` behavior for tuning guarded plaintext static responses. OxiBelt opens each configured static root directory once per active configuration generation and uses that directory file descriptor for Linux `openat2(2)` resolution, reducing per-request root-open cost while keeping path resolution anchored to the validated root. OxiBelt probes the real kernel `sendfile(2)` path once at runtime; when the probe fails or the platform is not Linux, static routes fall back to the general path, including the small-file inline path. Sendfile responses honor the route or global `response_send_timeout_ms` while waiting on downstream write backpressure. Effective route/global security response headers and request-wide system access logs are preserved on the sendfile path. Header-only and size-only WAF rules may run on the sendfile fast path and use the same resolved Real-IP client identity as the general path. HTTPS, HTTP/2, HTTP/3, WAF rules that require request or response body bytes, dynamic policy, rate limits, compression, Real-IP connection-limit modes, request bodies, upgrades, CONNECT, ambiguous `Content-Length`, and `Transfer-Encoding` all use the general Hyper path instead.

Static hot-object caching is opt-in. Set `open_file_cache_max_entries`, `open_file_cache_ttl_ms`, and `hot_object_cache_max_bytes` to enable a bounded TTL cache for verified small static responses. `open_file_cache_max_entries` and `open_file_cache_ttl_ms` bound the entry count and freshness window; `hot_object_cache_max_bytes` and `hot_object_cache_max_file_bytes` bound body memory globally and per file. Cache fill and cached-hit refresh open the current file through the secure static-root resolution path. Cached hits preserve validators and range behavior only when the current validator still matches the cached object. Deleted, inaccessible, or replaced files do not continue serving stale cached bodies; they refresh or fail closed from the current filesystem state. Use `0` values to keep the default no-cache behavior.

`proxy.http` controls HTTP compatibility details. `early_hints = "pass"` relays upstream `103 Early Hints` where the downstream transport supports interim responses, after applying the shared sanitizer that preserves only `Link` fields; `drop` captures no Early Hints. Upstream `100 Continue` and `102 Processing` remain interim and are never exposed as the final response, while `101 Switching Protocols` stays on the established upgrade path rather than entering ordinary response-body handling. `trailers = "drop"` removes body trailer frames for ordinary HTTP traffic while preserving native gRPC trailers; `pass` retains parsed trailer frames for downstream transports that support them. `expect_continue = "auto"` accepts `Expect: 100-continue` and rejects unsupported `Expect` values with `417`; `reject` rejects all `Expect` values. `priority = "ignore"` strips RFC 9218 `Priority` headers instead of forwarding them. `sse_auto_streaming = true` keeps `text/event-stream` responses streaming even when response buffering is enabled. `direct_h1_small_request_body_max_bytes` is the maximum `Content-Length` that the guarded direct-H1 fast path may read into memory before sending as an exact-size upstream request body; route/global request body limits, downstream body read timeouts, WAF body planning, retry replay gates, and trailer handling still apply.

`proxy.http3.inline_bodyless_fast_path = true` lets HTTP/3 requests that are already plain-proxy fast-path eligible skip per-request task spawning after OxiBelt proves the downstream request body is empty. The optimization is limited to HTTP/3 `GET` and `HEAD` requests without request-body framing headers; unsafe methods, DATA, trailers, delayed bodies, cache policies, body-inspecting WAF rules, dynamic policy, external auth, buffering, upgrades, CONNECT, WebTransport, and non-fast-path routes remain on the general spawned path. The default is `false`.

`proxy.http2` applies to downstream HTTP/2 connections and upstream HTTP/2 clients. `adaptive_window = true` lets Hyper tune flow-control windows dynamically and is the default recommended performance path. Manual `initial_stream_window_bytes`, `initial_connection_window_bytes`, and `max_frame_size_bytes` values are accepted only when `adaptive_window = false`; they are intended as an escape hatch for controlled deployments that need fixed HTTP/2 windows. `max_concurrent_streams` is the advertised remote-initiated stream cap for downstream H2 and the initial locally initiated stream cap for upstream H2. `max_send_buf_size` caps the per-stream HTTP/2 send buffer. `keep_alive_interval_ms = 0` disables HTTP/2 ping keep-alives; when set, `keep_alive_timeout_ms` is the ping acknowledgement timeout and `keep_alive_while_idle` also allows upstream clients to ping idle pooled H2 connections.

`proxy.http.grpc` enables native gRPC HTTP semantics. When enabled, OxiBelt preserves gRPC trailers, honors `grpc-timeout` by capping upstream first-byte and read timeouts, maps generated upstream failures to gRPC status trailers, and only retries gRPC requests when `retry = "safe_unary"`. If a client `grpc-timeout` deadline is the reason an upstream first-byte wait expires, OxiBelt returns the gRPC deadline response without counting that event as a passive upstream-pool health failure.

`proxy.http.errors.mode = "json"` changes proxy-generated error bodies to JSON with stable `error`, `status`, `code`, and `request_id` fields. `legacy_plain` preserves the historical body text without setting a content type; `plain` emits the same text with `text/plain`.

## Client Identity

```toml
[client_identity.asn]
mode = "disabled" # disabled | local | managed
database_file = "/etc/oxibelt/asn-prefixes.csv"
database_sha256 = ""
format = "prefix_asn_csv"
max_database_bytes = 67108864
max_entries = 1000000
max_database_age_seconds = 86400
failure_policy = "fail_closed" # fail_closed | degraded_null

[client_identity.asn.managed]
source_url = "https://operator.example/asn-prefixes.csv"
cache_dir = "/var/lib/oxibelt/asn"
tmpfs_dir = "/dev/shm/oxibelt-asn"
storage = "disk" # disk | tmpfs | memory
max_cache_bytes = 134217728
refresh_interval_seconds = 21600
request_timeout_ms = 3000

[client_identity.asn.iana_registry]
enabled = true
source_urls = [
  "https://www.iana.org/assignments/as-numbers/as-numbers-1.csv",
  "https://www.iana.org/assignments/as-numbers/as-numbers-2.csv",
]
```

ASN lookup is opt-in. `mode = "local"` loads an operator-supplied `prefix_asn_csv` file at startup; `mode = "managed"` downloads the same file shape from an HTTPS `source_url`, verifies size and optional SHA-256 pinning, writes disk/tmpfs cache entries atomically when configured, and refreshes in the background. When `database_sha256` is configured, OxiBelt verifies it before parsing local files, managed downloads, and managed disk/tmpfs cache entries. `failure_policy = "fail_closed"` rejects startup or reload when the configured database cannot be loaded. `degraded_null` starts with null ASN lookups and reports degraded runtime status.

`prefix_asn_csv` accepts `prefix,asn` rows, optional `prefix,asn` header, blank lines, and `#` comments. `asn` may be `64500` or `AS64500`. Prefixes are canonicalized and longest-prefix match wins for both IPv4 and IPv6. `Request.Client.Asn` and ASN rate-limit keys use this runtime table; `Request.Client.GeoCountry` remains `null`.

The IANA AS Numbers registry URLs are metadata/provenance inputs only. They describe allocated AS number ranges and are not an IP prefix-to-origin-ASN routing database, so OxiBelt does not provide a built-in default origin-ASN database URL. Operators must supply the prefix-to-ASN database directly or through a managed internal source.

## Limits, Cache, and Ops

```toml
[limits]
max_connections = 65536
max_connections_per_ip = 128
max_webtransport_sessions = 65536
max_webtransport_sessions_per_ip = 128
max_webtransport_sessions_per_connection = 256
connection_limit_identity = "proxy_protocol" # proxy_protocol | first_request_real_ip | per_request_real_ip
max_requests_per_connection = 1000
client_header_timeout_ms = 10000
client_body_timeout_ms = 30000
client_idle_timeout_ms = 75000
websocket_idle_timeout_ms = 75000
webtransport_idle_timeout_ms = 75000
tls_handshake_timeout_ms = 10000
response_send_timeout_ms = 60000
max_headers = 128
max_header_name_bytes = 128
max_header_value_bytes = 8192
max_total_header_bytes = 65536
max_uri_bytes = 8192
max_request_body_bytes = 10485760

[[rate_limits]]
name = "per-ip"
key = "client_ip"
rate = "10r/s"
burst = 50
max_buckets = 16384
mode = "enforcing" # enforcing | monitor
status = 429

[[rate_limits]]
name = "global-edge-budget"
key = "global"
rate = "1000r/s"
burst = 2000
max_buckets = 1
status = 429

[[rate_limits]]
name = "per-route-budget"
key = "route"
routes = ["api"]
rate = "500r/s"
burst = 1000
max_buckets = 128
status = 429

[[rate_limits]]
name = "per-api-token-route"
key = "access_token_route"
routes = ["api"]
access_token_source = "trusted_header"
token_header = "X-Api-Token"
rate = "60r/m"
burst = 60
max_buckets = 16384
status = 429

[[rate_limits]]
name = "per-client-prefix-route"
key = "client_ip_prefix_route"
routes = ["api"]
ipv4_prefix_bits = 24
ipv6_prefix_bits = 56
rate = "120r/m"
burst = 120
status = 429

[[rate_limits]]
name = "per-composite-client"
key = "composite_client_route"
routes = ["api"]
identity_parts = ["client_ip_prefix", "user_agent", "tls_fingerprint", "asn"]
rate = "120r/m"
burst = 120
status = 429

[[connection_limits]]
name = "per-ip-connections"
key = "client_ip"
limit = 64
status = 429
```

Limit values must be greater than zero. `limits.max_request_body_bytes` is the default request body cap and can be overridden per route with `routes.limits.max_request_body_bytes`. Top-level rate limit keys are `global`, `route`, `client_ip`, `client_ip_route`, `client_ip_path`, `access_token`, `access_token_route`, `access_token_path`, `client_ip_prefix`, `client_ip_prefix_route`, `client_ip_prefix_path`, `tls_fingerprint`, `tls_fingerprint_route`, `composite_client`, `composite_client_route`, `asn`, and `asn_route`; `client-ip` style spellings are accepted as compatibility aliases for the client-IP keys. `global` uses one bucket shared by all clients, and when it has no `routes` filter it runs before route matching for the earliest rejection point. `route` uses one bucket per resolved route. `routes` restricts a rate limit to named routes. Access-token limits must set `access_token_source` to either `trusted_authorization_bearer` or `trusted_header`. `trusted_authorization_bearer` reads only `Authorization: Bearer <token>` and must not set `token_header`; `trusted_header` reads only `token_header` and ignores any client-supplied `Authorization` value. Token values are hashed before storage, and missing configured tokens fall back to the client IP bucket. This is a breaking hardening change for existing `access_token*` configs: add `access_token_source` during migration, and avoid using arbitrary pre-auth bearer values as the only budget on public routes. Prefer `route`, `client_ip*`, `client_ip_prefix*`, `tls_fingerprint*`, `composite_client*`, and Person proof identities before trusting app/API access tokens. `client_ip_prefix*` canonicalizes the resolved client IP with `ipv4_prefix_bits` and `ipv6_prefix_bits`. `tls_fingerprint*` hashes OxiBelt's downstream TLS fingerprint and falls back to the client IP when unavailable. `asn*` uses `[client_identity.asn]` lookup and falls back to the client IP when no ASN is available. `composite_client*` hashes canonical `part=value` pairs from `identity_parts`, which may include `client_ip_prefix`, `user_agent`, `tls_fingerprint`, and `asn`; missing parts fall back to the client IP where possible instead of a shared unknown bucket. Top-level `[[rate_limits]]` rejects WAF-only `token_binding_hash*` and `person_proof_clearance*` keys. `max_buckets` caps the number of buckets kept for a single rate limit, defaults to `16384`, and should be lowered for attacker-controlled key modes when a route expects low identity cardinality. In enforcing mode, a request that would create a new bucket after the cap is reached is rejected with the rate limit status until an existing bucket expires or can be reclaimed; monitor mode stops adding new buckets after the cap. Rate and connection limit state is process-local by default. When `[shared_state].enabled = true` and the relevant feature maps to a backend, route rate token buckets, WAF `rate_limit` action buckets, and downstream connection leases are shared across instances. The shared rate-limit path supports both Redis-compatible and PostgreSQL backends and enforces `max_buckets` per configured limit before creating a new distributed bucket. `max_connections` applies at downstream accept time. `max_requests_per_connection` caps HTTP/1.1 requests, HTTP/2 streams, and ordinary HTTP/3 request streams on one downstream connection. `max_connections_per_ip` and `[[connection_limits]]` use the configured `connection_limit_identity`: `proxy_protocol` counts the direct peer or trusted PROXY protocol source for the whole connection, `first_request_real_ip` binds the connection to the first trusted Real-IP header value, and `per_request_real_ip` acquires a lease per HTTP request until its response body finishes. Active WebTransport sessions also acquire dedicated total and per-IP session leases; in Real-IP modes they must also acquire the same normal per-IP and named connection leases as ordinary requests for that identity. When not set, `max_webtransport_sessions` and `max_webtransport_sessions_per_ip` inherit `max_connections` and `max_connections_per_ip`, while `max_webtransport_sessions_per_connection` caps multiplexing on one downstream HTTP/3 connection. For HTTP/1 CONNECT, Upgrade tunnels, and WebTransport sessions, Real-IP connection leases remain held until the upgraded tunnel, session, or first-request connection context closes. TCP stream listeners use direct peer IPs. TLS handshake and header timeouts are listener-wide because no route is known yet; body, response-send, WebSocket, WebTransport idle timeouts can be overridden per route.

### Global Overload Manager

`[overload]` is disabled by default, preserving existing admission behavior. When enabled, OxiBelt samples process RSS, hierarchy-paired cgroup memory usage and limits (v2 or v1), host memory, open file descriptors, cgroup CPU usage, event-loop lag, and fixed-vocabulary active-work counters. It enters `soft` after `soft_enter_samples` consecutive soft breaches and enters `hard` immediately on a hard breach. Recovery requires `recovery_samples` samples below `recovery_ratio` times every soft threshold. A failed process probe retains the last good sample and enters hard overload only after `signal_stale_timeout_ms`; startup rejects enabled configurations whose critical RSS or descriptor probes are unavailable.

```toml
[overload]
enabled = true
sample_interval = "250ms"
soft_enter_samples = 2
recovery_samples = 8
recovery_ratio = 0.90
signal_stale_timeout_ms = 2000

[overload.thresholds]
memory_soft_ratio = 0.75
memory_hard_ratio = 0.90
fd_soft_ratio = 0.75
fd_hard_ratio = 0.90
cpu_soft_ratio = 0.85
cpu_hard_ratio = 0.95
event_loop_lag_soft = "25ms"
event_loop_lag_hard = "100ms"
shared_state_waiters_soft = 100
shared_state_waiters_hard = 500
# active_requests_soft = 500
# active_requests_hard = 1000

[overload.actions.soft]
disable_cache_fill = true
compression_level_cap = 2
reject_priority_classes = ["background", "crawler"]
retry_budget_multiplier = 0.5
waf_body_inspection_concurrency_cap = 0
decompression_concurrency_cap = 0
prefer_cached_or_stale = true

[overload.actions.hard]
reject_new_connections = true
reject_new_streams = true
reject_new_requests = true
stop_large_request_bodies = true
large_request_body_threshold_bytes = 1048576
disable_cache_fill = true
disable_compression = true
disable_retries = true
disable_request_mirroring = true
reject_expensive_waf_bodies = true
enter_recoverable_drain = true
fail_readiness = true
response_status = 503
retry_after = "3s"

[overload.reserved_capacity]
file_descriptors = 64
admin_connections = 32
admin_requests = 32
health_connections = 8
health_requests = 8
metrics_connections = 4
metrics_requests = 4
```

Each optional active-work threshold must be configured as a soft/hard pair with `0 < soft < hard`. Ratios require `0 < soft < hard <= 1`; a `compression_level_cap` must be `0..9` (`0` leaves compression effort unchanged); retry multipliers are finite values in `0..=1`; and hard response status must be `5xx`. `0` WAF/decompression caps select an automatic CPU-sized bound. `reserved_capacity` always bounds dedicated Admin, health, and metrics listener slots separately from public admission, including when `[overload].enabled = false`; its file-descriptor reserve is included in the public FD-pressure calculation. It is never granted from client-selected route metadata.

Hard overload rejects new public TCP/QUIC connections and HTTP streams/requests with the configured generic response. HTTP/1 responses include `Connection: close`; HTTP/2 and HTTP/3 do not. Known oversized bodies are rejected, and unknown-length bodies are conservatively rejected before body reads. Hard overload can set an independent recoverable lifecycle drain; it never clears an Admin or shutdown drain. Health responses always include `X-OxiBelt-Overload-State`; configured hard overload returns readiness `503` with `Retry-After` while liveness remains available.

Soft pressure blocks new cache-fill leaders and background refreshes while preserving completed cache hits, caps compression quality, reduces retry attempts, and rejects only trusted route classes selected below. Cache stale responses remain subject to their existing configured stale windows; overload does not widen cache freshness policy. Client `Priority` headers never select an overload priority class.

### Request, Queue, and Retry Circuit Breakers

`[circuit_breakers]` is enabled by default. It is a process-local guard that is independent of `[overload]`: normal work is admitted only while the global and configured route/pool limits have capacity, and bounded FIFO queues reject rather than accumulating unbounded waiters. `enabled = false` is a compatibility escape hatch that restores the pre-breaker admission behavior. Circuit-breaker rejections use the configured `5xx` response (default `503`) and `Retry-After`; unlike hard overload, they do not close reusable HTTP/1 connections and never make readiness fail.

```toml
[circuit_breakers]
enabled = true
response_status = 503
capacity_retry_after = "1s"

[circuit_breakers.global]
max_active_requests = "auto"
max_pending_requests = "auto"
pending_queue_timeout = "50ms"
max_connections = "auto"
max_streams = "auto"
max_body_inspection_jobs = "auto"
max_decompression_jobs = "auto"

[circuit_breakers.route_defaults]
max_active_requests = "auto"
max_pending_requests = "auto"
pending_queue_timeout = "50ms"

[circuit_breakers.pool_defaults]
max_active_requests = "auto"
max_pending_requests = "auto"
pending_queue_timeout = "50ms"
max_connections = "auto"
max_streams = "auto"

[circuit_breakers.retry_budget]
percent = 0.10
min_concurrency = 1
max_concurrency = "auto"
max_queue = "auto"
queue_timeout = "25ms"

[circuit_breakers.failure]
enabled = true
on = ["connect_error", "first_byte_timeout", "response_read_timeout", "protocol_error", "502", "503", "504"]
consecutive_failures = 5
minimum_requests = 20
failure_ratio = 0.50
window = "10s"
open_timeout = "1s"
max_open_timeout = "30s"
half_open_max_probes = 1
half_open_successes = 2

[circuit_breakers.priority]
enabled = true

[[circuit_breakers.priority.classes]]
name = "security_callback"
reserved_requests = 8
max_share = 0.50
max_pending_requests = 8
pending_queue_timeout = "50ms"
rejection_policy = "queue" # queue | reject
```

`"auto"` resolves once per process from cgroup CPU quota/cpuset, cgroup memory, file-descriptor limits, and the configured body buffers. In Kubernetes, OxiBelt uses projected CPU and memory requests only when the container has no corresponding hard cgroup limit. The global request default is CPU and memory bounded; route and pool defaults are smaller intersections, so an individual dependency cannot consume all process capacity. Limits are per Pod, not cluster-wide; add replicas to increase aggregate capacity. `max_pending_requests = 0` disables waiting and rejects immediately. Configured route names and pool names are the only scope labels exported to Prometheus; paths, hosts, clients, URLs, and raw errors are never labels.

### Priority Classes and Reserved Capacity

`[circuit_breakers.priority]` applies a fixed-vocabulary priority scheduler to the global downstream request limit. The supported classes are `admin`, `health`, `security_callback`, `interactive`, `default`, `background`, and `crawler`; a route receives its class only from its own `priority_class` configuration. By default, `background` is capped at `50%` of the global request capacity and `crawler` at `25%`; both reject immediately instead of queueing. Other classes can use the whole class-share cap and inherit the bounded global queue. This preserves at least one class of shared capacity because the combined `background` and `crawler` maximum shares must remain below `1`.

Each `[[circuit_breakers.priority.classes]]` entry may override one fixed class. `max_share` is a finite fraction in `(0, 1]`; `max_pending_requests` accepts a non-negative integer or `"auto"`; `pending_queue_timeout` bounds only that class's wait; and `rejection_policy = "reject"` forbids a positive class queue. The scheduler keeps FIFO order within each class lane and selects the oldest admissible shared waiter across classes, while an authenticated waiter can use an available dedicated reservation. This prevents a blocked route or low-priority class from starving compatible traffic.

`reserved_requests` is strict and non-borrowable: all configured reservations are removed from the public shared request pool, and validation requires at least one shared slot plus a reservation no larger than that class's `max_share`. A public request can use a reservation only after its selected route independently succeeds local IPM authorization or matches a verified TCP TLS client-certificate rule. Route labels, route names, and client-controlled `Priority` headers never grant a reservation. QUIC/HTTP/3 does not expose peer client-certificate metadata to this matcher, so HTTP/3 reservation eligibility is IPM-only. `admin` and `health` route classes may not reserve public request slots; their separately bounded listener connection/request slots, together with metrics capacity, remain under `[overload.reserved_capacity]` even when pressure sampling is disabled.

The failure circuit is applied to upstream-backed route and pool attempts while existing per-server passive health and outlier ejection remain separate. A circuit opens after either `consecutive_failures` or the rolling `failure_ratio` once `minimum_requests` are present, then permits only `half_open_max_probes` after the open interval. Successful probes close it after `half_open_successes`; failed probes reopen it with capped backoff. Downstream cancellation is neutral. Retry backoff, queueing, and every attempt consume the request's upstream deadline. When breakers are enabled and retry itself is enabled, omitted legacy zero-backoff settings resolve to a bounded jittered `25ms`–`250ms` backoff; disable the breaker explicitly to retain historical zero-backoff retry behavior.

```toml
[shared_state]
enabled = false
namespace = "oxibelt"
redis_plaintext_policy = "allow" # allow | loopback_only | deny
instance_id_env = "OXIBELT_INSTANCE_ID"
udp_flow_identity_key_env = "OXIBELT_UDP_FLOW_IDENTITY_KEY"
default_backend = "cluster"
operation_timeout_ms = 500
enumeration_page_size = 128
enumeration_max_items_per_operation = 4096
connection_lease_ms = 120000
cache_lock_ms = 10000
rate_limits_backend = "cluster"
connection_limits_backend = "cluster"
udp_flows_backend = "cluster"
person_proof_backend = "cluster"
upstream_health_backend = "cluster"
cache_backend = "cluster"
reload_backend = "cluster"
dynamic_policy_backend = "cluster"

[shared_state.failure_policies]
rate_limits = "fail_closed"
connection_limits = "reject_new_only"
udp_flows = "reject_new_only"
person_proof = "fail_closed"
upstream_health = "stale_snapshot"
sticky_sessions = "local_fallback"
cache = "local_fallback"
reload = "fail_open"

[[shared_state.backends]]
name = "cluster"
kind = "redis" # redis | postgres
connection_url_env = "OXIBELT_SHARED_STATE_URL"
max_connections = 4
connect_timeout_ms = 3000

[shared_state.backends.redis_pool]
min_idle_connections = 0
max_waiters = 16 # defaults to 4 * max_connections
pool_wait_timeout_ms = 500 # defaults to operation_timeout_ms
command_timeout_ms = 500 # defaults to operation_timeout_ms
idle_timeout_ms = 60000
health_check_interval_ms = 15000
reconnect_min_backoff_ms = 50
reconnect_max_backoff_ms = 5000
circuit_breaker_failure_threshold = 5
circuit_breaker_open_timeout_ms = 1000

[shared_state.backends.tls]
mode = "off" # off | verify_full, PostgreSQL only
# ca_cert = "postgres-ca.pem"
# client_cert = "postgres-client.pem"
# client_key = "postgres-client.key"
```

Shared state is opt-in. If it is disabled, features keep their local in-process behavior. When it is enabled, an omitted feature mapping uses `default_backend`, or the first configured backend when `default_backend` is not set. Durable UDP is stricter: `udp_flow_state = "shared_required"` requires an explicit `udp_flows_backend`, and that mapping may name either a Redis-compatible or PostgreSQL backend. Backends are named, and each feature maps to one backend; OxiBelt does not mirror writes or fall back through backend chains. Exactly one of `connection_url` or `connection_url_env` is required per backend. Effective config dumps redact shared-state `connection_url` values.

`udp_flow_identity_key_env` names an environment variable containing a standard-base64 32-byte key. The key derives opaque flow, route, target, owner, and configuration-generation identities; raw peer addresses, route names, origins, and resolved endpoint addresses are not stored as record authority. Every Pod that must recover the same flows needs the same key and shared-state namespace. Key rotation creates a new identity domain and deliberately makes old records unrecoverable; stage it as a flow drain rather than expecting continuity across the rotation. When shared connection limits are active, their effective backend must be the same backend selected by `udp_flows_backend`, so a recovered binding and its admission authority cannot diverge.

`[shared_state.failure_policies]` makes the post-activation failure decision explicit for every shared-state feature. It does not relax startup or reload activation: a PostgreSQL connect/init failure, a required Redis prewarm failure, or a failed secure Redis/auth preflight still prevents the new snapshot from becoming active. The defaults above preserve the previous behavior and are the secure-profile baseline.

| Feature | Default | Supported modes | Post-activation behavior |
| --- | --- | --- | --- |
| `rate_limits` | `fail_closed` | all five modes | Rejects when a distributed token decision cannot be made. `local_fallback` uses the bounded process-local bucket; `fail_open` permits the operation. `stale_snapshot` and `reject_new_only` are conservative for a consumptive token decision and reject rather than replaying a prior result. |
| `connection_limits` | `reject_new_only` | all five modes | Existing leases are never revoked because the backend is unavailable; a new lease is rejected. `local_fallback` applies the bounded process-local limit and `fail_open` admits without a shared lease. A stale count is never used to admit a new lease. |
| `udp_flows` | `reject_new_only` | `reject_new_only` | Keeps an already-local owned flow usable, but rejects a packet that requires a shared lookup, claim, ownership recovery, or distributed token decision while the backend is unavailable. The policy cannot be weakened to local fallback or fail open. |
| `person_proof` | `fail_closed` | `fail_closed` | Replay prevention, clearance revocation, and the Person proof Admin mutation stay fail closed. This field must remain `fail_closed`; OxiBelt rejects a weaker value during configuration validation. |
| `upstream_health` | `stale_snapshot` | `stale_snapshot` | Keeps the last successfully observed shared health/active-count state while backend I/O is unavailable. |
| `sticky_sessions` | `local_fallback` | `local_fallback`, `fail_open` | Retains the process-local sticky secret when the shared secret cannot be read. `fail_open` continues with the current process-local secret without recording a fallback entry. |
| `cache` | `local_fallback` | `local_fallback`, `fail_open` | Treats a failed shared-cache read as a local miss; local L1 and normal origin handling remain available. `fail_open` continues without the distributed lookup. Administrative shared cache purges still return an error rather than reporting a partial success. |
| `reload` | `fail_open` | `fail_open` | Logs a failed cross-instance generation heartbeat and continues the already-active process configuration. |

`fail_closed` rejects the feature operation, `fail_open` continues without a distributed decision, `local_fallback` uses only the feature's bounded process-local state, `stale_snapshot` uses only an already-published non-mutating observation, and `reject_new_only` preserves existing work while refusing new distributed reservations. Unsupported feature/mode pairs are rejected during configuration validation rather than silently behaving like a different policy. No mode retries an ambiguous distributed mutation after timeout or cancellation. Local fallback is per process, has no cluster-wide guarantee, and is intentionally visible in health and metrics. Use `fail_closed` for security controls unless the availability trade-off has been explicitly reviewed.

The existing feature-specific controls remain authoritative; the central shared-state table does not silently override them. DynamicPolicy `use_last_good` retains its last good snapshot, `disabled_on_error` disables matching, and `fail_closed_on_startup` keeps activation strict; `ipm.fail_closed = false` uses the static IPM configuration while refresh retains the last good dynamic snapshot; Admin audit durable modes reject required Admin work when the selected PostgreSQL or fsynced-spool acknowledgement cannot be completed, while `best_effort` records the delivery failure; mitigation `failure_policy = "closed"` or `"open"` remains its direct sink policy.

`operation_timeout_ms` remains the absolute deadline for each shared-state operation. `enumeration_page_size` defaults to `128` and bounds one shared-state scan page; it must be between `1` and `1000`. `enumeration_max_items_per_operation` defaults to `4096` and bounds total work for a complete status or purge operation; it must be between `1` and `65536`. The page size cannot exceed the total limit. PostgreSQL uses its existing operation concurrency permit. Redis uses one persistent FIFO pool per configured backend: `max_connections` is its physical socket cap, and `max_waiters` bounds active-plus-waiting Redis commands at `max_connections + max_waiters`; excess commands fail immediately. `pool_wait_timeout_ms`, connection creation, health recycling, and `command_timeout_ms` are independently bounded and still cannot outlive the outer operation deadline. Defaults preserve lazy startup with zero idle connections, four waiters per allowed Redis connection, and inherited wait/command timeouts. A positive `min_idle_connections` is a startup and reload requirement: the configured backend must prewarm that many sockets before the new snapshot activates. Unchanged plaintext pools retain their existing sockets; changed endpoint credentials or pool settings create a draining replacement generation. Every `rediss://` pool is rebuilt on a full reload so changed trust roots or client-certificate material at the same path cannot be retained.

Redis pools support single-endpoint `redis://` and verified `rediss://` URLs. Queries and fragments are rejected. `redis_plaintext_policy = "allow"` is the compatibility default; secure profiles should use `"deny"`, while `"loopback_only"` permits only literal loopback IP addresses. `rediss://` always uses normal Rustls PKI validation and hostname verification. `[shared_state.backends.redis_tls]` optionally selects `trust_store = "webpki"`, `"native"`, or an explicit `"custom"` CA bundle; custom roots replace rather than augment the selected public/native store. `server_name` overrides the URL host only for TLS name verification. `server_spki_sha256` adds one or more `sha256/<base64>` SPKI pins after PKI validation, rather than replacing PKI validation. `client_cert` and `client_key` are an optional pair for mTLS.

Redis credentials may stay outside TOML with `[shared_state.backends.redis_auth]`. `password_file` alone sends Redis `AUTH <password>` and is the normal non-mTLS token/password deployment. Supplying both `username_file` and `password_file` sends Redis ACL `AUTH <username> <password>`. File credentials are mutually exclusive with URL userinfo; URL userinfo remains supported only for compatibility and is redacted from effective config output. Secret files are bounded, require non-empty content, and may have one terminal LF or CRLF removed. TLS/auth secret files resolve beneath the certificate root and are watched as full-reload runtime inputs. A new `rediss://` or file-auth backend establishes a connection, completes TLS/authentication/database selection, and must pass that pre-activation check before the replacement snapshot publishes; failure leaves the previous snapshot active.

For a remote Redis deployment, mount the CA, optional client certificate/key, and ACL files below the certificate root and use relative paths:

```toml
[shared_state]
enabled = true
namespace = "oxibelt:prod:edge-a"
redis_plaintext_policy = "deny"
default_backend = "redis-main"

[[shared_state.backends]]
name = "redis-main"
kind = "redis"
connection_url = "rediss://redis.edge.svc:6380/0"
max_connections = 8

[shared_state.backends.redis_tls]
trust_store = "custom"
server_name = "redis.edge.svc"
ca_cert = "redis/redis-main/ca.pem"
# client_cert = "redis/redis-main/client.pem"
# client_key = "redis/redis-main/client-key.pem"
# server_spki_sha256 = ["sha256/<base64-encoded-32-byte-SPKI-hash>"]

[shared_state.backends.redis_auth]
username_file = "redis/redis-main/username"
password_file = "redis/redis-main/password"
```

The Helm chart can project these files with `sharedState.redisSecretProjections`; each item is mounted as `/etc/oxibelt/cert/redis/<projection-name>/<path>`. The chart rejects traversal-like paths and uses read-only projected Secrets with mode `0440`. Configure `runtime.hot_reload.mode = "full"` when Kubernetes Secret rotation should become a new verified Redis pool without restarting the Pod.

Authentication and database selection occur once when a physical connection is created. After an idle interval, a checkout performs a bounded `PING`; idle sockets above `min_idle_connections` are retired. Dial failures use bounded exponential backoff and a single half-open reconnect probe while healthy idle sockets remain usable. OxiBelt never retries a command after an ambiguous transport failure. A socket is returned only after every expected RESP reply has been consumed, including Redis `-ERR` replies in a pipeline; cancellation, command timeout, EOF, partial I/O, or malformed RESP drops the socket.

Shared-state enumeration is namespace-scoped and incremental. Redis uses bounded `SCAN` pages instead of `KEYS`, batches values with `MGET`, and pipelines per-key TTL inspection; PostgreSQL uses escaped-prefix, keyset-paginated queries. Cache vary lookups use only their narrow index, so a legacy shared entry without an index is an ordinary safe miss rather than a namespace-wide scan. Cache purges and Person proof status fail with `503` rather than claim a partial successful result when their configured work or deadline bound is exceeded. Person proof clearance lists return a bounded page and a versioned opaque cursor bound to the shared-state namespace and backend position; callers should discard outstanding cursors after a backend or deployment change.

Cancellation drops in-flight Redis I/O and its checkout rather than returning a potentially desynchronized socket; connection-lease release, pool active-count decrement, and cache-lock unlock use a bounded deferred-cleanup queue only as a cancellation fallback, with their existing TTLs as the final recovery boundary. This does not change documented fail-open/fail-closed behavior. Basic Prometheus output exposes bounded `oxibelt_shared_state_queue_duration_ms`, `oxibelt_shared_state_operation_duration_ms`, `oxibelt_shared_state_operations_total`, `oxibelt_shared_state_enumeration_total`, `oxibelt_shared_state_queued_operations`, `oxibelt_shared_state_in_flight_operations`, `oxibelt_shared_state_deferred_cleanup_dropped_total`, `oxibelt_shared_state_pool_connections`, `oxibelt_shared_state_pool_waiters`, `oxibelt_shared_state_pool_max_connections`, `oxibelt_shared_state_pool_circuit_state`, `oxibelt_shared_state_pool_acquisitions_total`, and `oxibelt_shared_state_pool_connection_events_total` series. Enumeration labels use only configured backend, backend kind, fixed scope, and fixed event (`pages`, `scanned_keys`, `returned_keys`, or `cap_exhausted`). Other labels contain only the configured backend name, backend kind, fixed operation name/outcome/event, and fixed connection state; keys, identities, tokens, URLs, and error text are never labels. A nonzero deferred-cleanup drop counter means cancellation saturated its bounded fallback queue; investigate it alongside backend timeout and queue metrics.

Redis backends target Redis-protocol compatible Redis, Valkey, and KeyDB single-endpoint deployments. PostgreSQL backends create OxiBelt-managed shared-state tables at startup. Security-sensitive operations such as rate limits, connection leases, and Person proof fail closed when the configured shared backend errors. Shared cache operations fall back to the local/no-shared-cache path for the current request. Health streak transitions, counter value-plus-expiry updates, multi-scope connection leases, pool active-count leases, Person proof replay transitions, and Person proof revocation/tombstone changes are one backend mutation: Redis uses one script and PostgreSQL uses one transaction. Connection and pool leases carry an opaque TTL-bound marker, so duplicate or stale cleanup cannot decrement a newer count. Person proof shared state stores the cluster HMAC secret and replay/revocation markers under OxiBelt-managed keys; narrow Admin revocation idempotency records use only a digest of `Idempotency-Key`, expire with the tombstone (maximum 24 hours), and are kept outside Person proof enumeration prefixes. Operators should use the Admin Person proof endpoints for hash-only status and revocation; direct backend inspection can expose implementation keys and has a different trust boundary than the Admin API. Mixed old/new replicas retain key and table compatibility but do not provide the atomic-update guarantee until old replicas drain; retain the new revision for at least `connection_lease_ms` before claiming full rollout coverage.

```toml
[dynamic_policy]
enabled = false
backend = "cluster"
refresh_interval_ms = 2000
max_policies = 10000
fail_policy = "use_last_good" # use_last_good | fail_closed_on_startup | disabled_on_error
default_status = 429
default_body = "Blocked by dynamic policy"

[dynamic_policy.automation_api]
enabled = false
require_ttl = true
signature_key_env = "OXIBELT_DYNAMIC_POLICY_HMAC_KEY"
# default_source_quota = 1000 # shared by all sources without an explicit source_quotas entry

[[dynamic_policy.automation_api.source_quotas]]
source = "vaultwarden"
max_active_policies = 100

[[dynamic_policy.automation_api.source_quotas]]
source = "oxibeltctl"
max_active_policies = 200

[[dynamic_policy.automation_api.source_quotas]]
source = "oxibeltctl-profile"
max_active_policies = 100

[dynamic_policy.matching]
trust_route_name = true
normalize_path = true
ipv4_prefix_bits = 24
ipv6_prefix_bits = 56
token_bindings = ["user_agent", "tls_fingerprint", "route", "direct_peer_ip_network_prefix"]
composite_identity_parts = ["client_ip_prefix", "user_agent", "tls_fingerprint", "asn"]

[shared_state]
enabled = true
namespace = "oxibelt"
dynamic_policy_backend = "cluster"

[[shared_state.backends]]
name = "cluster"
kind = "postgres"
connection_url_env = "OXIBELT_SHARED_STATE_URL"
max_connections = 4
connect_timeout_ms = 3000
```

Dynamic policy is an opt-in PostgreSQL-backed policy snapshot for external security automation. The selected backend comes from `dynamic_policy.backend`, then `shared_state.dynamic_policy_backend`, then `shared_state.default_backend`, and must be a PostgreSQL shared-state backend. PostgreSQL is only the policy source: OxiBelt creates dedicated `oxibelt_dynamic_policies`, `oxibelt_dynamic_policy_generation`, and `oxibelt_dynamic_policy_audit` tables, periodically loads active rows into an immutable in-memory snapshot, and never runs PostgreSQL queries from the request hot path. Legacy external translators, such as a Vaultwarden stdout sidecar, may write this supported policy API table while `dynamic_policy.automation_api.enabled = false`; they should not write `oxibelt_shared_state` or `oxibelt_shared_counters`.

When `[dynamic_policy.automation_api]` is enabled, `[admin]` must also be enabled and `signature_key_env` must point to base64 for exactly 32 random bytes. The Admin API signs rows with HMAC-SHA256 and the snapshot loader rejects active rows whose `signature_version` or `row_signature` does not verify. `require_ttl = true` requires `expires_at` or `ttl_seconds` for Admin-created/imported/applied active policies and for active signed rows loaded into a snapshot. Admin create, import, apply, and patch writes enforce `dynamic_policy.max_policies` before they can add another active row, so the automation API cannot create a snapshot that would exceed the loader cap. Explicit `source_quotas` bound active policies for the matching source. `default_source_quota` bounds the shared bucket for all sources that do not have an explicit `source_quotas` entry, preventing clients from rotating arbitrary source names to gain fresh quota.

Active rows must match `shared_state.namespace`, have `enabled = true`, and be unexpired. `action` is `allow`, `reject`, `silent_close`, `rate_limit`, or `challenge`; `subject_type` is `client_ip`, `client_ip_cidr`, `client_ip_route`, `client_ip_path`, `client_ip_prefix`, `client_ip_prefix_route`, `tls_fingerprint`, `tls_fingerprint_route`, `token_binding_hash`, `person_proof_clearance`, `asn`, `asn_route`, or `composite_client`. Composite subjects use a pipe separator: `client_ip_route` stores `203.0.113.10|app-route`, `client_ip_path` stores `203.0.113.10|/identity`, `client_ip_prefix_route` stores `203.0.113.0/24|app-route`, `tls_fingerprint_route` stores `fingerprint:<sha256>|app-route`, and `asn_route` stores `AS64500|app-route`. IP and CIDR portions are parsed and canonicalized when snapshots load, including equivalent IPv6 spellings such as expanded uppercase addresses. `client_ip_route`, `client_ip_prefix_route`, `tls_fingerprint_route`, and `asn_route` rows require `route_name`; `client_ip_path` rows require `path_prefix`. Optional `method`, `route_name`, and `path_prefix` further narrow the match. `mode = "dry_run"` records a match without applying an `allow`, `reject`, `silent_close`, `rate_limit`, or `challenge`; `mode = "enforce"` applies the selected policy.

`client_ip_prefix*` subjects accept explicit CIDR values stored in the policy row; `dynamic_policy.matching.ipv4_prefix_bits` and `ipv6_prefix_bits` are used for hashed composite and token-binding identities, not for rewriting arbitrary prefix subjects. `tls_fingerprint*`, `token_binding_hash`, `person_proof_clearance`, and `composite_client` subjects accept either a bare lowercase or uppercase 64-hex SHA-256 value, or the canonical prefixes `fingerprint:`, `binding:`, `clearance:`, and `hash:` respectively. OxiBelt stores and compares only those prefixed hashes, not raw TLS fingerprints, token-binding payloads, User-Agent values, composite parts, or clearance tokens. `asn*` accepts `64500` or `AS64500` and canonicalizes to `AS64500`; it matches only when `[client_identity.asn]` lookup returns an ASN for the resolved client IP. The IANA AS Numbers registry remains optional metadata/provenance for validating ASNs and is not an IP prefix-to-origin-ASN lookup source.

`challenge` is a v1 Person proof dynamic action. It uses the built-in Person proof session, verify, and OpenAPI paths from `[waf.person_proof]`; dynamic rows only choose whether the challenge applies and may override the response `status` for the issued challenge. If `status` is omitted, `challenge` defaults to `403`, independent of `dynamic_policy.default_status`. `challenge` rows reject `rate`, `burst`, and `body`, because those fields belong to `rate_limit` and text `reject` responses. Requests that already carry valid Person proof clearance pass through; when a `person_proof_clearance` dynamic subject can match the current request scope, the request flow evaluates the clearance once and reuses that status for dynamic challenge handling and request WAF evaluation so single-use replacement is preserved, including terminal dynamic responses and route redirects. Person proof API paths bypass only dynamic `challenge` so the browser can fetch session/verify/OpenAPI documents without a challenge loop. Dynamic `reject` and `rate_limit` still apply to those paths.

`silent_close` is a request-admission dynamic action. It closes or resets the downstream connection without sending HTTP response headers or body, and is intended for nginx-444-like emergency mitigations. Rows using `silent_close` reject `status`, `body`, `rate`, and `burst`; `reason`, `code`, selectors, priority, `mode`, and TTL/expiry fields remain valid for audit and matching context.

When multiple policies match, OxiBelt chooses the most specific match before applying the action: rows with `route_name` beat route-agnostic rows, longer `path_prefix` beats shorter prefixes, exact IP subjects beat CIDR subjects, longer CIDR prefixes beat shorter prefixes, then lower `priority`, then lower `id`. The first enforcing `allow` permits the request; the first enforcing `reject`, `silent_close`, `rate_limit`, or `challenge` applies as usual. If only dry-run policies match, `DynamicPolicy.*` context is populated and the request continues.

OxiBelt initializes the policy API schema:

```sql
CREATE TABLE IF NOT EXISTS oxibelt_dynamic_policies (
  id bigserial PRIMARY KEY,
  namespace text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  priority integer NOT NULL DEFAULT 100,
  name text NOT NULL,
  source text NOT NULL DEFAULT 'external',
  action text NOT NULL,
  subject_type text NOT NULL,
  subject text NOT NULL,
  route_name text NULL,
  method text NULL,
  path_prefix text NULL,
  rate text NULL,
  burst integer NULL,
  status integer NULL,
  body text NULL,
  reason text NULL,
  code text NULL,
  mode text NOT NULL DEFAULT 'enforce',
  writer_identity text NULL,
  signature_version text NULL,
  row_signature text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS oxibelt_dynamic_policies_active_idx
ON oxibelt_dynamic_policies (namespace, enabled, expires_at, priority);

CREATE INDEX IF NOT EXISTS oxibelt_dynamic_policies_subject_idx
ON oxibelt_dynamic_policies (namespace, subject_type, subject);

CREATE INDEX IF NOT EXISTS oxibelt_dynamic_policies_source_name_idx
ON oxibelt_dynamic_policies (namespace, source, name);

CREATE TABLE IF NOT EXISTS oxibelt_dynamic_policy_generation (
  namespace text PRIMARY KEY,
  generation bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oxibelt_dynamic_policy_audit (
  id bigserial PRIMARY KEY,
  namespace text NOT NULL,
  policy_id bigint NULL,
  actor text NOT NULL,
  operation text NOT NULL,
  source text NULL,
  name text NULL,
  outcome text NOT NULL,
  error text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
```

Example Vaultwarden translator output for a TTL block:

```sql
INSERT INTO oxibelt_dynamic_policies
  (namespace, priority, name, source, action, subject_type, subject, path_prefix, status, body, reason, expires_at)
VALUES
  ('oxibelt', 10, 'vaultwarden-login-block', 'vaultwarden-stdout', 'reject',
   'client_ip_path', '203.0.113.10|/identity', '/identity', 429,
   'Blocked by dynamic policy', 'repeated Vaultwarden login failures',
   now() + interval '15 minutes');

INSERT INTO oxibelt_dynamic_policy_generation (namespace, generation, updated_at)
VALUES ('oxibelt', 1, now())
ON CONFLICT (namespace)
DO UPDATE SET generation = oxibelt_dynamic_policy_generation.generation + 1,
              updated_at = now();
```

For layered login protection, keep a static route/path rate limit and let the translator add short-lived dynamic blocks when Vaultwarden logs repeated failures:

```toml
[[rate_limits]]
name = "vaultwarden-identity-path"
key = "client_ip_path"
routes = ["vaultwarden"]
rate = "30r/m"
burst = 30
status = 429

[[routes]]
name = "vaultwarden"
hosts = ["vault.example.com"]
path_prefix = "/identity"
upstream = "vaultwarden"
```

```toml
[cache]
enabled = false
store = "memory" # memory | tmpfs | disk | memory_then_disk
tmpfs_dir = "/dev/shm/oxibelt-cache"
# disk_dir = "/var/cache/oxibelt"
max_size_bytes = 1073741824
# memory_max_size_bytes = 536870912
# disk_max_size_bytes = 10737418240
memory_auto_fraction = 0.5
default_ttl_seconds = 60
cache_methods = ["GET", "HEAD"]
cache_key = "{scheme}:{host}:{uri}"
partition_key = ""
respect_cache_control = true
stream_large_objects = true
stream_chunk_bytes = 1048576
copy_file_range = "auto" # auto | off | required
stale_if_error_seconds = 30
stale_while_revalidate_seconds = 30
lock = true
lock_wait_timeout_ms = 10000
tag_headers = ["Surrogate-Key", "Cache-Tag"]
max_tags_per_entry = 32
max_tag_bytes = 128
max_vary_fields = 8
max_vary_variants_per_key = 64
bypass_request_headers = ["Authorization", "Cookie", "Proxy-Authorization"]
background_refresh = true
background_refresh_max_concurrent = 16
negative_statuses = []
negative_ttl_seconds = 0
# external_handler = "massive"

[cache.surrogate]
enabled = true
strip_response_header = true

[cache.admission]
statuses = [200, 203, 204, 301, 308]
content_types = []
max_body_bytes = 0
min_hits = 1
max_tracked_keys = 16384

[cache.stale_if_error]
connect_error = true
read_timeout = true
statuses = []
max_upstream_stale_seconds = 0

# [[cache.external_handlers]]
# name = "massive"
# kind = "http"
# endpoint = "https://cache-handler.internal.example/v1/cache/"
# token_env = "OXIBELT_EXTERNAL_CACHE_TOKEN"
# connect_timeout_ms = 250
# request_timeout_ms = 30000
# max_metadata_bytes = 1048576
# max_body_bytes = 1073741824
# max_inflight_requests = 64
# fail_policy = "local_only"

[[cache.policies]]
name = "assets"
store = "memory_then_disk"
# external_handler = "off"

[[cache.policies.rules]]
mime_types = ["image/*", "text/css", "application/javascript"]
store = "disk"

[admin]
enabled = false
bind = "127.0.0.1:9092"
bearer_token_env = "OXIBELT_ADMIN_TOKEN"
transport = "auto" # auto | tls | plaintext_allowlist | plaintext
allow_insecure_plaintext = false
plaintext_allowed_source_cidrs = ["127.0.0.0/8", "::1/128"]

[admin.cache_purge_signing]
enabled = false
key_env = "OXIBELT_CACHE_PURGE_HMAC_KEY"
max_skew_seconds = 300
nonce_ttl_seconds = 600

[ipm]
enabled = false
namespace = "oxibelt"
fail_closed = true

[ipm.break_glass]
argon2id_memory_mib = 128

[[ipm.principals]]
id = "upstream-ops"
subject = "upstream-ops@example.com"
groups = ["upstream-operators"]

[[ipm.credentials]]
name = "upstream-ops"
principal = "upstream-ops"
bearer_token_env = "OXIBELT_UPSTREAM_TOKEN"

[[ipm.policies]]
name = "upstream-pool-ops"

[[ipm.policies.statements]]
effect = "allow"
actions = ["upstream-pool:GetStatus", "upstream-pool:List", "upstream-pool:Get"]
resources = [
  "oxibelt:oxibelt:upstream-pool:status/current",
  "oxibelt:oxibelt:upstream-pool:*",
]

[[ipm.policies.statements]]
effect = "allow"
actions = [
  "upstream-pool:AddServer",
  "upstream-pool:UpdateServer",
  "upstream-pool:RemoveServer",
]
resources = ["oxibelt:oxibelt:upstream-pool:app-pool/server/*"]

[[ipm.bindings]]
group = "upstream-operators"
policy = "upstream-pool-ops"

[admin.tls]
enabled = false
min_version = "tls1.3"
max_version = "tls1.3"
session_tickets = false
require_sni = true
reject_unknown_sni = true

[admin.tls.resumption]
mode = "off" # off | stateful | stateless
session_cache_size = 1024
tls13_ticket_count = 2
rotation_seconds = 86400

[[admin.tls.certificates]]
server_names = ["admin.example.com", "*.ops.example.com"]
cert_chain = "admin-fullchain.pem"
private_key = "admin-privkey.pem"
default = true

[admin.tls.client_auth]
mode = "off"
ca_certs = []
verify_depth = 4

[metrics]
enabled = false
bind = "127.0.0.1:9090"
format = "prometheus"
detail = "detailed"
histogram_buckets_ms = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]

[telemetry.tracing]
enabled = false
endpoint = "http://127.0.0.1:4318/v1/traces"
service_name = "oxibelt"
sample_ratio = 1.0
export_timeout_ms = 3000
propagate_trace_context = true

[health]
enabled = false
bind = "127.0.0.1:9091"
ready_path = "/ready"
live_path = "/live"

[security.headers]
hsts = false
hsts_max_age_seconds = 31536000
hsts_include_subdomains = true
hsts_preload = false
# x_content_type_options = "nosniff"
# referrer_policy = "strict-origin-when-cross-origin"
# permissions_policy = "default"

[[security.header_policies]]
name = "api"
hsts = true
hsts_max_age_seconds = 31536000
hsts_include_subdomains = true
hsts_preload = false
x_content_type_options = "nosniff"
referrer_policy = "same-origin"
permissions_policy = "geolocation=()"

[compression]
enabled = true
gzip = true
deflate = true
zstd = true
br = true
min_size_bytes = 1024
statuses = [200]
mime_types = [
  "text/*",
  "application/json",
  "application/*+json",
  "application/javascript",
  "application/xml",
  "application/*+xml",
  "image/svg+xml",
]
level = 1
vary = true
proxied = ["expired", "no-cache"]
upstream_accept_encoding = "strip"
max_concurrent_responses = 0
```

`[security.headers]` is the default global response header policy. `[[security.header_policies]]` entries accept the same fields plus a unique `name`, and route `security_headers` selects `default`, `off`, or a named policy. Omitted route values preserve the current default behavior. Policy names must not be `default` or `off` because those exact lowercase values are reserved for route selection. Cached proxy responses store route-security-neutral metadata and reconcile OxiBelt-managed security headers at delivery time, so configured fields reflect the currently matched route policy while origin-provided values remain intact for fields that the current route policy leaves unset or disables.

Compression support is enabled by default for `br`, `zstd`, `gzip`, and `deflate`. OxiBelt only compresses downstream responses when the client permits an enabled encoding, the request does not carry `Cookie`, `Authorization`, or `Proxy-Authorization`, the response is not already encoded or secret-bearing, the status/MIME/size policy matches, and HTTP semantics such as `Cache-Control: no-transform` and range responses allow transformation. Responses with `Set-Cookie`, `Cache-Control: private`, or `Cache-Control: no-store` are not compressed. `level` is an nginx-style `1..9` compression level applied to all enabled encoders. `vary = true` adds `Vary: Accept-Encoding` for dynamic compression decisions; static precompressed file variants always vary on `Accept-Encoding`. `proxied` applies only to requests carrying `Via` and accepts `off`, `expired`, `no-cache`, `no-store`, `private`, `no-last-modified`, `no-etag`, `auth`, or `any`; `off` and `any` cannot be combined with other predicates. These proxied predicates are an additional gate and do not override OxiBelt's credential, `Set-Cookie`, private, or no-store skips. `upstream_accept_encoding = "strip"` preserves the default identity-upstream behavior; `preserve` forwards the downstream header when safe, and `configured` sends the enabled encoding list intersected with the downstream request. Response body WAF transforms and credential-bearing requests always strip upstream `Accept-Encoding`. `max_concurrent_responses = 0` uses an automatic CPU budget. Named `[[compression.policies]]` entries can override these fields and be selected with route `compression`; policy names must not be `default` or `off` because those exact lowercase values are reserved for route selection.

`cache.store = "tmpfs"` validates `tmpfs_dir` under `/dev/shm` when cache is enabled. `disk` and `memory_then_disk` require an explicit writable `disk_dir` and `disk_max_size_bytes`; OxiBelt does not choose a disk path implicitly. If `memory_then_disk` omits `memory_max_size_bytes`, OxiBelt uses `memory_auto_fraction` of the detected cgroup/container memory limit, falling back to system memory. `copy_file_range = "auto"` lets Linux cache/object file materialization clone bytes with `copy_file_range(2)` before falling back to userspace copying; `required` is Linux-only and fails the materialization when the kernel copy cannot be used. `cache_key` and `partition_key` support `{scheme}`, `{host}`, `{uri}`, `{path}`, `{query}`, `{query:name}`, `{header:Name}`, and `{cookie:name}`. Named cache policies are selected by `routes.cache`; `default` refers to the top-level `[cache]` policy. Policy rules select storage after the upstream response MIME type is known. When `cache_backend` maps to a shared backend, the configured local cache remains L1 and the shared backend stores collected full cacheable objects, disk-streamed objects, metadata, fill locks, and purge-visible L2 entries. Disk streaming fills commit to local L1 first, then publish the shared L2 body as bounded chunks using `cache.stream_chunk_bytes`; shared chunk hits are copied into bounded temporary files before downstream streaming instead of materializing the full object in memory.

`[[cache.external_handlers]]` defines optional HTTP L3 handlers behind local L1 and shared-state L2. `cache.external_handler = "name"` selects a top-level default, `cache.policies.external_handler = "name"` overrides it, and `cache.policies.external_handler = "off"` disables inherited L3 for that policy. Handler names must be unique runtime identifiers and cannot be `default` or `off`; endpoints must be `http://` or `https://`; timeout, metadata, body, and inflight limits must be positive. `request_timeout_ms` bounds each handler request/response exchange, including lookup and purge response-body reads. `token_env` supplies a bearer token without putting credentials in the TOML. The handler protocol uses JSON control requests for lookup, revalidation metadata refresh, and purge, plus framed cache entries with an 8-byte big-endian metadata length, UTF-8 JSON metadata, and raw body bytes. OxiBelt remains authoritative for keys, partitions, `Vary`, cacheability, credential bypasses, status headers, admission, and purge authorization; handler errors, malformed records, mismatches, and expired records are safe misses under `local_only`.

The cache honors HTTP cache metadata including `Cache-Control`, `Expires`, `ETag`, `Last-Modified`, and `Vary`. It can revalidate stale entries, serve stale entries on configured upstream errors, answer fresh conditional hits with `304`, attach `Age` to cached hits, serve single and multipart byte ranges from full stored responses, and cache configured negative statuses with `negative_statuses` and `negative_ttl_seconds`. `HEAD` can reuse a cached `GET` entry, but a `HEAD` miss is not stored. Named policies may override negative-cache defaults so routes can opt into different negative caching by selecting a policy. `stale-if-error` serving is controlled separately for connect errors, read timeouts, configured HTTP statuses, and `max_upstream_stale_seconds`, where `0` leaves stale lifetime uncapped beyond the response metadata.

Cache-enabled routes add authoritative `X-OxiBelt-Cache` and `X-OxiBelt-Cache-Reason` response headers for downstream observability. `X-OxiBelt-Cache` is one of `miss`, `hit`, `stale`, or `revalidated`; the reason is a bounded diagnostic label such as `stored`, `fresh`, `background_refresh`, `stale_if_error`, `not_modified`, `not_cacheable`, `admission_warming`, `admission_rejected`, `too_large`, `store_failed`, or `store_not_allowed`. OxiBelt strips upstream-supplied values for those header names before caching or forwarding so origins cannot spoof cache status. These headers intentionally do not expose cache keys, partition values, tags, request headers, cookies, authorization material, or credential-derived values; use the authenticated admin `key-explain` endpoint for cache-key inspection.

`[cache.surrogate]` parses `Surrogate-Control` for `no-store`, `max-age`, `stale-if-error`, and `stale-while-revalidate`. When enabled, those directives control OxiBelt cache metadata ahead of origin `Cache-Control`, and `strip_response_header = true` removes `Surrogate-Control` before downstream delivery and cached hits. `tag_headers` extracts whitespace- or comma-separated cache tags from response headers such as `Surrogate-Key` and `Cache-Tag`; admin tag purge can remove all entries carrying a tag. `background_refresh` serves a stale response immediately during `stale-while-revalidate` and refreshes eligible GET/HEAD responses in the background. OxiBelt skips background refresh for response-WAF inspected routes, HTTP/3 upstreams, and PROXY protocol egress routes, which continue to use foreground revalidation. `lock_wait_timeout_ms` bounds local collapsed-forwarding followers and shared fill-conflict polling so a stuck fill cannot block indefinitely.

`[cache.admission]` filters what is admitted into cache after HTTP cacheability checks. `statuses` limits response status codes, `content_types` optionally limits MIME patterns, `max_body_bytes = 0` means unlimited, `min_hits` requires repeated fills before storing, and `max_tracked_keys` bounds frequency tracking memory. `max_vary_fields` and `max_vary_variants_per_key` reject unbounded `Vary` explosions before storing. `bypass_request_headers` keeps credential-bearing requests out of cache by default. Cache fills collect only responses whose announced body size is no greater than both `cache.max_size_bytes` and `proxy.buffering.max_memory_body_bytes`; larger responses are eligible for bounded temp-file streaming when `stream_large_objects = true`, the policy resolves to `disk` or `memory_then_disk`, and the response length is known. Streaming fills forward the response while writing a temporary body file, atomically commit metadata at EOF, and remove the temporary file on limit or body errors. Memory-only policies and unknown-size responses continue to stream downstream without being stored. Named `[[cache.policies]]` may override partition keys, tag headers, tag limits, Vary limits, background refresh settings, lock wait timeout, admission, stale-if-error behavior, and negative-cache defaults.

Cache poisoning defenses should be explicit in production configs. Keep `Authorization` and `Cookie` requests out of cache unless the cache key intentionally varies by a safe credential-derived token; include the effective `Host` in `cache_key`; rely on upstream `Vary` for negotiated headers; and prefer `{query:name}` allowlist-style keys over broad `{query}` when only selected query parameters affect the response.

`[admin]` exposes operations APIs such as cache purge and upstream-pool runtime control. This section is available in the compatibility `oxibelt` package and its standalone and `dataplane` images. The optional `oxibelt-dataplane-strict` package accepts an omitted or disabled/default Admin section for configuration compatibility, but rejects any effective Admin listener, HTTP/3, mutation, operation, audit, cluster, or secret-activation capability before binding sockets or starting background services. It applies the same rule to reload candidates and keeps the active generation when a candidate is rejected. Use file/signal reload or `kubernetes_immutable` rollout for strict deployments; choose a compatibility artifact when Admin control is required.

For compatibility artifacts, `transport = "auto"` accepts plaintext only from `plaintext_allowed_source_cidrs`; other clients must use TLS. Use `plaintext_allowlist` for Docker bridge or same-host management networks that intentionally use plaintext, and add those CIDRs explicitly. `transport = "plaintext"` is rejected unless `allow_insecure_plaintext = true`. When admin TLS is enabled, `server_names` are matched case-insensitively and may use a leftmost wildcard such as `*.ops.example.com`; missing or unknown SNI is rejected by default. By default, Admin requests require `Authorization: Bearer <token>`.

`[admin.workload_identity]` is an opt-in Admin-only binding between a verified mTLS client certificate and IPM authorization. It requires `admin.transport = "tls"`, `admin.tls.enabled = true`, `admin.tls.client_auth.mode = "require"`, `ipm.enabled = true`, enabled Admin audit, and at least one `[[ipm.trust]]` mapping with `source = "mtls"` to a principal. OxiBelt accepts exact `spiffe_id`, `san_uri`, and lowercase exact `san_dns` mappings; wildcard DNS names and group mappings are rejected. A certificate must map to exactly one enabled principal. `spiffe_id` accepts a canonical SPIFFE URI SAN only when it is the certificate's single URI SAN.

```toml
[admin.workload_identity]
enabled = true
bearer_mode = "required" # required | optional
# Static emergency denylist; use 64-character lowercase SHA-256 leaf fingerprints.
revoked_certificate_fingerprints_sha256 = []

[[ipm.trust]]
source = "mtls"
claim = "spiffe_id"
value = "spiffe://example.test/ns/edge/sa/controller"
principal = "controller"
```

With `bearer_mode = "required"`, the bearer or break-glass credential must resolve to the same IPM principal as the certificate. `optional` permits a mapped certificate to act as that principal without a bearer credential. A missing, malformed, revoked, unmapped, ambiguous, or mismatched identity returns the generic Admin `401` response. Certificate rotation can overlap old and new exact SAN mappings while both target the same principal. Certificate-chain failures such as an unknown CA or expired certificate fail during TLS and never reach HTTP authorization. The binding applies to Admin TCP TLS and Admin HTTP/3 only; it does not change public listener identity behavior. `/admin/v1/capabilities` reports whether the binding is active and its bearer mode.

`[admin.http3]` enables an opt-in UDP HTTP/3 Admin listener for Admin WebTransport operation event subscriptions. It requires `admin.enabled = true`, `admin.tls.enabled = true`, and Admin TLS settings that allow TLS 1.3. When `bind` is omitted, OxiBelt listens on the same IP and port as `admin.bind` over UDP; the existing HTTP/1 Admin listener remains unchanged.

```toml
[admin.http3]
enabled = false
# bind = "127.0.0.1:9092"
```

`[admin.operations]` controls long-running operation execution and optional
PostgreSQL persistence:

```toml
[admin.operations]
enabled = true
persistence = "auto" # auto | ephemeral | postgres
# backend = "cluster"
artifact_key_env = "OXIBELT_ADMIN_OPERATION_ARTIFACT_KEY"
lease_seconds = 15
lease_renew_seconds = 5
max_lifetime_seconds = 86400
artifact_max_bytes = 16777216
checkpoint_max_bytes = 1048576
max_running = 4
max_queued = 64
max_stored = 256
retention_seconds = 3600
event_buffer = 256
result_max_bytes = 16777216
websocket = true
webtransport = true
webtransport_max_sessions = 64
```

`persistence = "ephemeral"` retains the process-local store, rejects `backend`,
and loses operation state on restart. `persistence = "postgres"` selects a
named PostgreSQL `[[shared_state.backends]]` entry, either directly through
`backend` or from `[admin.audit.store].backend`. It also requires enabled
PostgreSQL-acknowledged Admin audit on that same backend with enforcing coverage
for `operations.write` and `operations.lifecycle`, a non-empty stable instance
ID in `[shared_state].instance_id_env`, and a standard-base64 artifact key of
exactly 32 bytes in `artifact_key_env`. Durable operation inputs and checkpoints
are encrypted with that key; the key is never stored in TOML or the operation
journal.

The default `auto` mode activates PostgreSQL persistence only when the runtime
can establish all durable prerequisites. Supplying `backend` in `auto` still
requires it to name a configured PostgreSQL shared-state backend, but a missing
artifact key or enforcing audit configuration leaves the runtime explicitly
ephemeral instead of making otherwise compatible configurations fail startup.
Once durable handling activates it does not fall back to process-local state on
a database failure. Explicit `postgres` fails validation when any prerequisite
is missing.

`retention_seconds` must be between 1 and 2,592,000 seconds. `lease_seconds`
must be between 3 and 300, and `lease_renew_seconds` must be positive and no
more than one third of the lease. `max_lifetime_seconds` must be between 60 and
2,592,000 and at least as large as the lease. `artifact_max_bytes` is bounded
to 16 MiB, while
`checkpoint_max_bytes` must be positive and no larger than the artifact bound.
These limits prevent retained operation state from becoming unbounded.

Existing Admin endpoints remain synchronous unless `Prefer: respond-async` is
supplied. Accepted async requests return `202` with `Location`,
`Operation-Location`, and
`Preference-Applied: respond-async`. IDs are `op_<uuid-v4>` with canonical
lowercase UUIDs. `GET /admin/v1/operations/{id}/events` streams SSE by default
or NDJSON with `?format=ndjson`; this follows MCP Streamable HTTP-style event
streaming semantics, but OxiBelt is not a full MCP server. WebSocket event
subscriptions are limited to `/admin/v1/operations/{id}/events/ws`.
When both `[admin.http3]` and `admin.operations.webtransport` are enabled,
HTTP/3 clients may use WebTransport `CONNECT
/admin/v1/operations/{id}/events/wt`; OxiBelt accepts the session and writes
newline-delimited JSON operation events on one server-initiated unidirectional
stream. The server replays history, emits heartbeats, and closes the stream
after a terminal operation event.

The `webtransport_snapshot` and `webtransport_drain` operation kinds inspect
and control active data-plane WebTransport sessions tracked in the local
process. Sessions are exposed with opaque `wts_<uuid>` IDs and metadata for
route, upstream, peer IP, client IP, start time, and last activity. Drain
requests accept:

```json
{
  "scope": { "session_ids": [], "route": null, "upstream": null, "client_ip": null },
  "grace_ms": null,
  "close_code": 0,
  "reason": "admin webtransport drain"
}
```

If `grace_ms` is omitted, OxiBelt uses
`runtime.drain.long_connection_close_delay_ms`. A drain rule rejects new
matching sessions with `503`, then closes remaining matching sessions after
the grace period. Cancelling the drain operation removes the rule but cannot
restore sessions that have already closed.

`[admin.audit]` emits versioned structured Admin audit events and separates
standards-oriented export from audit-of-record acknowledgement. The canonical
modes are:

- `best_effort`: persistence/export failure is observable but does not reject
  the Admin operation.
- `durable_required`: every Admin audit event must reach the configured
  acknowledgement boundary.
- `durable_required_for_actions`: events for the exact entries in
  `required_actions` must reach that boundary; other events remain
  best-effort. The accepted action IDs are `config.load`, `config.rollback`,
  `config.files_sync`, `config.downstream_tls_reload`,
  `config.upstream_tls_refresh`, `config.key_rotate`,
  `config.secret_reference_update`, `ipm.write`, `break_glass.activate`,
  `break_glass.revoke`, `membership.propose`, `membership.activate`,
  `membership.cancel`, `operations.write`, `operations.lifecycle`,
  `cache.warm`, `cache.purge`,
  `person_proof.revoke`, `lifecycle.drain`, `lifecycle.undrain`,
  `dynamic_policy.write`, `upstream_pool.write`, and `stream_pool.write`.
  Unknown, duplicate, wildcard, or empty selections are rejected.

The legacy TOML value `mode = "enforcing"` is accepted as an alias for
`durable_required`; it is not a weaker fourth mode. `acknowledgement =
"postgres"` synchronously inserts the required event into the configured
PostgreSQL store. `acknowledgement = "fsynced_spool"` synchronously appends the
event to the local spool and acknowledges it only after the record and chain
head are fsynced; a background task replays it idempotently to PostgreSQL when
a store is configured. Required operations return `503` before their side
effect if their acknowledgement boundary is unavailable, full, oversized, or
fails integrity/I/O checks. Best-effort delivery warns, counts, and may drop
instead. Legacy `admin.audit.backend` and `required_sinks = ["store"]` retain
their PostgreSQL-acknowledgement meaning and cannot be combined with
`fsynced_spool` acknowledgement.

`[admin.audit.spool]` is disabled by default. When enabled it requires an
absolute, exclusive writable directory; defaults are 64 MiB
(`max_bytes = 67108864`), 16,384 records, and 64 KiB per encoded event. All
three bounds must be positive, and one event cannot exceed the total byte
bound. The spool does not evict unacknowledged records to admit new ones. It
reserves one event slot and `max_event_bytes` of byte capacity for the terminal
record while acknowledging a required intent, so ordinary/concurrent appends
cannot consume outcome capacity after a side effect is admitted. A required
intent is rejected before its handler unless both the intent and worst-case
terminal record fit; size `max_events` and `max_bytes` for these paired records.
It
uses restrictive directory/file permissions, atomic record publication,
directory fsync, a single-writer lock, startup recovery, and ordered integrity
verification. Corrupt, truncated, reordered, symlinked, or otherwise invalid
entries stop replay rather than being silently deleted. Spool, acknowledgement,
mode/action selection, and integrity authority are restart-only settings.

On Kubernetes, mount the spool through the chart's existing `extraVolumes` and
`extraVolumeMounts` interfaces as a per-Pod exclusive writable volume; do not
share one spool directory between replicas. An `emptyDir` survives an OxiBelt
container restart in the same Pod but not Pod replacement, eviction, or node
loss. Use an appropriately retained per-Pod volume when those failures must be
inside the durability boundary. The volume must remain writable when
`readOnlyRootFilesystem` is enabled, and operators must size it for their
worst-case PostgreSQL outage.

Every new event uses schema `oxibelt.admin.audit/v1` and records an occurrence
timestamp, event and instance IDs, `intent` or `terminal` phase, HTTP and
mutation request IDs, actor/workload/credential identity, canonical source
address and durability action, revisions and content digest, result/error code,
redacted request context, and an integrity envelope. OxiBelt always creates a
domain-separated SHA-256 chain over recursively key-sorted canonical JSON. Set
both `hmac_key_env` and `hmac_key_id` to add HMAC-SHA256; the environment value
must be standard base64 encoding of exactly 32 bytes and key material is
held in zeroizing memory and cleared when released. Existing PostgreSQL rows remain queryable as
`legacy-v0` with unavailable v1 occurrence/integrity fields represented as
`null`; OxiBelt does not fabricate hashes for historical data.
Changing between SHA-256 and HMAC-SHA256, or changing `hmac_key_id`, starts a
new event chain at sequence zero after startup anchoring drains the prior
chain's candidate. Retain the previous HMAC key under its historical ID for
independent verification of retained evidence; chain restart never rewrites
old events.

`[admin.audit.anchor]` optionally seals contiguous ranges of the local v1
event chain into signed `oxibelt.admin.audit.checkpoint/v1` checkpoints and
submits them to a separately administered PostgreSQL authority. The authority
receives chain and deployment metadata, the sequence range, chain head,
checkpoint predecessor, Ed25519 key ID, signature, and checkpoint digest. It
does not receive Admin event payloads, actor identity, request summaries,
credentials, or signing keys. This boundary makes later deletion or rewriting
of already anchored local evidence detectable without turning the authority
into a second Admin audit query store.

Anchoring requires all of the following:

- enabled PostgreSQL `[admin.audit.store]` acknowledgement with
  `acknowledgement = "postgres"`;
- enabled shared state, a stable nonempty value in
  `shared_state.instance_id_env`, and a nonempty deployment epoch in
  `deployment_epoch_env`;
- an anchor sink backend that names a PostgreSQL `[[shared_state.backends]]`
  entry different from the Admin audit store backend;
- a stable configured `authority_id` that exactly matches the external
  authority's `authority_info()` result; and
- a purpose-bound `oxibelt-keysigner` socket, an Ed25519 checkpoint key, a raw
  32-byte pinned public-key file, and a separate 32-byte base64 IPC token.

The dual-PostgreSQL boundary is mandatory, not a naming convention. OxiBelt
rejects two differently named backends when their resolved PostgreSQL targets
identify the same database. Use separate connection URLs, login roles,
databases, owners, and backup/administration policy for the local audit store
and checkpoint authority.
Activation and every submission also compare the live PostgreSQL database name
and postmaster identity, so DNS, loopback, Unix-socket, and connection-URL
aliases cannot collapse the two configured backends onto one database.

The instance ID must remain stable for one replica across process restarts.
The deployment epoch must remain stable for all restarts of the same deployed
artifact/configuration epoch and change deliberately when the operator starts
a new deployment epoch. Fixed-member cluster checkpoints also bind the
configured cluster and membership epoch. The stream ID is a deterministic,
domain-separated SHA-256 digest of namespace, optional cluster ID, and instance
ID, so deployment inventory can state the exact expected stream set without
trusting the checkpoint authority to enumerate it.

`record_interval` defaults to `1024` events and may be `1` to `1000000`.
`time_interval_ms` defaults to `60000` and may be `1000` to `3600000`; the
worker seals a nonempty candidate when either threshold is due. The local
PostgreSQL outbox and the audit event are updated in one transaction.
`max_pending_checkpoints` defaults to `1024` and may be `2` to `65536`;
`max_pending_bytes` defaults to 16 MiB and may be 128 KiB to 256 MiB. Anchored
deployments additionally limit `admin.audit.spool.max_event_bytes` to 64 MiB
so an independent verifier can configure a matching bounded per-event limit.
Pending signed checkpoints form an ordered predecessor chain and are never
evicted to admit a new checkpoint. If that bounded outbox is full or the next
checkpoint cannot yet be signed, the fixed-size candidate metadata keeps
advancing to the latest local chain head; after capacity recovers, one
checkpoint coalesces that
continuous outage range. This does not grow outbox rows or bytes, while
`anchor_lag_sequences` exposes the increasing assurance gap. `submit_timeout_ms`
defaults to `5000` and may be `100` to `60000`.

For `best_effort` audit, authority submission failures make anchoring degraded,
increment bounded-label metrics, and retain pending evidence for retry. For a
durable audit mode, the anchor is readiness-critical and required events do not
report success until their checkpoint has an external authority receipt. A
capacity, signer, authority, receipt, or continuity failure therefore rejects
required work and fails readiness. `admin.mutations.mode = "required"` also
requires anchoring to be enabled so a protected mutation cannot report success
with only evidence inside the mutation/audit database boundary. Anchor and
signer settings are restart-only.

Install the authority schema from
`deploy/postgres/admin-audit-anchor-v1.sql` while connected as a dedicated
authority owner (prefer a `NOLOGIN` owner selected by a narrowly privileged
installer with `SET ROLE`). Set the immutable authority ID in that same `psql`
session after selecting the owner role:

```sh
psql "$OXIBELT_AUDIT_ANCHOR_OWNER_URL" --set ON_ERROR_STOP=1 \
  --command "SET ROLE oxibelt_anchor_owner" \
  --command "SET oxibelt.anchor_authority_id = 'production-audit-authority-1'" \
  --file deploy/postgres/admin-audit-anchor-v1.sql
```

Create the runtime and verifier login roles separately, then grant only the
function surfaces each role needs (replace the example role names with
operator-managed identifiers):

```sql
GRANT USAGE ON SCHEMA oxibelt_audit_anchor_v1
  TO oxibelt_anchor_runtime, oxibelt_anchor_verifier;
GRANT EXECUTE ON FUNCTION oxibelt_audit_anchor_v1.authority_info()
  TO oxibelt_anchor_runtime, oxibelt_anchor_verifier;
GRANT EXECUTE ON FUNCTION oxibelt_audit_anchor_v1.append_checkpoint(jsonb),
  oxibelt_audit_anchor_v1.lookup_checkpoint(text, text, bigint)
  TO oxibelt_anchor_runtime;
GRANT EXECUTE ON FUNCTION oxibelt_audit_anchor_v1.checkpoints(text, text),
  oxibelt_audit_anchor_v1.head(text, text)
  TO oxibelt_anchor_verifier;
```

Do not grant either role direct table privileges. Keep the authority on a
separate failure, administration, backup, and credential boundary from the
OxiBelt host and local Admin audit database. Protect both database connections
with verified TLS, restrict runtime authority egress, retain authority backups,
and give the independent verifier read-only URLs that use the verifier role.

The checkpoint signer must use a dedicated socket, token, identity, peer
allowlist, and key set. A keysigner daemon is purpose-exclusive: activation is
rejected if one process loads both TLS and audit checkpoint keys, even when
their IDs and key material differ. `--audit-checkpoint-key` accepts
`KEY_ID=ED25519_PRIVATE_KEY_PEM`; it does not expose that key through the TLS
signing request purpose. The configured pin is the corresponding raw 32-byte
Ed25519 public key, not PEM or DER.

Rotate a checkpoint key only after writes have been quiet for at least one
configured `time_interval_ms`, `pending_checkpoints` and `pending_bytes` are
both zero, and the verifier has recorded the current authority head in its
independent witness. The quiet interval lets the background worker seal and
submit any in-progress candidate, which is durable but is not yet counted as
an outbox checkpoint. Then deploy the new signer key, `key_id`, and public-key
pin as one restart-only change, while retaining both old and new public keys in
the verifier trust set for every retained checkpoint. OxiBelt refuses to sign a
pending checkpoint whose embedded key ID differs from the active signer; if a
restart occurs mid-rotation, restore the prior signer configuration, drain the
outbox, and repeat the rotation. Never relabel a pending checkpoint with the
new key ID.

Checkpoint-key rotation is separate from local audit HMAC rotation. When
`admin.audit.integrity.hmac_key_id` changes, retain each historical raw
32-byte HMAC key on the independent verifier and pass it with
`oxibeltctl audit verify --trusted-hmac-key KEY_ID=FILE` for as long as local
events under that key are retained. Keep each verifier key file owner-only;
missing historical HMAC material produces an `incomplete` report and a tag
that fails verification produces `invalid`.

```sh
oxibelt-keysigner \
  --socket /run/oxibelt-audit-keysigner/signer.sock \
  --audit-checkpoint-key audit-anchor-2026-07=/run/secrets/audit-anchor.ed25519.pem \
  --token-env OXIBELT_AUDIT_KEYSIGNER_TOKEN \
  --allow-peer-uid 10001
```

An enabled configuration has this shape:

```toml
[shared_state]
enabled = true
namespace = "oxibelt"
instance_id_env = "OXIBELT_INSTANCE_ID"

[[shared_state.backends]]
name = "audit-local"
kind = "postgres"
connection_url_env = "OXIBELT_ADMIN_AUDIT_POSTGRES_URL"

[[shared_state.backends]]
name = "audit-anchor"
kind = "postgres"
connection_url_env = "OXIBELT_AUDIT_ANCHOR_POSTGRES_URL"

[admin]
enabled = true

[admin.audit]
enabled = true
mode = "durable_required"
acknowledgement = "postgres"

[admin.audit.store]
enabled = true
kind = "postgres"
backend = "audit-local"

[admin.audit.anchor]
enabled = true
record_interval = 1024
time_interval_ms = 60000
deployment_epoch_env = "OXIBELT_DEPLOYMENT_EPOCH"
max_pending_checkpoints = 1024
max_pending_bytes = 16777216

[admin.audit.anchor.sink]
kind = "postgres"
backend = "audit-anchor"
authority_id = "production-audit-authority-1"
submit_timeout_ms = 5000

[admin.audit.anchor.signer]
kind = "keysigner"
socket_path = "/run/oxibelt-audit-keysigner/signer.sock"
key_id = "audit-anchor-2026-07"
public_key_file = "admin-audit/audit-anchor-2026-07.ed25519.pub"
token_env = "OXIBELT_AUDIT_KEYSIGNER_TOKEN"
# token_file = "admin-audit/keysigner-token.b64"
token_reload_interval_ms = 1000
connect_timeout_ms = 250
sign_timeout_ms = 1000
```

Relative signer public-key and token files resolve under the configured
certificate directory. `token_file`, when set, takes precedence over
`token_env`, is reloadable, and must contain standard base64 for exactly 32
bytes. A signer-reported public key that differs from `public_key_file` fails
activation.

`[admin.audit.export]` can route events to the Access Log Admin source, which
projects OCSF or ECS JSON to stdout or OTLP according to
`[access_log.stdout]`, `[access_log.otlp]`, and `[access_log.admin]`. These
exports remain best-effort observability/SIEM integrations, not query stores or
acknowledgements. `[admin.audit.store]` is the query store for `GET
/admin/v1/audit`; PostgreSQL is the only store kind. Its `backend` must name a
PostgreSQL `[[shared_state.backends]]` entry and requires
`[shared_state].enabled = true`. The endpoint requires `admin:ReadAudit` on
`oxibelt:<namespace>:admin:audit/admin`; no configured query store returns
`409`, while an unavailable store or unreadable stored record returns `503`.
It supports `limit`, `outcome`, `actor`, `principal`, `service`, `operation`,
`request_id`, `path_prefix`, and `before_id`. Bodies, bearer tokens,
certificates, mutation signatures, keys, and arbitrary handler/database errors
are never retained; summaries contain bounded structure and explicitly safe
scalar context only.

Export-only Admin audit for container-native logs:

```toml
[admin]
enabled = true

[admin.audit]
enabled = true
mode = "best_effort"

[admin.audit.store]
enabled = false

[admin.audit.export]
enabled = true
sinks = ["access_log"]

[access_log.admin]
enabled = true

[access_log.stdout]
enabled = true
schema = "ocsf"
```

Fail-closed durable Admin audit with external exports:

```toml
[admin]
enabled = true

[admin.audit]
enabled = true
mode = "durable_required"
acknowledgement = "postgres"
queue_capacity = 4096

[admin.audit.store]
enabled = true
backend = "cluster"
kind = "postgres"

[admin.audit.export]
enabled = true
sinks = ["access_log"]

[access_log.admin]
enabled = true

[access_log.stdout]
enabled = true
schema = "ocsf"

[access_log.otlp]
enabled = true
endpoint = "https://otel-collector:4318/v1/logs"
trusted_ca_certs = ["otel-collector-ca.pem"]
schema = "ocsf"
```

Fail-closed selected actions with a local fsynced spool:

```toml
[admin.audit]
enabled = true
mode = "durable_required_for_actions"
acknowledgement = "fsynced_spool"
required_actions = [
  "config.load",
  "config.rollback",
  "config.files_sync",
  "config.downstream_tls_reload",
  "config.key_rotate",
  "config.secret_reference_update",
  "ipm.write",
  "break_glass.activate",
  "break_glass.revoke",
  "membership.propose",
  "membership.activate",
  "membership.cancel",
]

[admin.audit.spool]
enabled = true
directory = "/var/lib/oxibelt/admin-audit"
max_bytes = 67108864
max_events = 16384
max_event_bytes = 65536

[admin.audit.integrity]
hmac_key_env = "OXIBELT_ADMIN_AUDIT_HMAC_KEY"
hmac_key_id = "audit-2026-07"

[admin.audit.store]
enabled = true
backend = "cluster"
kind = "postgres"
```

The legacy compatibility shape remains accepted:

```toml
[admin.audit]
enabled = true
backend = "cluster"
queue_capacity = 4096
```

It is treated as `mode = "durable_required"`, `acknowledgement = "postgres"`,
with `[admin.audit.store]` enabled for `cluster` and
`required_sinks = ["store"]`.

`[admin.mutations]` enables durable replay protection for high-risk Admin
changes. `mode` is `off`, `optional`, or `required`. `optional` validates and
records supplied envelopes while preserving compatibility for callers that do
not send one; `required` rejects a protected request without
`X-OxiBelt-Mutation`. Both active modes require `backend` to name a PostgreSQL
shared-state backend and require durable Admin audit coverage for all twelve
protected action IDs with the durable store on that same backend. `required`
also requires `[admin.audit.anchor].enabled = true` and external authority
evidence before reporting protected-mutation success. A local fsynced audit
acknowledgement does not replace the P1-13 PostgreSQL replay ledger or its
transactional critical audit records; protected mutations still fail closed
when either required PostgreSQL authority is unavailable.
Expiry and retention are evaluated with PostgreSQL time. The retention window
must cover the maximum validity and clock-skew windows, and a live request or
terminal receipt is never evicted to admit another request.

```toml
[admin.mutations]
mode = "required" # off | optional | required
backend = "cluster"
max_validity_seconds = 600
max_clock_skew_seconds = 30
retention_seconds = 86400
max_response_bytes = 1048576
artifact_key_env = "OXIBELT_ADMIN_MUTATION_ARTIFACT_KEY"

[[admin.mutations.signers]]
id = "gateway-controller-2026-07"
principal = "controller"
suite = "ed25519" # ed25519 | ed25519_ml_dsa_44
ed25519_public_key_file = "admin-mutation/controller.ed25519.pub"
# ml_dsa_44_public_key_file = "admin-mutation/controller.ml-dsa-44.spki"

[admin.mutations.rollout]
mode = "single_instance" # single_instance | admin_cluster
cluster_id = "edge-a"
members = []
instance_id_env = "OXIBELT_INSTANCE_ID"
heartbeat_interval_seconds = 5
stale_after_seconds = 15
phase_timeout_seconds = 300
rollback_timeout_seconds = 300
canary_observation_seconds = 30

[admin.mutations.rollout.membership]
mode = "fixed" # fixed | staged
# readiness_private_key_file_env = "OXIBELT_ADMIN_MEMBERSHIP_READINESS_KEY_FILE"
# catchup_private_key_file_env = "OXIBELT_ADMIN_MEMBERSHIP_CATCHUP_KEY_FILE"

# [[admin.mutations.rollout.membership.bootstrap_members]]
# id = "edge-a"
# readiness_ed25519_public_key = "<canonical-base64-32-bytes>"
# catchup_x25519_public_key = "<different-canonical-base64-32-bytes>"
```

Signer IDs are unique and bind one signature suite and one IPM principal.
Public-key paths resolve under the configuration root, must be regular contained
files, and never contain private key material. The Ed25519 file contains the
32-byte public key; the ML-DSA-44 file contains its DER public key.
`ed25519_ml_dsa_44` is accepted
only when the post-quantum build feature is present and requires both public
keys and both valid signatures over the same suite-bound transcript; there is
no automatic downgrade. `artifact_key_env` supplies a base64-encoded 32-byte
AEAD key used for encrypted cluster commands and rollback artifacts. Every
member in one fixed cluster must receive the same key through a protected
external secret channel and keep it stable across restarts. The key and
plaintext artifacts must not be placed in TOML, PostgreSQL, audit events,
mutation receipts, support bundles, or logs.

`admin_cluster` uses fixed membership by default. It requires all of
the following:

- `[admin.mutations] mode = "required"` and the existing same-PostgreSQL
  mutation-ledger and enforcing-audit requirements;
- `OXIBELT_CONFIG_ROLLOUT_MODE=admin_cluster` and
  `[runtime.hot_reload] mode = "off"`;
- a non-empty cluster ID and 2 through 1,024 unique member IDs;
- `instance_id_env` naming a valid environment variable whose value is one
  configured member in fixed mode (staged mode also permits a non-participating
  learner identity);
- in fixed mode, `artifact_key_env` containing exactly 32 base64-encoded
  bytes; staged bootstrap and retained version-`1` epochs also require this
  legacy key until their encrypted artifacts no longer need to be opened;
- heartbeat interval `1..=60` seconds, stale interval at least twice heartbeat
  and at most 300 seconds, canary observation `1..=600` seconds, phase timeout
  greater than observation and at most 3,600 seconds, and rollback timeout
  `1..=3,600` seconds.

Member order is not significant. OxiBelt derives the signed membership target
from the cluster ID and canonical sorted member set. All members must use the
same membership, compatible build/capability version, and artifact key. A
missing, extra, stale, duplicate, incompatible, or differently keyed member
keeps durable write authority unavailable. In `fixed` mode, membership changes are an offline
operation: stop protected writes, allow old leases and nonterminal rollouts to
finish or expire, deploy the exact new set, and wait for every member to report
the same baseline revision/digest before admitting work. Do not reuse a cluster
ID to overlap old and new live memberships.

`membership.mode = "staged"` is experimental and replaces offline changes with
authenticated durable epochs; it does not replace the all-active-member
authorization rule. `bootstrap_members` must contain exactly the IDs in
`rollout.members`, with one distinct canonical-base64 32-byte Ed25519 readiness
public key and X25519 catch-up public key per member. Public keys are unique
within their purpose and the readiness and catch-up sets must be disjoint.
`instance_id_env` may identify a process outside the active epoch so that a new
instance can start as a learner, but that process remains unable to heartbeat
as active, coordinate, validate, acknowledge, serve privileged mutation
decisions, or make the rollout ready.

`readiness_private_key_file_env` and `catchup_private_key_file_env` name two
different environment variables. Each environment variable contains an
absolute member-local file path, not private-key bytes. At startup OxiBelt opens
each path once for reading; on Unix it uses no-follow and close-on-exec flags,
inspects the opened descriptor, and rejects a symlink, non-regular file, empty
file, oversized file, or permissions that grant any group or other access.
Use an owner-only mode such as `0400` or `0600`. The readiness file is bounded
to 4,096 bytes and contains an Ed25519 PKCS#8 private key either as raw DER or
canonical standard-base64 text. The catch-up file is bounded to 256 bytes and
contains exactly 32 raw X25519 private-key bytes or their canonical
standard-base64 text. OxiBelt derives both public keys and, when the local
identity is a bootstrap member, requires exact matches with that member's
configured public keys. Keep the private files and their environment-variable
values out of TOML, PostgreSQL, receipts, diagnostics, support bundles, and
logs; mount them read-only from an external secret channel.

A fresh staged cluster initially uses the configured legacy shared
`artifact_key_env` key for the fixed bootstrap boundary. Active and retained
version-`1` membership epochs also require that same key to reopen their
encrypted command or rollback artifacts after restart. Keep the legacy secret
available while any required version-`1` history remains; do not rotate it as
part of an ordinary membership transition. Every new proposal creates a
version-`2` epoch with a fresh random 32-byte per-epoch artifact key, `K_next`,
binds its SHA-256 fingerprint into the epoch digest, and wraps it independently
to every target member through that member's X25519 key. PostgreSQL stores only
the authenticated wraps and fingerprint. Each target member must unwrap the
same `K_next` binding and submit an Ed25519-signed key proof before activation.
After the cluster is active on version `2`, protected artifacts use the
epoch-specific key; the shared legacy environment key is not a substitute for
a missing version-`2` wrap.

Persisted epoch documents and readiness receipts with version `1` remain
readable and verifiable under their original digest and signature domains. A
readiness receipt must have the same version as its target epoch. Version `1`
does not carry source-epoch, epoch-key fingerprint, checkpoint, journal-tail,
or verified-position evidence and remains on the legacy manual readiness path.
Version `1` requires capability `admin-mutation-rollout-v1`; version `2`
requires all of the additional evidence fields and capability
`admin-membership-epoch-v2`. Both require the exact running build. OxiBelt
never rewrites old evidence or silently treats a version-`1` receipt as version
`2`.

Operate staged transitions in this order:

1. Submit an all-current-member protected `initialize`, `join`, `maintenance`,
   `remove`, or `rejoin` proposal with the exact active-epoch precondition.
2. For `join` or `rejoin`, provision the learner's configuration, IPM, and
   break-glass heads out of band. The learner opens the recipient-encrypted
   bounded checkpoint, reverifies its journal and retained commands, and
   requires all locally provisioned heads to match exactly.
3. Wait for every target member's exact `K_next` key proof and, for a learner,
   its distinct signed readiness receipt. Neither kind of evidence makes the
   member active.
4. Submit a separate protected activation mutation. Every old active member
   must authorize and acknowledge it; every version-`2` target member must have
   proved its exact epoch key.
5. Treat the target epoch as authoritative only after the activation mutation
   commits and the membership-finalizer transaction invalidates old
   heartbeats, advances the membership-head `fence_cutoff`, and appends the
   fence and activation receipts atomically.

`maintenance` and `remove` both propose an epoch without the exact named active
member. That member is not silently ignored: the complete old boundary must be
healthy enough to authorize the change, and the removed process releases its
old fence and remains unable to heartbeat under the new epoch. Return it only
through `rejoin`, with current trust material, new catch-up, key proof,
readiness, and a separate activation. This is intentionally different from
majority quorum.

Only one unresolved membership transition is permitted. A transition can be
cancelled through its protected cancellation mutation only before activation
authorization.
Proposal, activation-authorization, and cancellation rollback append
compensating receipts instead of erasing prior evidence. On restart OxiBelt
loads the durable epoch and key wraps and finalizes only a committed activation;
it never infers success from partial local files. A mutation whose activation
outcome is `indeterminate` makes the transition and staged epoch indeterminate
without activating the target. Its retained `membership` logical-resource
reservation blocks later membership transitions until an operator reconciles
and repairs the durable evidence. Unrelated protected resources may continue
only under the unchanged exact active epoch and its complete all-member proof.

The retained epoch/key history is bounded at 64 epochs per cluster. A proposal
that would exceed the bound is rejected before creating another epoch, with an
instruction to archive unreferenced terminal evidence. This release does not
provide an ordinary Admin endpoint that deletes or archives membership
authority. Do not delete PostgreSQL rows ad hoc to bypass the bound; keep staged
mode enabled and use an explicitly reviewed supported retirement/archive
procedure before proposing another epoch. Similarly, once any durable staged
head, epoch, or transition exists in the selected Admin-mutation PostgreSQL
backend and `shared_state.namespace`, startup requires
Admin mutations to remain enabled, `rollout.mode = "admin_cluster"`,
`membership.mode = "staged"`, and the same configured `cluster_id`. Disabling
Admin mutations, changing rollout mode to `single_instance`, changing
membership mode back to `fixed`, or changing the cluster ID fails startup
closed. Restore the exact staged authority settings or finish an explicit
supported retirement procedure; local TOML cannot disable, downgrade, or
rename a durable staged boundary.

Changing `shared_state.namespace` or selecting another Admin-mutation/audit
PostgreSQL backend points the process at a different authority domain. It does
not prove that the old staged cluster was retired and is never an ordinary
`initialize`, `join`, `maintenance`, `remove`, or `rejoin` transition. Treat
namespace or backend replacement as an explicit out-of-band authority migration
or disaster-recovery operation: fence the old domain, preserve and reconcile
its terminal evidence, and establish the replacement according to a separately
reviewed recovery procedure. Do not use a fresh namespace or backend merely to
bypass the durable downgrade check.

Membership metrics contain counts and a fixed transition-state label only:
`oxibelt_admin_membership_active_members`,
`oxibelt_admin_membership_fenced_members`, and
`oxibelt_admin_membership_pending_transition{state="..."}`. They never label a
series with a member ID, transition ID, epoch digest, cluster ID, or blocking
reason. Exact identities, learner cursor/digests, fenced members, and safe
blocking reasons are available only through access-controlled membership and
instance diagnostics. Emergency reconstitution after permanent loss of a
required old member is a separate disaster-recovery decision with explicit
security tradeoffs; neither ordinary membership transitions nor the normal
break-glass credential silently weaken the all-member boundary.

The PostgreSQL state machine uses database-time leases and monotonic fencing
epochs. It durably claims the signed request and encrypted command, validates
on every member, applies to a deterministic canary, observes it, expands to all
remaining members, and commits only after every exact member ACKs the same
revision and digest. NACK, timeout, readiness loss, or mismatch rolls back every
member that may have applied. An outcome that cannot prove convergence or
restoration is `indeterminate` and blocks later protected writes to that
logical resource.

The ordinary winning HTTP request waits up to 30 seconds for terminal
convergence and never returns its normal successful response early. If work is
still active it returns `409 mutation_in_progress` with `Location` and
`Retry-After`; disconnecting or reaching that timeout does not cancel ordinary
durable work, and the redacted mutation receipt is the recovery interface.
Credential create/rotate uses a longer bounded delivery window equal to four
configured phase timeouts plus the rollback timeout and stale-member interval.
Its plaintext token is process-local and non-replayable, so the admission-origin
request owns a cancellation-safe rendezvous through every forward phase. Owner
loss fails before an effect or initiates rollback; an origin crash prevents
forward takeover and reaches rollback after the durable phase timeout rather
than committing a credential whose token cannot be returned. Configuration,
file, downstream-TLS, key, and secret-reference changes are applied per member. IPM and
break-glass changes use a staged PostgreSQL mutation published once after all
members validate; the deterministic canary observes it first, then every
remaining member observes the same revision and digest before terminal commit.
Failure restores the encrypted before-image once, and an unprovable restoration
becomes `indeterminate`. Secret-reference validation additionally persists each
member's reference-set digest and assigned runtime revision; any mismatch fails
before the canary can apply.

Protected requests carry unpadded base64url JSON in
`X-OxiBelt-Mutation`. The strict envelope contains `version`, `signer_id`, a
canonical UUID `request_id`, RFC 3339 UTC `issued_at` and `expires_at`,
`expected_previous_revision`, `new_revision`,
`content_digest = "sha256:<lowercase-hex>"`, required `target` containing the
cluster and membership revision, and `signature`. Single-instance mode uses
its deterministic local target. The signature binds the
authenticated principal, IPM namespace, method, exact path/query, all unsigned
envelope fields, the normalized strong `If-Match` operational ETag, and exact
request-body bytes. The supplied ETag must equal the active operational
revision. The distinct signed `expected_previous_revision` is compared with the
PostgreSQL logical head, which is initialized from the operational revision and
advances to signed `new_revision` after a successful terminal result. Exact request-ID
retries return a reduced bounded safe result with the retained status, not
necessarily the original response body, without reapplying; conflicting reuse
and unresolved prior outcomes return `409`.

`POST /admin/v1/keys/rotate` advertises only `downstream_tls_default` and
`downstream_tls_sni`. It verifies the SHA-256 pin for the already configured,
contained key path and reloads downstream TLS; raw private-key values are
rejected. Admin TLS, QUIC host-key, and remote-signer activation are not
supported by this endpoint. `POST /admin/v1/config/secret-references/update`
activates one schema-version-1 typed environment or contained-file reference.
The request uses `field`, `reference`, and, for a file, a required lowercase
`sha256`; `schema_version` defaults to `1`. Raw values,
absolute/traversing paths, symlinks, unsupported fields, oversized values, and
mismatched file digests fail closed. The endpoint re-resolves the complete
active reference set, rebuilds an immutable runtime candidate, validates
dependent certificate/key/CA material and configured HTTPS connectivity, then
performs one atomic snapshot compare-and-swap. Readers retain their complete old
snapshot or acquire the complete new one. Candidate failure or a competing
activation leaves the old snapshot active.

The first successful response contains `ok = true` and binds the mutation
request, logical config revision, keyed reference-set digest, runtime snapshot
revision, and instance or cluster rollout target. A protected replay-safe
result also contains `token_recoverable = false` and may include `state`; those
five binding fields are present only while the retained terminal evidence can
provide them. References, environment names, paths, and plaintext material are
not returned. Only the bounded redacted result may enter receipts, audit
records, logs, and metrics. `admin_cluster` requires every configured member to
report the same reference-set digest and runtime revision before canary apply.
A prior snapshot is retained for the larger of the connection-drain and rollout
timeout windows, remains available to rollback during that grace, and is then
dropped. Owned candidate buffers and replaced remote-signer tokens are zeroized
on drop; memory copied into TLS or HTTP libraries is not claimed to be zeroized.

IPM (Identity Permission Management) is the authorization model for Admin APIs and opt-in data-plane authorization. The legacy `admin.rbac.tokens`, role names, and `permissions`/`deny_permissions` fields are rejected; use `[ipm]`, `[[ipm.credentials]]`, `[[ipm.principals]]`, `[[ipm.policies]]`, and `[[ipm.bindings]]` instead. IPM evaluates `Action`, `Resource`, and `Condition` statements with explicit deny first, matching allow second, and default deny otherwise. `admin.bearer_token_env` is retained only as a bootstrap fallback when `[ipm].enabled = false`.

Actions use `service:Action` syntax. Initial services are `admin`, `ipm`, `config`, `cache`, `upstream-pool`, `dynamic-policy`, `waf`, `lifecycle`, `runtime`, `route`, `stream`, and `turn`; `service:*` and `*` wildcards are accepted. Admin API metadata reads require `admin:ReadMetadata` on resources such as `oxibelt:<namespace>:admin:metadata/openapi`, and the unified Admin audit log requires `admin:ReadAudit` on `oxibelt:<namespace>:admin:audit/admin`. Protected control-plane configuration changes require `admin:UpdateConfig` on `oxibelt:<namespace>:admin:config` for `[admin]` changes and `ipm:UpdateConfig` on `oxibelt:<namespace>:ipm:config` for `[ipm]` changes, in addition to the base config operation permission. Route inventory reads for config-aware planning require `config:ReadRouteInventory` on `oxibelt:<namespace>:config:route-inventory/current`. IPM administration uses `ipm:GetStatus`, `ipm:ListPrincipals`, `ipm:GetPrincipal`, `ipm:CreatePrincipal`, `ipm:UpdatePrincipal`, `ipm:DeletePrincipal`, `ipm:ListCredentials`, `ipm:GetCredential`, `ipm:CreateCredential`, `ipm:UpdateCredential`, `ipm:RotateCredential`, `ipm:RevokeCredential`, `ipm:DeleteCredential`, `ipm:ListPolicies`, `ipm:GetPolicy`, `ipm:CreatePolicy`, `ipm:UpdatePolicy`, `ipm:DeletePolicy`, `ipm:ListBindings`, `ipm:CreateBinding`, `ipm:DeleteBinding`, `ipm:ReadAudit`, `ipm:SimulateSelf`, `ipm:SimulatePrincipal`, and `ipm:SimulatePolicy`. Dynamic policy automation uses `dynamic-policy:GetStatus`, `dynamic-policy:List`, `dynamic-policy:Get`, `dynamic-policy:Create`, `dynamic-policy:Apply`, `dynamic-policy:Update`, `dynamic-policy:Delete`, `dynamic-policy:Export`, `dynamic-policy:Import`, and `dynamic-policy:ReadAudit`. Upstream-pool automation uses `upstream-pool:GetStatus`, `upstream-pool:List`, `upstream-pool:Get`, `upstream-pool:AddServer`, `upstream-pool:UpdateServer`, and `upstream-pool:RemoveServer`. Runtime WebTransport operations use `runtime:GetWebTransportSessions` and `runtime:DrainWebTransportSessions`. WAF actions include telemetry reads (`waf:GetRuleHits`, `waf:GetRuleCosts`, `waf:GetCrsCompatibility`), OxiRule file management (`waf:PutOxiRule`, `waf:DeleteOxiRule`, `waf:PutOxiRuleGroup`, `waf:DeleteOxiRuleGroup`, `waf:PutOxiRulePack`, `waf:DeleteOxiRulePack`, `waf:ListOxiRulePacks`, `waf:PlanOxiRulePack`, `waf:ReloadOxiRule`), and OxiRule development tools (`waf:CheckOxiRule`, `waf:CheckOxiRuleGroup`, `waf:TestOxiRule`, `waf:ExplainOxiRule`, `waf:EstimateOxiRuleCost`, `waf:ReplayOxiRule`, `waf:ListOxiRuleTemplates`, `waf:RenderOxiRuleTemplate`, `waf:PlanOxiRuleFalsePositive`). Resources use `oxibelt:<namespace>:<service>:<resource>`, for example `oxibelt:oxibelt:admin:config`, `oxibelt:oxibelt:admin:metadata/openapi`, `oxibelt:oxibelt:admin:audit/admin`, `oxibelt:oxibelt:ipm:config`, `oxibelt:oxibelt:config:route-inventory/current`, `oxibelt:oxibelt:dynamic-policy:status/current`, `oxibelt:oxibelt:upstream-pool:status/current`, `oxibelt:oxibelt:runtime:webtransport/session/*`, `oxibelt:oxibelt:runtime:webtransport/session/<id>`, `oxibelt:oxibelt:runtime:webtransport/route/<route>`, `oxibelt:oxibelt:runtime:webtransport/upstream/<upstream>`, `oxibelt:oxibelt:runtime:webtransport/client-ip/<ip>`, `oxibelt:oxibelt:route:app`, `oxibelt:oxibelt:cache:policy/default`, `oxibelt:oxibelt:waf:oxirule/rules/block.oxirule.toml`, `oxibelt:oxibelt:waf:oxirule-rulepack/rulepacks/admin.oxirule-rulepack.toml`, `oxibelt:oxibelt:waf:oxirule-rulepack/plan`, `oxibelt:oxibelt:waf:template/admin-path`, or `oxibelt:oxibelt:waf:replay/*`. Conditions support `StringEquals`, `StringLike`, `StringNotEquals`, `IpAddress`, `NotIpAddress`, `Bool`, `DateBefore`, and `DateAfter` over keys such as `principal.subject`, `principal.groups`, `request.source_ip`, `request.method`, `request.host`, `request.path`, `request.route`, `request.protocol`, `resource.service`, `resource.name`, `time.now`, and `claim.<name>`. Admin API request conditions use the admin listener peer IP for `request.source_ip` and the Admin HTTP request method, normalized host, path, and protocol for the corresponding `request.*` keys.

Mutation-specific authorization adds `admin:ReadMutations` on
`mutation/<request_id>`, `config:GetInstances` on `instances/current`,
`config:RotateKey` on `key/<target>/<name-or-default>`, and
`config:UpdateSecretReference` on `secret-reference/<encoded-field>`.
Two-factor break glass uses `ipm:GetBreakGlassActivation` and
`ipm:ActivateBreakGlass` on `break-glass/principal/<principal>`, plus
`ipm:RevokeBreakGlass` on `break-glass/activation/<activation_id>`.

Resource-specific Admin endpoints use typed resource names and may require
multiple resources for one request. Cache operations use
`oxibelt:<namespace>:cache:policy/<policy>` plus
`oxibelt:<namespace>:cache:host/<normalized-host>`; hostless tag purge uses
`host/*`. Dynamic policy writes use
`oxibelt:<namespace>:dynamic-policy:source/<source>/name/<name>` and, when a
route is present, `oxibelt:<namespace>:dynamic-policy:route/<route>`.
Dynamic-policy and upstream-pool status reads use `status/current`.
Upstream-pool reads use `*` or `<pool>`, while server mutations use
`oxibelt:<namespace>:upstream-pool:<pool>/server/<server_id>`. IPM resources
are `status/current`, `principal/<id>`, `credential/<id>`, `policy/<name>`,
`binding/<id>`, `group/<group>`, `audit/current`, and `simulation/current`.
Dynamic resource components are percent-encoded when they contain reserved
characters such as `/`, `:`, or spaces; wildcards such as `*` and
`policy/*` continue to match through normal IPM wildcard evaluation.
Operation enqueue checks the same permission as the synchronous source action.
The creator can read, watch, and cancel their own operation. Other callers need
`admin:ListOperations` on `operation/*`, `admin:ReadOperation` on
`operation/<kind>/<id>` or `operation/*`, and `admin:CancelOperation` on the
same operation resource.

OxiRule development API requests that set `include_active_rules = true` evaluate active WAF policy as well as the submitted candidate, so they require the same devtools action on `oxirule/*`; replay uses `replay/*`.

Local OxiRule risk analysis uses `waf:AnalyzeOxiRuleRisk` on `oxibelt:<namespace>:waf:analyze/*`, and non-mutating malicious-intelligence and automation hardening suggestions use `waf:PlanOxiRuleHardening` on `oxibelt:<namespace>:waf:hardening-plan/*`. Non-mutating schema-v2 rulepack planning uses `waf:PlanOxiRulePack` on `oxibelt:<namespace>:waf:oxirule-rulepack/plan`. These endpoints do not install rules; deploy returned OxiRule, group, or rulepack TOML with `/admin/v1/files/sync`.

`[ipm].backend` optionally names a PostgreSQL `[[shared_state.backends]]` entry used to initialize the `oxibelt_ipm_*` operational tables. If `backend` is omitted and no shared-state default backend is configured, OxiBelt uses static TOML-defined IPM principals, credentials, policies, and bindings only. With a backend, OxiBelt builds a strict hybrid snapshot: TOML entries are bootstrap/read-only entries, DB rows augment them, and a DB row with the same principal, credential, policy, or binding ID as TOML fails refresh. Startup follows `[ipm].fail_closed`; later refresh failures keep the last-good IPM snapshot. With `[ipm].enabled = true`, each normal `[[ipm.credentials]]` bearer-token environment variable must be set and non-empty at startup.

DB-backed credentials store only `sha256-v1` token digests and token prefixes. Create and rotate generate a 32-byte random `obt_v1_<base64url>` token and return the plaintext token once. Rotation keeps the previous token digest accepted until the requested overlap expires, while revoke clears previous-token overlap and marks the credential unusable. Admin mutations require `If-Match` with the ETag from `GET /admin/v1/ipm/status`; `oxibeltctl ipm` fetches it automatically when `--etag` is omitted.

`[ipm.break_glass].argon2id_memory_mib` limits the Argon2id memory parameter accepted for break-glass access token hashes. The default is `128` MiB and the maximum configurable value is `16384` MiB. This bound is checked at configuration load time before any supplied break-glass token can be verified. `access_mode = "direct"` preserves the existing credential behavior. `two_factor_activation` allows an inactive break-glass credential to call only its self-status and activation routes until a mutation signer bound to the same principal creates a database-timed activation. `max_activation_seconds` defaults to `900`; exact activation replay never extends the original expiry.

```toml
[ipm]
enabled = true
namespace = "oxibelt"
backend = "cluster"
fail_closed = true

[ipm.break_glass]
argon2id_memory_mib = 128
access_mode = "direct" # direct | two_factor_activation
max_activation_seconds = 900

[[ipm.principals]]
id = "admin"
subject = "admin@example.com"
groups = ["platform-admins"]

[[ipm.credentials]]
name = "admin-env-token"
principal = "admin"
bearer_token_env = "OXIBELT_ADMIN_TOKEN"

[[ipm.policies]]
name = "admin-full-access"

[[ipm.policies.statements]]
effect = "allow"
actions = ["*"]
resources = ["*"]

[[ipm.bindings]]
group = "platform-admins"
policy = "admin-full-access"

[shared_state]
enabled = true
namespace = "oxibelt"
default_backend = "cluster"

[[shared_state.backends]]
name = "cluster"
kind = "postgres"
connection_url_env = "OXIBELT_SHARED_STATE_URL"
```

`oxibeltctl` is the bundled operations CLI for these Admin APIs. It defaults to
`http://127.0.0.1:9092`, reads `OXIBELT_ADMIN_TOKEN`, and sends the same
`Authorization: Bearer <token>` requests as any other Admin API client:

```sh
oxibeltctl status
oxibeltctl doctor
oxibeltctl support-bundle --redact
oxibeltctl runtime introspection --redact
oxibeltctl config diff source/config/oxibelt.toml
oxibeltctl lifecycle drain
oxibeltctl auth check --action config:GetStatus --resource '*'
```

Configuration activation planning is additive to `config diff`; neither
command applies a candidate. Offline planning loads and validates both files
through the production include, operational-profile, path-root, and semantic
configuration pipeline:

```sh
oxibeltctl config plan \
  --current /etc/oxibelt/config/oxibelt.toml \
  --candidate ./review/oxibelt.toml \
  --format text
```

Online planning merges the candidate's local includes, authenticates to the
configured Admin listener, and calls `POST /admin/v1/config/diff`:

```sh
oxibeltctl config plan \
  --online \
  --candidate ./review/oxibelt.toml \
  --format json
```

Exactly one of `--current CURRENT` and `--online` is required, and
`--candidate CANDIDATE` is always required. `--format` is `text` by default or
`json` for the stable activation-plan schema. A valid plan exits `0`, including
one that requires a process restart or orchestrated rollout. An invalid,
unsupported, confinement-blocked, authorization-failed, or otherwise failed
plan exits `1`. Offline output uses `basis = "offline_config"`; Admin-enriched
output uses `basis = "online_active"`.

The report separates the intrinsic `minimum_required_operation` from the
executor/deployment-aware `selected_operation`. It classifies each changed
schema field, unchanged listeners, listener additions/removals/rebinds and bind conflicts,
long-lived connection effects, rollback mode, confinement fit, and deployment
prerequisites. Mixed OxiRule and downstream-TLS changes promote to a full
snapshot reload. A plan never calls listener preparation, binds a socket,
publishes a snapshot, creates a signed/durable artifact, or grants apply
authority. Online planning can therefore select an operation that the caller
is not authorized to perform.

Secret fields emit only their stable config path, change operation, and
`secret = true`. Process-local domain-separated HMAC equality tags distinguish
unchanged from changed secret material before redaction, then remain
non-serializable and zeroized; raw secret values, tags, URLs, provider
references, and absolute secret paths never enter plan output. Because the
changed/unchanged result is still an equality oracle, grant
`config:DiffSecrets` only to principals trusted to test candidate secrets and
avoid low-entropy literal secrets. The legacy `config:Diff` action remains
valid in policy documents for migration compatibility but does not authorize
the endpoint; broad `config:*` and `*` grants include the new action. The
report is bounded to 4,096 per-field changes and rejects overflow instead of
truncating.

Listener transition output is a feasibility plan, not a zero-downtime promise.
An addition is ordered before removal where compatible live socket ownership
permits overlap; external port availability remains unknown until the executor
binds, and same-bind incompatible TCP/QUIC options or TURN replacement can
require drain or restart. A snapshot change may gracefully drain HTTP/1
keep-alive, HTTP/2, HTTP/3, WebSocket, CONNECT, and WebTransport generations
even if their socket remains. TCP streams and UDP flows are affected when
their listener generation or process is replaced. Configured and effective
force-close deadlines are reported separately.

Confinement output uses the candidate filesystem manifest and the process-installed
hardening snapshot. Equal and subset path/right requirements fit; a new path,
broader scope, or added right requires restart or orchestrated rollout; an
unavailable or identity-changed required path, incompatible mount, or unrepresentable right blocks
in-process activation. Online plans expose only bounded subject-tagged differences,
report-local filesystem path IDs, source configuration paths, and fixed difference
kinds. Seccomp assertion differences carry an assertion ID rather than a fabricated
path. Stable path-derived manifest and policy digests are withheld.
Offline plans remain conditional when active kernel or mount evidence is absent.
Seccomp fit comes from observed filter/NNP state plus separately labeled external
assertions, never from requested configuration or a checked-in profile alone.
Planning remains non-mutating and cannot expand Landlock, install seccomp, or
remount a filesystem.

Dynamic mitigation commands are panic-button wrappers around the dynamic policy
automation API. Durations accept seconds or `s`, `m`, `h`, and `d` suffixes;
`--dry-run` records match context without enforcing the action. If `--reason`
is omitted, `oxibeltctl` sends a non-empty operational reason derived from the
command. `oxibeltctl dynamic-policy create`, `import`, `patch`, and `delete`
fetch the current dynamic-policy ETag when `--etag` is omitted; `apply`,
`block`, `allow`, `silent-close`, `challenge`, `rate-limit`, and `mitigate` send `If-Match`
only when `--etag` is supplied.

```sh
oxibeltctl block ip 203.0.113.10 --ttl 1h --reason 'incident response'
oxibeltctl silent-close ip 203.0.113.11 --ttl 30m --reason 'drop scanner traffic'
oxibeltctl allow cidr 203.0.113.0/24 --ttl 30m --route app-root
oxibeltctl challenge --person-proof ip 203.0.113.11 --ttl 10m
oxibeltctl rate-limit source 203.0.113.12 --rps 1 --ttl 10m
oxibeltctl mitigate login-bruteforce --profile-file ./mitigation-profiles.json --source 203.0.113.13
oxibeltctl mitigate login-bruteforce \
  --profile-url https://profiles.example.test/oxibelt/mitigation-profiles.json \
  --profile-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --source 203.0.113.13
oxibeltctl mitigate login-bruteforce \
  --profile-url http://profiles.internal/oxibelt/mitigation-profiles.json \
  --allow-insecure-profile-url \
  --source 203.0.113.13
```

`oxibeltctl mitigate <profile>` renders a user-defined local JSON profile into
a dynamic policy through `/admin/v1/dynamic-policies/apply`. Profiles can be
read from a local `--profile-file` or downloaded once from `--profile-url`;
exactly one source is required. The downloaded document uses the same top-level
`profiles` object:

```json
{
  "profiles": {
    "login-bruteforce": {
      "action": "reject",
      "path_prefix": "/identity",
      "status": 429,
      "code": "login.bruteforce",
      "ttl_seconds": 900,
      "reason": "login brute-force mitigation"
    }
  }
}
```

Profile `action` is required. Optional fields are `source`, `priority`,
`route_name`, `path_prefix`, `method`, `rate`, `burst`, `status`, `body`,
`reason`, `code`, `ttl_seconds`, and `mode`. If `source` is omitted, the CLI
uses `oxibeltctl-profile`; if `name` is omitted, it derives a deterministic
`mitigate-<profile>-<subject_type>-<subject>` name. Common options such as
`--ttl`, `--reason`, `--name`, `--priority`, `--route`, `--path-prefix`,
`--method`, and `--dry-run` may override the rendered policy shape.

Remote profile URLs must use HTTPS by default. Use `--profile-ca-cert FILE` for
private CAs, `--profile-token-env ENV` to send a bearer token only to the
profile URL, and `--profile-sha256 HEX` to pin the downloaded bytes before JSON
parsing. URL usernames and passwords are rejected; use `--profile-token-env`
instead. Plain HTTP mirrors are allowed only with
`--allow-insecure-profile-url`, which is intended for trusted internal
networks.

Container images keep `ENTRYPOINT` on `oxibelt` but include the CLI for
same-container operations:

```sh
docker exec -it oxibelt oxibeltctl status
```

`oxibeltctl` does not grant special authority based on Linux UID, container
root, or `docker exec --user root`. A `403 Forbidden` means the bearer token
authenticated but IPM denied the requested action/resource; use
`oxibeltctl auth check --action ACTION --resource RESOURCE` with a token that
can run `ipm:SimulateSelf`, then adjust IPM policy or use an explicit break-glass
credential.

For break-glass recovery, configure a separate full-access credential and keep
its plaintext secret separate from the day-to-day Admin token. OxiBelt stores
only the Argon2id PHC hash:

```toml
[ipm.break_glass]
argon2id_memory_mib = 128

[[ipm.principals]]
id = "break-glass-admin"
subject = "break-glass"
groups = ["ipm-admin"]

[[ipm.credentials]]
name = "break-glass-token"
principal = "break-glass-admin"
break_glass_access_token_hash = "$argon2id$v=19$m=131072,t=3,p=1$..."
```

Generate the hash with an Argon2id tool using a memory parameter at or below
`argon2id_memory_mib` (`m=131072` is 128 MiB). `oxibeltctl
--break-glass-access ...` only switches the token source to
`OXIBELT_BREAK_GLASS_TOKEN`; it does not bypass Admin authentication or IPM.
Break-glass access credentials are Admin-listener-only: downstream route IPM
requests ignore them even if a client sends the token as `Authorization:
Bearer ...`. If a VPN, bastion, or upstream proxy container should gate
emergency access, configure that component to authenticate the operator first
and then use the break-glass token only when calling the Admin listener. Limit
break-glass use with loopback-only or management-network-only Admin listeners,
TLS or mTLS for non-loopback access, short-lived secret handling, and rotation
after use.

Full hot reload starts, stops, or rebinds the dedicated admin listener when `admin.enabled` or `admin.bind` changes.

The Admin API OpenAPI 3.1 contract is stored at `source/assets/admin-openapi.json` and
served by authenticated runtimes at `GET /admin/v1/openapi.json`.
`docs/AdminAPI.md` summarizes the discovery surface. Metadata endpoints:

- `GET /admin/v1/openapi.json`
- `GET /admin/v1/capabilities`
- `GET /admin/v1/version`

Metadata reads require `admin:ReadMetadata` on `metadata/openapi`,
`metadata/capabilities`, or `metadata/version`.

Admin config and downstream TLS endpoints:

- `GET /admin/v1/config/status`
- `GET /admin/v1/config/instances`
- `GET /admin/v1/config/effective`
- `POST /admin/v1/config/validate`
- `POST /admin/v1/config/diff`
- `POST /admin/v1/config/load`
- `POST /admin/v1/config/rollback`
- `POST /admin/v1/config/secret-references/update`
- `POST /admin/v1/files/sync`
- `POST /admin/v1/keys/rotate`
- `GET /admin/v1/mutations/{request_id}`
- `GET /admin/v1/membership`
- `POST /admin/v1/membership/transitions`
- `GET /admin/v1/membership/transitions/{transition_id}/catchup`
- `POST /admin/v1/membership/transitions/{transition_id}/readiness`
- `POST /admin/v1/membership/transitions/{transition_id}/activate`
- `POST /admin/v1/membership/transitions/{transition_id}/cancel`
- `GET /admin/v1/tls/downstream`
- `POST /admin/v1/tls/downstream/reload`
- `GET /admin/v1/tls/upstream`
- `POST /admin/v1/tls/upstream/refresh`
- `GET /admin/v1/ipm/principals`
- `GET /admin/v1/ipm/credentials`
- `GET /admin/v1/ipm/policies`
- `GET /admin/v1/ipm/bindings`
- `POST /admin/v1/ipm/simulate`
- `GET /admin/v1/break-glass/activations/self`
- `POST /admin/v1/break-glass/activations`
- `POST /admin/v1/break-glass/activations/{id}/revoke`
- `GET /admin/v1/diagnostics/preflight`
- `POST /admin/v1/diagnostics/preflight`
- `GET /admin/v1/diagnostics/support-bundle`
- `GET /admin/v1/runtime/snapshot`
- `GET /admin/v1/runtime/introspection`
- `GET /admin/v1/operations`
- `POST /admin/v1/operations`
- `GET /admin/v1/operations/{id}`
- `DELETE /admin/v1/operations/{id}`
- `GET /admin/v1/operations/{id}/events`
- `GET /admin/v1/operations/{id}/events/ws`

The IPM principal, credential, policy, and binding list endpoints support
opt-in `limit`, `cursor`, `sort`, `order`, and exact-match `filter[...]` query
parameters. Calls without these list query parameters keep returning the full
legacy array; paginated responses add a `pagination` object with an opaque
`next_cursor` when more rows are available.

Config read endpoints use `config:GetStatus` and `config:GetEffective`; validate, diff, load, rollback, file sync, downstream TLS, and upstream TLS revocation operations use the matching `config:*` IPM actions. `POST /admin/v1/config/load` installs a validated runtime snapshot only; it does not write TOML back to disk. `POST /admin/v1/config/rollback` restores the requested retained committed revision. Load and rollback require `admin:UpdateConfig` for `[admin]` changes and `ipm:UpdateConfig` for `[ipm]` changes. Config load, rollback, file sync, downstream TLS reload, key rotation, and secret-reference update require `If-Match` with the active config ETag from `/admin/v1/config/status` or `/admin/v1/config/effective`; stale ETags are rejected before applying changes. With required mutation protection they also require the signed `X-OxiBelt-Mutation` envelope. Downstream TLS reload re-reads configured certificate, key, and static OCSP files from disk or rebuilds the live OCSP runtime, and preserves the active TLS state if validation fails. Upstream TLS status reads require `config:ReadUpstreamTls`; `POST /admin/v1/tls/upstream/refresh` requires `config:RefreshUpstreamTls` and refreshes known upstream OCSP cache contexts without exposing certificate identifiers or responder URLs.

`GET /admin/v1/mutations/{request_id}` returns a redacted durable receipt for
the authenticated actor's protected request or callers with
`admin:ReadMutations` on `mutation/<request_id>`. `GET
/admin/v1/config/instances` returns configured member IDs plus currently live
heartbeat records. In `admin_cluster` mode it also reports the canonical
membership revision, durable authority/readiness, a safe blocking reason, the
active rollout summary, and per-instance configured/live/ready/compatible
status. This bounded read view is diagnostic; terminal mutation commit is the
authoritative convergence proof.

`GET /admin/v1/membership` requires `membership:GetStatus` on
`membership/current` and returns the staged membership `head`, `active_epoch`,
sorted `required_members`, one `pending_transition`, up to 32
`recent_transitions`, and `fenced_members`. Transition diagnostics include the
kind/state, monotonic state version, source and target epoch digests, affected
member, request IDs, bounded catch-up and verification evidence, key-proof and
receipt counts, fence cutoff, timestamps, and a safe blocking reason.

`POST /admin/v1/membership/transitions` requires `membership:Propose`, a strong
`If-Match`, and a signed mutation envelope. Its strict body has `version = 1`,
`kind`, `expected_active_epoch`, and `member`; `initialize` uses null epoch and
member values, join/rejoin supply a new member, and maintenance/remove supply
the exact active member including both public keys. The mutation request ID is
the transition ID. `GET .../{transition_id}/catchup` requires
`membership:GetCatchUp` and returns only bounded encrypted chunks. `POST
.../{transition_id}/readiness` requires `membership:SubmitReadiness`; the strict
signed receipt binds `version`, path-matching `transition_id`, target epoch,
member, catch-up cursor/digest, build, capability, issue time, and signature,
plus the version-`2` source epoch, artifact-key fingerprint, checkpoint digest,
journal-tail digest, and verified position. `POST .../activate` and `POST
.../cancel` require `membership:Activate` or `membership:Cancel`, strong
`If-Match`, and a signed mutation envelope; each strict body contains
`version = 1`, the path-matching transition ID, and
`expected_target_epoch`. Cancellation is accepted only before activation
authorization; an authorized activation must finish or enter explicit
indeterminate recovery. See `docs/AdminAPI.md` for response fields and the
complete lifecycle contract.

`POST /admin/v1/keys/rotate` verifies and
reloads only the configured default or SNI downstream TLS key path. `POST
/admin/v1/config/secret-references/update` validates the allowlisted reference
shape, preflights the complete runtime candidate, and atomically activates it.
The endpoint returns `200` with bounded revision/digest bindings on success;
`400` for malformed, unsupported, non-allowlisted, or invalid references;
`401` for invalid authentication or mutation-signer identity; `403` for failed
IPM authorization or a forbidden file; `409` for activation, preflight,
snapshot, mutation, or immutable-rollout conflicts; `412` for stale
`If-Match`; `413` above the 16 KiB request limit; `428` for missing `If-Match`
or required mutation metadata; and `503` for an unavailable provider, entropy
source, mutation store, audit authority, or cluster rollout dependency.

An Admin-cluster activation plan always selects an all-member coordinated
rollout for an ordinary config change. A configuration candidate that changes
membership bootstrap trust, mutation, audit, storage, or protected-write
settings uses `admin_cluster_membership_epoch` and requires out-of-band
coordination; the selected cluster rollout includes a coordinated process
restart, and an active cluster cannot replace those configured trust roots
through config load. Changes to the active staged member set use the separate
membership-transition API and leave those trust-root settings unchanged.
Planning reports the exact bounded target count, canonical membership
revision, and signed/durable artifact, all-member acknowledgement, protected
write, and rollback prerequisites. It returns member IDs only when the caller
has both `config:DiffSecrets` on `*` and `config:GetInstances` on
`instances/current`; otherwise `identities_withheld = true`. The plan does not
construct an envelope, encrypt or persist an artifact, perform canary apply,
or satisfy any of those prerequisites.

Kubernetes immutable rollout mode specifically returns
`409 immutable_rollout_conflict` without changing state. Break-glass activation is
exposed through `GET /admin/v1/break-glass/activations/self`,
`POST /admin/v1/break-glass/activations`, and
`POST /admin/v1/break-glass/activations/{id}/revoke`.

Kubernetes-native immutable rollout mode is enabled by setting
`OXIBELT_CONFIG_ROLLOUT_MODE=kubernetes_immutable` in a Pod. It requires
`runtime.hot_reload.mode = "off"`, an assigned
`OXIBELT_CONFIG_REVISION`, a lowercase raw SHA-256
`OXIBELT_CONFIG_DIGEST`, `OXIBELT_CONFIG_REVISION_FILE`, and
`OXIBELT_INSTANCE_ID`. The revision file must be a regular file beneath the
configured config root, appear in the loaded `ConfigSourcePaths.config_files`,
and hash to the assigned digest. Missing metadata, path escape, an excluded
file, unreadable/non-regular input, or a digest mismatch fails startup closed.
The revision becomes applied only after full configuration validation and the
runtime snapshot are built. Readiness returns `200` only when the assigned and
applied revision match; successful responses include revision and digest
headers. Config status adds rollout mode, instance ID, desired/applied
revision, digest, and apply state without replacing its existing process-local
revision or ETag fields. In this mode, the per-Pod config load, rollback,
file-sync, and downstream TLS reload mutations return `409`; read-only
validate, diff, effective-config, and status operations remain available.

Immutable Pods may also supply the optional all-or-none planning context
`OXIBELT_CONFIG_ROLLOUT_TARGET_NAMESPACE`,
`OXIBELT_CONFIG_ROLLOUT_TARGET_KIND` (`Deployment` or `DaemonSet`), and
`OXIBELT_CONFIG_ROLLOUT_TARGET_NAME`. The Helm chart populates these from its
workload identity and the Pod namespace. Missing, partial, or malformed values
do not invalidate the already verified config revision; the plan instead
reports `deployment_target_identity` unavailable. These values identify an
operator-asserted rollout target only. OxiBelt does not contact the Kubernetes
API, authorize a patch, prove that the workload still exists, or discover a
prior rollback artifact. `kubernetes_immutable` plans therefore select
`kubernetes_immutable_rollout`, prohibit per-Pod apply, and keep rollback
conditional unless an external controller supplies retained artifact evidence.

Admin diagnostics endpoints return the same production preflight report shape as
`oxibeltctl doctor`: `schema_version` (currently `1`), `ok`, `profile`,
severity `summary`, `findings`, and optional `probes`. Each finding has a
stable short `code` for machine policy and its dotted `id` compatibility alias,
plus severity, category, target, message, and remediation. `GET /admin/v1/diagnostics/preflight` diagnoses the active runtime
configuration and requires `diagnostics:ReadPreflight` on
`oxibelt:<namespace>:diagnostics:preflight/current`. `POST
/admin/v1/diagnostics/preflight` accepts JSON such as:

```json
{
  "format": "toml",
  "config": "[listeners]\n...",
  "external_probes": ["shared_state"]
}
```

Candidate TOML load or validation failures are returned as `200 OK` reports
with `ok = false` and a `config.invalid` critical finding, so deployment
automation can consume a stable diagnostics schema. Invalid JSON envelopes or
unsupported formats are rejected with `400`. Candidate preflight requires
`diagnostics:RunPreflight` on
`oxibelt:<namespace>:diagnostics:preflight/candidate`. Each requested external
probe also requires `diagnostics:RunProbe` on
`oxibelt:<namespace>:diagnostics:probe/<kind>`, where `<kind>` is
`shared_state`, `ipm_store`, `remote_signer`, or `upstream`. Candidate external
probes additionally require `diagnostics:RunProbe` on every resolved probe
target before OxiBelt opens any network or Unix socket connection. TCP targets
use `oxibelt:<namespace>:diagnostics:probe/<kind>/tcp/<host>:<port>` with DNS
names lowercased and IPv6 hosts bracketed. Remote signer Unix sockets use
`oxibelt:<namespace>:diagnostics:probe/remote_signer/unix/<absolute-socket-path>`.
For example, allow `upstream` probes to one origin with
`probe/upstream/tcp/api.example.test:443`; use a wildcard such as
`probe/upstream/tcp/*` only for intentionally delegated broad reachability
checks.

`GET /admin/v1/diagnostics/support-bundle?redact=true` returns a single
redacted JSON support bundle for sharing during incident response. It requires
`diagnostics:ReadSupportBundle` on
`oxibelt:<namespace>:diagnostics:support-bundle/current`. Repeated
`external_probe=KIND` query parameters run the same optional doctor probes and
therefore require the same `diagnostics:RunProbe` coarse and target
permissions before any network or Unix socket probe is opened. The bundled
`oxibeltctl support-bundle --redact` command calls this endpoint and prints the
JSON to stdout. Unredacted bundles are not supported. Support-bundle format
version `2` includes the resolved `runtime_topology` object used by the active
configuration generation.

`GET /admin/v1/runtime/snapshot?redact=true` returns the runtime snapshot
section used by the support bundle and requires `runtime:ReadSnapshot` on
`oxibelt:<namespace>:runtime:snapshot/current`. Runtime snapshot format
version `2` reports the requested and resolved runtime presets, topology
policy, resolution outcome and fixed reason, subsystem owners, worker
allocations, blocking strategy, compatibility boundaries, and requested,
resolved, and active direct-H1 transport state.

`GET /admin/v1/runtime/introspection?redact=true` returns the redacted runtime
snapshot plus live active connection, request, stream, WebSocket,
WebTransport, stream-listener, TURN TCP/TLS, TURN UDP-client, and TURN relay
allocation counters. It requires the
separate `runtime:ReadIntrospection` action on
`oxibelt:<namespace>:runtime:introspection/current`; `runtime:ReadSnapshot`
does not authorize this endpoint. Runtime-introspection format version `3`
uses the same topology object, so subsystem ownership and the active direct-H1
transport can be compared with live counters without inferring topology from a
mode name. Version `3` adds `turn.udp_clients_active` and
`turn.allocations_active`; both are aggregate counts and reveal no client or
relay address. The object contains fixed enums and counts only; it omits raw
preflight errors, paths, hostnames, routes, peers, and secrets.

Active `GET /admin/v1/config/explain` responses use config-report format
version `2` and include the same resolved topology with `basis = "active"`.
Offline `oxibeltctl config explain` reports the deterministic preflight result
with `basis = "preflight"`; it does not claim that listeners, worker pools, or
an experimental direct-H1 transport have been activated.

OxiBelt initializes the IPM schema when `[ipm].backend` is configured:

```sql
CREATE TABLE IF NOT EXISTS oxibelt_ipm_principals (
  id bigserial PRIMARY KEY,
  namespace text NOT NULL,
  principal_id text NOT NULL,
  subject text NOT NULL,
  groups text[] NOT NULL DEFAULT ARRAY[]::text[]
);
CREATE TABLE IF NOT EXISTS oxibelt_ipm_credentials (...);
CREATE TABLE IF NOT EXISTS oxibelt_ipm_policies (...);
CREATE TABLE IF NOT EXISTS oxibelt_ipm_policy_bindings (...);
CREATE TABLE IF NOT EXISTS oxibelt_ipm_generation (...);
CREATE TABLE IF NOT EXISTS oxibelt_ipm_audit (...);
```

Admin file sync endpoint:

- `POST /admin/v1/files/sync`

File sync authorizes each operation by root and operation type. `root = "config"` requires `config:SyncFiles`, and config deletes also require `config:SyncFiles` on resource `delete`. `root = "oxirule"` requires `waf:PutOxiRule` or `waf:DeleteOxiRule` on `oxibelt:<namespace>:waf:oxirule/<path>` and only accepts `.oxirule.toml` paths. `root = "oxirule_group"` requires `waf:PutOxiRuleGroup` or `waf:DeleteOxiRuleGroup` on `oxibelt:<namespace>:waf:oxirule-group/<path>` and only accepts `.oxirule-group.toml` paths. `root = "oxirule_rulepack"` requires `waf:PutOxiRulePack` or `waf:DeleteOxiRulePack` on `oxibelt:<namespace>:waf:oxirule-rulepack/<path>` and only accepts `.oxirule-rulepack.toml` paths. `apply = "oxirule"` requires `waf:ReloadOxiRule` on `*`, `apply = "full"` also requires `config:Load`, and `apply = "downstream_tls"` also requires `config:ReloadDownstreamTls`. Config-root writes are checked before commit against the staged config graph; changes to `[admin]` or `[ipm]` additionally require `admin:UpdateConfig` or `ipm:UpdateConfig`, even when `apply = "none"`, `oxirule`, or `downstream_tls`. Full apply also checks the disk candidate for protected `[admin]` and `[ipm]` changes. The request body is explicit: missing files are never implicitly removed.

```json
{
  "apply": "full",
  "operations": [
    {
      "op": "put",
      "root": "config",
      "path": "oxibelt.toml",
      "expected_sha256": "existing-file-sha256-or-null",
      "content": "[proxy]\n..."
    },
    {
      "op": "put",
      "root": "oxirule_group",
      "path": "groups/bot.oxirule-group.toml",
      "content": "[[rule_groups]]\nname = \"bot\"\n..."
    }
  ]
}
```

`root` is `config`, `oxirule`, `oxirule_group`, or `oxirule_rulepack`. Paths are UTF-8 relative paths, normalized, and must stay under the configured root. The WAF roots share the configured OxiRule directory but are separated by suffix: use `oxirule` for `.oxirule.toml` rule files, `oxirule_group` for `.oxirule-group.toml` shared group files, and `oxirule_rulepack` for `.oxirule-rulepack.toml` manifests. `put` writes `content`, optionally guarded by `expected_sha256`; `delete` removes exactly the named file. `apply` defaults to `none`; `oxirule` reloads rule policy from disk, `full` reloads the full TOML/runtime view from disk, and `downstream_tls` reloads downstream TLS material. File sync commits with same-directory temporary files and restores touched files if validation or apply fails. The endpoint is not a certificate lifecycle API: private key upload, ACME credentials, DNS provider credentials, and ACME issuance are out of scope.

Admin lifecycle endpoints:

- `GET /admin/v1/lifecycle`
- `POST /admin/v1/lifecycle/drain`
- `POST /admin/v1/lifecycle/undrain`

Lifecycle read requires `lifecycle:Get` and returns `{"draining": bool, "reason": string}`. Drain and undrain require `lifecycle:Drain` and `lifecycle:Undrain`. Admin drain makes `/ready` return `503 draining`, keeps `/live` at `200 live`, and rejects new data-plane requests with `503 draining` and `Connection: close`; in-flight requests continue. Undrain clears only admin-initiated drain state.

Admin WAF telemetry endpoint:

- `GET /admin/v1/waf/rule-hits`
- `GET /admin/v1/waf/rule-costs`
- `GET /admin/v1/waf/crs/compatibility`
- `GET /admin/v1/waf/person-proof/status`
- `GET /admin/v1/waf/person-proof/clearances`
- `POST /admin/v1/waf/person-proof/clearances/revoke`
- `POST /admin/v1/waf/oxirule/check`
- `POST /admin/v1/waf/oxirule/test`
- `POST /admin/v1/waf/oxirule/explain`
- `POST /admin/v1/waf/oxirule/cost`
- `POST /admin/v1/waf/oxirule/replay`
- `POST /admin/v1/waf/oxirule/analyze`
- `POST /admin/v1/waf/oxirule/hardening-plan`
- `GET /admin/v1/waf/oxirule/templates`
- `POST /admin/v1/waf/oxirule/templates/render`
- `POST /admin/v1/waf/oxirule/false-positive`
- `GET /admin/v1/waf/rulepacks`
- `POST /admin/v1/waf/rulepacks/plan`

These endpoints require the matching `waf:*` IPM actions. Rule hits returns active rule hit counters with `scope`, `route`, `phase`, `name`, optional `id`, `effective_mode`, and `hits`. Rule costs returns OxiRule evaluation counters and total/average runtime in nanoseconds using the same authenticated rule metadata; CRS rule cost accounting is intentionally not exposed through the public metrics listener. CRS rule hit entries also include `tags`, `tuned_hits`, latest observed anomaly scores, and latest blocking scores when available. The CRS compatibility endpoint returns the OxiBelt-supported CRS release lines, supported directives/operators/transforms/variables/actions, accepted-but-ignored syntax, fail-closed policy, and known unsupported surfaces. Rulepacks returns active loaded manifest summaries, including name, version, default mode, rule and group-file counts, loaded files, optional source commit metadata, and optional URL install provenance fields: `source_url`, `source_sha256`, `source_openpgp_signature_url`, and `source_openpgp_signer_fingerprint`. Rulepack planning requires `waf:PlanOxiRulePack` for every request, `config:ReadRouteInventory` only when `include_route_candidates = true`, `waf:ListOxiRulePacks` only when `include_diff = true`, and `waf:EstimateOxiRuleCost` only when `include_cost = true`.

Person proof Admin endpoints expose only aggregate state and canonical `clearance:<sha256>` identifiers. `status` reports policy counts, store scope, active hash-keyed clearance count, challenge replay-marker count, revocation tombstone count, and legacy raw-key count. `clearances` lists only hash-keyed active clearance entries and never lists legacy raw-key replay markers. `clearances/revoke` accepts a bare SHA-256 value or canonical `clearance:<sha256>`, writes an exact-match revocation tombstone, and removes a matching hash-keyed active clearance marker when present. Raw session credentials, raw clearance credentials, provider responses, token-binding payloads, MACs, and the Person proof HMAC secret are not returned by these endpoints.

OxiRule development endpoints are synchronous and stateless: they never write rule files or install policy. `check`, `test`, `explain`, `cost`, and `replay` accept inline candidate rule content plus optional inline OxiRule group files, compile them against the active configuration context, and return JSON with `ok`, `diagnostics`, `matched_rules`, `actions`, `terminal`, `mutations`, `tags`, `stream_close`, `body_need`, `cost_warnings`, and `explain_steps` where relevant. `analyze` scores fixture URI, header, body, response-body, and stream-payload surfaces with deterministic local malicious-intelligence and malformed-payload heuristics and returns `risk` plus `bot` summaries. `hardening-plan` returns suggested OxiRule, group, or rulepack TOML for prompt-injection, malformed payload, and suspicious automation defenses without deploying it. Fixtures support request, response, and stream-phase inputs; stream fixtures evaluate `WafStreamInput` only and do not create live WebSocket or WebTransport sessions. Template endpoints expose built-in `vaultwarden`, `gitea`, `nextcloud`, `generic-login`, and `admin-path` templates. The false-positive endpoint returns suggested TOML changes for CRS allowlists/overrides or native OxiRule monitor/condition tuning; it does not mutate configuration.

`POST /admin/v1/waf/rulepacks/plan` is synchronous and non-mutating. The request accepts `manifest`, optional `source { url, sha256, openpgp_signature_url, openpgp_signer_fingerprint }`, `values`, `bindings`, `profile`, `mode`, `force_mode`, `include_route_candidates`, `include_diff`, and `include_cost`. The response returns `ok`, `rulepack`, `required_inputs`, `route_candidates`, `rendered_manifest`, `install_plan`, `diff`, `risk`, `cost_warnings`, `warnings`, and `permission_hints`. Route candidates are built from the active typed `Config` and expose only route name, hosts, effective path prefix, and upstream or upstream-pool name. They do not expose upstream URLs, credentials, TLS details, token environment variable names, or config file paths. The endpoint supports current rulepack schema version `2` only; schema version `1` and legacy `[variables.discovery]` manifests are rejected.

Admin upstream-pool endpoints:

- `GET /admin/v1/upstream-pools/status`
- `GET /admin/v1/upstream-pools`
- `GET /admin/v1/upstream-pools/{pool}`
- `POST /admin/v1/upstream-pools/{pool}/servers`
- `PATCH /admin/v1/upstream-pools/{pool}/servers/{server_id}`
- `DELETE /admin/v1/upstream-pools/{pool}/servers/{server_id}`

`GET /admin/v1/upstream-pools/status` returns `{ "generation": n, "etag": "\"oxibelt-upstream-pools-n\"" }` and checks `upstream-pool:GetStatus` on `status/current`. Runtime server mutation accepts JSON fields `id`, `origin`, `state`, `weight`, `backup`, and `max_conns` where applicable. Pool list checks `upstream-pool:List` on `*`, pool get checks `upstream-pool:Get` on `<pool>`, and add, update, or remove server checks the matching action on `<pool>/server/<server_id>`. Server mutations require `If-Match` with the current upstream-pool status ETag; missing ETags return `428`, stale ETags return `412`. `DELETE` is limited to servers created by the admin API. Every admin mutation emits a structured audit log with actor, peer, operation, target, outcome, and validation error when rejected.
`oxibeltctl pool` mutating commands fetch the current upstream-pool ETag automatically when `--etag` is omitted.

Admin stream-pool endpoints:

- `GET /admin/v1/stream-pools/status`
- `GET /admin/v1/stream-pools`
- `GET /admin/v1/stream-pools/{pool}`
- `POST /admin/v1/stream-pools/{pool}/servers`
- `PATCH /admin/v1/stream-pools/{pool}/servers/{server_id}`
- `DELETE /admin/v1/stream-pools/{pool}/servers/{server_id}`

`GET /admin/v1/stream-pools/status` returns `{ "generation": n, "etag": "\"oxibelt-stream-pools-n\"" }` and checks `stream-pool:GetStatus` on `status/current`. Runtime server mutation accepts JSON fields `id`, `origin`, `state`, `weight`, `backup`, and `max_conns`; `origin` must use `tcp://host:port` or `udp://host:port`. Pool list checks `stream-pool:List` on `*`, pool get checks `stream-pool:Get` on `<pool>`, and add, update, or remove server checks the matching action on `<pool>/server/<server_id>`. Server mutations require `If-Match` with the current stream-pool status ETag; missing ETags return `428`, stale ETags return `412`. Every stream-pool mutation emits the same structured Admin audit fields as upstream-pool mutations.

Dynamic policy automation endpoints:

- `GET /admin/v1/dynamic-policies/status`
- `GET /admin/v1/dynamic-policies`
- `GET /admin/v1/dynamic-policies/{id}`
- `POST /admin/v1/dynamic-policies`
- `POST /admin/v1/dynamic-policies/apply`
- `PATCH /admin/v1/dynamic-policies/{id}`
- `DELETE /admin/v1/dynamic-policies/{id}`
- `GET /admin/v1/dynamic-policies/audit?limit=&policy_id=`
- `GET /admin/v1/dynamic-policies/export`
- `POST /admin/v1/dynamic-policies/import`

`GET /admin/v1/dynamic-policies/status` returns `{ "namespace": "...", "generation": n, "etag": "\"oxibelt-dynamic-policy-n\"" }` and checks `dynamic-policy:GetStatus` on `status/current`. Create/import/apply JSON accepts `source`, `name`, `action`, `subject_type`, `subject`, optional `route_name`, `path_prefix`, `method`, `rate`, `burst`, `status`, `body`, `reason`, `code`, `mode`, and either `expires_at` or `ttl_seconds` when TTL is required. Admin JSON/API rows support the full dynamic subject set, including IP/CIDR, route/path composites, prefix-route, hashed TLS fingerprint, hashed token-binding, verified Person proof clearance hash, ASN, ASN-route, and hashed composite-client subjects; `oxibeltctl block`, `allow`, `silent-close`, `challenge`, and `rate-limit` remain IP/CIDR-focused operator shortcuts. `silent_close` JSON rejects `status`, `body`, `rate`, and `burst` because it sends no downstream response. Create, import, and apply check `source/<source>/name/<name>` plus `route/<route_name>` when present before writing. Get, patch, and delete by ID first resolve the existing row, return `404` if absent, and then authorize the stored source/name/route; patch also authorizes the proposed source/name/route when those fields change. Create, import, apply, and patch reject changes that would exceed either the global active policy cap or the matching source quota bucket. Raw `POST /admin/v1/dynamic-policies` preserves create semantics and requires `If-Match` with the current dynamic-policy status ETag, as do import, patch, and delete; missing ETags return `428`, stale ETags return `412`. `POST /admin/v1/dynamic-policies/apply` is the operator UX upsert endpoint: it creates or replaces the row selected by `namespace + source + name`, disables duplicate rows beyond the lowest `id`, and is intended for repeat panic-button clicks that should not consume extra quota. `apply` accepts optional `If-Match`; omitted ETags are allowed, while stale supplied ETags return `412`. Import payloads use `{ "policies": [...] }` and upsert by `namespace + source + name`; duplicate rows beyond the lowest `id` are disabled. `DELETE` disables the row instead of physically removing it.

`GET /admin/v1/dynamic-policies` supports opt-in `limit`, `cursor`, `sort`, `order`, and exact-match `filter[source]`, `filter[name]`, and `filter[enabled]` query parameters. Unpaginated calls keep the legacy full response ordered by `source`, `name`, and `id`; paginated calls use keyset pagination and return the existing `policies` field plus `pagination`.

`GET /admin/v1/dynamic-policies/audit` returns recent audit rows as `{ "audit": [...] }`. `limit` defaults to `100` and is capped at `1000`; `policy_id` restricts results to one policy. Dynamic policy create, apply, import, patch, and delete successes are audited, and validation or quota rejects are written as best-effort audit rows with `outcome = "rejected"`. The audit actor is derived from Admin authentication and authorization, not from JSON supplied by a CLI or automation client.

Admin purge endpoints:

```sh
POST /cache/purge?policy=default&scheme=https&host=example.test&uri=/path
POST /cache/purge-prefix?policy=default&scheme=https&host=example.test&path_prefix=/assets/
POST /cache/purge-tag?policy=default&tag=release-2026-05-09
POST /admin/v1/cache/purge
```

The `/admin/v1/cache/purge` endpoint accepts JSON with `"type": "exact"`, `"prefix"`, or `"tag"`, plus the same selectors used by the query endpoints. Exact purge uses `policy`, `scheme`, `host`, `uri`, and optional `partition`; prefix purge uses `path_prefix`; tag purge uses `tag` plus optional `scheme`, `host`, and `partition`. It returns `{"purged": number}` and requires the matching `cache:PurgeObject`, `cache:PurgePrefix`, or `cache:PurgeTag` IPM action on both `policy/<policy>` and `host/<normalized-host>`. Tag purge without a host requires `host/*`.

Query-string purge requests also accept optional `partition`. When `[admin.cache_purge_signing]` is enabled, the `/cache/purge*` query endpoints may authenticate with `X-OxiBelt-Cache-Timestamp`, `X-OxiBelt-Cache-Nonce`, and `X-OxiBelt-Cache-Signature` instead of a bearer token. The signature is base64 HMAC-SHA256 over `OXIBELT-CACHE-PURGE-V1\n{method}\n{path_and_query}\n{sha256(body)}\n{timestamp}\n{nonce}`; signed purge requests must use an empty body. The JSON v1 purge endpoint is bearer-token only.

Admin cache diagnostics and warming endpoints:

```sh
POST /admin/v1/cache/key-explain
POST /admin/v1/cache/warm
```

`key-explain` requires `cache:ExplainKey` on both `policy/<policy>` and `host/<normalized-host>` and accepts `{ "policy": "default", "method": "GET", "scheme": "https", "host": "example.test", "uri": "/asset.css", "headers": {}, "response_headers": {} }`. It returns the selected policy, partition, base key, optional variant key, Vary fields, and cacheability reasons. `warm` requires `cache:Warm` on each item's effective cache policy and normalized host, and accepts `{ "items": [{ "scheme": "https", "host": "example.test", "uri": "/asset.css", "method": "GET", "headers": {} }] }`; methods are limited to `GET` and `HEAD`, and each item returns `stored`, `not_cacheable`, `upstream_error`, or `validation_error`. The warm effective policy is evaluated with the same synthesized request context used for execution, including the `Host` header, trusted Real-IP identity, and scheme-derived TLS metadata. If any warm item is not authorized, the request returns one `403` and no warm request is issued.

Health paths must start with `/`. Readiness returns `503 draining` while lifecycle drain is active and `503 runtime subsystem unavailable` while an active-generation critical subsystem is failed/degraded or a restartable-critical task is recovering. Liveness remains `200 live` so process supervisors can distinguish intentional drain or contained runtime failure from process death. A connection-task panic is isolated to that connection and does not by itself change readiness. Prometheus metrics include aggregate TLS server session storage diagnostic counters for stateful resumption cache calls and approximate lock/put timing. Basic metrics also expose `oxibelt_runtime_panics_total`, `oxibelt_runtime_task_restarts_total`, `oxibelt_runtime_task_state`, `oxibelt_runtime_lock_recoveries_total`, and `oxibelt_runtime_subsystem_state`; all labels come from fixed task, scope, subsystem, state, and outcome vocabularies. UDP stream metrics add aggregate active, created, restored, persistence-error, fence-rejection, expired, evicted, admission-rejection, forced-shutdown, rate-limited, and dropped-datagram series without listener, peer, route, target, origin, or backend-key labels. Upstream-pool metrics expose public-safe server counts, health-report counters, and outlier-ejection counters with pool/source/state/outcome/reason labels; they never include discovery endpoint URLs, upstream origins, credentials, raw discovery errors, or response bodies. With `metrics.detail = "detailed"`, Prometheus also includes bounded-label HTTP, upstream, cache, TLS handshake, QUIC Retry, WebSocket, WebTransport, and TURN counters/histograms using route/upstream/protocol/status/cache-reason style labels. Cache miss reasons include lookup misses, fill lock timeouts, shared fill lock conflicts, and fills that completed without storing an entry. Detailed mode also emits `oxibelt_cache_fill_stage_duration_ms` with `route`, `policy`, `stage`, and `outcome` labels for `lock_wait`, `head_decision`, `body_collect`, `local_store`, and `shared_store`. `metrics.detail = "basic"` keeps only aggregate counters and gauges. `metrics.histogram_buckets_ms` must be a non-empty strictly increasing list of positive millisecond buckets. The public metrics listener omits detailed WAF rule names, IDs, modes, routes, and per-rule hit/cost counters because it is intended for unauthenticated operational scraping. Use the authenticated admin WAF telemetry endpoints and upstream-pool Admin snapshots for per-rule or per-server operational detail. The operator-facing bundle and secure starter configuration are documented in [Observability.md](Observability.md).

Runtime recovery has no configuration keys. The metrics listener is restartable-optional; the health listener is fatal; active pool health, enabled overload sampling, and configured upstream discovery are restartable-critical. Restart delay doubles from `100ms` to a `30s` cap, a restarted task reports healthy after `5s` of stable execution, and the delay resets after `60s` of uninterrupted execution. Poisoned disposable cache or registry state is cleared and rebuilt, while poisoned security-critical admission state fails closed and makes readiness fail. Disk response-cache recovery advances at most 256 directory entries when cache state is accessed and stops after 16,384 scanned entries, preventing one request from performing an unbounded rebuild.

`[telemetry.tracing]` enables W3C `traceparent` extraction/injection and OTLP HTTP/protobuf trace export. `enabled = false` is the default. The v1 exporter supports `http://` OTLP collector endpoints, uses `service_name` as the OpenTelemetry resource service name, samples new root traces with `sample_ratio`, and bounds blocking exporter I/O with `export_timeout_ms`. Export failures after startup or reload are logged and dropped; they do not block data-plane requests. `propagate_trace_context = true` forwards trace context to upstream HTTP/1.1, HTTP/2, HTTP/3, and WebTransport CONNECT requests. Full reload and admin config load apply telemetry changes to the replacement snapshot.

## Access Log Runtime

```toml
[access_log.system]
enabled = false

[access_log.waf]
enabled = true

[access_log.admin]
enabled = false

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
```

`[access_log.system]` emits request-wide records built from `[logging.access_log].fields`. `[access_log.waf]` emits OxiRule `emit_access_log` records. `[access_log.admin]` emits Admin API records derived from the TLS/IPM-aware audit gate, including safe actor, principal, subject, group, source IP, method, path, operation, status, outcome, and request-summary metadata. For `[admin.audit.export]`, both `admin.audit.export.sinks = ["access_log"]` and `[access_log.admin].enabled = true` are required for visible Admin audit export records.

`[access_log.stdout].schema = "ocsf"` writes Open Cybersecurity Schema Framework JSON and preserves the original OxiBelt record under `unmapped.oxibelt`. System and WAF records use OCSF HTTP Activity; Admin API records use OCSF API Activity so fine-grained token identity, authorization checks, TLS scheme state, and redacted request summaries stay in the access-log stream.

`[access_log.stdout].schema = "ecs"` writes Elastic Common Schema JSON with `ecs.version = "9.4.0"` and preserves the original OxiBelt record under `oxibelt.access.original`. System and WAF records map HTTP, URL, client, user-agent, TLS, and WAF rule fields where present; Admin API records map API categorization, source IP, TLS scheme state, safe token identity, authorization resource metadata, and redacted request summaries.

`[access_log.otlp]` exports the selected OCSF or ECS projection as the OpenTelemetry log body over OTLP HTTP/protobuf. It is disabled by default, supports certificate-validated `https://` endpoints, accepts `http://` only for loopback collectors such as `127.0.0.1`, `127.0.0.0/8`, `::1`, and `localhost`, uses a bounded queue with best-effort drops on exporter backpressure or delivery failure, and does not block data-plane or Admin API enforcement decisions. `trusted_ca_certs` adds private collector CA roots from the cert directory to the WebPKI roots used for HTTPS verification. OpenTelemetry trace export under `[telemetry.tracing]` is configured separately and is unaffected.

PostgreSQL access-log support has been removed. Configurations containing `[database.access_log]` or `[logging.access_log.database]` fail during loading so stale credentials and tables cannot silently remain configured.

## Database Mitigation Sink

```toml
[database.mitigation]
enabled = false
mode = "managed" # managed | existing
connection_url_env = "OXIBELT_MITIGATION_DATABASE_URL"
# backend = "cluster"
table = "oxibelt_mitigation_events"
namespace = "oxibelt"
queue_capacity = 8192
dedupe_window_ms = 60000
ttl_seconds = 300
failure_policy = "open" # open | closed
```

This optional PostgreSQL sink receives OxiRule `emit_mitigation` actions for external DOTS, BGP FlowSpec, RTBH/blackhole, or provider-specific mitigation controllers. OxiBelt only writes PostgreSQL rows; it does not call ISP or IaaS APIs directly.

Set either `connection_url`/`connection_url_env` or `backend`. `backend` must name a PostgreSQL `[[shared_state.backends]]` entry. In `managed` mode OxiBelt creates `oxibelt_mitigation_events`; in `existing` mode the table must already expose compatible `namespace`, `dedupe_key`, `status`, `count`, `first_seen`, `last_seen`, `expires_at`, and `record jsonb` columns plus a unique conflict target on `(namespace, dedupe_key)`.

Rows are aggregated by dedupe key and time window. OxiBelt preserves controller-owned statuses such as `processing`, `applied`, `failed`, and `withdrawn`; rows start as `observing` when an action sets `min_count > 1` and promote to `pending` when the aggregate count reaches that threshold.

## WAF Attachment

```toml
[waf]
enabled = false
mode = "enforcing"      # enforcing | monitor
fail_policy = "closed"  # closed | open
duplicate_metadata_policy = "fail_closed" # fail_closed | null_on_duplicate | reject_request

[waf.http_body_compression]
mode = "off" # off | transform
encodings = ["gzip", "deflate", "br", "zstd"]
max_decoded_body_bytes = 10485760
max_expansion_ratio = 20
decode_timeout_ms = 1000
max_concurrent_bodies = 0

[waf.limits]
max_rule_runtime_ms = 5
max_total_waf_runtime_ms = 20
max_expression_steps = 2000
max_memory_bytes = 262144
max_string_bytes = 8192
max_body_inspection_bytes = 1048576
max_header_count = 128
max_header_value_bytes = 8192
max_mutations = 32
max_regex_runtime_ms = 2
max_advanced_regex_subject_bytes = 1048576
max_advanced_regex_backtracks = 1000000
max_helper_items = 128
max_helper_pattern_count = 32
max_helper_result_bytes = 8192
max_person_proof_reuse_tokens = 4096

[[waf.pattern_sets]]
name = "sql-injection-keywords"
kind = "contains" # contains | regex
patterns = ["UNION SELECT", "DROP TABLE", "information_schema"]

[waf.crs]
enabled = false
mode = "monitor" # monitor | enforcing
setup_file = "crs/crs-setup.conf"
rule_files = ["crs/rules/*.conf"]
paranoia_level = 1
inbound_anomaly_score_threshold = 5
outbound_anomaly_score_threshold = 4
unsupported_directive_policy = "fail_closed"

[[waf.crs.rule_overrides]]
name = "monitor-sqli-rule"
rule_ids = ["942100"]
tags = ["attack-sqli"]
mode = "monitor" # enforcing | monitor | disabled
reason = "known application false positive"

[[waf.crs.allowlists]]
name = "allow-editor-html"
rule_ids = ["941320"]
methods = ["POST"]
routes = ["app-root"]
path_prefixes = ["/editor/"]
reason = "editor intentionally submits HTML"
```

`max_body_inspection_bytes` controls the request body, response body, and native stream payload prefix captured for OxiRule and CRS body inspection. The default is `1048576` bytes. Bytes after this prefix are forwarded or replayed without inspection and are reflected through `Body.IsTruncated` or `Stream.Payload.IsTruncated`. The same value also bounds WebSocket stream-WAF frame buffering: an individual WebSocket frame payload larger than this value is closed fail-closed instead of being buffered for prefix inspection.

Policy-authored WAF regex literals compile with the linear Rust `regex`
engine first and fall back to bounded `fancy-regex` matching when lookahead,
lookbehind, backreferences, or another supported advanced construct requires
it. `max_advanced_regex_subject_bytes` limits the UTF-8 byte length presented
to an advanced matcher, and `max_advanced_regex_backtracks` is passed to its
backtracking budget. An exceeded subject, backtrack, or matcher stack limit in
a request, response, or stream phase uses that phase's fail-closed decision
even when `fail_policy = "open"`; input is not truncated into a different
regex subject. Unrelated WAF evaluation errors continue to follow
`fail_policy`. The `edge-secure-medium` v1 and v2 profiles cap these values at
`65536` and `100000`, respectively. Request-derived dynamic regex arguments
remain restricted to the linear engine. Syntax must be accepted by `regex` or
`fancy-regex`; PCRE-specific compatibility is not provided.

`[waf.http_body_compression]` is off by default and opt-in per effective route. Global `mode = "transform"` enables the transform for routes that inherit it; route-level `[routes.waf.http_body_compression] mode = "off"` disables it for a route, and `mode = "transform"` enables it even when the global mode is `off`. Supported single `Content-Encoding` values are controlled by `encodings`; `identity` is a no-op, while multiple codings or unsupported codings fail closed. `max_decoded_body_bytes` is the decoded transform cap, `max_expansion_ratio` bounds compression-bomb expansion relative to the encoded bytes, `decode_timeout_ms` bounds each decode, and `max_concurrent_bodies = 0` uses an automatic CPU-sized concurrency budget covering each compressed-body transform from encoded-body collection through decode and request re-encode. `waf.limits.max_body_inspection_bytes` remains the OxiRule/CRS inspection prefix cap after any transform has produced a decoded view.

On transform-enabled routes, route matching, route rate limits, dynamic policy, built-in Person proof precheck, redirects, and external auth run before body decoding. OxiRule, OxiRule Group, external OxiRule files, rulepacks, and CRS request/response body inspection then share the decoded body view. DynamicPolicy remains header/metadata-based for this feature and does not receive a decoded body subject. Request transform errors return `415` for unsupported or multiple codings, `400` for malformed coding, `413` for decoded cap or expansion-ratio rejection, and `408` for decode/read timeout. Response transforms strip upstream `Accept-Encoding` when response body WAF is needed, regardless of `compression.upstream_accept_encoding`; if a compressed response must be inspected but carries unsupported/multiple codings, `Cache-Control: no-transform`, `Content-Range`, malformed coding, or exceeds transform caps, OxiBelt fails closed with `502`, or `504` on timeout. After response WAF, cache, and route response actions, the normal downstream `[compression]` policy may re-compress the identity response.

When any transform-enabled route can be selected, `Content-Encoding` ownership belongs to the WAF body transform layer. Configuration validation rejects route and WAF request/response header mutations that set, add, or remove `Content-Encoding` on transform routes, because those mutations would invalidate the decode/replay boundary.

Inline global rules are configured under `[[waf.rules]]`; route-level rules use `[[routes.waf.rules]]`. Reusable rule groups are configured under `[[waf.rule_groups]]` or `[[routes.waf.rule_groups]]` and are referenced from rules with `groups = ["name"]`. Shared group files can be loaded with `[waf] rule_group_files = ["groups/*.oxirule-group.toml"]` and route-level `rule_group_files`. Rulepacks can be loaded with `[waf] rulepack_files = ["rulepacks/*.oxirule-rulepack.toml"]` and route-level `rulepack_files`. Each group file uses a top-level `[[rule_groups]]` array and the same fields as inline `WafRuleGroupConfig`. Each rulepack file uses a `[rulepack]` manifest plus `[[rules]]` and/or `[[group_files]]`, then expands into the same native OxiRule rule and group configuration. Exact file paths must exist; glob entries may match zero files and are loaded in sorted order. External rule, group, and rulepack paths resolve under the oxirule directory. A rule entry may use inline `when`, `groups`, or both; `path` cannot be combined with inline `when`, `merge_condition_as`, `groups`, or `actions` on the same rule entry. OxiBelt supports rulepack schema version `2` only; v2 manifests may declare scalar typed variables, route `[[bindings]]`, scalar-value `[[profiles]]`, typed `[[overrides]]`, and scoped `[[exceptions]]` for `oxibeltctl rulepack fit`, `render`, `check`, and `apply`. Variables are ordinary render values; bindings describe local OxiBelt objects and render through `bind_as` during installation. Manifest `[[overrides]]` and values-file `[[rule_overrides]]` can adjust only supported typed rule fields (`mode`, `priority`, `enabled`) and selected action fields (`rate`, `burst`, `status`, `body`) by rulepack, tag, rule ID, or rule name selector. Manifest and values-file `[[exceptions]]` provide false-positive tuning by adding a negative predicate to matched rules; they require at least one rule selector (`rule_ids`, `rule_names`, or `tags`), at least one traffic selector (`routes`, `methods`, `path_prefixes`, or `source_cidrs`), and a `reason`. Optional `expires_at` values must use strict UTC `YYYY-MM-DDTHH:MM:SSZ`; expired exceptions are ignored and logged, while future-dated exceptions stop matching requests once `expires_at` is reached without requiring a reload. Raw content replacement, arbitrary regex patching, scripts, callbacks, header/body exception selectors, and stream-phase exception matches are not supported. URL-installed rulepacks may also carry optional installed-source fields under `[rulepack]`: `source_url`, `source_sha256`, `source_openpgp_signature_url`, and `source_openpgp_signer_fingerprint`.

`oxibeltctl rulepack --url` accepts HTTPS rulepacks with `--sha256`, or HTTPS rulepacks with a detached OpenPGP signature verified against local public keys. HTTP rulepack URLs require both `--allow-insecure-rulepack-url` and a valid detached OpenPGP signature. Use `--rulepack-openpgp-signature-url URL` or `--rulepack-openpgp-signature-file FILE` for the detached signature, `--rulepack-openpgp-key FILE` for per-command public-key trust, `--rulepack-openpgp-keyring DIR` for installed trust stores, and `--rulepack-openpgp-fingerprint HEX` for full-fingerprint pins. If no explicit key material is provided, `oxibeltctl` checks `OXIBELT_RULEPACK_OPENPGP_KEYRING_DIR`, then `/etc/oxibelt/oxirule/trusted-rulepack-publishers` when present. Values files may provide local `[[rule_overrides]]` and `[[exceptions]]`, but they do not change URL pinning or OpenPGP requirements. Private keys, remote key download, raw rule overrides, and Sigstore are out of scope for rulepack URL installs.

`oxibeltctl rulepack repo add NAME URL` stores remote catalog indexes in `${OXIBELT_RULEPACK_REPOS_FILE}` when set, otherwise `${XDG_CONFIG_HOME:-$HOME/.config}/oxibelt/rulepack-repos.toml`. The registry stores only repo metadata: URL, CA certificate paths, token environment variable names, insecure URL opt-in, and OpenPGP trust paths/fingerprint pins. It never stores bearer token values. Catalog repo tokens are forwarded to catalog-selected rulepack source URLs only when the source URL uses the same scheme, host, and port as the catalog repo URL. Catalog indexes use `[index] schema_version = 1` and `[[rulepacks]]` entries with `name`, `version`, `source`, required `sha256`, optional `signature_type = "openpgp"`, optional `signature`, `targets`, `min_oxibelt_version`, `license`, `maintainers`, and `description`. `rulepack search`, `rulepack info`, `rulepack install`, and `rulepack update --plan` ignore incompatible entries whose `min_oxibelt_version` is newer than the running `oxibeltctl`; installing an explicitly incompatible entry fails before download. `rulepack install NAME` resolves the catalog entry into the same URL apply pipeline, so route fitting, values files, interactive prompts, dry-run reports, install locks, source provenance, and `/admin/v1/files/sync` behavior are unchanged. Catalog entries still install only schema version `2` rulepacks; schema version `1` and legacy `[variables.discovery]` source manifests are rejected. Catalog signatures currently reuse OpenPGP detached signatures; Sigstore and SLSA provenance are reserved for a future catalog schema.

`oxibeltctl rulepack adapt` is local import tooling, not a runtime rulepack compatibility layer. The `modsecurity-crs-exclusion` adapter reads a local ModSecurity CRS exclusion file and emits OxiBelt CRS tuning TOML to stdout or `--output FILE`; it does not contact Admin APIs, install files, fetch remote inputs, execute adapter binaries, or change rulepack schema handling. It supports only `SecRuleRemoveById`, `SecRuleRemoveByTag`, `SecRuleRemoveByMsg`, and literal `<Location "/prefix">` scopes. Scoped removals become `[[waf.crs.allowlists]]`; unscoped removals require `--allow-global-disable` and become `[[waf.crs.rule_overrides]] mode = "disabled"`. Unsupported update directives, `ctl:ruleRemove*`, regex locations, rule ID ranges, scripts, callbacks, and unsafe path prefixes are rejected.

Rulepack manifests must end with `.oxirule-rulepack.toml`:

```toml
[waf]
enabled = true
rulepack_files = ["rulepacks/*.oxirule-rulepack.toml"]

# /etc/oxibelt/oxirule/rulepacks/admin.oxirule-rulepack.toml
[rulepack]
schema_version = 2
name = "admin-path"
version = "0.1.0"
default_mode = "monitor" # monitor | enforcing

[[variables]]
name = "admin_cidr"
type = "cidr"
default = "10.0.0.0/8"

[[rules]]
name = "admin-path-allowlist"
phase = "request"
priority = 100
content = '''
when = "Request.Http.Path.startsWith('/admin') && !Request.Client.Ip.inCidr('{{admin_cidr}}')"

[[actions]]
type = "reject"
status = 403
'''
```

Rules inside a rulepack may use inline `content` or a `path` to a `.oxirule.toml` file under the oxirule directory. `[[group_files]]` entries may use inline `content` or a `path` to a `.oxirule-group.toml` file. OxiBelt renders declared scalar variables from defaults at load time; required variables without defaults are intended for `oxibeltctl rulepack render`, `oxibeltctl rulepack check`, or `oxibeltctl rulepack apply --var KEY=VALUE` or `--values FILE`. Environment objects such as routes are declared as bindings and supplied with `--bind KEY=VALUE` or `[bindings]` in a values file.

Route bindings use `kind = "route"` and `bind_as` to name the render placeholder populated during render. `bind_as` must not collide with a scalar `[[variables]]` name or another binding target:

```toml
[[bindings]]
name = "app_route"
kind = "route"
bind_as = "route_name"
required = true

[bindings.discovery]
name_any = ["vault", "secret"]
host_contains_any = ["vaultwarden", "vault"]
upstream_contains_any = ["vaultwarden"]
path_prefix_any = ["/"]
```

`oxibeltctl rulepack fit` uses Admin `/admin/v1/config/effective` and the redacted effective TOML to rank route candidates without installing the rulepack. `oxibeltctl rulepack plan`, `diff`, and non-interactive `apply --dry-run` prefer Admin `/admin/v1/waf/rulepacks/plan` for config-aware, content-level reports, and fall back to the older local planning path when the Admin server returns `404` or `405`. `oxibeltctl rulepack apply --interactive` prompts for unresolved required bindings and required scalar variables, then deploys a rendered manifest through Admin `/admin/v1/files/sync`. Values files may contain `[bindings]`, `[values]`, `[overrides]` with `profile`, `mode`, and `force_mode`, plus local `[[rule_overrides]]` and `[[exceptions]]`. Precedence is rulepack defaults, selected profile values/mode, values file, then CLI `--bind`, `--var`, `--profile`, `--mode`, and `--force-mode`. Installed manifests contain concrete rendered rule content and do not require source binding/profile metadata at runtime. Direct runtime loading rejects source manifests that still declare unresolved required bindings; render or apply them with `--bind` first. `rulepack apply` also writes `rulepacks/{name}.install.toml` as metadata with source provenance, selected profile, effective mode, bindings, values, local rule overrides, and local exceptions; this install lockfile is not loaded as an executable rulepack.

```toml
[[waf.rules]]
name = "block-public-admin"
id = "block-admin-public"
tags = ["access-control", "admin"]
mode = "monitor" # optional: enforcing | monitor; defaults to [waf].mode
phase = "request"
priority = 100
when = "Request.Http.Path.startsWith('/admin')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Forbidden"
```

`merge_condition_as = "and" | "or" | "override"` controls how a rule or group `when` joins earlier referenced group conditions and defaults to `and`. Action-level `priority` defaults to `0`; grouped and rule-local actions are sorted together by lower priority first, with declaration order preserved for ties.

`[waf].mode` sets the default mode for all rules. A rule-level `mode` overrides that default in both directions: `monitor` counts matches without applying actions, while `enforcing` applies actions normally.

`[waf.crs]` enables the CRS-compatible execution layer. It loads `setup_file` and each `rule_files` glob from the OxiRule directory, using the same normalized relative path restrictions as external OxiRule files. CRS starts in `monitor` mode by default so hits and anomaly scores are recorded without blocking; set `mode = "enforcing"` to apply inbound and outbound anomaly thresholds. Unsupported CRS directives, operators, transforms, variables, or actions fail closed at configuration load/compile time and report the file and line that must be changed.

`[[waf.crs.rule_overrides]]` applies the first matching static rule override. Select rules with `rule_ids`, `tags`, or `msg_contains`; at least one selector is required. `mode = "monitor"` records observed hits and anomaly score without contributing to blocking score, `mode = "enforcing"` can enforce even when global CRS mode is monitor, and `mode = "disabled"` records hits without scoring/actions.

`[[waf.crs.allowlists]]` is for scoped false-positive tuning. It uses the same rule selectors and also requires at least one traffic selector: `methods`, `routes`, or `path_prefixes`. Traffic selector categories are ANDed together, while values within a category are ORed. A matching allowlist suppresses CRS scoring/actions for that transaction and increments `tuned_hits`; broad rule disables should use `rule_overrides` instead. `header_equals` is rejected for CRS allowlists because inbound request headers are client-controlled before proxy forwarding.

Existing ModSecurity CRS exclusion snippets can be imported with `oxibeltctl rulepack adapt --adapter modsecurity-crs-exclusion`, then reviewed and pasted into `[waf.crs]`. The adapter intentionally emits CRS tuning, not `.oxirule-rulepack.toml`, because CRS exclusions affect the CRS compatibility engine rather than native OxiRule rulepack expansion.

Recommended CRS rollout is monitor first, inspect `/admin/v1/waf/rule-hits`, add scoped allowlists or per-rule overrides for confirmed false positives, then switch `[waf.crs].mode` to `enforcing`. The compatibility matrix is available from `/admin/v1/waf/crs/compatibility`; OxiBelt targets the CRS current release and `v4.25.x` LTS line as of 2026-05-10. Official CRS references: [v4.25.0 LTS announcement](https://coreruleset.org/20260321/announcing-crs-v4-25-lts/), [false positives and tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/), and [installation](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/).

Response body CRS inspection uses the same bounded prefix behavior as OxiRule response body inspection and can affect cache/background refresh behavior. Treat response inspection as a targeted control for leakage detection, not a substitute for upstream output encoding. WebTransport frame/datagram payload inspection is not supported by the CRS layer.

Rule syntax, actions, helpers, and Person proof settings are documented in [OxiRule.md](OxiRule.md).

Person proof uses `person_proof_mode` to select one of four public modes. `built_in` is OxiBelt built-in PoW plus the built-in challenge frontend. `openapi` uses OxiBelt built-in PoW session/verify/OpenAPI endpoints with a custom challenge frontend. `third_party_provider` uses OxiBelt's built-in Turnstile, hCaptcha, or Friendly Captcha v2 adapters. `custom_provider` calls a configured JSON HTTP provider that returns `{ "success": true|false }` and may describe external Proof of Something flows with `proof_kind`, `proof_challenge_kind`, `proof_label`, and arbitrary `provider_metadata`.

`custom_frontend_url` is not a filesystem path. It is an origin-relative URL routed by the same OxiBelt instance, either to a static route asset or to a proxied challenge frontend backend. Custom frontends call OxiBelt's `session_path` and `verify_path`; browser code should not call provider-native server APIs directly. Clearance tokens can be issued to a cookie, localStorage, or JSON response, and protected requests can read them from configured cookie keys, `Authorization: Bearer`, or configured header keys.

```toml
[waf.person_proof]
session_path = "/.oxibelt/person-proof/session"
verify_path = "/.oxibelt/person-proof/verify"
openapi_path = "/.oxibelt/person-proof/openapi.json"

[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "third_party_provider"
third_party_provider = "turnstile"
custom_frontend_url = "/person-proof/index.html"
site_key = "0x4AAAA..."
secret_env = "OXIBELT_TURNSTILE_SECRET"
provider_fail_policy = "closed"
clearance.issue_to = "cookie"
clearance.cookie.key = "__oxibelt_person_proof"

[[waf.rules.actions.clearance.sources]]
type = "cookie"
key = "__oxibelt_person_proof"
```

Custom Proof of Knowledge through an external provider:

```toml
[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "custom_provider"
custom_frontend_url = "/proof/pok.html"
provider = "passkey-knowledge"
proof_kind = "knowledge"
proof_challenge_kind = "proof_of_knowledge_v1"
proof_label = "passkey"
provider_endpoint = "https://proofs.internal.example/verify"
provider_metadata = { prompt = "login-passkey" }
```

Custom Proof of Work through an external provider, separate from OxiBelt built-in `pow_sha256_v1`:

```toml
[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "custom_provider"
custom_frontend_url = "/proof/external-work.html"
provider = "external-work-service"
proof_kind = "work"
proof_challenge_kind = "external_proof_of_work_v1"
proof_label = "managed-work"
provider_endpoint = "https://proofs.internal.example/work/verify"
provider_metadata = { difficulty_profile = "interactive" }
```

The built-in PoW page embeds a signed `session` and uses the same `session_path` and `verify_path` as custom frontends; the old direct `token.nonce` proof cookie flow is not used. A challenge redirect includes `session`, `session_path`, `verify_path`, `openapi_path`, `return_path`, and `expires_unix_ms`. Challenge issuance does not reserve replay state. Provider-specific values such as `site_key` and clearance storage metadata are returned by `GET session_path?session=...`. Verification accepts only JSON `POST verify_path` with `{ "session": "...", "response": { "token": "...", "fields": {} } }`. `single_use` defaults to `true`; with it enabled, the session is consumed before PoW/provider verification, including failed provider responses. In localStorage mode, the browser must send the stored token on later protected requests using `clearance.local_storage.request_header` because servers cannot read localStorage directly.

Admin Person proof status and revocation operate on exact SHA-256 clearance hashes, not user accounts or browser sessions. With process-local Person proof state, Admin revocation affects only the current process. With `[shared_state].person_proof_backend` configured, hash-keyed clearance markers and revocation tombstones are shared across workers using the configured backend. Older raw-key replay markers remain honored for replay prevention until they expire, but Admin output reports them only as aggregate legacy counts. Dynamic policy can match the existing Person proof object-model state and verified clearance-hash subjects, but it does not currently trigger a second staged proof profile or ask upstream applications to require a new proof step.

## Upstreams

```toml
[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2" # h1 | h2 | h3
connect_timeout_ms = 3000
request_timeout_ms = 30000
first_byte_timeout_ms = 30000
read_timeout_ms = 30000
send_timeout_ms = 30000
idle_timeout_ms = 75000
pool_max_idle_per_host = 128
preserve_host = false
websocket = true
webrtc = true
webtransport = true
proxy_protocol_egress = "off" # off | v1 | v2

[upstreams.tls.ech]
mode = "disabled" # disabled | grease | config_list
# config_list_file = "app.echconfiglist"

[upstreams.tls.resumption]
mode = "enabled" # enabled | disabled
session_cache_size = 1024
tls12 = "session_id_or_tickets" # disabled | session_id_only | session_id_or_tickets

# Optional override for this direct upstream only. Omitted fields inherit their
# own defaults, not partial values from [proxy.upstream_revocation].
[upstreams.tls.upstream_revocation.ocsp]
mode = "disabled" # disabled | live_fetch
# failure_policy = "fail_closed" # fail_closed | degraded_allow

[upstreams.tls.upstream_revocation.crlite]
mode = "disabled" # disabled | enforce | managed
# filter_file = "app-upstream-crlite.filter"
```

Upstream origins must use `http://` or `https://`. `max_http_version = "h3"` requires an `https://` origin. ECH `config_list_file` is required only with `mode = "config_list"` and is invalid for other modes. Upstream TLS resumption controls OxiBelt's client-side cache only; the upstream server still chooses whether its own tickets are stateful or stateless. When the effective outbound upstream revocation policy is enabled, OxiBelt disables upstream client-side resumption so every new upstream TLS connection reaches certificate and revocation verification. `proxy_protocol_egress` writes a PROXY protocol header to TCP-based upstream connections and is rejected with HTTP/3 upstream selection. `[upstreams.tls.upstream_revocation]` overrides the global runtime outbound revocation policy for that direct upstream; use `mode = "disabled"` in both nested tables to opt one upstream out of a global policy.

`request_timeout_ms` is the compatibility upper bound for sending a request and receiving response headers. `first_byte_timeout_ms` separately controls the response-header/first-byte wait and is capped by `request_timeout_ms` when both are configured. The guarded direct-H1 transports keep that response-head deadline active across any accepted informational responses until the final response head arrives. `read_timeout_ms` is an upstream response body idle timeout: progress resets the idle window while fixed-length data, chunk metadata and data, trailers, close-delimited bodies, SSE, and long downloads remain streaming. It is not a total response-body deadline. `send_timeout_ms` controls upstream request body send backpressure.

`idle_timeout_ms` is also the idle connection timeout for the upstream Hyper client pool. `pool_max_idle_per_host` caps idle HTTP/1.1 and HTTP/2 TCP upstream connections retained per origin; `0` disables keeping idle connections for that upstream. For `[[upstream_pools]]`, each synthetic upstream server uses `[upstream_pools.keepalive].max_idle` as this cap.

```toml
[[external_auth]]
name = "edge-auth"
provider = "authelia" # authelia | oauth2 | oidc
endpoint = "https://auth.internal.example/api/authz/forward-auth"
timeout_ms = 2000
fail_policy = "closed" # closed | open
forward_headers = ["authorization", "cookie"]
identity_headers = ["remote-user", "remote-groups", "remote-email", "remote-name"]
terminal_response_headers = ["location", "www-authenticate", "set-cookie"]
max_response_body_bytes = 65536
# OAuth2 introspection only:
# client_id_env = "OAUTH2_INTROSPECTION_CLIENT_ID"
# client_secret_env = "OAUTH2_INTROSPECTION_CLIENT_SECRET"
# required_scopes = ["openid", "profile"]

[[external_auth.required_claims]]
name = "aud"
value = "oxibelt"

[[external_auth.claim_headers]]
claim = "sub"
header = "remote-user"
```

`[[external_auth]]` defines authorization checks that routes can reference with `external_auth = "edge-auth"`. OxiBelt does not implement the browser login flow. For `provider = "authelia"`, it performs a forward-auth GET to `endpoint`, forwarding the configured request headers plus `X-Forwarded-*` context. When present, downstream `Accept` and `X-Requested-With` are also forwarded as Authelia protocol metadata even if they are omitted from `forward_headers`, so Authelia can distinguish browser navigation from XHR or non-HTML requests. OxiBelt does not synthesize either header. A 2xx allows the request and a non-2xx becomes the downstream terminal response with only allowlisted response headers. `provider = "gateway_ext_auth_http"` uses the same HTTP forward-auth runtime for Gateway API `ExternalAuth.protocol = "HTTP"` translations, but controller-generated entries render explicit `forward_headers`, `identity_headers`, and `terminal_response_headers` arrays so no non-Gateway defaults are inherited. For `provider = "oauth2"`, it requires an inbound `Authorization: Bearer` token and POSTs to an OAuth2 token introspection endpoint; `required_scopes` must all be present when configured. For `provider = "oidc"`, it calls an OIDC UserInfo endpoint with the bearer token and enforces `required_claims`.

Before forwarding upstream, OxiBelt strips configured `identity_headers` from the client request and injects identity headers only from the trusted auth response/token claims. Routes with `external_auth` use the general proxy path so fast paths cannot bypass the check. `timeout_ms` is a wall-clock deadline for the full auth exchange, including request send, response headers, and response body collection. `max_response_body_bytes` caps the auth response body size but is not a time limit. `fail_policy = "closed"` returns `503` on auth-service errors; `open` allows the request and records an auth error metric.

External-auth header lists never delegate message framing or routing identity.
`forward_headers` and `identity_headers` reject framing, hop-by-hop, `Host`,
`Forwarded`, and trusted forwarding headers; `terminal_response_headers`
rejects framing and hop-by-hop headers. OxiBelt derives request and response
framing from the actual body even if an invalid runtime object bypasses normal
configuration admission.

```toml
[[upstream_pools]]
name = "app-pool"
algorithm = "power_of_two_choices" # power_of_two_choices | weighted_least_conn | rendezvous_hash | rendezvous_ip_hash | ewma | least_time | sticky_cookie

[upstream_pools.sticky_cookie]
cookie_name = "oxibelt_sticky"
ttl_seconds = 3600
fallback_algorithm = "power_of_two_choices" # power_of_two_choices | weighted_least_conn | rendezvous_hash | rendezvous_ip_hash | ewma | least_time
secret_env = "OXIBELT_STICKY_COOKIE_SECRET"
secure = true
http_only = true
same_site = "lax" # lax | strict | none
path = "/"

[upstream_pools.keepalive]
max_idle = 32
idle_timeout_ms = 75000
max_lifetime_ms = 300000

[upstream_pools.slow_start]
enabled = false
duration_ms = 30000
min_weight_percent = 10

[upstream_pools.outlier_ejection]
enabled = false
consecutive_failures = 5
base_ejection_ms = 30000
max_ejection_ms = 300000

[[upstream_pools.servers]]
id = "app-1"
origin = "https://app-1.internal.example"
weight = 1
max_conns = 1024
backup = false
state = "ready" # ready | drain | down | maintenance

[upstream_pools.servers.tls]
server_name = "app.internal.example"
trust = "exclusive" # inherit | system | exclusive
trusted_ca_certs = ["app-ca.pem"]
trusted_ca_sha256 = ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]

[[upstream_pools.discovery]]
provider = "file"
file = "discovery/app-pool.json"
refresh_interval_ms = 5000

[[upstream_pools.discovery]]
provider = "dns"
name = "app.internal.example"
record_type = "a_aaaa" # a | aaaa | a_aaaa | srv
scheme = "http"
port = 8080
refresh_interval_ms = 30000
min_ttl_ms = 1000

[[upstream_pools.discovery]]
provider = "kubernetes"
id = "app-primary"
weight_multiplier = 20
endpoint = "https://kubernetes.default.svc"
namespace = "default"
service = "app"
port_name = "http"
kubernetes_resource = "endpoints" # endpoints | endpoint_slice
watch = false
watch_timeout_seconds = 300
update_debounce_ms = 250
# token_env = "KUBERNETES_SERVICE_TOKEN"
# token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
refresh_interval_ms = 30000

[[upstream_pools.discovery]]
provider = "consul"
endpoint = "http://consul.service.consul:8500"
service = "app"
# namespace = "default"
# datacenter = "dc1"
# filter = "Service.Meta.version == v1"
# token_env = "CONSUL_HTTP_TOKEN"
refresh_interval_ms = 30000

[[upstream_pools.discovery]]
provider = "etcd"
endpoint = "https://etcd.internal.example:2379"
key_prefix = "/oxibelt/upstreams/app/"
# token_env = "ETCD_TOKEN"
refresh_interval_ms = 30000

[[upstream_pools.discovery]]
provider = "nomad"
endpoint = "https://nomad.internal.example:4646"
namespace = "default"
service = "app"
filter = "Tags contains \"blue\""
token_env = "NOMAD_TOKEN"
scheme = "https"
watch = true
watch_timeout_seconds = 45
refresh_interval_ms = 30000

[upstream_pools.health_check]
enabled = true
mode = "passive" # passive | active
protocol = "http" # http | grpc
method = "POST"
path = "/health"
health_port = 18081
health_host = "health.internal.example"
body = "{\"probe\":\"ok\"}"
interval_ms = 10000
timeout_ms = 2000
healthy_threshold = 2
unhealthy_threshold = 3
rise = 2 # alias for healthy_threshold; do not configure both
fall = 3 # alias for unhealthy_threshold; do not configure both
expected_status = [204]
expected_body_regex = "ready"
body_match_max_bytes = 65536
jitter_ms = 250
grpc_service = ""
grpc_expected_statuses = ["SERVING"]

[[upstream_pools.health_check.headers]]
name = "X-OxiBelt-Health"
value = "active"

[[upstream_pools.health_check.expected_status_ranges]]
start = 200
end = 299

[upstream_pools.health_check.tls]
trusted_ca_certs = ["upstream-health-ca.pem"]

[upstream_pools.health_check.tls.upstream_revocation.ocsp]
mode = "live_fetch"
failure_policy = "fail_closed"
```

Pool names and upstream names are separate namespaces. `algorithm` defaults to `power_of_two_choices`. HTTP pools support `power_of_two_choices`, `weighted_least_conn`, `rendezvous_hash`, `rendezvous_ip_hash`, `ewma`, `least_time`, and `sticky_cookie`. `algorithm = "sticky_cookie"` selects an upstream by a signed affinity cookie when present, otherwise it uses `sticky_cookie.fallback_algorithm` and emits `Set-Cookie`; the fallback must be one of the non-sticky modern algorithms. Legacy names such as `round_robin`, `least_conn`, `least_connections`, `random`, `hash`, and `ip_hash` are rejected by default and must be migrated explicitly. With `[config] lb_policy_compat_profile = "nginx"` or `"caddy"`, OxiBelt converts `least_conn` and `least_connections` to `weighted_least_conn`, and `ip_hash` to `rendezvous_ip_hash`, across HTTP pools, sticky-cookie fallbacks, TURN pools, and WAF `set_load_balancing_policy` actions. The profile does not convert `round_robin`, `random`, or `hash`; those names fail with diagnostics because they do not have exact OxiBelt equivalents. Prefer running `oxibeltctl config lb-policy-compat source/config/oxibelt.toml --profile nginx --format text` or `--format json`, updating the TOML to canonical policy names, and then returning `lb_policy_compat_profile` to `strict`. The cookie HMAC secret comes from `sticky_cookie.secret_env` when set, from `[shared_state].sticky_sessions_backend` when configured, or from a process-local generated secret. Pool servers must use `http://` or `https://`, server IDs must be unique within a pool, and server weights must be greater than zero.

Each HTTPS `[[upstream_pools.servers]]` and HTTPS
`[[upstream_pools.discovery]]` may define a nested `tls` table. `server_name`
overrides the connection authority only for SNI and certificate authentication.
`trust = "inherit"` preserves the global proxy trust behavior, `system` uses
only system/WebPKI roots, and `exclusive` requires nonempty
`trusted_ca_certs` without adding global or system roots. CA paths resolve
under the certificate root. `trusted_ca_sha256` must contain one lower-case
SHA-256 digest for every CA file; startup and reload fail on missing files or a
digest mismatch. Plain HTTP servers/discovery reject a nondefault TLS table.
This per-member policy is used by forwarding and active probes. Health-check
extra roots cannot augment members using `system` or `exclusive` trust.

`upstream_pools.health_check` defaults remain compatible with existing configs: HTTP active checks use `GET /healthz`, `expected_status = [200, 204]`, `interval_ms = 5000`, `timeout_ms = 1000`, and thresholds `healthy_threshold = 2` / `unhealthy_threshold = 3`. `mode = "passive"` records passive request results only; `mode = "active"` schedules background probes when `enabled = true`. For HTTP probes, `method`, `path`, `health_port`, `health_host`, `headers`, and `body` build the probe request. `health_port` changes only the TCP connect port. `health_host` changes only the HTTP `Host` header; TLS SNI and hostname verification still use the probe URI host from the pool server origin. Header names and values must be valid HTTP fields, and OxiBelt rejects reserved hop-by-hop, forwarding identity, and `Host` headers in `headers`; use `health_host` for Host.

HTTP health success is `(expected_status OR expected_status_ranges) AND expected_body_regex when configured`. Status codes and inclusive status ranges must be valid HTTP statuses, and ranges require `start <= end`. `expected_body_regex` is compiled during config validation and matches only the first `body_match_max_bytes` bytes collected from the response. `body_match_max_bytes`, `interval_ms`, `timeout_ms`, and nonzero thresholds must be greater than zero. `jitter_ms` adds up to that many milliseconds to each active schedule interval to avoid synchronized probes. `rise` and `fall` are TOML aliases for `healthy_threshold` and `unhealthy_threshold`; configuring an alias and its canonical field together is invalid.

`protocol = "grpc"` preserves the gRPC health checking wire format: OxiBelt sends `POST /grpc.health.v1.Health/Check` over HTTP/2 with the configured `grpc_service` and checks `grpc_expected_statuses`. `health_port`, `health_host`, custom non-reserved headers, timeout, interval, thresholds, jitter, and health-check TLS policy still apply. HTTP body regex matching is not supported for gRPC health checks.

`upstream_pools.health_check.tls.trusted_ca_certs` is health-check only. These roots are resolved under the cert directory, appended to `proxy.trusted_ca_certs` for active health and diagnostics probes only when the selected member inherits trust, and tracked as runtime reload files. They cannot augment a member whose `tls.trust` is `system` or `exclusive`, and they do not change normal upstream-pool forwarding trust. `upstream_pools.health_check.tls.upstream_revocation` can override outbound OCSP/CRLite policy for health-check HTTPS clients only. OxiBelt does not expose an insecure skip-verify mode for health checks.

Pool server `state` controls new request selection. `ready` accepts traffic. `drain`, `down`, and `maintenance` stop new selection while already selected in-flight requests finish naturally. `slow_start` and `outlier_ejection` are opt-in and disabled by default. When slow start is enabled, newly added, discovered, or recovered servers ramp from `min_weight_percent` to full effective weight over `duration_ms` across all pool algorithms, including sticky fallback, rendezvous, EWMA, and least-time scoring. When outlier ejection is enabled, passive retry/health failures can temporarily exclude a server after `consecutive_failures`; the ejection duration starts at `base_ejection_ms`, backs off per ejection count, and is capped by `max_ejection_ms`. If no ready, healthy, non-ejected server remains, OxiBelt preserves the existing fail-closed upstream-pool response.

`[upstream_pools.circuit_breaker]` is a sparse override of `[circuit_breakers.pool_defaults]`. Use it for a dependency-wide active-request, pending-queue, physical-connection, or stream cap; it does not reinterpret `[[upstream_pools.servers]].max_conns`, which remains the existing selected-server request cap. Pool circuit failures are aggregate attempt outcomes and complement, rather than replace, per-server passive health and outlier ejection.

Dynamic discovery applies to `upstream_pools` only. Every discovery block may
set a stable `id` and positive `weight_multiplier` (default `1`). IDs must be
unique within the pool. Repeating a provider requires an explicit ID for every
instance; a legacy single instance may omit it and retains its provider-derived
identity. Runtime reconciliation replaces only servers owned by the matching
provider and instance ID. Across instances, OxiBelt treats each multiplier as
the instance's aggregate traffic share, divides that share among the instance's
ready endpoint weights, and then produces one deterministic bounded `u32`
weight vector using checked arithmetic and GCD reduction. An update is rejected
without replacing the active pool if normalization would lose a positive share
or collapse distinct shares. Admission permits at most 64 discovery instances
per pool and 256 across one configuration, before the supervisor can create any
polling or watch worker. Runtime server IDs are deterministic opaque identities
scoped to the provider and discovery instance; provider-local endpoint IDs are
validated as input but cannot collide with a sibling cohort.

`provider = "file"` reads a JSON document from a path under the config
directory, for example `source/config/discovery/app-pool.json` when running
from the repository layout. `provider = "nomad"` polls
`GET /v1/service/:service_name`; when `watch = true`, OxiBelt uses Nomad
blocking-query `index` and `wait` parameters derived from successful
`X-Nomad-Index` responses and `watch_timeout_seconds`. Nomad `token_env` is read
from the environment and sent only as `X-Nomad-Token`; bearer-style
configuration is intentionally not exposed in OxiBelt TOML. Nomad responses
are treated as untrusted input: entries need non-empty service IDs, matching
service names, valid addresses and ports, and generated `http`/`https` origins.
Invalid discovery responses or rejected runtime updates keep the previous
active pool state. The file discovery document shape is:

```json
{
  "servers": [
    {
      "id": "app-2",
      "origin": "http://app-2.internal.example:8080",
      "weight": 1,
      "max_conns": 1024,
      "backup": false
    }
  ]
}
```

`provider = "dns"` resolves `name` using `record_type = "a"`, `"aaaa"`, `"a_aaaa"`, or `"srv"`. A/AAAA discovery requires `port`; SRV discovery uses the SRV target port. DNS refresh uses the lower of the configured `refresh_interval_ms` and the observed DNS TTL, bounded by `min_ttl_ms`. DNS discovery rejects unsuccessful responses and responses whose transaction ID, question, answer owner, or verified CNAME chain does not match the active query.

`provider = "kubernetes"` defaults to polling the core Endpoints API at `/api/v1/namespaces/{namespace}/endpoints/{service}` and uses ready endpoint addresses with either `port` or `port_name`. Set `kubernetes_resource = "endpoint_slice"` to use the stable EndpointSlice API at `/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices`; EndpointSlice discovery selects endpoints unless `conditions.ready = false` or `conditions.terminating = true`, ignores FQDN endpoint slices, and accepts IPv4/IPv6 endpoint addresses. Set `watch = true` only with `kubernetes_resource = "endpoint_slice"` to maintain a streaming watch with `resourceVersion`, `allowWatchBookmarks`, `watch_timeout_seconds`, and `update_debounce_ms` coalescing before pool updates. EndpointSlice watch rejects any single streamed watch event line above 8 MiB and reconnects locally after `watch_timeout_seconds` plus one `refresh_interval_ms` grace interval if the stream has not ended. The Kubernetes service account needs `list` for polling and `list,watch` for EndpointSlice watch on `endpointslices.discovery.k8s.io` in the configured namespace. Use exactly one of `token_env` or `token_file` when Kubernetes discovery needs bearer authentication; `token_file` is intended for mounted service-account tokens and is read from the configured runtime path. `provider = "consul"` polls `/v1/health/service/{service}?passing=true` and uses service addresses and ports. `provider = "etcd"` polls the v3 KV range API under `key_prefix`; each value may be a URL string or a JSON object with `origin`, optional `id`, `weight`, `max_conns`, `backup`, and `state`. Kubernetes and etcd `token_env` values are sent as bearer tokens; Consul uses `X-Consul-Token`.

## Routes

```toml
[[routes]]
name = "api-v1"
hosts = ["api.example.com"]
path_prefix = "/v1"
replace_prefix_with = "/"
upstream = "app"
# upstream_pool = "app-pool"
# static_root = "public"
# upstream_http_version = "h2" # h1 | h2 | h3
# external_auth = "edge-auth"
# generic_http_upgrade = false
# connect_tunneling = false
# grpc_web = false
# cache = "default"
# compression = "default" # default | off | named policy
# security_headers = "default" # default | off | named policy
# priority_class = "default" # admin | health | security_callback | interactive | default | background | crawler

[routes.match]
# methods = ["GET", "HEAD"]
# source_cidrs = ["203.0.113.0/24"]
# protocols = ["http", "http2"] # http | http1 | http2 | http3 | websocket | webtransport
# priority = 0
# terminal = false

[routes.match.path]
# exact = "/v1/users"
# prefix = "/v1"
# regex = "^/v1/(users|groups)(/|$)"

#[[routes.match.headers]]
# name = "X-Route-Mode"
# exact = "canary"

#[[routes.match.queries]]
# name = "debug"
# present = true

#[routes.actions.rewrite]
# path = "/edge{path_suffix}"
# query = "id={capture:1}&debug={query:debug}"

#[routes.actions.redirect]
# status = 308
# location_template = "/new{path_suffix}?{query}"

#[[routes.actions.request_headers.set]]
# name = "x-route"
# value = "api-v1"

#[[routes.actions.request_headers.add]]
# name = "x-forwarded-tags"
# value = "edge"

#[routes.actions.response_headers]
# remove = ["server"]

#[[routes.actions.response_headers.set]]
# name = "x-served-by"
# value = "oxibelt"

#[routes.actions.cors]
# allow_origins = ["https://app.example.com"]
# allow_methods = ["GET", "POST"]
# allow_headers = ["authorization", "content-type"]
# expose_headers = ["x-served-by"]
# allow_credentials = true
# max_age_seconds = 600

#[routes.waf.http_body_compression]
# mode = "inherit" # inherit | off | transform

#[[routes.actions.request_mirrors]]
# upstream_pool = "shadow-pool"
# sample_percent = 10
# max_body_bytes = 0

#[routes.match.tls.client_cert]
# present = true

#[routes.match.tls.client_cert.subject_cn]
# suffix = ".example.com"

[routes.tls]
# ssl_early_data = "off" # off | safe_methods | on
# min_version = "tls1.2"
# max_version = "tls1.3"

[routes.timeouts]
# client_body_timeout_ms = 15000
# response_send_timeout_ms = 30000
# websocket_idle_timeout_ms = 60000
# webtransport_idle_timeout_ms = 60000
# upstream_connect_timeout_ms = 1000
# upstream_request_timeout_ms = 15000
# upstream_first_byte_timeout_ms = 2000
# upstream_read_timeout_ms = 10000
# upstream_send_timeout_ms = 10000

[routes.limits]
# max_request_body_bytes = 10485760

[routes.buffering]
# request = "streaming"
# response = "streaming"
# max_memory_body_bytes = 1048576
# max_temp_file_bytes = 0

[routes.retry]
# enabled = true
# tries = 2
# total_budget_ms = 5000
# per_attempt_timeout_ms = 1000
# on = ["connect_error", "read_timeout", "502", "503", "504"]
# retry_non_idempotent = false
# backoff_base_ms = 0
# backoff_max_ms = 0
# jitter = false
# reselect_pool_on_retry = true
# exclude_failed_pool_upstreams = true
# report_passive_health = true

[routes.circuit_breaker]
# max_active_requests = 64
# max_pending_requests = 16
# pending_queue_timeout = "25ms"
# max_body_inspection_jobs = 2
# max_decompression_jobs = 2

# Static routes only. These options require static_root.
#[routes.static_files]
# directory_index = ["index.html"]
# try_files = ["{path}.html", "/index.html"]
# spa_fallback = "/index.html"
# precompressed = ["br", "zstd", "gzip"]
# cache_control = "public, max-age=3600"
#
#[routes.static_files.cache_control_by_extension]
# html = "no-cache"
# css = "public, max-age=31536000, immutable"
#
#[routes.static_files.mime_overrides]
# wasm = "application/wasm"
#
#[routes.static_files.error_pages]
# not_found = "/404.html"
# server_error = "/50x.html"
```

`upstream_http_version` is a route-level backend protocol override and must not exceed the selected upstream capability. HTTP/3 overrides are rejected for upstream-pool routes and for upstreams with PROXY protocol egress enabled.

Route timeout overrides are optional. Omitted values inherit from `[limits]` for downstream behavior and from the selected `[[upstreams]]` entry for upstream behavior. TLS handshake and downstream header read timeouts are not route-level because route matching has not happened yet.

Route limit overrides are optional. `routes.limits.max_request_body_bytes` inherits from `[limits].max_request_body_bytes` when omitted, and configured values must be greater than zero.

Route buffering overrides are optional. Omitted values inherit from `[proxy.buffering]`; `temp_dir` is always global. CONNECT tunnels, HTTP Upgrade, and WebTransport forwarding remain streaming even when buffering is enabled.

Route retry overrides are optional. Omitted values inherit from `[proxy.retry]`, while each configured `[routes.retry]` field replaces only that global field. A route can set `enabled = true` to opt into retry when global retry is disabled, or `enabled = false` to opt out when global retry is enabled. The same duplicate-write warning for global `retry_non_idempotent = true` applies to route-level retry.

`[routes.circuit_breaker]` is a sparse override of `[circuit_breakers.route_defaults]`; each configured field replaces only that default. It gates work after route resolution and before WAF/body processing. Route request capacity is logical request/stream capacity, not a partition of a reusable multiplexed upstream connection.

Fields:

- `name`: unique route name.
- `hosts`: host match list; defaults to `["*"]`. Wildcard hosts such as `*.example.com` match only request hosts with at least one non-empty label before the suffix.
- `path_prefix`: path prefix match; defaults to `/`.
- `match`: optional extended route matcher. Conditions inside one `[routes.match]` table are ANDed together. Values inside list fields such as `methods`, `source_cidrs`, and `protocols` are ORed. Use multiple `[[routes]]` entries for broader OR logic.
- `replace_prefix_with`: optional upstream path prefix replacement.
- `actions.rewrite`: optional upstream request URI rewrite for proxy routes. It can set `path`, `query`, or both. Omitted `query` preserves the original query; `query = ""` removes it.
- `actions.redirect`: terminal redirect target with required `status` and `location_template`.
- `actions.request_headers` and `actions.response_headers`: optional route-level header modifiers with `set`, `add`, and `remove`. Request header actions cannot mutate OxiBelt-managed proxy identity or authority headers: `Host`, `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Real-IP`, or `CF-Connecting-IP`. Routes that use `external_auth` also cannot mutate that provider's configured `identity_headers`; those headers remain owned by the trusted auth result. This is a breaking hardening for configurations that previously used route actions to override proxy identity metadata.
- `actions.cors`: optional route-level CORS policy with allowed origins, methods, headers, exposed headers, credentials, and max-age controls.
- `actions.request_mirrors`: optional best-effort request mirroring to one or more upstream pools.
- `ct_log`: named Certificate Transparency log target; see
  [Certificate Transparency operations](certificate-transparency.md).
- `upstream`, `upstream_pool`, `static_root`, `ct_log`, or `actions.redirect`: exactly one target.
- `cache`: optional cache reference; `default` uses `[cache]`, and any other value must match `[[cache.policies]].name`.
- `compression`: optional downstream response compression policy; omitted means `default`, `off` disables compression for the route, and any other value must match `[[compression.policies]].name`. Named compression policies must not use the exact lowercase names `default` or `off`.
- `security_headers`: optional security response header policy; omitted means `default`, `off` disables OxiBelt-managed security header insertion for the route, and any other value must match `[[security.header_policies]].name`. Named security header policies must not use the exact lowercase names `default` or `off`.
- `priority_class`: trusted configuration-assigned admission and overload class. It defaults to `default`. Soft overload shedding acts only on `background` and `crawler`; priority admission additionally caps `background` at `50%` and `crawler` at `25%` by default. A label alone never grants reserved request capacity: the selected route must independently pass local IPM authorization or match a verified TCP TLS client certificate. `admin` and `health` never create public-listener reservations; their capacity belongs to the dedicated listener controls. Never derive this value from a client header or route name, and ignore HTTP `Priority` for admission.
- `waf.http_body_compression`: optional route override for compressed HTTP request/response bodies before WAF body inspection. `inherit` uses the global setting, `off` disables the transform for the route, and `transform` enables it for that route.

Route path values must start with `/` and must not contain control characters, backslashes, query strings, fragments, dot segments, or encoded dot/slash separators such as `%2e`, `%2f`, or `%5c`.

Route action templates support `{scheme}`, `{host}`, `{path}`, `{path_suffix}`, `{query}`, `{query:name}`, and `{capture:N}`. Capture references require `match.path.regex` and must refer to a valid regex capture index; `{capture:0}` is the full regex match. `actions.rewrite` is mutually exclusive with `replace_prefix_with`, `static_root`, and `actions.redirect`, and requires `upstream` or `upstream_pool`. Rendered rewrite paths must remain origin-form paths beginning with one `/`. When rendering `actions.rewrite.query`, token output is percent-encoded as a query component so request-derived values cannot add extra parameters; omit `query` to preserve the original downstream query string unchanged.

`actions.redirect.status` must be `301`, `302`, `303`, `307`, or `308`. Redirect locations are origin-relative only: the rendered `location_template` must start with `/` and not `//`; absolute redirects are intentionally out of scope. Redirect routes run after route matching, route IPM, route rate limits, dynamic policy, and built-in Person proof API handling, then return before external auth, request WAF, static files, cache, body capture, or upstream selection. Redirect routes therefore reject `external_auth`, route-level WAF config, cache, buffering, retry, upstream HTTP version overrides, upgrades, CONNECT, and gRPC-Web.

Route header modifiers are validated with the same framing safety boundary as WAF header mutations. They cannot mutate hop-by-hop or request framing headers such as `connection`, `content-length`, `transfer-encoding`, `te`, `trailer`, `upgrade`, `proxy-authenticate`, or `proxy-authorization`. Request header modifiers run after forwarded-header normalization and WAF request mutations, before upstream dispatch. Response header modifiers run after security headers and WAF response mutations, before downstream response finalization and cache status headers.

`actions.cors` handles valid preflight requests immediately after route matching and before route IPM, redirects, external auth, WAF, static files, cache, or upstream selection. Successful preflight responses return `204` with CORS response headers and no backend data. Credentialed CORS must not use wildcard origins. Non-preflight responses receive CORS response headers only when the request carries an allowed `Origin`.

`actions.request_mirrors` selects the configured `upstream_pool` independently from the primary upstream and sends a bodyless best-effort mirror for `GET` and `HEAD` requests after outbound request construction. Bodyful mirrors may set `max_body_bytes` up to 16 MiB; the runtime reserves that configured capture size from a fail-fast 64-MiB process-wide mirror budget before reading any body frames and holds the reservation until every dispatched clone drops. Budget exhaustion skips the mirror without changing the primary request. Mirror failures, unavailable pools, unsupported HTTP/3/proxy-protocol egress targets, and sampled-out requests never affect the primary response; they update `oxibelt_request_mirror_success_total`, `oxibelt_request_mirror_errors_total`, or `oxibelt_request_mirror_skips_total`.

Extended route matching keeps existing `hosts` and `path_prefix` behavior by default. `match.path.prefix` is an alias for the effective route prefix; when `path_prefix` is also set to a non-root value, both prefixes must be identical. `match.path.exact` and `match.path.regex` add extra path constraints without changing the prefix used for upstream rewrite or static-file stripping.

Header, query, and client-certificate value matchers allow exactly one of `present`, `exact`, `prefix`, `suffix`, `contains`, or `regex`. Regex values are compiled during configuration validation. Header matching checks any duplicate value for the named header. Query matching uses form-style decoded query pairs. `source_cidrs` matches the resolved client IP after trusted Real-IP processing. `priority` defaults to `0`; higher values win before host and path specificity. `terminal = true` documents an intentional final route and is honored by conflict detection, but it does not override a route with a higher priority or more specific match.

TLS client-certificate route matchers can check `present`, `fingerprint_sha256`, `subject_cn`, `san_dns`, and `san_ip`. TCP TLS populates this metadata from the presented downstream client certificate. HTTP/3 currently exposes TLS SNI, ALPN, and fingerprint metadata, but not client-certificate identity through the stable QUIC metadata path; client-certificate-specific matchers therefore fail closed for HTTP/3 requests unless that metadata becomes available.

`routes.tls.ssl_early_data` overrides the global `tls.ssl_early_data` mode for requests resolved to that route. Use `off` for replay-sensitive routes, `safe_methods` for idempotent `GET`/`HEAD` handling, and `on` only when every accepted method on the route is replay-safe by application design. `routes.tls.min_version` and `routes.tls.max_version` override downstream TCP TLS protocol versions by SNI for exact-host root routes and inherit omitted values from `[tls]`. If a request's HTTP Host resolves to a route with a different TLS negotiation policy than the SNI-selected policy, OxiBelt returns `421 Misdirected Request`.

`static_root` enables the built-in static file server for the route. The value must resolve to an existing directory; absolute paths are accepted, and relative paths loaded through `Config::load` resolve under the configuration directory. OxiBelt strips the matched `path_prefix`, percent-decodes each remaining path segment, and serves only regular files whose resolved path stays under `static_root`. Directory listing is forbidden, and symlinks are allowed only when secure resolution can prove they remain inside the static root. On Linux kernels with `openat2(2)`, OxiBelt opens static files relative to a read-only `static_root` directory file descriptor with `RESOLVE_BENEATH` and `RESOLVE_NO_MAGICLINKS`; this path does not require `/proc/self/fd` and is compatible with read-only root filesystems. On kernels without `openat2`, and on non-Linux platforms, OxiBelt falls back to opening the file and rechecking the opened descriptor through `/proc/self/fd`; if that verification is unavailable, the request fails closed instead of serving an unverified file. Response metadata, validators, ranges, and bytes are all derived from the same verified descriptor. Static routes accept `GET` and `HEAD`, emit `ETag`, `Last-Modified`, and `Accept-Ranges`, support a single `Range: bytes=...` request, and honor `If-None-Match` and `If-Modified-Since`. Request WAF, response WAF, rate limits, dynamic policy, security headers, compression, and Alt-Svc still apply on the general path. Static routes reject upstream-only options such as `replace_prefix_with`, `actions.rewrite`, `cache`, `upstream_http_version`, `generic_http_upgrade`, `connect_tunneling`, and `grpc_web`.

`[routes.static_files]` applies only when the same route sets `static_root`; non-static routes reject these options. `directory_index` is a list of simple filenames, such as `["index.html"]`, tried only when the requested path resolves to a directory. Directory listing remains forbidden when no configured index file exists. `try_files` runs after the normal requested file and directory index miss; entries must be root-relative literal paths such as `/index.html` or use the single `{path}` placeholder with an optional extension suffix, such as `{path}.html`. `spa_fallback` is a root-relative file returned with status `200` only for `GET` or `HEAD` misses that are extensionless, do not end with `/`, and explicitly accept `text/html` or `application/xhtml+xml`.

`precompressed` accepts `br`, `zstd`, and `gzip` and maps them to sibling `.br`, `.zst`, and `.gz` files. OxiBelt selects a precompressed file by downstream `Accept-Encoding` q-value, breaks ties by the configured order, sets `Content-Encoding`, and adds `Vary: Accept-Encoding`. Range requests skip precompressed variants and use the original file. `cache_control` sets a default `Cache-Control` value on successful static responses, and `[routes.static_files.cache_control_by_extension]` overrides it by lowercase extension without a leading dot. `[routes.static_files.mime_overrides]` uses the same lowercase extension keys and overrides the response `Content-Type`; precompressed files keep the logical original file type. `[routes.static_files.error_pages] not_found` and `server_error` point to root-relative custom pages for built-in static `404` and static-root `50x` responses. Missing, forbidden, or invalid custom error pages fall back to the built-in text response without recursive fallback handling.

Static routes are one supported deployment path for custom Person proof challenge pages. Place frontend files under a configured `static_root` and use the origin-relative asset URL as the WAF action's `custom_frontend_url`. `custom_frontend_url` may also point to a separate frontend backend proxied by the same OxiBelt instance.

## TCP/UDP Stream Listeners

```toml
[[stream_listeners]]
name = "postgres"
network = "tcp" # tcp | udp, defaults to tcp for backward compatibility
bind = "0.0.0.0:15432"
target = "db.internal.example:5432"
connect_timeout_ms = 3000
idle_timeout_ms = 75000
proxy_protocol_egress = "off" # off | v1 | v2
```

Stream listeners proxy raw L4 traffic from a dedicated bind address. Existing TCP configs that set only `target = "host:port"` continue to work. New listeners can set `network = "tcp"` or `network = "udp"`, choose either a direct `target` or a named `upstream_pool`, and add `[[stream_listeners.sni_rules]]` for visible TCP TLS ClientHello SNI or UDP QUIC Initial SNI. Stream listeners do not terminate TLS, perform HTTP routing, inspect WAF payloads, or add UDP PROXY protocol egress. TCP stream connections and pinned UDP flows are counted by the global connection limits.

```toml
[[stream_upstream_pools]]
name = "edge-tls"
algorithm = "power_of_two_choices" # power_of_two_choices | weighted_least_conn | rendezvous_hash | rendezvous_ip_hash

[[stream_upstream_pools.servers]]
id = "edge-a"
origin = "tcp://edge-a.internal.example:9443"
weight = 2

[[stream_upstream_pools.servers]]
id = "edge-b"
origin = "tcp://edge-b.internal.example:9443"

[[stream_upstream_pools]]
name = "edge-quic"
algorithm = "rendezvous_ip_hash"

[[stream_upstream_pools.servers]]
id = "quic-a"
origin = "udp://quic-a.internal.example:443"

[[stream_listeners]]
name = "tls-passthrough"
network = "tcp"
bind = "0.0.0.0:10443"
upstream_pool = "edge-tls"
idle_timeout_ms = 120000

[[stream_listeners.sni_rules]]
name = "tenant-a"
server_names = ["tenant-a.example.com", "*.tenant-a.example.com"]
target = "tenant-a.internal.example:9443"

[[stream_listeners]]
name = "quic-passthrough"
network = "udp"
bind = "0.0.0.0:10443"
upstream_pool = "edge-quic"
udp_flow_state = "shared_required" # local | shared_required
max_udp_flows = 4096
udp_new_flow_rate = "200r/s"
udp_new_flow_burst = 400
udp_datagram_rate = "200r/s"
udp_datagram_burst = 400
udp_batch = "auto" # auto | off | required
udp_batch_size = 16
```

Each `[[stream_upstream_pools.servers]]` origin must use `tcp://host:port` or `udp://host:port`. A stream listener or SNI rule must set exactly one of `target` or `upstream_pool`; a listener may omit its default only when it has SNI rules, in which case no-SNI or unparseable flows fail closed without displacing established UDP flows. UDP listeners reject `proxy_protocol_egress`, pin each downstream client flow to one selected upstream until idle expiry or capacity eviction, and use `max_udp_flows` to bound the listener's flow scope. `udp_new_flow_rate` and `udp_new_flow_burst` bound admission of previously unseen peer flows before per-flow allocation. Capacity eviction only happens after a new UDP flow is routable, admitted by connection limits and the new-flow limit, and ready to insert. `udp_datagram_rate` and `udp_datagram_burst` apply per pinned downstream UDP flow. `udp_batch = "auto"` uses Linux `recvmmsg(2)`/`sendmmsg(2)` batches when available and falls back to the existing Tokio `UdpSocket` path; `required` is Linux-only and fails on batch backend errors.

`udp_flow_state = "local"` is the default and retains the historical process-local table, rate state, connection permit, and connected upstream socket; restart or Pod replacement starts with an empty table. `shared_required` is UDP-only and refuses activation unless shared state is enabled, `udp_flows_backend` names an existing Redis-compatible or PostgreSQL backend with at least two connections, the configured identity-key environment variable contains exactly 32 base64-decoded bytes, and `idle_timeout_ms` is at least six times `shared_state.operation_timeout_ms`. Its accepted `max_udp_flows` is also bounded by that operation/idle timing and the selected backend's `max_connections`, reserving one connection for foreground claims, releases, permits, and token decisions while renewal uses bounded 64-record, up-to-eight-batch work; increase `idle_timeout_ms` or backend capacity, or reduce the flow cap when validation reports the computed maximum. Shared rate values must be representable from `0.000001` through `1048576` requests per second. If shared connection limits resolve to a backend, it must be the same backend. Ordinary datagrams on an owned local flow retain the local socket fast path. A miss or recovery uses an atomic shared claim with a server-time idle deadline, bounded capacity and token state, an owner generation, and a monotonically fenced lease. Stale owners cannot renew, consume tokens for, or release a replacement owner's record; a routing-generation mismatch fails closed rather than selecting a different target.

Recovery preserves only the same configured route and direct target or pool server identity that remains valid in the active configuration. It does not preserve a kernel socket, upstream source port, NAT or conntrack mapping, the exact endpoint chosen behind a Kubernetes Service, in-flight or upstream-initiated datagrams, or application/session state. A stateful UDP protocol may therefore need its own retry, migration, or handshake after recovery even when logical backend affinity is restored.

Stream SNI routing is passthrough classification only. OxiBelt peeks bounded TCP TLS ClientHello bytes or QUIC Initial CRYPTO frames when rules are configured, selects the first matching exact or wildcard server name rule, and forwards the untouched stream/datagrams to the chosen target. Flows without visible TLS or QUIC SNI use the listener default if present. Use `[sni_forward]` instead when TLS or QUIC traffic on `listeners.https_binds` must be selected by visible SNI before local HTTP termination.

## WebRTC TURN Listeners

```toml
[[turn_upstream_pools]]
name = "turn-udp"
algorithm = "power_of_two_choices"

[[turn_upstream_pools.servers]]
id = "turn-a"
origin = "turn://turn-a.internal.example:3478"
weight = 1

[[turn_upstream_pools]]
name = "turn-tcp"
algorithm = "power_of_two_choices"

[[turn_upstream_pools.servers]]
id = "turn-tcp-a"
origin = "turn+tcp://turn-a.internal.example:3478"
weight = 1

[[turn_upstream_pools]]
name = "turn-tls"
algorithm = "power_of_two_choices"

[[turn_upstream_pools.servers]]
id = "turn-tls-a"
origin = "turns://turn-a.internal.example:5349"
weight = 1

[[webrtc_turn_listeners]]
name = "turn-edge"
mode = "proxy_pool" # proxy_pool | edge_relay
bind_udp = "0.0.0.0:3478"
bind_tcp = "0.0.0.0:3478"
bind_tls = "0.0.0.0:5349"
realm = "example.test"
udp_pool = "turn-udp"
tcp_pool = "turn-tcp"
tls_pool = "turn-tls"
idle_timeout_ms = 75000

[webrtc_turn_listeners.auth]
mode = "validate" # pass_through | validate | enforce
rest_shared_secret_env = "OXIBELT_TURN_REST_SECRET"
```

`mode = "proxy_pool"` forwards TURN UDP, TCP, and TLS traffic to `[[turn_upstream_pools]]`. Upstream servers use `turn://`, `turn+tcp://`, or `turns://` origins and advertise their own relay addresses. TURN pools default to `power_of_two_choices` and support `power_of_two_choices`, `weighted_least_conn`, `rendezvous_hash`, and `rendezvous_ip_hash`; HTTP-only algorithms `ewma`, `least_time`, and `sticky_cookie` are rejected. Listener pool fields are transport-specific: `udp_pool` must reference `turn://` servers, `tcp_pool` must reference `turn+tcp://` servers, and `tls_pool` must reference `turns://` servers. `auth.mode = "validate"` checks authenticated TURN messages when credentials are present, but lets the upstream TURN server issue nonce challenges and remain authoritative.

```toml
[[webrtc_turn_listeners]]
name = "edge-relay"
mode = "edge_relay"
bind_udp = "0.0.0.0:3478"
bind_tcp = "0.0.0.0:3478"
bind_tls = "0.0.0.0:5349"
realm = "example.test"
idle_timeout_ms = 75000
stream_outbound_queue_capacity = "auto" # auto or 1..256; default is 32

[[webrtc_turn_listeners.relay_families]]
family = "ipv4"
public_ip = "203.0.113.10"
relay_bind_ip = "0.0.0.0"

[webrtc_turn_listeners.relay_families.relay_port_range]
start = 49152
end = 49200

[[webrtc_turn_listeners.relay_families]]
family = "ipv6"
public_ip = "2001:db8:10::10"
relay_bind_ip = "::"

[webrtc_turn_listeners.relay_families.relay_port_range]
start = 49152
end = 49200

[webrtc_turn_listeners.limits]
max_allocations_per_listener = 4096
max_allocations_per_client = 2
max_permissions_per_allocation = 256
max_channels_per_allocation = 256
max_allocation_lifetime_seconds = 600

[webrtc_turn_listeners.peer_policy]
allow_private_peers = false
allow_loopback_peers = false
allow_link_local_peers = false
allow_unspecified_peers = false
allow_multicast_peers = false

[webrtc_turn_listeners.auth]
mode = "enforce"

[[webrtc_turn_listeners.auth.static_credentials]]
username = "media-user"
password_env = "OXIBELT_TURN_MEDIA_PASSWORD"
```

`mode = "edge_relay"` makes OxiBelt allocate UDP relay sockets and advertise one or more configured `relay_families`. This provides TURN relay infrastructure for ICE-based client-to-client WebRTC flows; the application still owns signaling, SDP exchange, and ICE candidate distribution. `family = "ipv4"` supports clients behind IPv4 NAT. `family = "ipv6"` supports IPv6 relay candidates, including deployments that need IPv6 NAT/NAT66 traversal. When a client sends TURN `REQUESTED-ADDRESS-FAMILY`, OxiBelt allocates the matching family. When a client sends `ADDITIONAL-ADDRESS-FAMILY = IPv6`, OxiBelt allocates both IPv4 and IPv6 relay sockets when both families are configured. If no family is requested, OxiBelt defaults to IPv4 and returns `440 Address Family not Supported` when IPv4 is unavailable.

The legacy single-family `public_ip`, `relay_bind_ip`, and `[webrtc_turn_listeners.relay_port_range]` fields remain accepted when all three are set together. Do not mix the legacy fields with `[[webrtc_turn_listeners.relay_families]]`. Each relay family must use matching address families for `public_ip` and `relay_bind_ip`, and each port range must have positive `start <= end`.

`edge_relay` requires enforced TURN authentication and rejects open relay configurations. `limits` bounds listener allocations, per-client allocations, per-allocation permissions, channel bindings, and allocation lifetime; defaults are shown in the example. Capacity exhaustion returns TURN errors such as `486 Allocation Quota Reached` or `508 Insufficient Capacity` without failing the listener. `peer_policy` is default-deny for private, loopback, link-local, unspecified, multicast, and broadcast peer addresses. IPv4 peers must use the IPv4 relay family; IPv4-mapped IPv6 peer addresses are rejected. Set `allow_private_peers = true` only for intentional private/VPC or lab relays, including private IPv6/ULA peers behind NAT66.

TCP and TLS edge-relay outbound queues are bounded per downstream connection by `stream_outbound_queue_capacity`; omitted configs use `32`, `"auto"` resolves conservatively from available parallelism with a `32..=64` clamp, and explicit values must be `1..=256`. Full queues fail closed by closing the affected TURN stream rather than buffering without bound. TURN over TLS reuses `[tls]` certificate material by default; set `[webrtc_turn_listeners.tls] cert_chain` plus exactly one of `private_key` or `remote_signer_key_id` to override it for a listener. `remote_signer_key_id` uses the global `[tls.remote_signer]` socket and token. TURN payloads are protocol-forwarded only; OxiRule/WAF inspection applies to signaling HTTP, not SRTP/media payloads.

Route-level WAF example:

```toml
[[routes.waf.rules]]
name = "api-large-body-guard"
phase = "request"
priority = 100
when = "Request.Http.Method == 'POST' && Request.Http.Body.Size > 1048576"

[[routes.waf.rules.actions]]
type = "reject"
status = 413
body = "Payload Too Large"
```

## Validation Summary

Configuration validation rejects:

- Invalid include values, include cycles, escaped include paths, and missing exact include files.
- Duplicate scalar keys or incompatible value types across included TOML files.
- Unknown keys when `config.strict_unknown_fields = true`.
- No enabled downstream HTTP versions or SNI forwarding protocols.
- Privileged listener ports when `runtime.unprivileged_mode = true`, except configured data-plane listener ports `1..1023` when `runtime.netport_switcher.enabled = true`.
- Non-Linux runtime when `runtime.linux_only = true`.
- Invalid main-runtime or topology-policy values, an unsatisfied `require_exact` topology, zero worker counts, non-positive worker multipliers, invalid hot reload mode, zero `poll_interval_ms`, zero accept backlog/backoff values, accept worker counts greater than one without `runtime.accept.reuse_port = true`, or HTTP/3 QUIC socket worker counts greater than one without `quic.socket.reuse_port = true`.
- Missing all `[[routes]]`, `[sni_forward]` rule/default targets, `[[stream_listeners]]`, and `[[webrtc_turn_listeners]]`; duplicate names; empty route hosts; or unknown route targets.
- Invalid SNI forwarding targets, duplicate SNI forwarding rule names or server-name patterns, unsupported wildcard placement, zero SNI forwarding timeouts or QUIC Initial reassembly limits, a per-session QUIC Initial buffer cap above its total cap, or QUIC SNI forwarding without downstream HTTP/3.
- Invalid stream upstream-pool origins, unsupported stream pool algorithms, duplicate stream SNI rule names or server-name patterns, stream listener/SNI rule target conflicts, missing stream listener defaults without SNI rules, UDP stream listeners with PROXY protocol egress, stream listeners that reference a pool without matching `tcp://` or `udp://` servers, or `shared_required` UDP state without its shared backend, identity key, timeout floor, and same-backend connection-limit prerequisites.
- Routes that set zero or more than one of `upstream`, `upstream_pool`, `static_root`, `ct_log`, or `actions.redirect`.
- Unsafe route paths.
- Unsupported upstream schemes or HTTP/3 upstreams without HTTPS.
- Invalid runtime file paths or runtime files outside their purpose-specific directory.
- `runtime.drain.graceful_timeout_ms = 0` or `runtime.drain.long_connection_close_delay_ms = 0`.
- TLS client auth without CA roots, invalid TLS version ranges, TCP TLS early data without TLS 1.3 stateful resumption, static OCSP without `response_file`, live OCSP with `response_file`, invalid OCSP fetch limits, unsafe OCSP responder URLs, CRLite enforcement without `filter_file`, invalid CRLite filter limits/digests, invalid upstream revocation limits, upstream CRLite enforcement without `filter_file`, invalid ASN identity database settings, or managed ASN sources that are not HTTPS.
- Reserved sticky-cookie settings, and spool buffering without a writable `temp_dir` and positive temp-file quota.
- Invalid WebRTC TURN listener binds, missing proxy pools, open `edge_relay` auth, invalid TURN upstream schemes, or invalid relay port ranges.
- Enabled Admin mutation protection without Admin/IPM, a PostgreSQL backend,
  same-backend enforcing audit, a valid retained-response/expiry window, or at
  least one contained principal-bound signer key; hybrid signers without the
  post-quantum feature or both public keys; two-factor break glass without
  mutation protection; or `admin_cluster` without matching process mode,
  disabled hot reload, a valid shared artifact key, an exact 2..=1,024-member
  set containing the local instance, or bounded rollout timing values.
- Invalid rate, connection, cache, health, security-header, database, WAF, pattern-set, OxiRule, or budget settings.

## Minimal Example

```toml
[logging]
level = "info"

[logging.access_log]
enabled = false
stdout = true

[access_log.system]
enabled = false

[access_log.waf]
enabled = true

[access_log.stdout]
enabled = true
schema = "ocsf"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true

[runtime.hot_reload]
mode = "off"
poll_interval_ms = 2000

[runtime.netport_switcher]
enabled = false
socket_dir = "/run/oxibelt-netport-switcher"
main_uid = 10001
main_gid = 10001
io_timeout_ms = 5000

[listeners]
https_binds = ["0.0.0.0:8443"]
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

[proxy.forwarded_headers]
mode = "overwrite"
client_ip_source = "resolved"

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"

[compression]
enabled = true
gzip = true
deflate = true
zstd = true
br = true
min_size_bytes = 1024
statuses = [200]
mime_types = ["text/*", "application/json", "application/*+json"]
level = 1
vary = true
proxied = ["expired", "no-cache"]
upstream_accept_encoding = "strip"
max_concurrent_responses = 0

[waf]
enabled = false
mode = "enforcing"
fail_policy = "closed"
duplicate_metadata_policy = "fail_closed"

[waf.http_body_compression]
mode = "off"
encodings = ["gzip", "deflate", "br", "zstd"]
max_decoded_body_bytes = 10485760
max_expansion_ratio = 20
decode_timeout_ms = 1000
max_concurrent_bodies = 0

[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2"

[[routes]]
name = "app-root"
hosts = ["example.com", "www.example.com"]
path_prefix = "/"
upstream = "app"
```
