# Kubernetes Deployment

Status: Draft

OxiBelt provides two Helm charts:

- `deploy/helm/oxibelt`: data-plane chart for the `oxibelt` reverse proxy and WAF.
- `deploy/helm/oxibelt-gateway-controller`: Gateway API controller chart for publishing immutable generated configuration and rolling the selected data-plane workload.

The Gateway controller remains a Gateway API controller. It is not an Ingress controller.

Both charts and the controller integration are currently `experimental`.
[KubernetesSupport.md](KubernetesSupport.md) defines the machine-enforced
graduation target and mandatory evidence. Its Kubernetes `1.34`–`1.36` matrix
does not turn Helm rendering, API-server dry-run, or one successful rollout
into a supported-production claim.

## Graduation compatibility and support metadata

The controller and `kubernetes_immutable` data-plane pairing targets Kubernetes
`>=1.34.0-0 <1.37.0-0`, Helm `3.21.3` and `4.2.3`, and the operator-installed
Gateway API `v1.6.1` standard CRD bundle. The charts do not install, convert,
downgrade, or delete Gateway API CRDs. Install and establish the pinned CRDs
before the controller, then install or upgrade the data plane.

Chart metadata, rendered workload annotations, Helm NOTES, controller
`/supportz`, and `oxibeltctl doctor --kubernetes` expose the lifecycle state
and compatibility policy without exposing Secret data. The data-plane
Pod-template annotation `oxibelt.dev/effective-version` is the controller's
running-Pod version boundary. Normal pairing is exact. A declared
`rolling_upgrade` may permit only the current and explicitly named immediately
preceding minor version until an RFC3339 deadline no more than 24 hours away; see
[the skew contract](KubernetesSupport.md#controller-and-data-plane-skew).

Graduation also requires IPv4 single-stack cluster evidence on Calico and
Cilium, `restricted` Pod Security admission, multi-node failure tests, and
native `linux/amd64`, `linux/arm64`, and `linux/riscv64` Kubernetes runs. Other
Kubernetes minors, Helm versions, Gateway API bundles/channels, CNIs, IP
families, architectures, or component skew are unqualified and must produce a
clear diagnostic.

Both charts accept either `image.tag` or an immutable `image.digest`. When a
digest is set it takes precedence and renders `repository@sha256:...`; the
schema rejects malformed or uppercase digests. Production deployments of
official images should use an operator-approved digest recorded for the exact
repository, role, release, and target platform:

```yaml
image:
  role: dataplane
  repository: ghcr.io/oxibelt/oxibelt-dataplane
  digest: sha256:FULL_64_CHARACTER_LOWERCASE_DIGEST
```

The data-plane chart defaults to `image.role: dataplane` and the role-specific
minimal image. It contains only `/usr/local/bin/oxibelt`; Admin remains
available through the same process when securely enabled, and Person Proof APIs
plus the built-in frontend remain embedded. It does not contain a shell,
operator CLI, Gateway Controller, keysigner, Node.js, package manager, or
compiler. Use `image.role: standalone` only when in-container `oxibeltctl`
convenience or compatibility helpers are intentionally required.

Set `image.role: dataplane-strict` to select
`ghcr.io/oxibelt/oxibelt-dataplane-strict` and
`/usr/local/bin/oxibelt-dataplane-strict`. This optional package retains the
public proxy, WAF, Person Proof, health, metrics, signal lifecycle, and immutable
configuration-rollout surfaces, but does not compile or embed the Admin
listener, Admin mutation runtime, Admin cluster/operation workers, or Admin
OpenAPI asset. The chart rejects Admin listener values, secret projections,
network-policy peers, or inline Admin TOML for this role. Operator-managed
ConfigMaps cannot be inspected by Helm and are therefore also checked by the
strict executable before sockets or background services start.

The role/repository mapping is fail closed for official OxiBelt repositories.
Custom repositories remain possible, but they are operator-owned artifacts and
must provide the executable contract declared by `image.role`. Person Proof is
available in both data-plane roles and does not require the Gateway Controller.
The `edge-secure-medium` v2 deployment envelope is narrower: it accepts only
the official `ghcr.io/oxibelt/oxibelt-dataplane-strict` repository at a
lowercase SHA-256 digest and records that exact repository/digest/role tuple in
its Secret-free profile report.

The release workflow creates and verifies GitHub API-hosted keyless SLSA
provenance and CycloneDX SBOM attestations before promoting these image digests.
They are not Cosign signatures or GHCR OCI referrers, and OxiBelt does not ship
a Kubernetes admission policy that fetches the API bundles. Historical digests
may still have unrelated OCI referrers from earlier releases. Keep the last
accepted digest pinned until any operator-owned replacement admission policy
has been approved and tested; do not change a webhook to fail open merely to
unblock an upgrade. See [Release Image Trust and
Attestations](SupplyChain.md).

## Data-Plane Chart

The data-plane chart can run OxiBelt as either a `Deployment` or a `DaemonSet`:

```yaml
workload:
  kind: Deployment
```

The chart exposes HTTP, HTTPS, and HTTP/3 through the main Service. HTTP/3 uses a UDP service port that targets the same OxiBelt HTTPS bind port. `service.type` may be `LoadBalancer`, `NodePort`, or `ClusterIP`.

TLS private keys are operator-owned Kubernetes Secrets. By default the chart mounts the `oxibelt-tls` Secret at `/etc/oxibelt/cert` and the default inline config reads:

```toml
[tls]
cert_chain = "tls.crt"
private_key = "tls.key"
```

In Kubernetes immutable rollout mode, rotate downstream TLS and Admin material
by creating a new immutable/versioned Secret and applying a Helm rollout that
references it. In-place Secret projection alone is not a claimed rotation
mechanism because the mode disables local mutable reload. BackendTLSPolicy
public-CA ConfigMap changes instead require the controller to publish and
converge a new immutable generated revision within the 300-second rollout
bound.

The chart-generated base configuration is content addressed: it creates an
`immutable: true` ConfigMap named from a SHA-256 digest of the rendered key and
content. The Pod template records that digest, so a Helm change creates a new
ConfigMap and a normal Kubernetes rollout rather than modifying a mounted file.
Old chart-created ConfigMaps are kept for rollback safety; prune only revisions
that no live Pod references.

Set `config.existingConfigMap` to use an operator-managed base configuration.
The referenced ConfigMap must be immutable, uniquely named for its content
revision, and paired with its lowercase SHA-256 value in
`config.existingConfigMapDigest`. When `oxirule.enabled = true`, the same
contract applies to `oxirule.existingConfigMap` and
`oxirule.existingConfigMapDigest`. Helm rejects a missing or non-lowercase
64-character digest. When `config.create` is `false`,
`config.existingConfigMap` is required; Helm rejects an unowned deterministic
base ConfigMap name.

For `kubernetes_immutable` controller pairing, every base configuration
ConfigMap must contain an empty `gateway-config-directory` key. Only in that
mode, the chart projects it as both `conf.d/.keep` and the exact managed
configuration path. The exact empty placeholder gives the bootstrap Pods a
valid revision file while `.keep` preserves a safe data-plane-first upgrade
path. Ordinary `helm_immutable` releases do not project or require this
sentinel from an existing ConfigMap. `config.key` must be a single safe
ConfigMap key/base filename
(`[A-Za-z0-9][A-Za-z0-9._-]{0,252}`), not a path and not the reserved
`gateway-config-directory` key. The config path remains mounted read-only and
passed to OxiBelt with `--config`.

## Configuration Rollout Modes

`configRollout.mode` selects one unambiguous configuration owner:

- `helm_immutable` is the default. Helm owns immutable base ConfigMaps and a
  standard Deployment or DaemonSet rollout. It does not enable the Gateway
  controller.
- `kubernetes_immutable` is required when pairing the data-plane chart with
  `oxibelt-gateway-controller`. The chart adds the immutable-rollout opt-in,
  Downward API environment declarations, and, for chart-created bases, a
  bootstrap revision/digest identity. The controller owns generated ConfigMaps,
  the composed `gateway-config` projected config root, and assigned
  revision/digest annotations after reconciliation.

For controller pairing, keep the generated include inside the base config root
at a nested relative `.toml` path (not a root-level filename) and disable
in-process hot reload:

```yaml
configRollout:
  mode: kubernetes_immutable
  managedConfigPath: conf.d/gateway-api.generated.toml
```

```toml
include = ["conf.d/*.toml"]

[runtime.hot_reload]
mode = "off"
```

In this mode the chart declares `OXIBELT_CONFIG_ROLLOUT_MODE`, assigned
revision and digest Downward API fields, the generated-file path, and the Pod
UID. It also supplies the all-or-none planning context
`OXIBELT_CONFIG_ROLLOUT_TARGET_NAMESPACE`,
`OXIBELT_CONFIG_ROLLOUT_TARGET_KIND`, and
`OXIBELT_CONFIG_ROLLOUT_TARGET_NAME`. The namespace comes from Pod metadata;
the workload kind and workload name come from chart-owned Pod-template
annotations through the Downward API, so the name identifies the owning
Deployment or DaemonSet rather than an individual Pod. This context lets a
configuration activation plan name the immutable rollout target. It is not
Kubernetes API authorization or proof that the target still exists. OxiBelt
treats absent, partial, or malformed target context as unavailable planning
enrichment without weakening or failing the immutable revision proof. The
chart does not add a service-account token, Kubernetes API access, or RBAC for
this enrichment.

For a chart-created, content-addressed base, the Pod template initially sets
`oxibelt.dev/config-revision` to the immutable base ConfigMap name and
`oxibelt.dev/config-digest` to the SHA-256 of the empty managed placeholder.
This bootstrap identity does not weaken configuration validation; a base
configuration without routes remains unready until the controller assigns its
generated revision. For `config.existingConfigMap`, the chart cannot verify the
external object's bytes and therefore leaves both annotations unassigned;
OxiBelt fails closed until controller reconciliation assigns them.
The chart deliberately does not declare a `gateway-config` volume or mount.
The controller replaces the selected container's direct base-config mount with
one projected config root that combines the base key mappings and generated
ConfigMap; it leaves the original base volume available to sidecars. Do not add
an overlapping mount through `extraVolumes` or `extraVolumeMounts`.

## Security Defaults

The chart defaults are compatible with the release image's non-root runtime:

- `runAsNonRoot: true`
- UID/GID `10001`
- `readOnlyRootFilesystem: true`
- all Linux capabilities dropped
- `seccompProfile.type: RuntimeDefault`
- config, TLS, and OxiRule mounts read-only
- compatibility roles get `/var/cache/oxibelt` backed by an `emptyDir`

`cacheVolume.mode: auto` preserves the compatibility-role cache and omits it
for `dataplane-strict`, leaving the strict Pod without a default writable
mount. Select `cacheVolume.mode: enabled` for strict only when configured cache,
CRLite, ASN, spool, or other data-plane behavior genuinely needs disk, and set
a nonempty `cacheVolume.sizeLimit`. Other writable state uses deliberately
reviewed `extraVolumes`/`extraVolumeMounts`; mounting a writable host path or a
Kubernetes API credential changes the strict deployment's threat boundary.

`edge-secure-medium` v2 does not accept the legacy generic writable-mount
escape. Declare every writable path with `writableVolumes` and exactly one
bounded `emptyDir` or named PVC:

```yaml
writableVolumes:
- name: response-cache
  mountPath: /var/cache/oxibelt
  purpose: response-cache
  emptyDir:
    sizeLimit: 128Mi
- name: durable-state
  mountPath: /var/lib/oxibelt
  purpose: durable-state
  persistentVolumeClaim:
    claimName: oxibelt-state-v1
```

V2 rejects `hostPath`, overlapping or ambiguous paths, `subPath`, generic
`extraVolumes`/`extraVolumeMounts`, and an unbounded `emptyDir`. The chart
places the normalized paths in native
`runtime.hardening.filesystem_manifest.expected_writable_paths` and the
profile report. A PVC declaration names a mount contract; storage-class,
encryption, backup, tenancy, and access-mode guarantees remain operator owned.

`RuntimeDefault` is the portable seccomp baseline. Clusters that install the
repository profiles from `deploy/seccomp/` may instead select a `Localhost`
profile appropriate to the configured Tokio or Compio runtime. Test that
profile against the exact image and enabled protocols before enforcing it.
AppArmor and SELinux policy names, loading, and labels are distribution and
cluster specific; the chart does not invent or install a generic profile.
Apply an operator-tested policy through Pod annotations or admission only after
verifying probes, TLS/QUIC, reload, and graceful drain behavior.

### External Admin audit anchoring

The chart does not create or administer the external checkpoint authority,
database roles, audit-only keysigner, private key, verifier witness, or
expected-stream inventory. Provision those as independent security boundaries
and install `deploy/postgres/admin-audit-anchor-v1.sql` with the least-privilege
grants documented in [Configuration.md](Configuration.md). The anchor database
must use a separate PostgreSQL `[[shared_state.backends]]` entry and credential
from the local Admin audit/mutation database.

An audit-only keysigner needs a writable, `noexec`/`nosuid` Unix-socket volume
shared with the OxiBelt container, a read-only Secret projection containing its
Ed25519 private key and IPC token, a distinct UID/GID, and a peer UID/GID
allowlist. OxiBelt receives the socket, its own token projection, and the raw
32-byte public-key pin, not the private key. The chart has no generic
`extraContainers` surface; add this narrowly scoped sidecar through a reviewed
parent chart or workload overlay, then use `extraVolumes` and
`extraVolumeMounts` for the OxiBelt half of the socket and public material.
Do not place the checkpoint private key in `config.inline`, a ConfigMap, the
standalone OxiBelt container, or the verifier Pod.

Set `OXIBELT_DEPLOYMENT_EPOCH` through `extraEnv` to an immutable, non-secret
rollout identifier. In `kubernetes_immutable` mode the chart already supplies
`OXIBELT_INSTANCE_ID` from the Pod UID. In other modes, add the same Downward
API mapping through `extraEnv`. A Pod UID stays stable across container
restarts and changes on Pod replacement, deliberately creating a new stream.
Keep replaced/retired Pod streams in the verifier's expected-stream manifest
for at least the audit and incident-retention period; otherwise deleting a Pod
could also delete its expectation. A deployment epoch should stay unchanged
for restarts of one deployed revision and change with an intentional rollout.
Add each replacement Pod stream with a signing-key schedule beginning at
checkpoint ordinal 1. The verifier expands an existing witness only after the
new stream's complete genesis, local chain, checkpoint signature, epoch, and
authority-head evidence verifies; retained stream heads cannot be removed from
the manifest. During signer rotation, close each active stream's old key range
at its witnessed head and begin the new unique key ID at the next ordinal.

```yaml
extraEnv:
  - name: OXIBELT_INSTANCE_ID
    valueFrom:
      fieldRef:
        fieldPath: metadata.uid
  - name: OXIBELT_DEPLOYMENT_EPOCH
    value: deploy-2026-07-19
```

When the portable NetworkPolicy is enabled, add the local Admin audit
PostgreSQL destination and the separate authority PostgreSQL destination as
distinct `shared-state` egress entries with exact peers and TCP ports. The Unix
signer socket needs no network egress. Place the authority in a separate
namespace/account/cluster or equivalent external administrative boundary;
namespace separation alone is not independent if the same principals can
rewrite both databases and backups.

Required anchoring marks Admin audit readiness-critical. Readiness therefore
returns `503` when signing, authority submission, receipt verification,
continuity, or pending-capacity guarantees cannot be met; liveness remains
process-only. Ensure the authority and signer are available before rolling out
a required configuration, and choose checkpoint intervals, retention, and
disruption budgets that keep the possible uncheckpointed tail inside the
deployment's evidence policy. Best-effort anchoring may remain ready while
reporting a degraded capability state and retry backlog. Monitor the anchoring
metrics in [Observability.md](Observability.md) and run
`oxibeltctl audit verify` from an independently administered CronJob or
external scheduler whose read-only credentials and retained witness are not
mounted into OxiBelt.

### ServiceAccount credentials and Kubernetes discovery

The data-plane chart and every rendered data-plane Pod set
`automountServiceAccountToken: false`. This remains true when
`serviceAccount.create: false` selects an operator-managed ServiceAccount, so
an existing ServiceAccount cannot restore an ambient Kubernetes credential at
the Pod level. The default data-plane release creates neither discovery RBAC
nor a Kubernetes API token projection.

Enable Kubernetes API access only for a configured upstream discovery path.
The chart has two deliberate modes:

```yaml
kubernetesDiscovery:
  # Use this only when RBAC is managed outside this chart.
  serviceAccountToken:
    enabled: false
    audience: ""
    expirationSeconds: 3600
  rbac:
    # This also enables the explicit projection below.
    create: true
    # Empty means the release namespace. List every discovery namespace.
    namespaces:
      - application-a
      - application-b
```

`rbac.create: true` renders one `Role` and `RoleBinding` per listed namespace;
it is not cluster-wide. The Role permits `get` on core `Endpoints` and
`list`/`watch` on `discovery.k8s.io` `EndpointSlice` resources—the exact
requests used by the data-plane discovery providers. It grants no Service,
Secret, wildcard resource, or wildcard verb access. For externally managed
RBAC, leave `rbac.create: false` and set `serviceAccountToken.enabled: true`
only after granting the equivalent minimum permissions elsewhere.

Either opt-in mounts a read-only `kube-api-access` projected volume at the
standard service-account path. It contains a short-lived token and the
`kube-root-ca.crt` CA only; the token lifetime must be from 600 through 3600
seconds and defaults to 3600. V2 additionally requires a nonempty explicit
audience; do not reuse an audience granted to a different service boundary.
Configure the corresponding OxiBelt Kubernetes
discovery `token_file` to use that path. When `networkPolicy.enabled: true`, a
token projection requires an explicit `kubernetes-api` egress destination;
the chart fails rendering instead of granting a credential that its policy
blocks.

The controller runs from the separate
`ghcr.io/oxibelt/oxibelt-gateway-controller` image and uses a separate
ServiceAccount. Its automatic token mount is
also disabled, but it always gets the same explicit 3600-second token/CA
projection because reconciliation calls the Kubernetes API. By default the
chart passes `--watch-namespace=<controller release namespace>` and grants
only the namespace GET needed for that scope plus a namespaced Gateway API
read Role. That Role lists the supported Gateway routes, BackendTLSPolicy,
ReferenceGrant, and Services; patches only their status subresources; and can
`get` but not list referenced ConfigMaps. It has no Secret access. Set
`watchNamespace` to another single namespace when required.
Set `watchAllNamespaces: true` only for an intentional cluster-wide
controller; it is mutually exclusive with `watchNamespace` and changes the
Gateway API read Role and namespace access to cluster-wide. Existing
cluster-wide installations must opt in explicitly during upgrade rather than
silently retaining broad authority.

### NetworkPolicy

`networkPolicy.enabled` is deliberately `false` in the ordinary chart values
so an existing installation does not acquire an accidental deny rule during an
upgrade. Enable it only after mapping every intended data-plane dependency.
The chart then selects only this release's OxiBelt Pods and renders a portable
Kubernetes `NetworkPolicy` baseline:

- public ingress is limited to the enabled named `http`, `https`, `http3`, and
  `service.additionalPorts` ports. Set `ingress.public.allowAll: true` for an
  Internet-facing edge, or
  use nonempty `ingress.public.from` peers for a private ingress boundary.
- metrics ingress is limited to the named `metrics` port and the explicitly
  configured monitoring peers.
- a non-loopback Admin listener is limited to the named `admin` port and the
  explicitly configured management or controller peers. The chart does not
  assume that the Gateway Controller calls Admin and adds no controller peer by
  default.
- egress is deny-by-default except for TCP/UDP DNS to the configured resolver
  peers and each explicitly declared destination. A destination has a
  reviewable category (`upstream`, `shared-state`, `telemetry`, `revocation`,
  `kubernetes-api`, `control-plane`, or `external-dependency`), concrete peers,
  and bounded TCP/UDP ports. The category documents the trust decision; it does
  not widen the policy. Enabling an explicit Kubernetes discovery token
  projection also requires a `kubernetes-api` destination.

V2 emits an explicit ingress-and-egress default-deny policy plus separate
allow policies. It rejects IPv4 or IPv6 world CIDRs unless the individual
destination sets `unrestrictedCidrs.enabled: true`, includes a nonempty review
justification, and lists explicit ports. That marker does not make the peer
safe; it makes a deliberately broad trust decision visible and local to one
dependency. The Admin-free v2 role rejects `control-plane` traffic.

The secure companion
[`edge-secure-medium-v1-values.yaml`](../deploy/helm/oxibelt/examples/edge-secure-medium-v1-values.yaml)
enables this baseline, permits the intended public named ports, and scopes
metrics to the `monitoring` namespace's Prometheus identity. It leaves Admin
peers and non-DNS egress empty. Before using it against a live route set, add
each upstream, Redis/Valkey or PostgreSQL backend, OCSP/CRL responder, API
server, and other external dependency that the selected configuration actually
uses. An undeclared dependency is intentionally unavailable rather than
implicitly allowed.

The opt-in v2 companion
[`edge-secure-medium-v2-values.yaml`](../deploy/helm/oxibelt/examples/edge-secure-medium-v2-values.yaml)
adds the strict image, hardening-manifest, typed writable-storage, rollout, and
profile-report contracts described below. Its placeholder digests are not
production identities; replace and independently approve them before rollout.

The optional `networkPolicy.cilium` section emits a `CiliumNetworkPolicy` only
when both it and the portable baseline are enabled. It requires an already
installed Cilium CRD, trusted Cilium DNS-proxy endpoint selectors, and exact
lower-case FQDNs for every extra external destination; wildcard names and
empty selectors are rejected. The chart does not install Cilium CRDs. Keep the
standard DNS peer and the Cilium DNS endpoint selection aligned with the
resolver path used by the workload.

Render and review the resources before rollout, including the actual Pod and
namespace labels used by monitoring and management workloads:

```sh
helm template oxibelt deploy/helm/oxibelt \
  -f deploy/helm/oxibelt/examples/edge-secure-medium-v2-values.yaml
```

NetworkPolicy enforcement is supplied by the cluster CNI, not by Kubernetes
API validation alone. Test the policy with the production CNI and probe
sources; installed policies selecting the same Pods can combine with this
baseline. In particular, confirm cluster probe and DNS behavior before a
production cutover, and keep CNI-specific host/node traffic behavior in the
deployment review.

### `edge-secure-medium` v2 profile report and rollout identity

The v2 chart renders an immutable, content-addressed ConfigMap containing a
deterministic schema-v1 profile report. It contains only allowlisted facts:
the selected profile, exact image identity, Pod-security and seccomp intent,
token projection and audience, ingress/egress dependency classes, writable
mount paths and purposes, availability settings, safe artifact-reference
identities, and stable unmet-requirement codes. A deployable render has no
unmet requirements; Helm otherwise fails with the same requirement code.

Pod-template checksums cover the generated configuration, OxiRule content,
Secret references, hardening inputs, and profile report. Secret-reference
checksums hash only canonical names, keys, and projected paths—never Secret
data and never live `lookup` results. Rotate Secret contents by creating a new
immutable/versioned Secret name and rolling the reference. The report is
review evidence for chart intent, not a runtime or admission attestation.

Before installing v2, generate the resolved filesystem-access manifest in a
trusted local environment and set
`runtimeHardening.filesystemManifest.expectedDigest` to the path-disclosing
SHA-256 value. Manifest schema v3 recognizes ConfigMap and Secret projected
files only after verifying the complete Kubernetes AtomicWriter symlink
topology. It uses the stable logical mount path for digest identity across
timestamp-directory rotations while retaining the resolved backing file for
checks and Landlock installation. Incomplete, ambiguous, escaping, or lookalike
layouts are not treated as projected volumes and fail an unchanged expected
digest closed. Regenerate every schema-v2 expected digest with a schema-v3
`oxibeltctl` against the final logical mount paths before upgrading the runtime;
do not copy a v2 digest forward. Namespace admission should enforce, audit, and
warn on the restricted Pod Security Standard:

```sh
kubectl label namespace oxibelt \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

Use `RuntimeDefault` when only portable kernel filter/NNP evidence is available.
Use `Localhost` only after the exact node-installed profile identity and digest
have been independently managed and injected through the admission boundary.
Neither the chart nor `RuntimeDefault` invents a semantic seccomp digest.

### Admin Listener

Admin API exposure is disabled by default. Its generated listener is loopback
only, has no Service, and accepts plaintext only through OxiBelt's loopback
allowlist. When `admin.enabled = true`, `admin.tokenSecretName` remains
required and is injected as `OXIBELT_ADMIN_TOKEN`; bearer authentication is
still required when mTLS is enabled.

For a non-loopback Admin listener, enable `admin.tls`, supply an identity
Secret and at least one DNS name, and use the generated TLS 1.3-only Admin
configuration. The chart projects the server certificate/key as
`admin-server/tls.crt` and `admin-server/tls.key` below the same read-only
certificate root used by OxiBelt runtime configuration. Enable `admin.mtls` to
project a client CA as `admin-client-ca/ca.crt` and require a client
certificate.

Use [the production mTLS values example](../deploy/helm/oxibelt/examples/admin-mtls-values.yaml)
as the starting point. It intentionally contains only Secret names and keys.
The Admin Service defaults to disabled and `ClusterIP`; `NodePort` and
`LoadBalancer` exposure require mTLS under the default policy.

`admin.mtls.enforcement` controls deliberate TLS-plus-bearer-only operation:

- `required_non_loopback` is the default and requires mTLS on every
  non-loopback bind.
- `required_external` allows TLS-plus-bearer access through a disabled or
  `ClusterIP` Admin Service, but requires mTLS for `NodePort` or
  `LoadBalancer`.
- `optional` permits TLS-plus-bearer access at any exposure level and emits a
  prominent Helm warning for externally exposed Admin without mTLS.

`admin.insecureDevelopmentMode.enabled = true` is the only plaintext
non-loopback escape hatch. It cannot be combined with TLS, mTLS, `NodePort`,
or `LoadBalancer` exposure. It is intended only for isolated development
clusters.

The `dataplane-strict` role has no Admin listener to secure or expose. Helm
rejects every Admin opt-in for that role rather than silently ignoring it. Use
the compatibility `dataplane` or `standalone` role when an Admin operation,
runtime mutation, Admin audit endpoint, or fixed-member Admin cluster is a
deployment requirement.

The chart validates its generated default Admin TOML. If an operator replaces
`config.inline` or uses `config.existingConfigMap`, that TOML remains
operator-owned and must be checked with `oxibelt --config <file> --check`.

Runtime Kubernetes upstream discovery uses the explicit projected token when
generated config sets
`token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"`. Enable
`kubernetesDiscovery.rbac.create` only when the data plane must read Kubernetes
Endpoints or EndpointSlices; otherwise leave both discovery RBAC and the token
projection disabled.

## Health and Metrics

The chart enables OxiBelt health and basic Prometheus metrics in the generated config. Pods use readiness, liveness, and startup probes against the health listener. The metrics Service is enabled by default so a cluster scraper can target the named `metrics` port.

Horizontal scaling is chart-owned only through the optional `autoscaling` block,
which renders an `autoscaling/v2` HPA for `Deployment` workloads. Its default
HPA metric is CPU utilization. Set `autoscaling.activeRequests.enabled: true`
to add the per-Pod custom metric `oxibelt_active_http_requests` alongside CPU;
the HPA takes the higher replica recommendation. The metrics Service remains
available whether or not HPA rendering is enabled. DaemonSets deliberately
reject HPA values instead of silently rendering no scaler.

The custom metric is a fixed adapter alias for OxiBelt's existing raw gauge:

```text
oxibelt_overload_active_work{kind="active_http_requests"}
```

Prometheus must attach Kubernetes `namespace` and `pod` labels while scraping
the metrics Service. Deploy the separately operated Prometheus Adapter with the
fixed mapping in
[`prometheus-adapter-oxibelt-values.yaml`](../deploy/observability/prometheus-adapter-oxibelt-values.yaml).
Review and pin the adapter chart and image through the cluster's normal supply
chain before installing it; the OxiBelt chart intentionally does not install an
adapter `APIService` or cluster-scoped RBAC. For example, use a reviewed adapter
release with the overlay:

```sh
helm upgrade --install prometheus-adapter prometheus-community/prometheus-adapter \
  --namespace monitoring --create-namespace \
  --version <reviewed-version> \
  -f deploy/observability/prometheus-adapter-oxibelt-values.yaml
```

Layer the active-request overlay after the secure base profile. It preserves the
base profile's CPU target and adds a source-derived starting target of 24 active
HTTP requests per Pod; it is not a measured capacity guarantee. Tune it only
from production saturation, latency, and overload evidence.

```sh
helm upgrade --install oxibelt deploy/helm/oxibelt \
  --namespace edge --create-namespace \
  -f deploy/helm/oxibelt/examples/edge-secure-medium-v1-values.yaml \
  -f deploy/helm/oxibelt/examples/edge-secure-medium-v1-autoscaling-values.yaml
```

Active-request HPA mode requires the `edge-secure-medium` profile, which turns
on the runtime overload sampler that owns the active-work gauge, plus
`autoscaling.enabled=true`, `metrics.enabled=true`, an enabled fixed pre-stop
drain, and a positive termination grace period. The chart rejects a scale-down
stabilization window shorter than the drain and a one-Pod scale-down period
shorter than the termination grace. The secure overlay therefore keeps a 300-second
stabilization window and permits at most one Pod removal every 360 seconds.
CPU-only HPA mode preserves Kubernetes defaults for scale-down behavior.

Allow for Prometheus scrape delay, adapter relist/query delay, and the HPA
controller sync before treating the custom metric as absent or stale. A missing
custom metric can prevent a safe scale-down, while the CPU metric can still
recommend a scale-up. Check the adapter and HPA before changing targets:

```sh
kubectl get --raw \
  "/apis/custom.metrics.k8s.io/v1beta1/namespaces/edge/pods/*/oxibelt_active_http_requests"
kubectl -n edge describe hpa oxibelt
kubectl -n edge get hpa oxibelt -o yaml
```

Deployment defaults are deliberately conservative for immutable configuration:
`maxUnavailable: 0`, `maxSurge: 1`, `minReadySeconds: 5`,
`progressDeadlineSeconds: 300`, and `revisionHistoryLimit: 3`. DaemonSets use a
one-at-a-time rolling update (`maxUnavailable: 1`) with the same ready and
history defaults. Override these values only with an availability analysis for
the target topology.

## Pod Distribution and Lifecycle

The ordinary chart keeps topology and pre-stop draining disabled so existing
single-node installations do not become unschedulable or acquire a longer
termination path on upgrade. Enable the managed Deployment policy only on a
cluster with at least three eligible worker nodes and two labelled zones:

```yaml
replicaCount: 3

podDistribution:
  enabled: true
  nodeSpread:
    maxSkew: 1
    minDomains: 2
    whenUnsatisfiable: DoNotSchedule
  zoneSpread:
    maxSkew: 1
    whenUnsatisfiable: ScheduleAnyway
  podAntiAffinity:
    enabled: true
    weight: 100

podDisruptionBudget:
  enabled: true
  minAvailable: null
  maxUnavailable: 1
  unhealthyPodEvictionPolicy: AlwaysAllow

lifecycle:
  preStop:
    enabled: true
    drainSeconds: 300
  terminationGracePeriodSeconds: 360
```

The managed policy applies only to `Deployment` workloads. It requires
different `kubernetes.io/hostname` values when capacity permits, uses an
identical-release selector, prefers an even
`topology.kubernetes.io/zone` distribution without blocking a single-zone
cluster, and adds preferred same-release hostname anti-affinity. It merges
with raw `affinity` but rejects a raw `affinity.podAntiAffinity` block when the
managed policy is active, rather than silently discarding either policy.
`minDomains` requires `DoNotSchedule` and Kubernetes 1.30 or later. The secure companion requires
Kubernetes 1.31 or later because it also selects
`unhealthyPodEvictionPolicy: AlwaysAllow`.

A rendered PDB always uses exactly one of `minAvailable` and
`maxUnavailable`. For three secure-profile replicas, `maxUnavailable: 1`
allows one voluntary disruption while the Deployment strategy retains at least
two Ready Pods during a normal update. A PDB does not protect against an
involuntary node loss; three replicas on distinct nodes keep two running after
one verified worker failure. The chart intentionally does not render this PDB
or managed spread policy for a DaemonSet: it already places at most one Pod on
each eligible node. The secure DaemonSet setting instead uses
`maxUnavailable: 0` plus `maxSurge: 1`.

When `lifecycle.preStop.enabled` is true, the chart invokes the selected role's
executable with the fixed internal
`__lifecycle-prestop --wait-seconds <drainSeconds>` command. The duration is a
validated integer and no shell is
present or invoked. The helper signals PID 1 into OxiBelt's drain-only state
before Kubernetes sends its final termination signal: readiness withdraws, new
traffic is rejected, HTTP/2 emits graceful shutdown/GOAWAY, and HTTP/3 stops
accepting new streams while permitted work drains. Kubernetes counts pre-stop
time inside `terminationGracePeriodSeconds`; choose a grace period that covers
the pre-stop delay, the runtime shutdown delay, the ordinary graceful timeout,
and an orchestration margin. The secure companion's `300 + 10 + 30 + 20 = 360`
second budget is its supported contract.

Long-lived WebSocket, Upgrade, CONNECT, WebTransport, and stream sessions use
the runtime long-connection delay after drain begins. QUIC connection state is
process-local: address migration may continue only while the original Pod is
alive; a Pod replacement cannot transfer HTTP/3 or WebTransport sessions to a
different Pod, so clients must reconnect after the graceful drain. This is why
the Service must expose both TCP and UDP for HTTPS/HTTP/3 and why a pre-stop
window is required before forced exit.

In `kubernetes_immutable` mode, `/ready` additionally stays unavailable until
the exact assigned revision and raw digest have been applied. An older healthy
ReplicaSet remains ready until it is selected for replacement; a Pod whose own
assigned digest does not match its mounted immutable configuration is never
ready.

## Gateway Controller Pairing

The Gateway controller never calls a load-balanced OxiBelt Admin Service to
claim cluster-wide configuration success. It validates a deterministic Gateway
API translation, creates an immutable ConfigMap, patches only its selected
workload, and waits until every Ready Pod verified as owned by that workload
reports the assigned raw content digest. On failure it restores the last
committed revision.

Install the controller/RBAC first, then enable `kubernetes_immutable` on the
data-plane chart. The data-plane workload must opt in through the chart-created
`oxibelt.dev/immutable-config-rollout: "true"` annotation. A controller paired
with an older data chart remains non-mutating rather than falling back to Admin
file sync.

The data-plane base config must include the controller-owned path:

```toml
include = ["conf.d/*.toml"]
```

Configure the controller target explicitly; an empty target namespace means the
controller release namespace:

```yaml
rollout:
  target:
    namespace: ""
    kind: deployment # or daemonset
    name: oxibelt
    containerName: oxibelt
  volumeName: gateway-config
  timeoutSeconds: 300
  configMapPrefix: oxibelt-gateway-config
```

The controller chart has no Admin URL, Admin token, client certificate, or
Secret permission. It uses only its projected Kubernetes API token and
`kube-root-ca.crt` CA. Its default Gateway API read Role is scoped to the
controller release namespace and permits list operations plus status patching.
BackendTLSPolicy public-CA resolution adds ConfigMap `get` without ConfigMap
`list`; Secret-backed client identity is unsupported. The watched Gateway API
set includes v1 TCPRoute, UDPRoute, and BackendTLSPolicy. The cluster role is
limited to GatewayClass list/status patch and an exact
namespace GET. Its target-namespace Role gets and creates ConfigMaps, lists
Pods and, for a Deployment target, ReplicaSets, and gets and patches only the
named Deployment or DaemonSet. It neither watches nor deletes target-namespace
resources. Generated immutable
revisions are preserved for named rollback; their retention is operator
controlled rather than controller garbage collected. ConfigMap access is still
namespace scoped because content-addressed artifact names are known only at
runtime.

TCPRoute and UDPRoute listeners are exposed only through operator-owned
data-plane ports. Declare each port in the paired data-plane chart and point
`statusService` at that Service:

```yaml
# deploy/helm/oxibelt values
service:
  additionalPorts:
  - name: gateway-tcp
    protocol: TCP
    port: 9000
    targetPort: 9000
  - name: gateway-udp
    protocol: UDP
    port: 9001
    targetPort: 9001
```

Names are unique lower-case Service port names, the list is limited to 32,
and `targetPort` must be a numeric unprivileged container port. TCP and UDP
may share a numeric port, but the same transport cannot reuse a Service or
container socket. The data chart renders these ports consistently into the
Service, Deployment or DaemonSet, and enabled NetworkPolicy. The controller
does not mutate that Service.

The controller chart exposes bounded generated-listener defaults under `l4`:

```yaml
statusService: oxibelt/oxibelt
statusAddresses: []
l4:
  bindAddress: 0.0.0.0
  connectTimeoutMs: 3000
  idleTimeoutMs: 75000
  udp:
    flowState: disabled # disabled | shared_required
    maxFlows: 3072
    newFlowRate: 200r/s
    newFlowBurst: 400
    datagramRate: 200r/s
    datagramBurst: 400
    batch: auto
    batchSize: 16
```

`statusAddresses` emits repeated explicit `--status-address` values and takes
precedence in controller behavior over Service-derived addresses. UDP flow
generation is disabled by default. `flowState: disabled` refuses `UDPRoute`
translation and status programming instead of emitting process-local data-plane
state.

Before setting `flowState: shared_required`, configure every selected data-plane
Pod with `[shared_state].enabled = true`, one explicit
`udp_flows_backend`, the same `shared_state.namespace`, and the same
`udp_flow_identity_key_env` name resolving to the same Secret-backed 32-byte
base64 key. Redis-compatible and PostgreSQL backends are supported. The effective
`connection_limits_backend` must resolve to that same backend, and each
generated listener's 75-second default idle timeout must remain at least six
times `shared_state.operation_timeout_ms`. Mount the identity key only into the
data-plane container; the Gateway Controller neither reads nor owns that
Secret.

Shared mode allows a replacement Pod to recover the same configured
`backendRef` identity while the record is inside its idle window. Fencing keeps
an older Pod generation from renewing or releasing the replacement's record.
It does not migrate the old socket, upstream source port, Service
NAT/conntrack selection, exact endpoint Pod, datagrams already in flight, or
application/session protocol state. During a shared-state outage,
already-local owned flows may continue, but a packet that needs a lookup,
claim, recovery, or distributed token decision is rejected.

The controller chart defaults to two replicas with `RollingUpdate`
(`maxUnavailable: 0`, `maxSurge: 1`), a `minAvailable: 1` PDB, and preferred
hostname anti-affinity. Only the holder of the Helm-owned metadata-only Lease
may translate or mutate. The selected Lease Role is confined to the release
namespace and exact name with `get`, `watch`, and `patch`; the controller cannot
create, list, or delete Leases. If that Lease is deleted, both replicas become
unready and stop writing. Restore it by reapplying the Helm release, then verify
the new Lease UID and holder before resuming operations.

Use `/healthz` for liveness, `/readyz` for election-participant readiness,
`/leaderz` to identify the current writer, and `/reconcilez` when an operator
needs the leader's committed reconciliation proof. On normal termination the
replica revokes local writer authority before attempting a guarded Lease
release; expiry remains the fallback. Scale to one replica before downgrading
to a release that predates Lease fencing.

Pod proof follows exact controller-owner UIDs: a DaemonSet Pod must be directly
controlled by the selected DaemonSet, while a Deployment Pod must be directly
controlled by a ReplicaSet directly controlled by the selected Deployment. This
defense in depth excludes label-colliding Pods, but target-namespace RBAC and
admission policy must also prevent less-trusted principals from creating or
altering a colliding ownership chain. The target workload still needs the
controller opt-in annotation; the Role alone is not authority to mutate
arbitrary workloads.
