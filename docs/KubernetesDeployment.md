# Kubernetes Deployment

Status: Draft

OxiBelt provides two Helm charts:

- `deploy/helm/oxibelt`: data-plane chart for the `oxibelt` reverse proxy and WAF.
- `deploy/helm/oxibelt-gateway-controller`: Gateway API controller chart for publishing immutable generated configuration and rolling the selected data-plane workload.

The Gateway controller remains a Gateway API controller. It is not an Ingress controller.

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
64-character digest.

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
UID. For a chart-created, content-addressed base, the Pod template initially
sets `oxibelt.dev/config-revision` to the immutable base ConfigMap name and
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
- `/var/cache/oxibelt` backed by an `emptyDir`

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

The chart validates its generated default Admin TOML. If an operator replaces
`config.inline` or uses `config.existingConfigMap`, that TOML remains
operator-owned and must be checked with `oxibelt --config <file> --check`.

Runtime Kubernetes upstream discovery uses the mounted service-account token when generated config sets `token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"`. Enable `kubernetesDiscovery.rbac.create` only when the data plane must read Kubernetes Endpoints or EndpointSlices.

## Health and Metrics

The chart enables OxiBelt health and basic Prometheus metrics in the generated config. Pods use readiness, liveness, and startup probes against the health listener. The metrics Service is enabled by default so a cluster scraper can target the named `metrics` port.

Horizontal scaling is chart-owned only through the optional `autoscaling` block, which renders an `autoscaling/v2` HPA for Deployment workloads. The metrics Service remains available whether or not HPA rendering is enabled.

Deployment defaults are deliberately conservative for immutable configuration:
`maxUnavailable: 0`, `maxSurge: 1`, `minReadySeconds: 5`,
`progressDeadlineSeconds: 300`, and `revisionHistoryLimit: 3`. DaemonSets use a
one-at-a-time rolling update (`maxUnavailable: 1`) with the same ready and
history defaults. Override these values only with an availability analysis for
the target topology.

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

The controller chart has no Admin URL, token, CA, client certificate, or Secret
permission. Its target-namespace Role gets and creates ConfigMaps, lists Pods
and, for a Deployment target, ReplicaSets, and gets and patches only the named
Deployment or DaemonSet.
It neither watches nor deletes target-namespace resources. Generated immutable
revisions are preserved for named rollback; their retention is operator
controlled rather than controller garbage collected. ConfigMap access is still
namespace scoped because content-addressed artifact names are known only at
runtime.

Pod proof follows exact controller-owner UIDs: a DaemonSet Pod must be directly
controlled by the selected DaemonSet, while a Deployment Pod must be directly
controlled by a ReplicaSet directly controlled by the selected Deployment. This
defense in depth excludes label-colliding Pods, but target-namespace RBAC and
admission policy must also prevent less-trusted principals from creating or
altering a colliding ownership chain. The target workload still needs the
controller opt-in annotation; the Role alone is not authority to mutate
arbitrary workloads.
