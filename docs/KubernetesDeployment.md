# Kubernetes Deployment

Status: Draft

OxiBelt provides two Helm charts:

- `deploy/helm/oxibelt`: data-plane chart for the `oxibelt` reverse proxy and WAF.
- `deploy/helm/oxibelt-gateway-controller`: Gateway API controller chart for rendering controller-owned TOML includes through the Admin API.

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
cert_chain = "/etc/oxibelt/cert/tls.crt"
private_key = "/etc/oxibelt/cert/tls.key"
```

Set `config.existingConfigMap` to use an operator-managed config file instead of the chart-generated ConfigMap. The config path is mounted read-only and passed to OxiBelt with `--config`.

## Security Defaults

The chart defaults are compatible with the release image's non-root runtime:

- `runAsNonRoot: true`
- UID/GID `10001`
- `readOnlyRootFilesystem: true`
- all Linux capabilities dropped
- `seccompProfile.type: RuntimeDefault`
- config, TLS, and OxiRule mounts read-only
- `/var/cache/oxibelt` backed by an `emptyDir`

Admin API exposure is disabled by default. When `admin.enabled = true`, set `admin.tokenSecretName`; the chart injects the token as `OXIBELT_ADMIN_TOKEN` and can expose a separate Admin Service when `admin.service.enabled = true`.

Runtime Kubernetes upstream discovery uses the mounted service-account token when generated config sets `token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"`. Enable `kubernetesDiscovery.rbac.create` only when the data plane must read Kubernetes Endpoints or EndpointSlices.

## Health and Metrics

The chart enables OxiBelt health and basic Prometheus metrics in the generated config. Pods use readiness, liveness, and startup probes against the health listener. The metrics Service is enabled by default so a cluster scraper can target the named `metrics` port.

Horizontal scaling is chart-owned only through the optional `autoscaling` block, which renders an `autoscaling/v2` HPA for Deployment workloads. The metrics Service remains available whether or not HPA rendering is enabled.

## Gateway Controller Pairing

When using the Gateway controller chart with the data-plane chart, mount a config that includes the controller-owned path:

```toml
include = ["conf.d/*.toml"]
```

The controller chart expects an Admin token Secret and uses the authenticated Admin API to sync only its managed include file.
