# Kubernetes Gateway API Controller

`oxibelt-gateway-controller` translates selected Kubernetes Gateway API
resources into an OxiBelt TOML include file, publishes it as an immutable
Kubernetes ConfigMap, and rolls a selected OxiBelt workload to that revision.

The controller is intentionally narrow in v1. It is useful for running
OxiBelt in Kubernetes without making OxiBelt itself own certificate issuance,
listener binding, Admin/IPM policy, or base runtime configuration.
The controller, Gateway API translations, and Helm chart are currently
`experimental` in the canonical [feature lifecycle matrix](FeatureStatus.md).
The data-plane chart and controller chart are documented together in
[KubernetesDeployment.md](KubernetesDeployment.md).

## Supported Resources

The controller watches:

- `GatewayClass`
- `Gateway`
- `HTTPRoute`
- `GRPCRoute`
- `TLSRoute`
- `ReferenceGrant`
- `Service`
- `TCPRoute` when the CRD exists, for unsupported diagnostics only

Only `GatewayClass.spec.controllerName = "oxibelt.dev/gateway-controller"` is
in scope by default. Use `--controller-name` to change that value.

`HTTPRoute` and `GRPCRoute` rules generate deterministic `[[routes]]` and
`[[upstream_pools]]` entries. Service backends use static cluster DNS origins
by default, such as:

```toml
origin = "http://app.default.svc.cluster.local:8080"
```

Weighted `backendRefs` become OxiBelt upstream-pool server weights. The
controller reads `oxibelt.dev/upstream-scheme = "http" | "https"` from a
`Service`; the default is `http`.

Set `--backend-resolution=endpoint_slice_watch` to generate a Kubernetes
EndpointSlice discovery block for route rules that reference exactly one
nonzero Service backend. Weighted multi-backend rules remain static-DNS-only in
this mode and are rejected with a blocking diagnostic rather than silently
dropping weights. For direct EndpointSlice routing, generated discovery uses a
named Service port as `port_name`, otherwise it uses numeric `targetPort` when
available, falling back to the Service port only when `targetPort` is omitted.
Generated discovery uses the in-pod service-account token file:

```toml
token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
```

`TLSRoute` is supported only for Gateway listeners with
`tls.mode = "Passthrough"`. It generates `[[sni_forward.rules]]` with
`protocols = ["tcp_tls"]`. The base OxiBelt config must enable
`[sni_forward]`; the generated include does not set operator-owned scalar
fields such as `enabled`.

`TCPRoute` is not translated in v1. The controller reports it as unsupported
and emits no TOML.

## HTTPRoute Mapping

Supported matches:

- hostname intersection between `Gateway` listener and `HTTPRoute`
- `PathPrefix`
- `Exact`
- method
- exact header
- exact query parameter

Unsupported matches fail the route translation for the affected rule:

- regular expression path, header, or query matches
- wildcard method matches

Supported filters:

- `URLRewrite` path rewrite when it maps to OxiBelt `actions.rewrite.path`
- `RequestRedirect` path-only redirect when it maps to origin-relative
  `actions.redirect.location_template`
- `RequestHeaderModifier` and `ResponseHeaderModifier`, mapped to
  `routes.actions.request_headers` and `routes.actions.response_headers`
- `RequestMirror`, mapped to a generated mirror `upstream_pool`
- `CORS`, mapped to `routes.actions.cors`
- `ExternalAuth` with `protocol: HTTP`, mapped to generated
  `[[external_auth]] provider = "gateway_ext_auth_http"`

Unsupported filters include extension refs, hostname rewrite, port rewrite,
scheme rewrite, gRPC ext-authz, and `ExternalAuth.forwardBody.maxSize > 0`.
`RequestHeaderModifier` follows OxiBelt route request-header hardening: route
authors cannot mutate OxiBelt-managed proxy identity or authority headers such
as `Host`, `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, or `CF-Connecting-IP`,
and cannot mutate the same rule's `ExternalAuth.headersToBackend` identity
headers. The controller reports these as blocking diagnostics and omits the
affected generated route.
Gateway HTTP external auth uses explicit header allowlists; omitted allowlists
render as empty arrays instead of inheriting OxiBelt's non-Gateway defaults.

## GRPCRoute Mapping

`GRPCRoute` attaches to in-scope `HTTP` and `HTTPS` listeners. Supported
matches are host intersection, exact headers, exact service+method matches, and
service-only matches. Exact service+method lowers to an exact gRPC path such as
`/pkg.Service/Method`; service-only lowers to a prefix such as
`/pkg.Service/`. Method-only and regular-expression method matches are rejected
with a blocking diagnostic.

Supported `GRPCRoute` filters share the same bounded implementation as
`HTTPRoute` where applicable: request/response header modifiers,
`RequestMirror`, and HTTP `ExternalAuth`. CORS, redirects, and URL rewrites are
not applicable to `GRPCRoute`.

## Conformance Support

| Gateway API feature | Status | Notes |
| --- | --- | --- |
| `HTTPRoute` host/path/method/exact header/exact query matches | Supported | Regex and wildcard method matches are rejected. |
| `HTTPRoute` weighted Service backendRefs | Supported | Cross-namespace refs require `ReferenceGrant`. |
| `HTTPRoute` `URLRewrite` and `RequestRedirect` | Partial | Path-only bounded mappings; host/scheme/port rewrites are rejected. |
| `HTTPRoute` header modifiers, CORS, `RequestMirror` | Partial | Mapped to native route actions; mirrors are best-effort and bodyless in v1. |
| `HTTPRoute`/`GRPCRoute` HTTP `ExternalAuth` | Partial | HTTP subset only, explicit header allowlists, no body forwarding. |
| `GRPCRoute` service/method/header matches | Partial | Exact service+method and service-only matches only. |
| `TLSRoute` passthrough | Partial | Requires `tls.mode = Passthrough`; emits `sni_forward` rules. |
| `TCPRoute` | Unsupported/status-only | Watched for status diagnostics; no TOML is emitted. |

Cross-namespace `Service` references require a `ReferenceGrant` in the target
namespace. Without the grant, the controller emits a blocking diagnostic and
does not apply the generated config.

Gateway listener `allowedRoutes` is enforced for `HTTPRoute`, `GRPCRoute`, and `TLSRoute`
attachment. Omitted `allowedRoutes.namespaces` defaults to `Same`, so routes in
other namespaces must be explicitly allowed with `All` or a matching
`Selector`. Namespace selectors are evaluated from the Kubernetes `Namespace`
objects in the controller snapshot. If a selector cannot be evaluated, the
route is not attached.

`allowedRoutes.kinds` may further restrict which Gateway API route kinds bind
to a listener. When omitted or empty, the controller uses the listener protocol
default: `HTTPRoute` for `HTTP` and `HTTPS`, and `TLSRoute` for passthrough
`TLS`. HTTP and HTTPS listeners accept both `HTTPRoute` and `GRPCRoute` by
default.

`ReferenceGrant.spec.to[].name` narrows a cross-namespace `Service` grant to the
named Service. When `name` is omitted, the grant allows all Services of that
kind in the ReferenceGrant namespace, matching Gateway API semantics.

## Status Updates

In `run` mode the controller patches Kubernetes status subresources for
resources owned by its configured `--controller-name`.

- `GatewayClass`: sets `Accepted=True` for matching classes.
- `Gateway`: sets `Accepted`, `Programmed`, listener `SupportedKinds`,
  `ResolvedRefs`, and listener conflict conditions. `--status-address` values
  are published as Gateway addresses. When explicit addresses are not set,
  `--status-service namespace/name` publishes the referenced Service
  `status.loadBalancer.ingress` IPs or hostnames as Gateway addresses.
- `HTTPRoute`, `GRPCRoute`, and `TLSRoute`: replaces only this controller's entries in
  `status.parents`, preserving entries for other controllers from the observed
  object snapshot. Blocking translation diagnostics are reflected as
  `Accepted=False` or `ResolvedRefs=False`.
- `TCPRoute`: when attached to an in-scope parent, sets
  `Accepted=False, reason=UnsupportedKind` and emits no TOML.

`--dry-run` skips immutable artifact/workload mutations and Kubernetes status
mutations.

## Immutable Rollout Model

The base OxiBelt config must include the controller-owned path, usually with a
glob, and set `runtime.hot_reload.mode = "off"`:

```toml
include = ["conf.d/*.toml"]
```

The default managed path is `conf.d/gateway-api.generated.toml`. It must remain
a safe nested relative `.toml` path, not a root-level filename, so the
controller can prove its target remains beneath the config root. The controller
derives the selected container's config root from its `--config` argument and
mounts this one file from an immutable ConfigMap. In `kubernetes_immutable`
mode, the data-plane chart projects the empty `gateway-config-directory` key
to both `conf.d/.keep` and the exact managed path. The exact empty placeholder
gives the read-only single-file mount a target; `.keep` remains for a safe
data-plane-first upgrade. Existing ConfigMaps used only for ordinary
`helm_immutable` rollouts do not need this sentinel.

At reconcile time the controller:

1. Polls Gateway API resources and Services from the Kubernetes API.
2. Renders and validates one deterministic TOML file with ownership/source
   comments; blocking diagnostics stop before publication.
3. Computes the raw SHA-256 of the exact TOML bytes and a tagged artifact
   digest, then creates or reuses an immutable ConfigMap named
   `<prefix>-<deployment-or-daemonset>-<target-name>-<full-64-hex-artifact-digest>`.
4. Requires `oxibelt.dev/immutable-config-rollout: "true"` on the selected
   Deployment or DaemonSet before patching it.
5. Applies a resource-version-guarded patch for the generated volume/mount and
   `oxibelt.dev/config-revision` plus `oxibelt.dev/config-digest` pod-template
   annotations.
6. Waits for observed generation, availability, and every Ready Pod proven to
   be owned by the selected workload before checking its revision/digest proof
   and reporting `Programmed=True` and committing.

The rollout phases are `Generated`, `Validated`, `CanaryApplying`,
`CanaryHealthy`, `Expanding`, `FullyApplied`, and `Committed`. Any rejection,
unreachable Pod, conflict, or timeout requests the last committed immutable
revision and verifies rollback before reporting failure. The controller resumes
persisted rollout state after restart. Generated immutable revisions are
preserved for named rollback; operators control their retention rather than the
controller garbage collecting ConfigMaps.

Ownership verification follows controller-owner UIDs: a DaemonSet Pod must be
directly controlled by the selected DaemonSet, while a Deployment Pod must be
directly controlled by a ReplicaSet directly controlled by the selected
Deployment. This excludes selector-colliding Pods as defense in depth. It does
not replace target-namespace RBAC and admission policy: less-trusted principals
must not be able to create or alter a colliding ownership chain.

A successful translation alone does not mean `Programmed=True`: Gateway,
listener, and route `Programmed` conditions become true only after the desired
digest is committed across all Ready selected replicas. During convergence they
remain `False` with a bounded rollout reason. Route attachment and reference
conditions continue to reflect translation independently.

The controller does not read, write, or authenticate to an OxiBelt Admin
Service. In `kubernetes_immutable` mode, the data plane rejects local mutable
config load, rollback, file-sync, and downstream TLS reload operations rather
than allowing a Pod to diverge from the assigned Kubernetes revision.

## CLI

Render local manifests without contacting Kubernetes:

```sh
cargo run --manifest-path source/Cargo.toml \
  --bin oxibelt-gateway-controller -- \
  render --input deploy/helm/oxibelt-gateway-controller/examples --output -
```

Run in-cluster:

```sh
oxibelt-gateway-controller \
  --managed-config-path conf.d/gateway-api.generated.toml \
  --rollout-target-namespace default \
  --rollout-target-kind deployment \
  --rollout-target-name oxibelt \
  --rollout-target-container-name oxibelt \
  --rollout-volume-name gateway-config \
  --rollout-timeout-seconds 300 \
  --rollout-config-map-prefix oxibelt-gateway-config \
  --health-bind 0.0.0.0:9090 \
  run
```

The `run` command uses the pod service account token and CA from
`/var/run/secrets/kubernetes.io/serviceaccount`. Use `--watch-namespace` to
limit namespaced resource polling.

## Helm

A minimal chart lives under:

```text
deploy/helm/oxibelt-gateway-controller
```

It installs a single-replica `Recreate` controller `Deployment`,
`ServiceAccount`, read-only Gateway API RBAC, a target-namespace rollout Role,
health probes, and an example Gateway API manifest. The target Role grants no
Secret access; it gets and creates ConfigMaps, lists Pods and, for a Deployment
target, ReplicaSets, and may get and patch only the named Deployment or
DaemonSet. It has no target
namespace `watch` or `delete` permission. The controller image is the normal
OxiBelt image; the Docker image includes
`/usr/local/bin/oxibelt-gateway-controller`.
