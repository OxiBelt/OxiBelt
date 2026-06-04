# Kubernetes Gateway API Controller

`oxibelt-gateway-controller` translates selected Kubernetes Gateway API
resources into an OxiBelt TOML include file and applies that file through the
authenticated Admin API.

The controller is intentionally narrow in v1. It is useful for running
OxiBelt in Kubernetes without making OxiBelt itself own certificate issuance,
listener binding, Admin/IPM policy, or base runtime configuration.
The controller, Gateway API translations, and Helm chart are currently
`experimental` in the canonical [feature lifecycle matrix](FeatureStatus.md).

## Supported Resources

The controller watches:

- `GatewayClass`
- `Gateway`
- `HTTPRoute`
- `TLSRoute`
- `ReferenceGrant`
- `Service`
- `TCPRoute` when the CRD exists, for unsupported diagnostics only

Only `GatewayClass.spec.controllerName = "oxibelt.dev/gateway-controller"` is
in scope by default. Use `--controller-name` to change that value.

`HTTPRoute` rules generate deterministic `[[routes]]` and
`[[upstream_pools]]` entries. Service backends become static cluster DNS
origins such as:

```toml
origin = "http://app.default.svc.cluster.local:8080"
```

Weighted `backendRefs` become OxiBelt upstream-pool server weights. The
controller reads `oxibelt.dev/upstream-scheme = "http" | "https"` from a
`Service` or `HTTPRoute`; the default is `http`.

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

Unsupported filters include header modifiers, mirroring, CORS, external auth,
extension refs, hostname rewrite, port rewrite, and scheme rewrite. Use native
OxiBelt TOML and OxiRule policy for those behaviors until a later controller
version adds explicit bounded mappings.

Cross-namespace `Service` references require a `ReferenceGrant` in the target
namespace. Without the grant, the controller emits a blocking diagnostic and
does not apply the generated config.

Gateway listener `allowedRoutes` is enforced for `HTTPRoute` and `TLSRoute`
attachment. Omitted `allowedRoutes.namespaces` defaults to `Same`, so routes in
other namespaces must be explicitly allowed with `All` or a matching
`Selector`. Namespace selectors are evaluated from the Kubernetes `Namespace`
objects in the controller snapshot. If a selector cannot be evaluated, the
route is not attached.

`allowedRoutes.kinds` may further restrict which Gateway API route kinds bind
to a listener. When omitted or empty, the controller uses the listener protocol
default: `HTTPRoute` for `HTTP` and `HTTPS`, and `TLSRoute` for passthrough
`TLS`.

`ReferenceGrant.spec.to[].name` narrows a cross-namespace `Service` grant to the
named Service. When `name` is omitted, the grant allows all Services of that
kind in the ReferenceGrant namespace, matching Gateway API semantics.

## Status Updates

In `run` mode the controller patches Kubernetes status subresources for
resources owned by its configured `--controller-name`.

- `GatewayClass`: sets `Accepted=True` for matching classes.
- `Gateway`: sets `Accepted`, `Programmed`, listener `SupportedKinds`,
  `ResolvedRefs`, and listener conflict conditions. `--status-address` values
  are published as Gateway addresses.
- `HTTPRoute` and `TLSRoute`: replaces only this controller's entries in
  `status.parents`, preserving entries for other controllers from the observed
  object snapshot. Blocking translation diagnostics are reflected as
  `Accepted=False` or `ResolvedRefs=False`.
- `TCPRoute`: when attached to an in-scope parent, sets
  `Accepted=False, reason=UnsupportedKind` and emits no TOML.

`--dry-run` skips both Admin file sync and Kubernetes status mutations.

## Apply Model

The base OxiBelt config must include the controller-owned path, usually with a
glob:

```toml
include = ["conf.d/*.toml"]
```

The default managed path is:

```text
conf.d/gateway-api.generated.toml
```

At reconcile time the controller:

1. Polls Gateway API resources and Services from the Kubernetes API.
2. Renders one deterministic TOML file with ownership/source comments.
3. Refuses to apply if translation produced blocking diagnostics.
4. Fetches `/admin/v1/config/status` for the active config ETag.
5. Calls `/admin/v1/files/sync` with `apply = "full"` and `If-Match`.

The controller never reconstructs a full candidate from redacted
`/admin/v1/config/effective` output. It only writes its own include file.

Required Admin/IPM actions are:

- `config:GetStatus`
- `config:SyncFiles`
- `config:Load`

If generated config would affect protected `[admin]` or `[ipm]` sections,
OxiBelt's existing Admin file-sync precheck still requires the corresponding
`admin:UpdateConfig` or `ipm:UpdateConfig` actions. The controller-generated
file does not intentionally emit those sections.

## CLI

Render local manifests without contacting Kubernetes or Admin:

```sh
cargo run --manifest-path source/Cargo.toml \
  --bin oxibelt-gateway-controller -- \
  render --input deploy/helm/oxibelt-gateway-controller/examples --output -
```

Run in-cluster:

```sh
oxibelt-gateway-controller \
  --admin-url http://oxibelt-admin.oxibelt.svc.cluster.local:9092 \
  --admin-token-file /var/run/oxibelt-admin-token/token \
  --managed-config-path conf.d/gateway-api.generated.toml \
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

It installs a controller `Deployment`, `ServiceAccount`, RBAC, Admin token
secret reference, health probes, and an example Gateway API manifest. The
controller image is the normal OxiBelt image; the Docker image includes
`/usr/local/bin/oxibelt-gateway-controller`.
