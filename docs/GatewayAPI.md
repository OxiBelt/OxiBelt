# Kubernetes Gateway API Controller

`oxibelt-gateway-controller` translates selected Kubernetes Gateway API
resources into an OxiBelt TOML include file, publishes it as an immutable
Kubernetes ConfigMap, and rolls a selected OxiBelt workload to that revision.

The controller is intentionally narrow in v1. It is useful for running
OxiBelt in Kubernetes without making OxiBelt itself own certificate issuance,
listener binding, Admin/IPM policy, or base runtime configuration.
The controller, Gateway API translations, and Helm chart are currently
`experimental` in the canonical [feature lifecycle matrix](FeatureStatus.md).
The version, conformance, architecture, failure-recovery, and promotion
requirements are defined in the
[Kubernetes support and graduation contract](KubernetesSupport.md). Its
Kubernetes `1.34`–`1.36`, Helm `3.21.3`/`4.2.3`, and Gateway API `v1.6.1`
matrix is a graduation target, not a supported-production claim.
The data-plane chart and controller chart are documented together in
[KubernetesDeployment.md](KubernetesDeployment.md).

## Supported Resources

“Supported” in this section describes implemented translation input. The
feature rows remain `experimental` until their mandatory graduation gates pass.

The controller watches:

- `GatewayClass`
- `Gateway`
- `HTTPRoute`
- `GRPCRoute`
- `TLSRoute`
- `TCPRoute`
- `UDPRoute`
- `BackendTLSPolicy`
- `ReferenceGrant`
- `Service`
- referenced `ConfigMap` objects containing public CA bundles

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

`TCPRoute` and `UDPRoute` attach only to same-protocol listeners and generate
deterministic `[[stream_listeners]]` and `[[stream_upstream_pools]]` entries.
Each supported route has one rule and core Service backend references. Service
port protocol, parent `sectionName`/port, `allowedRoutes`, and cross-namespace
`ReferenceGrant` authorization must all agree. An invalid route contributes no
stream TOML; the controller never weakens it into a direct target.

Raw TCP and UDP payloads bypass the HTTP router and HTTP WAF. Operators must
expose each listener explicitly through the data-plane chart's
`service.additionalPorts` and protect it as an application-protocol boundary.
The controller validates against the operator-owned `--status-service`; it
does not create or patch Services.

When multiple TCPRoutes or UDPRoutes attach to the same listener, all attached
routes receive status, but only the oldest `creationTimestamp` is translated.
Ties are resolved by namespace/name. An invalid winner does not cause fallback
to a newer route.

## BackendTLSPolicy Mapping

The stable-core subset applies to generated HTTPRoute and GRPCRoute Service
backends. It supports exactly one same-namespace Service `targetRef`, required
`validation.hostname`, and one of:

- `wellKnownCACertificates: System`; or
- one core ConfigMap `caCertificateRefs` entry whose `ca.crt` key is a valid,
  bounded PEM CA bundle.

The policy hostname is used for both SNI and certificate authentication while
OxiBelt still connects to the Service address. Exclusive ConfigMap trust does
not inherit the system or operator global trust roots. The controller fetches
only exact referenced ConfigMaps, copies only the public `ca.crt` bytes into
the immutable generated artifact, and binds their UID, resource version, and
content digest into rollout proof.

Multiple targets, target `sectionName`, multiple CA references,
`subjectAltNames`, `options`, cross-namespace CA refs, Secret refs, mTLS client
identity, and certificate/SPKI pins are unsupported. They receive explicit
policy status and never fall back to plaintext or broader TLS trust. Gateway
API v1 does not define a portable client-identity or pin field, and a
`ReferenceGrant` cannot make an otherwise invalid cross-namespace policy CA
reference valid.

## UDP Safety Bounds

Generated UDP listeners default to a 75-second idle timeout, 8,192 process-local
flows, a `200r/s` new-flow rate with burst 400, a `200r/s` per-flow datagram
rate with burst 400, automatic batching, and batch size 16. Configure these
bounded controller-wide defaults under chart `l4.udp`. UDP flows are pinned to
one weighted backend until idle expiry or eviction and do not survive Pod
replacement or immutable rollout. Stateful continuity, source-IP preservation,
UDP PROXY, BackendTLSPolicy, and arbitrary filters are not approximated.

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
| `TCPRoute` | Experimental | One rule, weighted core Service backends, deterministic listener winner, and explicit operator-owned port exposure. |
| `UDPRoute` | Experimental | Same bounded Service mapping plus process-local flow, admission, and datagram limits. |
| `BackendTLSPolicy` | Experimental/partial | Stable-core hostname plus System or one ConfigMap `ca.crt`; extensions, Secrets, mTLS, pins, and SAN overrides are rejected. |

Cross-namespace `Service` references require a `ReferenceGrant` in the target
namespace. Without the grant, the controller emits a blocking diagnostic and
does not apply the generated config.

Gateway listener `allowedRoutes` is enforced for `HTTPRoute`, `GRPCRoute`,
`TLSRoute`, `TCPRoute`, and `UDPRoute`
attachment. Omitted `allowedRoutes.namespaces` defaults to `Same`, so routes in
other namespaces must be explicitly allowed with `All` or a matching
`Selector`. Namespace selectors are evaluated from the Kubernetes `Namespace`
objects in the controller snapshot. If a selector cannot be evaluated, the
route is not attached.

`allowedRoutes.kinds` may further restrict which Gateway API route kinds bind
to a listener. When omitted or empty, the controller uses the listener protocol
default: `HTTPRoute` and `GRPCRoute` for `HTTP` and `HTTPS`, `TLSRoute` for
passthrough `TLS`, `TCPRoute` for `TCP`, and `UDPRoute` for `UDP`.

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
- `HTTPRoute`, `GRPCRoute`, `TLSRoute`, `TCPRoute`, and `UDPRoute`: replaces only this controller's entries in
  `status.parents`, preserving entries for other controllers from the observed
  object snapshot. Blocking translation diagnostics are reflected as
  `Accepted=False` or `ResolvedRefs=False`.
- `BackendTLSPolicy`: replaces only this controller's matching ancestor entry
  and reports accepted, conflicted, invalid, unresolved, and unsupported
  policy states without removing status owned by other controllers.

`--dry-run` skips immutable artifact/workload mutations and Kubernetes status
mutations.

## High Availability and Fencing

In `run` mode, every replica participates in a named
`coordination.k8s.io/v1` Lease election. The process identity combines the Pod
name, Pod UID, and a fresh cryptographic nonce. A leadership term is the tuple
of Lease UID, `leaseTransitions` epoch, and holder identity. Followers stay
warm at the election boundary but do not translate resources or perform
ConfigMap, workload, rollback, cleanup, or status writes.

Every mutating request requires a current local write permit and a fresh GET of
the exact Lease immediately before the request. Workload patches also persist
the Lease UID, epoch, and holder in `oxibelt.dev/gateway-controller-*`
annotations and reject an older epoch in the same Lease UID fencing domain.
The ConfigMap identity remains content-addressed and independent of the
leader, so a replacement leader reconstructs an in-progress rollout from the
workload annotations, immutable ConfigMap, ReplicaSets, and Pods rather than
from process memory.

The chart owns a metadata-only Lease. Controller RBAC permits only `get`,
`watch`, and `patch` for that exact Lease name in the release namespace; it
does not grant Lease `create`, `list`, or `delete`. Deleting the Lease therefore
revokes all writers and readiness. Reapply or upgrade the Helm release to
recreate the exact Lease, then wait for a new UID and leader before considering
the controller recovered. Do not grant namespace-wide Lease creation merely
to automate this recovery.

## Immutable Rollout Model

The base OxiBelt config must include the controller-owned path, usually with a
glob, and set `runtime.hot_reload.mode = "off"`:

```toml
include = ["conf.d/*.toml"]
```

The default managed path is `conf.d/gateway-api.generated.toml`. It must remain
a safe nested relative `.toml` path, not a root-level filename, so the
controller can prove its target remains beneath the config root. The controller
derives the selected container's config root from its `--config` argument. In
`kubernetes_immutable` mode, the data-plane chart initially mounts its
immutable base ConfigMap directly and projects the empty
`gateway-config-directory` key to both `conf.d/.keep` and the exact managed
path. For a chart-generated, content-addressed base, the Pod template identifies
this bootstrap state with the base ConfigMap name and the SHA-256 of the empty
managed placeholder, so every Pod has a nonempty, verifiable identity while it
waits for controller assignment. This does not relax base-config validation:
when the base has no routes, Pods remain unready until generated configuration
is assigned. For `config.existingConfigMap`, Helm cannot verify the external
object's bytes, so it leaves the revision/digest unassigned and OxiBelt fails
closed until the controller assigns the generated revision. Existing
ConfigMaps used only for ordinary `helm_immutable` rollouts do not need this
sentinel.

During reconciliation, the controller replaces only the selected container's
config-root mount with a projected volume composed from the immutable base and
generated ConfigMaps. It preserves the base key mappings except for the exact
managed placeholder, then maps the generated key to the full managed path. The
original base volume remains in the Pod template for any sidecar mounts; the
controller does not nest one volume mount inside another.

At reconcile time the controller:

1. Polls Gateway API resources and Services from the Kubernetes API.
2. Renders and validates deterministic TOML plus any referenced public CA
   assets with ownership/source comments. Resource-invalid fragments are
   omitted or replaced by explicit terminal rejection; snapshot, authorization,
   artifact, or final validation failures stop publication.
3. Computes the raw SHA-256 of the exact TOML bytes and a tagged full-artifact
   digest, then creates or reuses an immutable ConfigMap named
   `<prefix>-<deployment-or-daemonset>-<target-name>-<full-64-hex-artifact-digest>`.
4. Requires `oxibelt.dev/immutable-config-rollout: "true"` on the selected
   Deployment or DaemonSet before patching it.
5. Applies a resource-version-guarded patch for the composed projected
   config-root volume, the selected container mount, and
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

Before a true `Programmed` commit, the leader re-lists the source resources,
requires unchanged deterministic output, re-reads the workload and owned Pod
chain, checks generation and resource version, and revalidates its Lease term.
Status writes use a resource-version JSON Patch. The condition message records
a bounded proof containing the workload UID/generation/resource version,
owner-chain and source-snapshot digests, immutable content digest context, and
leadership term.

The controller does not read, write, or authenticate to an OxiBelt Admin
Service. In `kubernetes_immutable` mode, the data plane rejects local mutable
config load, rollback, file-sync, and downstream TLS reload operations rather
than allowing a Pod to diverge from the assigned Kubernetes revision.

## CLI

Render local manifests without contacting Kubernetes:

```sh
cargo run -p oxibelt-gateway-controller -- \
  render --input deploy/helm/oxibelt-gateway-controller/examples --output -
```

Run in-cluster:

```sh
oxibelt-gateway-controller \
  --managed-config-path conf.d/gateway-api.generated.toml \
  --health-bind 0.0.0.0:9090 \
  run \
  --rollout-target-namespace default \
  --rollout-target-kind deployment \
  --rollout-target-name oxibelt \
  --rollout-target-container-name oxibelt \
  --rollout-volume-name gateway-config \
  --rollout-timeout-seconds 300 \
  --rollout-config-map-prefix oxibelt-gateway-config \
  --leader-election-namespace default \
  --leader-election-lease-name oxibelt-gateway-controller \
  --leader-election-lease-duration-seconds 15 \
  --leader-election-renew-deadline-seconds 10 \
  --leader-election-retry-period-seconds 2
```

The `run` command uses a Kubernetes API token and CA from
`/var/run/secrets/kubernetes.io/serviceaccount`. The Helm chart disables the
automatic mount and instead projects only a short-lived token plus
`kube-root-ca.crt` at that path. Deployments that invoke the binary directly
must provide an equivalent explicit projection rather than relying on an
ambient ServiceAccount token. Use `--watch-namespace` to limit namespaced
resource polling; omitting it is cluster-wide and therefore requires the
corresponding explicit RBAC. The chart defaults to its release namespace and
omits the argument only when `watchAllNamespaces: true` is explicitly set.

## Helm

A minimal chart lives under:

```text
deploy/helm/oxibelt-gateway-controller
```

It installs a two-replica `RollingUpdate` controller `Deployment`, a separate
ServiceAccount with automatic mounting disabled, an explicit bounded API
projection, read-only-by-default Gateway API RBAC, a target-namespace rollout
Role, exact-name Lease Role, metadata-only Lease, `PodDisruptionBudget`, soft
hostname anti-affinity, health probes, and an example Gateway API manifest. The default Gateway
API read Role is limited to the release namespace; set `watchAllNamespaces:
true` only after reviewing the resulting cluster-wide permissions. The target
Role grants no Secret access; it gets and creates ConfigMaps, lists Pods and,
for a Deployment target, ReplicaSets, and may get and patch only the named
Deployment or DaemonSet. It has no target namespace `watch` or `delete`
permission. The controller chart defaults to the role-specific
`ghcr.io/oxibelt/oxibelt-gateway-controller` image. It contains
`/usr/local/bin/oxibelt-gateway-controller` and intentionally excludes
`oxibelt`, `oxibeltctl`, and the public runtime filesystem. The data-plane
chart independently defaults to `ghcr.io/oxibelt/oxibelt-dataplane`; the two
images must use the same release version and source revision. The data-plane
chart may instead select `image.role: dataplane-strict` and
`ghcr.io/oxibelt/oxibelt-dataplane-strict`; immutable ConfigMap rollout and
Gateway translation do not require the Admin API. The strict role retains
Person Proof and rejects any Admin configuration rather than falling back to
Admin file sync.

Normal operation uses `--compatibility-mode exact`. The selected workload's
Pod-template annotation `oxibelt.dev/effective-version` must equal the
controller's effective version. A controlled adjacent-minor transition may
temporarily use `--compatibility-mode rolling_upgrade` together with
`--compatibility-previous-version` and an RFC3339
`--compatibility-deadline` no more than 24 hours in the future. An invalid,
unlisted, or expired skew keeps readiness false and prevents reconciliation.
See [KubernetesSupport.md](KubernetesSupport.md#controller-and-data-plane-skew)
for upgrade and rollback order.

The rolling strategy uses `maxUnavailable: 0` and `maxSurge: 1`; the default
PDB keeps `minAvailable: 1`. `replicaCount: 1` remains available for deliberate
development use, normally with the PDB disabled. `/healthz` is process health,
`/readyz` means the replica is a current election participant (leader or
follower), `/leaderz` is leader-only, and `/reconcilez` is leader-only and
requires a committed proof. Leader-election values default to 15/10/2 seconds
for Lease duration, renew deadline, and retry period and are rejected unless
they satisfy the chart and CLI safety bounds.

During an upgrade, leave the metadata-only Lease in place and let
`RollingUpdate` replace replicas. To downgrade to a controller version without
Lease fencing, first scale this controller to one replica and wait for the
rolling update to finish; running multiple unfenced old replicas is unsafe.
