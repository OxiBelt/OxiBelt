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
Kubernetes `1.34`–`1.36`, Helm `3.21.4`/`4.2.4`, and Gateway API `v1.6.1`
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
- `OxiBeltRoutePolicy.gateway.oxibelt.dev/v1alpha1`
- `ReferenceGrant`
- `Service`
- operator-owned `OxiBeltDataPlaneTarget.gateway.oxibelt.dev/v1alpha1`
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

Set `--backend-resolution=endpoint_slice_watch` to generate one Kubernetes
EndpointSlice discovery instance per nonzero Service backend. HTTPRoute and
GRPCRoute rules may therefore combine multiple dynamically discovered Services
without one Service's refresh replacing another Service's endpoints. Each
instance has a deterministic ID and carries the Gateway `backendRef.weight` as
its aggregate weight multiplier. Zero-weight backends are omitted; an absent
weight is `1`; malformed or out-of-range weights block translation. This new
multi-Service artifact shape requires `--compatibility-mode=exact` and is
blocked during a previous-minor rolling-upgrade window.

Within each discovery instance, ready endpoint weights are normalized so that
the instance's endpoints share its aggregate Gateway weight. The controller and
data plane use checked arithmetic, deterministic ordering, GCD reduction, and
bounded scaling; they reject a vector whose positive shares cannot be retained
in the core `u32` weight range. EndpointSlice generation uses a named Service
port as `port_name`, otherwise it uses numeric `targetPort` when available,
falling back to the Service port only when `targetPort` is omitted. Generated
discovery uses the in-pod service-account token file:

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

The implemented subset applies to generated HTTPRoute and GRPCRoute Service
backends. It supports exactly one same-namespace Service `targetRef`, required
lowercase precise `validation.hostname`, and one of:

- `wellKnownCACertificates: System`; or
- one to eight core ConfigMap `caCertificateRefs` entries whose `ca.crt` keys
  form a valid PEM CA set of at most 256 KiB in aggregate.

The policy hostname is used for both SNI and certificate authentication while
OxiBelt still connects to the Service address. Exclusive ConfigMap trust does
not inherit the system or operator global trust roots. The controller fetches
only exact referenced ConfigMaps, copies only the public `ca.crt` bytes into
the immutable generated artifact, and binds their UID, resource version, and
content digest into rollout proof. Multiple references are checked for
duplicates and merged by content-addressed path, so reference or watch order
cannot alter the trust bundle or artifact digest.

`validation.subjectAltNames` accepts one to five exact Gateway API v1.6.1
`Hostname` or `URI` entries. Hostnames must be lowercase DNS names without
wildcards or IP literals; URIs must be exact absolute ASCII URIs. The configured
`hostname` remains TLS SNI. When an explicit SAN list is present, it is not an
authentication identity unless it is also listed. OxiBelt first performs the
ordinary WebPKI chain, time, purpose, and CA verification and then requires at
least one configured DNS or URI SAN to match the leaf certificate. The SAN set
is also part of TCP/QUIC client and resumption identity, preventing reuse across
different authentication policies.

Multiple targets, target `sectionName`, `options`, cross-namespace CA refs,
Secret refs, mTLS client identity, and certificate/SPKI pins are unsupported.
They receive explicit
policy status and never fall back to plaintext or broader TLS trust. Gateway
API v1 does not define a portable client-identity or pin field, and a
`ReferenceGrant` cannot make an otherwise invalid cross-namespace policy CA
reference valid.

## UDP Safety Bounds

Generated UDP listeners default to a 75-second idle timeout, 3,072 bounded
flows, a `200r/s` new-flow rate with burst 400, a `200r/s` per-flow datagram
rate with burst 400, automatic batching, and batch size 16. Configure these
controller-wide bounds under chart `l4.udp`.

The controller defaults `l4.udp.flowState` to `disabled` and refuses to render
or program a `UDPRoute` while it remains disabled; it does not silently emit
process-local generated flow state. Set it to `shared_required` only after
every selected data-plane Pod is configured with the same
`shared_state.namespace`, 32-byte base64 identity key, and explicit
`udp_flows_backend`. The backend may be Redis-compatible or PostgreSQL and
must also be the effective shared connection-limit backend. Invalid or missing
prerequisites keep the generated data-plane configuration from activating.

Within the idle window, shared recovery restores the same still-configured
weighted `backendRef` identity and fences stale owners. It does not restore the
old socket or source port, NAT/conntrack state, the exact endpoint Pod behind a
Service, in-flight or upstream-initiated datagrams, or application/session
state. A shared-state outage preserves already-local owned work but rejects
lookups, claims, recoveries, and distributed token decisions for unknown or
displaced flows. Source-IP preservation, UDP PROXY, BackendTLSPolicy, and
arbitrary filters are not approximated.

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

- `URLRewrite` exact hostname/authority and `ReplacePrefixMatch` or
  `ReplaceFullPath` path rewrite, mapped to `actions.rewrite`
- `RequestRedirect` scheme, hostname, port, status code, and path fields,
  mapped to structured `actions.redirect`; an omitted scheme and port retains
  the selected listener port
- `RequestHeaderModifier` and `ResponseHeaderModifier`, mapped to
  `routes.actions.request_headers` and `routes.actions.response_headers`
- `RequestMirror`, mapped to a generated mirror `upstream_pool`; the operator
  chooses a global `--request-mirror-max-body-bytes` cap of at most 16 MiB,
  with `0` preserving bodyless behavior. The data plane also reserves each
  capture against a fail-fast 64-MiB process-wide budget until all mirror body
  clones are dropped; exhaustion skips only the mirror
- `CORS`, mapped to `routes.actions.cors`
- `ExternalAuth` with `protocol: HTTP`, exact HTTP path/header allowlists, and
  bounded `forwardBody.maxSize`, mapped to generated
  `[[external_auth]] provider = "gateway_ext_auth_http"`
- same-namespace `ExtensionRef` to
  `OxiBeltRoutePolicy.gateway.oxibelt.dev/v1alpha1`

`RequestRedirect` cannot be combined with a backend or any other filter;
unsupported combinations block the affected rule. gRPC ext-authz remains
unsupported because the native runtime does not expose an exact gRPC auth
contract.
`RequestHeaderModifier` follows OxiBelt route request-header hardening: route
authors cannot mutate OxiBelt-managed proxy identity or authority headers such
as `Host`, `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, or `CF-Connecting-IP`,
and cannot mutate the same rule's `ExternalAuth.headersToBackend` identity
headers. The controller reports these as blocking diagnostics and omits the
affected generated route.
Gateway HTTP external auth uses explicit operator ceilings for forwarded,
identity, terminal-response, and credential headers. Route allowlists must be
subsets. Forwarded and identity lists cannot include `Host`, trusted
forwarding identity, framing, or hop-by-hop headers; terminal-response lists
cannot include framing or hop-by-hop headers. Body forwarding requires both a route `forwardBody.maxSize` no larger
than 65,535 bytes and the operator's byte/content-type allowlists. Unsupported
media types fail locally with `415`; oversized bodies fail with `413`; the auth
decision occurs before the protected upstream receives the replayed body.

Bodyful mirroring is best-effort and never changes or waits indefinitely on the
primary response. OxiBelt tees at most the operator cap while the primary body
continues streaming; oversize, failed, cancelled, or non-replayable copies are
not dispatched. Set the cap to `0` for namespaces or installations where
sensitive bodies must never be mirrored. Status and logs contain no body bytes.

## OxiBeltRoutePolicy v1alpha1

The namespaced `OxiBeltRoutePolicy.gateway.oxibelt.dev/v1alpha1` CRD is an
operator-installed alpha API. A route rule attaches it through a same-namespace
Gateway `ExtensionRef`; `spec.targetRef` must select that HTTPRoute or
GRPCRoute. The initial bounded fields are:

- up to 16 named WAF/OxiRule request groups;
- `limits.maxRequestBodyBytes`, capped by the operator and 100 MiB schema
  maximum; and
- `timeouts.upstreamRequestMilliseconds`, capped by the operator and 300-second
  schema maximum.

The policy cannot contain raw TOML, listener/Admin fields, filesystem paths,
trust roots, arbitrary headers, Secrets, credentials, or another route's
settings. Unknown fields, a missing or mismatched target, more than one policy
filter on a rule, and over-cap values reject the affected rule transactionally.
Operator caps are the upper authority; the route policy may only choose a
bounded value at or below them. Standard route filters remain independently
validated and cannot weaken those caps.

Policy status publishes `Accepted`, `ResolvedRefs`, `Conflicted`, and
`Programmed` conditions plus the lowercase immutable artifact-bundle digest
only after rollout proof and only when the target route and policy fragment
exist in the translated artifact. The status and explain views include effective group/body/timeout values
but never rule contents, request bodies, credentials, or generated TOML. Apply
the CRD from
`deploy/kubernetes/oxibelt-gateway-controller/crds/oxibeltroutepolicies.gateway.oxibelt.dev.yaml`
before installing or upgrading the chart.

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
| `HTTPRoute` `URLRewrite` and `RequestRedirect` | Experimental/partial | Exact hostname/path rewrite and structured scheme/hostname/port/path/status redirect; incompatible combinations are rejected. |
| `HTTPRoute` header modifiers, CORS, `RequestMirror` | Experimental/partial | Mapped to native route actions; mirror bodies are opt-in, bounded, and best-effort. |
| `HTTPRoute`/`GRPCRoute` HTTP `ExternalAuth` | Experimental/partial | HTTP only, explicit operator/route header and media-type allowlists, bounded body forwarding. |
| `HTTPRoute`/`GRPCRoute` OxiBelt `ExtensionRef` | Experimental | Same-namespace v1alpha1 WAF group, body-limit, and timeout subset only. |
| `GRPCRoute` service/method/header matches | Partial | Exact service+method and service-only matches only. |
| `TLSRoute` passthrough | Partial | Requires `tls.mode = Passthrough`; emits `sni_forward` rules. |
| `TCPRoute` | Experimental | One rule, weighted core Service backends, deterministic listener winner, and explicit operator-owned port exposure. |
| `UDPRoute` | Experimental | Same bounded Service mapping plus required Redis-compatible or PostgreSQL logical flow affinity, fenced ownership, admission, and datagram limits. Disabled unless the controller is explicitly set to `shared_required`. |
| `BackendTLSPolicy` | Experimental/partial | Exact hostname/SNI, System or up to eight bounded ConfigMap CAs, and up to five enforced DNS/URI SANs; Secrets, mTLS, pins, and options are rejected. |

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
- `OxiBeltRoutePolicy`: reports accepted, resolved-reference, conflict, rollout,
  and proven artifact identity without publishing policy or body contents.
- `OxiBeltDataPlaneTarget`: reports assignment, source snapshot, artifact,
  apply, active, degraded, and rollback state independently for each target.
  Translation can succeed while one target remains unprogrammed.

`--dry-run` skips immutable artifact/workload mutations and Kubernetes status
mutations.

## Explain and Offline Evidence

The offline explain command accepts one manifest file or a symlink-free
directory and emits bounded JSON without contacting Kubernetes or mutating a
target:

```bash
oxibelt-gateway-controller explain \
  --input ./gateway-snapshot \
  --gateway default/edge \
  --route default/app \
  --format json
```

Every directory entry is checked independently for symlinks and file type.
Input is limited to 1,024 manifest files, a bounded post-open read of 16 MiB per
file, and 10,000 objects.
The controller canonicalizes object and JSON-map ordering before translation.
The explain document contains its alpha schema version, source snapshot digest,
path-bound artifact and content digests, source UID/resourceVersion/generation,
typed diagnostics, generated fragment identities, normalized backend weights,
effective route-policy values, operator-owned target assignments, validation
state, and the explicit `experimental-unqualified` marker. Blocking diagnostics
are evidence output rather than a reason to hide the explanation.

Secret objects, values, and value-derived digest material are excluded.
ConfigMap CA contents, generated TOML,
bearer tokens, credentials, private keys, request bodies, and rollout endpoints
are not present. An offline result has no active rollout receipt; live
`Programmed` status remains the authority for a committed generation. The
shareable source digest includes canonical desired spec, labels, annotations,
and public ConfigMap data digest while excluding API bookkeeping and status
written by other controllers. The internal rollout digest additionally binds
Secret data required by translation without publishing that digest in explain
output. Equivalent desired snapshots therefore keep the same semantic artifact
regardless of list/watch arrival order or status/resourceVersion churn.

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

### Static replicated data-plane targets

The first multi-target topology is an operator-owned, static replicated set for
one OxiBelt-managed `GatewayClass`. Configure up to 32 entries under Helm
`rollout.targets`; the chart creates a versioned
`OxiBeltDataPlaneTarget.gateway.oxibelt.dev/v1alpha1` resource and an exact-name
workload Role for each entry only after the operator installs the CRD from
`deploy/kubernetes/oxibelt-gateway-controller/crds/`. The Helm chart does not
own the CRD lifecycle. See
`deploy/helm/oxibelt-gateway-controller/examples/multi-target-values.yaml` for a
two-target example. When the array is empty, the legacy `rollout.target` CLI
and Helm configuration remains authoritative.

Each target restricts assignment to an explicit list of Gateway namespaces,
names one Deployment or DaemonSet, and declares a sorted bounded capability
set. Route authors attach through ordinary Gateway parent references; the
target schema has no route-authored target ID, raw Admin URL, credential, or
Secret field. The controller rejects unknown fields, duplicate workloads,
unowned GatewayClasses, more than one class in the v1alpha1 static set, more
than 32 targets, a managed Gateway with no allowed target assignment, and any
per-target concurrency other than one.

Target reconciliation is deterministic and sequential, giving v1alpha1 a
global concurrency bound of one. The generated artifact identity binds the
target resource identity, GatewayClass, policy version, sorted capabilities,
target rollout policy, and target-specific source snapshot digest. A full
target-context SHA-256 annotation is revalidated whenever an immutable artifact
is reused or loaded for rollback, so a capability or assignment-policy change
cannot adopt the prior context's ConfigMap. Workload annotations and immutable
ConfigMaps remain the durable per-target state, so restart recovery and
rollback can never substitute another target's committed revision. A failed
target becomes `Blocked` or `Degraded` without cancelling or patching another
target; each target snapshot retains only selected Gateways/routes and their
reference-reachable Services, ReferenceGrants, BackendTLSPolicies, and CA
ConfigMaps. Before status publication the controller re-reads the target set
and independently re-proves every successful target, then recomputes the
aggregate. Gateway and route `Programmed=True` requires that final active proof
for every target in the static replicated set.

The target status is bounded and contains digests, revision names, conditions,
and state only. It contains no generated TOML, request data, Admin endpoint,
token, or Secret material. The per-target Roles grant no Secret access and can
patch only the exact named workload. This initial mode is static replicated
placement, not dynamic load-aware sharding, active/standby failover, or
consistent-hash rebalancing.

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
