# Kubernetes Support and Feature Graduation

Status: Experimental graduation contract

This document defines the compatibility target, evidence, and review rules for
OxiBelt's Kubernetes Gateway controller and Helm features. The canonical
[feature lifecycle matrix](FeatureStatus.md) remains authoritative for the
public lifecycle state. The machine-readable
[`kubernetes-feature-graduation.json`](../devops/config/kubernetes-feature-graduation.json)
registry is authoritative for the compatibility matrix, mandatory gates,
cadence, and current blockers.

Every governed feature is currently `experimental`. The matrix below is the
target that a promotion candidate must prove; it is not a supported-production
claim. Helm rendering, API-server dry-run, one successful installation, or a
happy-path route test cannot by itself promote a feature.

## Compatibility target

### Kubernetes and Helm

The current graduation target is Kubernetes minors `1.34`, `1.35`, `1.36`,
and `1.37`. The controller and
its `kubernetes_immutable` data plane must reject versions outside
`>=1.34.0-0 <1.38.0-0` with a clear diagnostic. This floor does not change the
separate runtime Kubernetes discovery or active-request-autoscaling contracts.

The test matrix uses Helm `3.21.4` and `4.2.4`. Each supported Kubernetes minor
must pass end-to-end tests under both Helm lines at release-candidate cadence.
The exact Kind images are reviewable registry inputs rather than workflow-local
defaults. Updating the active-minor window, patch representatives, Kind
digests, or Helm versions requires a policy PR and fresh evidence; dropping an
end-of-life minor is not automatic.

### Gateway API and CRDs

The target is Gateway API `v1.6.1`, standard channel, with the pinned
`standard-install.yaml` SHA-256 in the registry and required resources served
as `v1`. Gateway API CRDs are operator-owned:

- OxiBelt charts do not install, convert, downgrade, or delete them.
- Install or upgrade the pinned standard CRD bundle and wait for it to become
  established before upgrading the controller.
- Upgrade the controller before its selected data plane. Roll back the data
  plane before the controller.
- Uninstalling OxiBelt retains Gateway API CRDs and unrelated Gateway API
  objects.
- A missing required `v1` API resource is an incompatibility, not an empty
  object list. Mixed channels, unverified bundles, and unsupported conversion
  histories are not qualifying combinations.

Runtime and `oxibeltctl doctor --kubernetes` discovery verify the required
served resources without adding CRD read permission to the controller. The
operator must separately verify the exact installed CRD-bundle identity and
conversion history.

### Controller and data-plane skew

`exact` is the default and normal operating mode. The controller's effective
version must equal the value in the selected workload's
`spec.template.metadata.annotations["oxibelt.dev/effective-version"]`.
Controller health/support metadata, rendered workload annotations, and
operator diagnostics expose the comparison without exposing credentials.

The bounded `rolling_upgrade` mode is only a transition:

1. Set `--compatibility-mode rolling_upgrade`,
   `--compatibility-previous-version` to the one explicitly approved version
   from the immediately preceding OxiBelt minor, and
   `--compatibility-deadline` to an RFC3339 timestamp no more than 24 hours in
   the future.
2. Upgrade the controller, then the data plane.
3. Restore `--compatibility-mode exact` after every selected Pod reports the
   target effective version.

For rollback, keep the bounded mode active, roll back the data plane before the
controller, and restore `exact` after convergence. Missing annotations, a
newer data plane, an unlisted or non-adjacent previous version, a malformed
deadline, or an expired transition fails controller readiness and prevents
reconciliation.

### Architectures, networking, and Pod Security

Except for `supply-chain-admission-bundle`, graduation of the governed
controller, Gateway API, and Helm rows requires native `linux/amd64`,
`linux/arm64`, and `linux/riscv64` Kubernetes evidence. QEMU user-mode image
smoke is not native Kubernetes qualification. RISC-V therefore remains an
explicit blocker for those fourteen rows until a native worker exists. The
supply-chain admission row targets only native `linux/amd64` and
`linux/arm64`; that target is not a RISC-V support claim.

The bounded networking contract is IPv4 single stack with the portable
NetworkPolicy behavior tested on both Calico and Cilium. It does not claim that
every CNI or a dual-stack/IPv6 cluster is qualified. Both charts must install
and operate in a namespace enforcing the `restricted` Pod Security Standard.
Operators still own the cluster admission chain, CNI configuration, external
DNS, load-balancing, storage, webhook availability, and certificate issuance.

The `edge-secure-medium` v2 deployment envelope targets this same Kubernetes
1.34–1.37 and Helm 3.21.4/4.2.4 range. CI verifies its exact digest-pinned
strict-image render and server-side dry-run under restricted Pod Security
labels, while the shared strict-data-plane harness supplies live
RuntimeDefault/Landlock evidence. The dedicated supply-chain admission harness
installs the complete v2 values contract on exactly three Ready nodes. It
renders webhook ingress from exact `/32` IPv4 or `/128` IPv6 API-server source
prefixes and uses short-lived webhook TLS plus the build-validated strict
data-plane and tools image artifacts. Local runs default to an isolated
rootless Minikube profile; the mandatory CI floor runs on the immutable
Kubernetes 1.34 Kind image.

The live matrix admits every exact signed regular, init, native-sidecar, and
ephemeral class/name/digest identity; rejects missing, unlisted, replayed, or
drifted identities; proves bad-CA and unavailable-endpoint failures remain
closed; and verifies that unrelated ConfigMaps and `pods/status` are not
intercepted. It also exercises overlapping webhook-CA rotation and staged
signed-bundle rotation with rollback. A successful run can emit bounded
feature-scoped exact-revision evidence, but the immutable gate descriptor does
not store mutable pass/fail state. Promotion requires a complete detached
receipt for every assigned gate and both intended platforms. Rendering or
API-server dry-run alone still does not establish live admission.

<!-- BEGIN KUBERNETES GRADUATION GENERATED -->

> Generated from `devops/config/kubernetes-feature-graduation.json` by
> `pnpm run kubernetes-graduation:render`. Do not edit this block directly.

### Graduation target Kubernetes matrix

| Kubernetes minor | CI representative | Immutable Kind node image |
| --- | --- | --- |
| `1.34` | `v1.34.11` | `kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d` |
| `1.35` | `v1.35.8` | `kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0` |
| `1.36` | `v1.36.4` | `kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed` |
| `1.37` | `v1.37.0` | `kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5` |

### Governed feature states

| Feature ID | State | Last validated version | Qualification platforms | Required artifacts | Mandatory gates | Active blockers |
| --- | --- | --- | --- | --- | ---: | --- |
| `gateway-controller` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 16 | `previous-stable-role-topology`, `native-riscv64-cluster-runner` |
| `gateway-api-httproute` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 8 | `native-riscv64-cluster-runner` |
| `gateway-api-grpcroute` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 8 | `native-riscv64-cluster-runner` |
| `gateway-api-tlsroute` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 8 | `native-riscv64-cluster-runner` |
| `gateway-api-tcproute` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 8 | `native-riscv64-cluster-runner` |
| `gateway-api-udproute` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 8 | `native-riscv64-cluster-runner` |
| `gateway-api-backendtlspolicy` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 9 | `native-riscv64-cluster-runner` |
| `gateway-api-weighted-discovery` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 10 | `native-riscv64-cluster-runner` |
| `gateway-api-standard-filters-backend-tls` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 10 | `native-riscv64-cluster-runner` |
| `gateway-api-route-policy` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 8 | `native-riscv64-cluster-runner` |
| `gateway-controller-multi-target` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 16 | `previous-stable-role-topology`, `native-riscv64-cluster-runner` |
| `gateway-controller-explain` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 8 | `native-riscv64-cluster-runner` |
| `supply-chain-admission-bundle` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64` | `image-standalone`, `image-dataplane`, `image-dataplane-strict`, `image-controller`, `image-tools`, `image-keysigner`, `chart-oxibelt`, `chart-gateway-controller` | 3 | None |
| `helm-data-plane` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 16 | `previous-stable-role-topology`, `native-riscv64-cluster-runner` |
| `helm-gateway-controller` | `experimental` | `unvalidated` | `linux/amd64`, `linux/arm64`, `linux/riscv64` | None | 16 | `previous-stable-role-topology`, `native-riscv64-cluster-runner` |

### Mandatory graduation gates

| Gate ID | Earliest cadence | Applies to |
| --- | --- | --- |
| `policy-contract` | `pull_request` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain`, `supply-chain-admission-bundle`, `helm-data-plane`, `helm-gateway-controller` |
| `unsupported-combination-diagnostics` | `pull_request` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain`, `supply-chain-admission-bundle`, `helm-data-plane`, `helm-gateway-controller` |
| `clean-lifecycle` | `release_candidate` | `gateway-controller`, `gateway-controller-multi-target`, `helm-data-plane`, `helm-gateway-controller` |
| `leader-election-failover` | `nightly` | `gateway-controller`, `gateway-controller-multi-target`, `helm-gateway-controller` |
| `api-outage-recovery` | `nightly` | `gateway-controller`, `gateway-controller-multi-target`, `helm-gateway-controller` |
| `watch-reconnect-compaction` | `pull_request` | `gateway-controller`, `gateway-api-weighted-discovery`, `gateway-api-route-policy`, `gateway-controller-multi-target` |
| `stale-object-convergence` | `nightly` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain` |
| `partial-rollout-recovery` | `pull_request` | `gateway-controller`, `gateway-controller-multi-target`, `gateway-controller-explain`, `helm-data-plane`, `helm-gateway-controller` |
| `network-partition` | `nightly` | `gateway-controller`, `gateway-controller-multi-target`, `helm-data-plane`, `helm-gateway-controller` |
| `configmap-propagation` | `nightly` | `gateway-controller`, `gateway-api-backendtlspolicy`, `gateway-api-standard-filters-backend-tls`, `gateway-controller-multi-target`, `helm-data-plane`, `helm-gateway-controller` |
| `secret-rotation` | `nightly` | `helm-data-plane` |
| `multi-node` | `nightly` | `gateway-controller`, `gateway-controller-multi-target`, `helm-data-plane`, `helm-gateway-controller` |
| `pod-security-restricted` | `pull_request` | `helm-data-plane`, `helm-gateway-controller` |
| `live-supply-chain-admission` | `pull_request` | `supply-chain-admission-bundle`, `helm-data-plane` |
| `network-policy-cnis` | `nightly` | `helm-data-plane`, `helm-gateway-controller` |
| `previous-minor-interop` | `release_candidate` | `gateway-controller`, `gateway-controller-multi-target`, `helm-data-plane`, `helm-gateway-controller` |
| `long-duration-soak` | `release_candidate` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain`, `helm-data-plane`, `helm-gateway-controller` |
| `native-amd64` | `release_candidate` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain`, `helm-data-plane`, `helm-gateway-controller` |
| `native-arm64` | `release_candidate` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain`, `helm-data-plane`, `helm-gateway-controller` |
| `native-riscv64` | `release_candidate` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain`, `helm-data-plane`, `helm-gateway-controller` |
| `gateway-conformance-http` | `release_candidate` | `gateway-api-httproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls` |
| `gateway-conformance-grpc` | `release_candidate` | `gateway-api-grpcroute`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls` |
| `gateway-conformance-tls` | `release_candidate` | `gateway-api-tlsroute` |
| `gateway-conformance-tcp` | `release_candidate` | `gateway-api-tcproute` |
| `gateway-conformance-udp` | `release_candidate` | `gateway-api-udproute` |

<!-- END KUBERNETES GRADUATION GENERATED -->

Gate objectives are machine-readable in the registry. All applicable gates are
mandatory. A gate cannot be skipped, treated as not applicable, or replaced by
a narrower local test after it has been assigned to a feature.

## Evidence and promotion

The policy checker enforces JSON Schema shape, exact identifiers, reciprocal
feature-to-gate mappings, immutable Kubernetes inputs, generated-document
freshness, intended qualification platforms, and agreement with
`docs/FeatureStatus.md`. Gate rows are immutable requirements, not mutable
pass/fail claims shared between features. A supported feature must bind target
version `0.8.1` and retain no blocker.

Qualification evidence is detached from the registry and scoped to one exact
feature. `pnpm run kubernetes-graduation:verify` accepts only a bounded
non-symlink evidence directory and the checked-in policy and schemas. It
requires exactly one canonical receipt for every supported Kubernetes row and
rejects missing receipts, duplicate rows, and evidence for experimental rows.
Each receipt binds the feature, intended `supported` state, policy hash and
version, exact repository/ref/SHA, candidate or official-beta phase,
qualification platforms, successful workflow run/attempt/jobs, tool versions,
immutable artifact subjects where applicable, report and log hashes, every
assigned gate, and final `pass`. Each gate contains an exact platform-result
set: one distinct successful job plus its exact hashed report for each
qualified platform. Missing platforms and reused platform jobs fail closed.

The `supply-chain-admission-bundle` row additionally binds an exact artifact
inventory in the hashed registry. Candidate and official-beta receipts must
contain precisely the six official image repositories—`oxibelt`,
`oxibelt-dataplane`, `oxibelt-dataplane-strict`,
`oxibelt-gateway-controller`, `oxibelt-tools`, and `oxibelt-keysigner`—and the
two official OCI chart repositories, `charts/oxibelt` and
`charts/oxibelt-gateway-controller`, all below `ghcr.io/oxibelt` and referenced
as the exact registry repository plus `@sha256` digest. Missing, renamed,
additional, differently typed, or substituted subjects fail verification.
For every other row, the current registry records no required artifact
subjects, so its receipt must contain an empty artifact list; arbitrary image
or chart placeholders are not accepted. Adding any future subject requires an
explicit policy change and therefore changes the policy hash.

Candidate receipts require `refs/heads/main`; official-beta receipts require an
exact `refs/tags/0.8.1-beta.N` ref. The verifier resolves the supplied ref and
the checked-out `HEAD` to the supplied full SHA before reading evidence. These
local checks establish receipt structure and repository binding; the
qualification workflow must separately authenticate the run, jobs, signer,
attestations, and immutable subjects through read-only GitHub API and
attestation readback. Missing, failed, cancelled, skipped, duplicate, stale,
mutable, or mismatched evidence blocks promotion. Receipts must not contain
Secret values.

Feature promotion is per row and follows an exact-revision sequence:

1. Land the candidate lifecycle change, blocker resolution, release ledgers,
   and retained focused OxiBelt tests on `main`.
2. Manually qualify the exact unchanged pushed `main` SHA and read back its
   workflow jobs, attestations, receipt subjects, source ref, and source SHA.
3. Rerun canonical non-benchmark CI at that same SHA without a tracked change.
4. Cut and person-review the beta, then run the `official_beta` phase against
   the exact beta tag and official image and chart digests.
5. Consider a row qualified only after both exact-main and official-beta
   evidence, every assigned gate, and all independent readbacks succeed.

A local check, pull-request run, candidate receipt without authenticated
readback, or source promotion alone is not qualification evidence. All rows in
the current registry remain `experimental` and `unvalidated`.

If a mandatory guarantee regresses or evidence proves invalid, restore
`experimental` in the next safe change and block publication. Documentation
or status metadata must never continue claiming `supported` while policy
admission fails.

## Test cadence

- Pull requests validate registry/schema/docs drift, both Helm lines, chart
  admission, the Kubernetes floor full E2E path, ceiling smoke, restricted Pod
  Security, fail-closed diagnostics, watch compaction, and rejected/partial
  rollout recovery.
- Nightly runs cover every Kubernetes minor, both Helm lines, Calico and
  Cilium, multi-node behavior, leader and API failure, network partition,
  object convergence, ConfigMap/Secret propagation, and a one-hour soak.
- Release candidates run every mandatory gate, every Kubernetes/Helm pair,
  version-specific upstream conformance without skipped/exempted core tests,
  native architecture lanes, released or release-equivalent previous-minor
  upgrade/rollback, and an eight-hour correctness soak.
- Stable release validation consumes and independently verifies the exact
  release-candidate receipt. It does not rebuild, substitute a mutable tag, or
  manufacture missing evidence.

All cluster work uses rootless `docker`, unique labels and names, bounded
timeouts, and exact cleanup. These are correctness and security gates, not
performance benchmarks; they do not require `docker-rootful`.
