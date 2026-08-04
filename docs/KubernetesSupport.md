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

The graduation target is the three Kubernetes minors actively maintained when
policy version 1 was adopted: `1.34`, `1.35`, and `1.36`. The controller and
its `kubernetes_immutable` data plane must reject versions outside
`>=1.34.0-0 <1.37.0-0` with a clear diagnostic. This floor does not change the
separate runtime Kubernetes discovery or active-request-autoscaling contracts.

The test matrix uses Helm `3.21.3` and `4.2.3`. Each supported Kubernetes minor
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

Graduation requires native `linux/amd64`, `linux/arm64`, and `linux/riscv64`
Kubernetes evidence. QEMU user-mode image smoke is not native Kubernetes
qualification. RISC-V is therefore an explicit blocker until a native worker
exists.

The bounded networking contract is IPv4 single stack with the portable
NetworkPolicy behavior tested on both Calico and Cilium. It does not claim that
every CNI or a dual-stack/IPv6 cluster is qualified. Both charts must install
and operate in a namespace enforcing the `restricted` Pod Security Standard.
Operators still own the cluster admission chain, CNI configuration, external
DNS, load-balancing, storage, webhook availability, and certificate issuance.

The `edge-secure-medium` v2 deployment envelope targets this same Kubernetes
1.34–1.36 and Helm 3.21.3/4.2.3 range. CI verifies its exact digest-pinned
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
signed-bundle rotation with rollback. A successful run can emit a bounded
exact-revision receipt, but the registry deliberately leaves the
`live-supply-chain-admission` gate unmet until qualifying immutable receipts
are reviewed and recorded. That receipt does not claim NetworkPolicy CNI
enforcement or native-architecture qualification, and rendering or API-server
dry-run alone still does not establish live admission.

<!-- BEGIN KUBERNETES GRADUATION GENERATED -->

> Generated from `devops/config/kubernetes-feature-graduation.json` by
> `pnpm run kubernetes-graduation:render`. Do not edit this block directly.

### Graduation target Kubernetes matrix

| Kubernetes minor | CI representative | Immutable Kind node image |
| --- | --- | --- |
| `1.34` | `v1.34.8` | `kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256` |
| `1.35` | `v1.35.5` | `kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95` |
| `1.36` | `v1.36.1` | `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5` |

### Governed feature states

| Feature ID | State | Last validated version | Mandatory gates | Active blockers |
| --- | --- | --- | ---: | --- |
| `gateway-controller` | `experimental` | `unvalidated` | 16 | `previous-stable-role-topology`, `native-riscv64-cluster-runner` |
| `gateway-api-httproute` | `experimental` | `unvalidated` | 8 | `native-riscv64-cluster-runner` |
| `gateway-api-grpcroute` | `experimental` | `unvalidated` | 8 | `native-riscv64-cluster-runner` |
| `gateway-api-tlsroute` | `experimental` | `unvalidated` | 8 | `native-riscv64-cluster-runner` |
| `gateway-api-tcproute` | `experimental` | `unvalidated` | 8 | `native-riscv64-cluster-runner` |
| `gateway-api-udproute` | `experimental` | `unvalidated` | 8 | `native-riscv64-cluster-runner` |
| `gateway-api-backendtlspolicy` | `experimental` | `unvalidated` | 9 | `native-riscv64-cluster-runner` |
| `gateway-api-weighted-discovery` | `experimental` | `unvalidated` | 10 | `native-riscv64-cluster-runner` |
| `gateway-api-standard-filters-backend-tls` | `experimental` | `unvalidated` | 10 | `native-riscv64-cluster-runner` |
| `gateway-api-route-policy` | `experimental` | `unvalidated` | 8 | `native-riscv64-cluster-runner` |
| `gateway-controller-multi-target` | `experimental` | `unvalidated` | 16 | `previous-stable-role-topology`, `native-riscv64-cluster-runner` |
| `gateway-controller-explain` | `experimental` | `unvalidated` | 8 | `native-riscv64-cluster-runner` |
| `supply-chain-admission-bundle` | `experimental` | `unvalidated` | 3 | None |
| `helm-data-plane` | `experimental` | `unvalidated` | 16 | `previous-stable-role-topology`, `native-riscv64-cluster-runner` |
| `helm-gateway-controller` | `experimental` | `unvalidated` | 16 | `previous-stable-role-topology`, `native-riscv64-cluster-runner` |

### Mandatory graduation gates

| Gate ID | Earliest cadence | State | Applies to |
| --- | --- | --- | --- |
| `policy-contract` | `pull_request` | `unmet` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain`, `supply-chain-admission-bundle`, `helm-data-plane`, `helm-gateway-controller` |
| `unsupported-combination-diagnostics` | `pull_request` | `unmet` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain`, `supply-chain-admission-bundle`, `helm-data-plane`, `helm-gateway-controller` |
| `clean-lifecycle` | `release_candidate` | `unmet` | `gateway-controller`, `gateway-controller-multi-target`, `helm-data-plane`, `helm-gateway-controller` |
| `leader-election-failover` | `nightly` | `unmet` | `gateway-controller`, `gateway-controller-multi-target`, `helm-gateway-controller` |
| `api-outage-recovery` | `nightly` | `unmet` | `gateway-controller`, `gateway-controller-multi-target`, `helm-gateway-controller` |
| `watch-reconnect-compaction` | `pull_request` | `unmet` | `gateway-controller`, `gateway-api-weighted-discovery`, `gateway-api-route-policy`, `gateway-controller-multi-target` |
| `stale-object-convergence` | `nightly` | `unmet` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain` |
| `partial-rollout-recovery` | `pull_request` | `unmet` | `gateway-controller`, `gateway-controller-multi-target`, `gateway-controller-explain`, `helm-data-plane`, `helm-gateway-controller` |
| `network-partition` | `nightly` | `unmet` | `gateway-controller`, `gateway-controller-multi-target`, `helm-data-plane`, `helm-gateway-controller` |
| `configmap-propagation` | `nightly` | `unmet` | `gateway-controller`, `gateway-api-backendtlspolicy`, `gateway-api-standard-filters-backend-tls`, `gateway-controller-multi-target`, `helm-data-plane`, `helm-gateway-controller` |
| `secret-rotation` | `nightly` | `unmet` | `helm-data-plane` |
| `multi-node` | `nightly` | `unmet` | `gateway-controller`, `gateway-controller-multi-target`, `helm-data-plane`, `helm-gateway-controller` |
| `pod-security-restricted` | `pull_request` | `unmet` | `helm-data-plane`, `helm-gateway-controller` |
| `live-supply-chain-admission` | `pull_request` | `unmet` | `supply-chain-admission-bundle`, `helm-data-plane` |
| `network-policy-cnis` | `nightly` | `unmet` | `helm-data-plane`, `helm-gateway-controller` |
| `previous-minor-interop` | `release_candidate` | `unmet` | `gateway-controller`, `gateway-controller-multi-target`, `helm-data-plane`, `helm-gateway-controller` |
| `long-duration-soak` | `release_candidate` | `unmet` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain`, `helm-data-plane`, `helm-gateway-controller` |
| `native-amd64` | `release_candidate` | `unmet` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain`, `helm-data-plane`, `helm-gateway-controller` |
| `native-arm64` | `release_candidate` | `unmet` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain`, `helm-data-plane`, `helm-gateway-controller` |
| `native-riscv64` | `release_candidate` | `unmet` | `gateway-controller`, `gateway-api-httproute`, `gateway-api-grpcroute`, `gateway-api-tlsroute`, `gateway-api-tcproute`, `gateway-api-udproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls`, `gateway-api-route-policy`, `gateway-controller-multi-target`, `gateway-controller-explain`, `helm-data-plane`, `helm-gateway-controller` |
| `gateway-conformance-http` | `release_candidate` | `unmet` | `gateway-api-httproute`, `gateway-api-backendtlspolicy`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls` |
| `gateway-conformance-grpc` | `release_candidate` | `unmet` | `gateway-api-grpcroute`, `gateway-api-weighted-discovery`, `gateway-api-standard-filters-backend-tls` |
| `gateway-conformance-tls` | `release_candidate` | `unmet` | `gateway-api-tlsroute` |
| `gateway-conformance-tcp` | `release_candidate` | `unmet` | `gateway-api-tcproute` |
| `gateway-conformance-udp` | `release_candidate` | `unmet` | `gateway-api-udproute` |

<!-- END KUBERNETES GRADUATION GENERATED -->

Gate objectives are machine-readable in the registry. All applicable gates are
mandatory. A gate cannot be skipped, treated as not applicable, or replaced by
a narrower local test after it has been assigned to a feature.

## Evidence and promotion

The policy checker enforces JSON Schema shape, exact identifiers, reciprocal
feature-to-gate mappings, immutable Kubernetes inputs, generated-document
freshness, and agreement with `docs/FeatureStatus.md`. A feature cannot move to
`supported` while it has a blocker or any mandatory gate is `unmet`.

A passed gate must reference a bounded JSON evidence receipt under
`evidence/kubernetes-graduation/`. The receipt binds the policy-definition
SHA-256, policy version, exact 40-character source revision, GitHub run,
attempt and job IDs, generation time, exact validated product version, and
passed gate IDs. A feature's `lastValidatedVersion` can name a version only
after all of that feature's mandatory gates pass, and every referenced receipt
must name that same version. Workspace validation of any passed gate also
requires the caller to supply the independently derived release identity with
`--expected-version vMAJOR.MINOR.PATCH`; the receipt, feature row, and at least
one versioned Helm chart package must all match it. The ordinary pull-request
check intentionally supplies only `--expected-source-revision`, so a
registry-only promotion fails closed until a release/promotion workflow
provides the trusted version input. Release validation
must read back the exact run through an authenticated GitHub API call and
reject missing, failed, cancelled, skipped, duplicate, stale, or mismatched
evidence. Evidence must bind immutable image/chart digests and hashes of
reports and logs; it must not contain Secret values.

Feature promotion is per row. A promotion PR must:

1. change only the intended `experimental` row or rows after every assigned
   gate is `passed`;
2. remove every recorded blocker with reviewable evidence;
3. update the stable/beta feature-lifecycle and upgrade contract;
4. pass the required promotion workflow for the exact PR source revision; and
5. retain focused OxiBelt tests in addition to upstream conformance.

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
