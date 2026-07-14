# OxiBelt Image Admission Policy

These assets configure Sigstore Policy Controller to admit an official OxiBelt
image only when its immutable digest has both:

- a valid keyless Cosign signature issued by the GitHub Actions OIDC issuer for
  `OxiBelt/OxiBelt`'s release workflows; and
- a signed SLSA provenance v1 attestation whose GitHub-hosted builder, source
  repository, release workflow, tag ref, and 40-character source commit satisfy
  the minimum SLSA Build Level 2 policy.

The policy matches only `ghcr.io/oxibelt/oxibelt@sha256:*`. The controller is
configured with `failurePolicy: Fail` and `no-match-policy: deny`, and policy
enforcement is enabled only in namespaces labeled
`policy.sigstore.dev/include=true`. A labeled namespace therefore needs a
matching policy for every image it runs, including sidecars and init
containers.

## Install

Use Kubernetes 1.27 or later, Helm, and `kubectl`. First render and verify the
checked-in policy and the exact upstream chart digests:

```sh
tests/scripts/check-image-admission-policy.sh
```

Install the two pinned charts and the two OxiBelt policies. The expected OCI
chart digests are checked by the command above and recorded in that script.

```sh
helm upgrade --install policy-controller \
  oci://ghcr.io/sigstore/helm-charts/policy-controller \
  --version 0.10.6 \
  --namespace artifact-attestations \
  --create-namespace \
  --atomic --wait \
  --values deploy/admission/sigstore/policy-controller-values.yaml

helm upgrade --install trust-policies \
  oci://ghcr.io/github/artifact-attestations-helm-charts/trust-policies \
  --version v0.7.0 \
  --namespace artifact-attestations \
  --atomic --wait \
  --values deploy/admission/sigstore/trust-policies-values.yaml

kubectl apply \
  -f deploy/admission/sigstore/oxibelt-signature-policy.yaml \
  -f deploy/admission/sigstore/oxibelt-provenance-policy.yaml
```

Review every workload in a namespace before opting it in, then enable
enforcement:

```sh
kubectl label namespace oxibelt policy.sigstore.dev/include=true
```

Deploy by digest. `image.digest` takes precedence over `image.tag` in both
OxiBelt Helm charts:

```yaml
image:
  repository: ghcr.io/oxibelt/oxibelt
  digest: sha256:FULL_64_CHARACTER_LOWERCASE_DIGEST
```

The policy validates identity and provenance, not image freshness. Operators
remain responsible for selecting an approved release digest and preventing
rollback to an older, correctly signed release. Vulnerability admission is an
optional independent policy and is not enabled by these assets.

## Test

The release gate runs the static renderer and a rootless Docker-backed
Minikube proof against the just-produced index digest. The proof must admit
that signed digest and reject a historical unsigned OxiBelt digest before
mutable index aliases can be promoted.

To reproduce it with an already signed release:

```sh
tests/scripts/run-image-admission-policy.sh \
  --trusted-image ghcr.io/oxibelt/oxibelt@sha256:FULL_64_CHARACTER_LOWERCASE_DIGEST
```

Before the first P2-4 release exists, the rejection half can be exercised on
its own with `--reject-only`. Release CI never uses that option; alias
promotion always requires both acceptance of the current digest and rejection
of the unsigned fixture.

The live test refuses to run as root unless the `docker` client reports a
rootless daemon. It creates a unique Minikube profile and removes it on exit.
