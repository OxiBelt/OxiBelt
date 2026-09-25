#!/usr/bin/env bash
# Sourced by run-kubernetes-immutable-rollout.sh after its baseline checks.
# It deliberately reuses that Kind cluster and its controller/data-plane release.

gateway_identity_port_forward_pod=""
gateway_identity_protocol_probe_image=""

gateway_identity_certificate() {
  local name="$1"
  local ca_cert="$2"
  local ca_key="$3"
  local certificate="$4"
  local private_key="$5"
  local csr="${certificate}.csr"
  local extension="${certificate}.ext"

  openssl req -newkey rsa:2048 -sha256 -nodes \
    -subj "/CN=${name}" \
    -keyout "${private_key}" \
    -out "${csr}" >/dev/null 2>&1
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n' \
    >"${extension}"
  openssl x509 -req -sha256 -days 1 \
    -in "${csr}" \
    -CA "${ca_cert}" \
    -CAkey "${ca_key}" \
    -CAcreateserial \
    -extfile "${extension}" \
    -out "${certificate}" >/dev/null 2>&1
}

gateway_identity_sha256() {
  openssl x509 -in "$1" -outform DER | sha256sum | awk '{print $1}'
}

gateway_identity_derived_secret() {
  local derived
  derived="$(kube -n "${namespace}" get deployment "${workload_name}" -o json 2>/dev/null \
    | jq -r '
        [.. | objects | .secret? | objects | .secretName? // empty
          | select(test("^oxibelt-upstream-client-[a-f0-9]{32}$"))]
        | unique | if length == 1 then .[0] else empty end
      ')" || return 1
  [[ "${derived}" =~ ^oxibelt-upstream-client-[a-f0-9]{32}$ ]] || return 1
  printf '%s\n' "${derived}"
}

gateway_identity_start_port_forward() {
  local pod="$1"
  local port="$2"
  local log="${work_dir}/gateway-identity-port-forward.log"

  [[ -z "${port_forward_pid}" ]] || die "Gateway identity probe requires no active port forward"
  kubectl --context "kind-${cluster_name}" -n "${namespace}" port-forward \
    --address 127.0.0.1 "pod/${pod}" "${port}:8443" >"${log}" 2>&1 &
  port_forward_pid="$!"
  wait_for "Gateway identity HTTPS port-forward" 30 \
    grep -Fq "Forwarding from 127.0.0.1:${port} -> 8443" "${log}"
  gateway_identity_port_forward_pod="${pod}"
}

gateway_identity_stop_port_forward() {
  [[ -n "${port_forward_pid}" ]] || return 0
  kill "${port_forward_pid}" >/dev/null 2>&1 || true
  wait "${port_forward_pid}" >/dev/null 2>&1 || true
  port_forward_pid=""
  gateway_identity_port_forward_pod=""
}

gateway_identity_refresh_port_forward() {
  local port="$1"
  local revision="$2"
  local pod

  gateway_identity_stop_port_forward
  pod="$(kube -n "${namespace}" get pods -l "${selector}" -o json \
    | jq -r --arg revision "${revision}" '
        .items
        | map(select(
            .metadata.deletionTimestamp == null
            and .metadata.annotations["oxibelt.dev/config-revision"] == $revision
            and any(.status.conditions[]?; .type == "Ready" and .status == "True")
          ))
        | .[0].metadata.name // empty
      ')"
  [[ -n "${pod}" ]] || return 1
  gateway_identity_start_port_forward "${pod}" "${port}"
}

gateway_identity_request() {
  local port="$1"
  shift
  curl --silent --show-error --max-time 10 --tlsv1.3 \
    --resolve "verified-client.example.test:${port}:127.0.0.1" \
    --cacert "${work_dir}/tls.crt" \
    --cert "${work_dir}/frontend-client.crt" \
    --key "${work_dir}/frontend-client.key" \
    --header 'Client-Cert: forged-by-downstream-client' \
    "$@" \
    "https://verified-client.example.test:${port}/identity"
}

gateway_identity_request_is_503() {
  local port="$1"
  local status
  status="$(gateway_identity_request "${port}" -o /dev/null -w '%{http_code}' 2>/dev/null)" || return 1
  [[ "${status}" == "503" ]]
}

gateway_identity_route_forwards() {
  local port="$1"
  local expected_header="$2"
  local response
  response="$(gateway_identity_request "${port}")" || return 1
  jq -e --arg expected "${expected_header}" '
      .headers["client-cert"] == $expected
      and .headers["client_cert"] == null
    ' >/dev/null <<<"${response}"
}

gateway_identity_requires_downstream_client() {
  local port="$1"
  local curl_log="${work_dir}/gateway-identity-no-client.log"

  # A completed HTTP exchange, even a 4xx/5xx, crosses the mTLS boundary.
  if curl --silent --show-error --max-time 10 --tlsv1.3 \
    --resolve "verified-client.example.test:${port}:127.0.0.1" \
    --cacert "${work_dir}/tls.crt" \
    "https://verified-client.example.test:${port}/identity" \
    >/dev/null 2>"${curl_log}"; then
    return 1
  fi

  # Curl must identify the TLS certificate-required alert. This excludes a
  # dead port-forward, DNS failure, or an unrelated transport error.
  grep -Eiq 'alert.*certificate required|certificate required' "${curl_log}"
}

gateway_identity_tls_handshake_failure_count() {
  local pod="$1"
  local count
  local logs

  logs="$(kube -n "${namespace}" logs "pod/${pod}" -c oxibelt 2>/dev/null)" || return 1
  count="$(grep -Fc 'TLS handshake failed' <<<"${logs}" || true)"
  [[ "${count}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${count}"
}

gateway_identity_tls_rejection_observed() {
  local pod="$1"
  local before="$2"
  local after

  after="$(gateway_identity_tls_handshake_failure_count "${pod}")" || return 1
  ((10#${after} > 10#${before}))
}

gateway_identity_backend_ready() {
  kube -n "${namespace}" rollout status deployment/gateway-identity-backend --timeout=5s \
    >/dev/null 2>&1
}

gateway_identity_set_backend_fingerprint() {
  local fingerprint="$1"
  local patch

  [[ "${fingerprint}" =~ ^[a-f0-9]{64}$ ]] || return 1
  patch="$(jq -cn --arg fingerprint "${fingerprint}" '
    {
      spec: {
        template: {
          spec: {
            containers: [{
              name: "probe",
              args: [
                "h2-upstream",
                "--listen", "0.0.0.0:18443",
                "--cert", "/tls/server.pem",
                "--key", "/tls/server.key",
                "--name", "gateway-identity-upstream",
                "--client-ca", "/tls/client-ca.pem",
                "--expect-client-cert-sha256", $fingerprint
              ]
            }]
          }
        }
      }
    }
  ')" || return 1
  kube -n "${namespace}" patch deployment/gateway-identity-backend \
    --type=strategic --patch "${patch}" >/dev/null
}

verify_gateway_verified_client_identity() {
  local frontend_header
  local denied_revision
  local first_derived_secret
  local first_revision
  local gateway_port
  local pre_phase_revision
  local revoked_revision
  local second_revision
  local second_derived_secret
  local tls_failures_before

  # This phase is intentionally after verify_cross_namespace_l4_reference_grants:
  # it needs the harness's proven cluster-wide controller scope and must not
  # change the baseline RBAC assertions made before that transition.
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj '/CN=OxiBelt Gateway upstream server CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "${work_dir}/gateway-upstream-ca.key" \
    -out "${work_dir}/gateway-upstream-ca.pem" >/dev/null 2>&1
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj '/CN=OxiBelt Gateway upstream client CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "${work_dir}/gateway-upstream-client-ca.key" \
    -out "${work_dir}/gateway-upstream-client-ca.pem" >/dev/null 2>&1

  gateway_identity_certificate frontend-client \
    "${work_dir}/downstream-client-ca.pem" "${work_dir}/downstream-client-ca.key" \
    "${work_dir}/frontend-client.crt" "${work_dir}/frontend-client.key"
  gateway_identity_certificate orders-client-v1 \
    "${work_dir}/gateway-upstream-client-ca.pem" "${work_dir}/gateway-upstream-client-ca.key" \
    "${work_dir}/orders-client-v1.crt" "${work_dir}/orders-client-v1.key"
  gateway_identity_certificate orders-client-v2 \
    "${work_dir}/gateway-upstream-client-ca.pem" "${work_dir}/gateway-upstream-client-ca.key" \
    "${work_dir}/orders-client-v2.crt" "${work_dir}/orders-client-v2.key"

  openssl req -newkey rsa:2048 -sha256 -nodes \
    -subj '/CN=gateway-identity-backend' \
    -keyout "${work_dir}/gateway-backend.key" \
    -out "${work_dir}/gateway-backend.csr" >/dev/null 2>&1
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:gateway-identity-backend.%s.svc.cluster.local\n' \
    "${namespace}" >"${work_dir}/gateway-backend.ext"
  openssl x509 -req -sha256 -days 1 \
    -in "${work_dir}/gateway-backend.csr" \
    -CA "${work_dir}/gateway-upstream-ca.pem" \
    -CAkey "${work_dir}/gateway-upstream-ca.key" \
    -CAcreateserial \
    -extfile "${work_dir}/gateway-backend.ext" \
    -out "${work_dir}/gateway-backend.crt" >/dev/null 2>&1

  frontend_header=":$(openssl x509 -in "${work_dir}/frontend-client.crt" -outform DER | base64 -w 0):"
  [[ "$(gateway_identity_sha256 "${work_dir}/orders-client-v1.crt")" =~ ^[a-f0-9]{64}$ ]] \
    || die "Gateway identity v1 fingerprint must be a SHA-256 hex digest"

  kube -n "${outside_namespace}" create secret tls orders-client \
    --cert "${work_dir}/orders-client-v1.crt" \
    --key "${work_dir}/orders-client-v1.key" >/dev/null
  kube -n "${namespace}" create secret generic gateway-identity-backend-tls \
    --from-file=server.pem="${work_dir}/gateway-backend.crt" \
    --from-file=server.key="${work_dir}/gateway-backend.key" \
    --from-file=client-ca.pem="${work_dir}/gateway-upstream-client-ca.pem" >/dev/null
  kube -n "${namespace}" create configmap gateway-identity-backend-ca \
    --from-file=ca.crt="${work_dir}/gateway-upstream-ca.pem" >/dev/null

  if [[ -n "${OXIBELT_PROTOCOL_PROBE_IMAGE:-}" || "${OXIBELT_REQUIRE_PRELOADED_HELPER_IMAGES:-0}" == "1" ]]; then
    gateway_identity_protocol_probe_image="${OXIBELT_PROTOCOL_PROBE_IMAGE:-oxibelt/protocol-probe:ci}"
    docker image inspect "${gateway_identity_protocol_probe_image}" >/dev/null \
      || die "Gateway identity requires preloaded protocol-probe image: ${gateway_identity_protocol_probe_image}"
  else
    gateway_identity_protocol_probe_image="oxibelt/gateway-identity-protocol-probe:${run_id}"
    docker build --tag "${gateway_identity_protocol_probe_image}" \
      --file "${repo_root}/tests/docker/protocol_probe/Dockerfile" \
      "${repo_root}" >/dev/null
    gateway_identity_protocol_probe_image_created=1
  fi
  kind load docker-image --name "${cluster_name}" "${gateway_identity_protocol_probe_image}"

  kube -n "${namespace}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata:
  name: gateway-identity-backend
spec:
  selector: {app: gateway-identity-backend}
  ports:
  - {name: https, port: 18443, targetPort: 18443}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gateway-identity-backend
spec:
  replicas: 1
  selector: {matchLabels: {app: gateway-identity-backend}}
  template:
    metadata: {labels: {app: gateway-identity-backend}}
    spec:
      automountServiceAccountToken: false
      containers:
      - name: probe
        image: ${gateway_identity_protocol_probe_image}
        imagePullPolicy: Never
        args:
        - h2-upstream
        - --listen
        - 0.0.0.0:18443
        - --cert
        - /tls/server.pem
        - --key
        - /tls/server.key
        - --name
        - gateway-identity-upstream
        - --client-ca
        - /tls/client-ca.pem
        - --expect-client-cert-sha256
        - "$(gateway_identity_sha256 "${work_dir}/orders-client-v1.crt")"
        ports: [{containerPort: 18443, name: https}]
        volumeMounts: [{name: tls, mountPath: /tls, readOnly: true}]
      volumes:
      - name: tls
        secret: {secretName: gateway-identity-backend-tls}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge-identity
spec:
  gatewayClassName: oxibelt
  tls:
    backend:
      clientCertificateRef:
        group: ""
        kind: Secret
        name: orders-client
        namespace: ${outside_namespace}
  listeners:
  - name: https
    protocol: HTTPS
    port: 443
    hostname: verified-client.example.test
    tls:
      mode: Terminate
      certificateRefs:
      - {group: "", kind: Secret, name: oxibelt-tls}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: verified-client
spec:
  parentRefs: [{name: edge-identity, sectionName: https}]
  hostnames: [verified-client.example.test]
  rules:
  - matches: [{path: {type: PathPrefix, value: /identity}}]
    filters:
    - type: ExtensionRef
      extensionRef: {group: gateway.oxibelt.dev, kind: OxiBeltRoutePolicy, name: verified-client}
    backendRefs: [{name: gateway-identity-backend, port: 18443}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata:
  name: verified-client-backend
spec:
  targetRefs: [{group: "", kind: Service, name: gateway-identity-backend}]
  validation:
    hostname: gateway-identity-backend.${namespace}.svc.cluster.local
    caCertificateRefs: [{group: "", kind: ConfigMap, name: gateway-identity-backend-ca}]
---
apiVersion: gateway.oxibelt.dev/v1alpha1
kind: OxiBeltRoutePolicy
metadata:
  name: verified-client
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: verified-client}
  clientCertificateForwarding: {header: client-cert, format: rfc9440}
EOF
  wait_for "Gateway identity backend" 120 gateway_identity_backend_ready

  # Allow only this source Secret and header after all preexisting narrow RBAC
  # assertions. The Source Role remains exact-name get/watch, never list.
  pre_phase_revision="$(kube -n "${namespace}" get deployment "${workload_name}" \
    -o jsonpath='{.metadata.annotations.oxibelt\.dev/gateway-config-committed}')"
  [[ "${pre_phase_revision}" =~ ^oxibelt-gateway-config-deployment-oxibelt-[a-f0-9]{64}$ ]] \
    || die "Gateway identity pre-phase state did not expose a committed immutable revision"
  helm upgrade "${controller_release}" "${repo_root}/deploy/helm/oxibelt-gateway-controller" \
    --namespace "${namespace}" --reuse-values \
    --set-string 'routePolicy.allowedClientCertificateForwardHeaders[0]=client-cert' \
    --set-string "upstreamClientTls.sourceSecretAllowlist[0].namespace=${outside_namespace}" \
    --set-string 'upstreamClientTls.sourceSecretAllowlist[0].name=orders-client' \
    --set-string 'upstreamClientTls.sourceSecretAllowlist[0].certificateKey=tls.crt' \
    --set-string 'upstreamClientTls.sourceSecretAllowlist[0].privateKeyKey=tls.key' \
    --wait --timeout "${rollout_timeout_seconds}s"
  assert_controller_can_i yes get "secrets/orders-client" --namespace "${outside_namespace}"
  assert_controller_can_i yes watch "secrets/orders-client" --namespace "${outside_namespace}"
  assert_controller_can_i no list secrets --namespace "${outside_namespace}"

  wait_for "Gateway identity denied immutable revision" "${rollout_timeout_seconds}" \
    deployment_committed_revision_changed "${pre_phase_revision}"
  denied_revision="$(kube -n "${namespace}" get deployment "${workload_name}" \
    -o jsonpath='{.metadata.annotations.oxibelt\.dev/gateway-config-committed}')"
  [[ "${denied_revision}" =~ ^oxibelt-gateway-config-deployment-oxibelt-[a-f0-9]{64}$ ]] \
    || die "Gateway identity denial did not commit an immutable revision"
  gateway_port="$((31000 + RANDOM % 1000))"
  wait_for "Gateway identity denied Pod for its committed revision" "${rollout_timeout_seconds}" \
    gateway_identity_refresh_port_forward "${gateway_port}" "${denied_revision}"
  wait_for "Gateway identity ReferenceGrant denial" "${rollout_timeout_seconds}" \
    gateway_identity_request_is_503 "${gateway_port}"

  kube -n "${outside_namespace}" apply -f - >/dev/null <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: ReferenceGrant
metadata:
  name: allow-edge-identity-client-secret
spec:
  from:
  - {group: gateway.networking.k8s.io, kind: Gateway, namespace: ${namespace}}
  to:
  - {group: "", kind: Secret, name: orders-client}
EOF
  wait_for "Gateway identity derived Secret projection" "${rollout_timeout_seconds}" \
    gateway_identity_derived_secret
  wait_for "Gateway identity authorized immutable revision" "${rollout_timeout_seconds}" \
    deployment_committed_revision_changed "${denied_revision}"
  first_derived_secret="$(gateway_identity_derived_secret)"
  first_revision="$(kube -n "${namespace}" get deployment "${workload_name}" \
    -o jsonpath='{.metadata.annotations.oxibelt\.dev/gateway-config-committed}')"
  kube -n "${namespace}" get secret "${first_derived_secret}" >/dev/null
  wait_for "Gateway identity authorized Pod for its committed revision" "${rollout_timeout_seconds}" \
    gateway_identity_refresh_port_forward "${gateway_port}" "${first_revision}"
  wait_for "Gateway verified identity forwarding and upstream mTLS" "${rollout_timeout_seconds}" \
    gateway_identity_route_forwards "${gateway_port}" "${frontend_header}"
  tls_failures_before="$(gateway_identity_tls_handshake_failure_count "${gateway_identity_port_forward_pod}")" \
    || die "could not read Gateway identity probe Pod TLS failures: ${gateway_identity_port_forward_pod}"
  gateway_identity_requires_downstream_client "${gateway_port}" \
    || die "Gateway public TLS listener accepted a request without its required client certificate"
  wait_for "Gateway public TLS certificate-required rejection" 30 \
    gateway_identity_tls_rejection_observed "${gateway_identity_port_forward_pod}" "${tls_failures_before}"

  gateway_identity_set_backend_fingerprint "$(gateway_identity_sha256 "${work_dir}/orders-client-v2.crt")" \
    || die "could not set the Gateway identity backend v2 client-certificate fingerprint"
  kube -n "${namespace}" rollout status deployment/gateway-identity-backend --timeout=120s
  kube -n "${outside_namespace}" create secret tls orders-client \
    --cert "${work_dir}/orders-client-v2.crt" \
    --key "${work_dir}/orders-client-v2.key" \
    --dry-run=client -o yaml | kube -n "${outside_namespace}" apply -f - >/dev/null
  wait_for "Gateway client identity rotation revision" "${rollout_timeout_seconds}" \
    deployment_committed_revision_changed "${first_revision}"
  wait_for "rotated Gateway derived Secret" "${rollout_timeout_seconds}" \
    gateway_identity_derived_secret
  second_derived_secret="$(gateway_identity_derived_secret)"
  [[ "${second_derived_secret}" != "${first_derived_secret}" ]] \
    || die "Gateway client identity rotation reused the prior derived Secret"
  kube -n "${namespace}" get secret "${second_derived_secret}" >/dev/null
  second_revision="$(kube -n "${namespace}" get deployment "${workload_name}" \
    -o jsonpath='{.metadata.annotations.oxibelt\.dev/gateway-config-committed}')"
  wait_for "Gateway identity rotated Pod for its committed revision" "${rollout_timeout_seconds}" \
    gateway_identity_refresh_port_forward "${gateway_port}" "${second_revision}"
  wait_for "rotated upstream identity with unchanged downstream Client-Cert" "${rollout_timeout_seconds}" \
    gateway_identity_route_forwards "${gateway_port}" "${frontend_header}"

  kube -n "${outside_namespace}" delete referencegrant allow-edge-identity-client-secret >/dev/null
  wait_for "Gateway identity revoked immutable revision" "${rollout_timeout_seconds}" \
    deployment_committed_revision_changed "${second_revision}"
  revoked_revision="$(kube -n "${namespace}" get deployment "${workload_name}" \
    -o jsonpath='{.metadata.annotations.oxibelt\.dev/gateway-config-committed}')"
  wait_for "Gateway identity revoked Pod for its committed revision" "${rollout_timeout_seconds}" \
    gateway_identity_refresh_port_forward "${gateway_port}" "${revoked_revision}"
  wait_for "Gateway identity grant revocation fail-closed route" "${rollout_timeout_seconds}" \
    gateway_identity_request_is_503 "${gateway_port}"
  gateway_identity_stop_port_forward
}
