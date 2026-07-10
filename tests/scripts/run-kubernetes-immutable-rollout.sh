#!/usr/bin/env bash
# Exercise the Kubernetes-native immutable Gateway API rollout using only a
# short-lived Kind cluster. It uses the normal `docker` CLI through Kind and
# removes only the uniquely named cluster it created.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

gateway_api_version="v1.3.0"
gateway_api_url="https://github.com/kubernetes-sigs/gateway-api/releases/download/${gateway_api_version}/experimental-install.yaml"
gateway_api_sha256="3e7a27e4456ff3d68606a6a8516306aaff354d6f0950b32bb31930669b7bf8b8"
# `kind create --image` accepts an OCI image reference. Keep the known v1.31.4
# tag for operator readability but pin its multi-platform manifest list.
kind_node_image="kindest/node:v1.31.4@sha256:2cb39f7295fe7eafee0842b1052a599a4fb0f8bcf3f83d96c7f4864c357c6c30"
rollout_timeout_seconds="${OXIBELT_KUBERNETES_ROLLOUT_TIMEOUT_SECONDS:-420}"

run_id=""
cluster_name=""
namespace=""
work_dir=""

data_release="oxibelt-data"
controller_release="oxibelt-gateway-controller"
workload_name="oxibelt"
selector="app.kubernetes.io/name=oxibelt,app.kubernetes.io/instance=${data_release}"
managed_config_path="conf.d/gateway-api.generated.toml"
port_forward_pid=""
cluster_created=0
admin_server_name=""
admin_service_name="${workload_name}-admin"

die() {
  echo "kubernetes immutable rollout test: $*" >&2
  exit 1
}

require_command() {
  local command="$1"
  command -v "${command}" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
}

kube() {
  kubectl --context "kind-${cluster_name}" "$@"
}

cleanup() {
  local status="$?"
  set +e

  if [[ -n "${port_forward_pid}" ]]; then
    kill "${port_forward_pid}" >/dev/null 2>&1 || true
    wait "${port_forward_pid}" >/dev/null 2>&1 || true
  fi

  if ((status != 0 && cluster_created == 1)); then
    echo "Kubernetes immutable rollout diagnostics for ${cluster_name}/${namespace}:" >&2
    kube -n "${namespace}" get deployments,replicasets,pods --ignore-not-found >&2 || true
    kube -n "${namespace}" get events --sort-by=.metadata.creationTimestamp >&2 || true
  fi

  if ((cluster_created == 1)); then
    # The Kind cluster is named from this invocation only. Do not run broad
    # Docker or Kubernetes cleanup commands here.
    kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
  fi

  case "${work_dir}" in
    "${repo_root}"/tests/.tmp/kubernetes-immutable-rollout-*)
      rm -rf "${work_dir}"
      ;;
    *)
      echo "refusing to remove unexpected test work directory: ${work_dir}" >&2
      ;;
  esac

  exit "${status}"
}
trap cleanup EXIT

wait_for() {
  local description="$1"
  local timeout_seconds="$2"
  shift 2
  local deadline=$((SECONDS + timeout_seconds))

  until "$@"; do
    if ((SECONDS >= deadline)); then
      die "timed out waiting for ${description}"
    fi
    sleep 1
  done
}

deployment_is_committed() {
  local deployment
  deployment="$(kube -n "${namespace}" get deployment "${workload_name}" -o json 2>/dev/null)" || return 1
  jq -e \
    '.metadata.annotations["oxibelt.dev/gateway-config-phase"] == "Committed"
      and (.metadata.annotations["oxibelt.dev/gateway-config-desired"] | type == "string" and length > 0)
      and (.metadata.annotations["oxibelt.dev/gateway-config-committed"]
        == .metadata.annotations["oxibelt.dev/gateway-config-desired"])' \
    >/dev/null <<<"${deployment}"
}

gateway_is_programmed() {
  local gateway
  gateway="$(kube -n "${namespace}" get gateway edge -o json 2>/dev/null)" || return 1
  jq -e \
    'any(.status.conditions[]?; .type == "Programmed" and .status == "True")' \
    >/dev/null <<<"${gateway}"
}

health_endpoint_is_ready() {
  local url="$1"
  curl --fail --silent --show-error --max-time 2 "${url}/ready" >/dev/null 2>&1
}

admin_endpoint_accepts_client() {
  local port="$1"
  curl --fail --silent --show-error --max-time 5 --tlsv1.3 \
    --resolve "${admin_server_name}:${port}:127.0.0.1" \
    --cacert "${work_dir}/admin-server-ca.crt" \
    --cert "${work_dir}/admin-client.crt" \
    --key "${work_dir}/admin-client.key" \
    --header "@${work_dir}/admin-headers.txt" \
    "https://${admin_server_name}:${port}/admin/v1/openapi.json" \
    >/dev/null
}

verify_admin_mtls() {
  local port="$1"
  local url="https://${admin_server_name}:${port}/admin/v1/openapi.json"

  kubectl --context "kind-${cluster_name}" -n "${namespace}" port-forward \
    --address 127.0.0.1 "service/${admin_service_name}" "${port}:9092" \
    >"${work_dir}/admin-port-forward.log" 2>&1 &
  port_forward_pid="$!"

  wait_for "mTLS Admin response" 60 admin_endpoint_accepts_client "${port}"

  if curl --fail --silent --show-error --max-time 5 --tlsv1.3 \
    --resolve "${admin_server_name}:${port}:127.0.0.1" \
    --cacert "${work_dir}/admin-server-ca.crt" \
    --header "@${work_dir}/admin-headers.txt" \
    "${url}" \
    >/dev/null 2>&1; then
    die "Admin listener accepted a bearer-authenticated client without a certificate"
  fi

  admin_endpoint_accepts_client "${port}" \
    || die "Admin listener rejected the configured mTLS client and bearer token"

  kill "${port_forward_pid}" >/dev/null 2>&1 || true
  wait "${port_forward_pid}" >/dev/null 2>&1 || true
  port_forward_pid=""
}

check_pod_runtime_proof() {
  local pod="$1"
  local port="$2"
  local revision="$3"
  local digest="$4"
  local url="http://127.0.0.1:${port}"
  local headers

  kubectl --context "kind-${cluster_name}" -n "${namespace}" port-forward \
    --address 127.0.0.1 "pod/${pod}" "${port}:9091" \
    >"${work_dir}/port-forward-${pod}.log" 2>&1 &
  port_forward_pid="$!"

  wait_for "ready health response from ${pod}" 60 health_endpoint_is_ready "${url}"
  headers="$(curl --fail --silent --show-error --max-time 5 --dump-header - --output /dev/null "${url}/ready")"
  headers="${headers//$'\r'/}"
  grep -Fxi "x-oxibelt-config-revision: ${revision}" <<<"${headers}" >/dev/null \
    || die "${pod} did not prove the assigned config revision through health headers"
  grep -Fxi "x-oxibelt-config-digest: ${digest}" <<<"${headers}" >/dev/null \
    || die "${pod} did not prove the assigned raw config digest through health headers"

  kill "${port_forward_pid}" >/dev/null 2>&1 || true
  wait "${port_forward_pid}" >/dev/null 2>&1 || true
  port_forward_pid=""
}

for command in docker kind kubectl helm curl jq openssl sha256sum tr; do
  require_command "${command}"
done

if ! [[ "${rollout_timeout_seconds}" =~ ^[1-9][0-9][0-9]?$ ]] \
  || ((10#${rollout_timeout_seconds} < 60 || 10#${rollout_timeout_seconds} > 900)); then
  die "OXIBELT_KUBERNETES_ROLLOUT_TIMEOUT_SECONDS must be a decimal value from 60 through 900"
fi

# CI event values are untrusted input. Reduce them to a fixed-length lower-case
# hexadecimal identifier before using one in any Kubernetes name or filesystem
# path that cleanup touches.
run_seed="${GITHUB_RUN_ID:-local}:${GITHUB_RUN_ATTEMPT:-1}:$$:${RANDOM}"
run_id="$(printf '%s' "${run_seed}" | sha256sum)"
run_id="${run_id%% *}"
run_id="${run_id:0:24}"
[[ "${run_id}" =~ ^[a-f0-9]{24}$ ]] || die "failed to derive a safe test run identifier"
cluster_name="oxibelt-rollout-${run_id}"
namespace="oxibelt-rollout-${run_id}"
work_dir="${repo_root}/tests/.tmp/kubernetes-immutable-rollout-${run_id}"
admin_server_name="${admin_service_name}.${namespace}.svc"

[[ -n "${OXIBELT_DOCKER_IMAGE:-}" ]] \
  || die "OXIBELT_DOCKER_IMAGE must name the locally loaded OxiBelt image"
image="${OXIBELT_DOCKER_IMAGE}"
[[ "${image}" =~ ^[a-z0-9][a-z0-9._-]*(:[0-9]{1,5})?(/[a-z0-9][a-z0-9._-]*)*:[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || die "OXIBELT_DOCKER_IMAGE must be a lower-case local repository:tag without Helm metacharacters"
image_repository="${image%:*}"
image_tag="${image##*:}"
[[ -n "${image_repository}" && -n "${image_tag}" ]] \
  || die "OXIBELT_DOCKER_IMAGE must include non-empty repository and tag"

# This verifies the configured Docker endpoint before Kind delegates image and
# cluster lifecycle operations to the normal `docker` command.
docker version --format '{{.Server.Version}}' >/dev/null
docker image inspect "${image}" >/dev/null

if kind get clusters | grep -Fqx "${cluster_name}"; then
  die "refusing to reuse an existing Kind cluster named ${cluster_name}"
fi

mkdir -p "${work_dir}"
gateway_api_manifest="${work_dir}/gateway-api-${gateway_api_version}.yaml"
image_values="${work_dir}/image-values.yaml"
printf 'image:\n  repository: "%s"\n  tag: "%s"\n  pullPolicy: "IfNotPresent"\n' \
  "${image_repository}" "${image_tag}" >"${image_values}"

cluster_created=1
kind create cluster \
  --name "${cluster_name}" \
  --image "${kind_node_image}" \
  --wait 120s

kind load docker-image --name "${cluster_name}" "${image}"

curl --fail --location --retry 3 --retry-delay 2 --retry-all-errors \
  --silent --show-error \
  --output "${gateway_api_manifest}" \
  "${gateway_api_url}"
printf '%s  %s\n' "${gateway_api_sha256}" "${gateway_api_manifest}" | sha256sum --check --status
kube apply --server-side --force-conflicts -f "${gateway_api_manifest}" >/dev/null
kube wait --for=condition=Established --timeout=120s \
  crd/gatewayclasses.gateway.networking.k8s.io \
  crd/gateways.gateway.networking.k8s.io \
  crd/httproutes.gateway.networking.k8s.io \
  crd/grpcroutes.gateway.networking.k8s.io \
  crd/tlsroutes.gateway.networking.k8s.io \
  crd/referencegrants.gateway.networking.k8s.io

kube create namespace "${namespace}" >/dev/null
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=oxibelt-rollout.test' \
  -addext 'subjectAltName=DNS:oxibelt-rollout.test' \
  -keyout "${work_dir}/tls.key" \
  -out "${work_dir}/tls.crt" \
  >/dev/null 2>&1
kube -n "${namespace}" create secret tls oxibelt-tls \
  --cert "${work_dir}/tls.crt" \
  --key "${work_dir}/tls.key" \
  >/dev/null

# Keep all credentials inside this invocation's guarded temporary directory.
# The data-plane image receives only the corresponding Kubernetes Secrets; the
# test never reads Secret data back from the API.
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=OxiBelt test Admin server CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "${work_dir}/admin-server-ca.key" \
  -out "${work_dir}/admin-server-ca.crt" \
  >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=${admin_server_name}" \
  -keyout "${work_dir}/admin-server.key" \
  -out "${work_dir}/admin-server.csr" \
  >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' \
  "${admin_server_name}" >"${work_dir}/admin-server.ext"
openssl x509 -req -sha256 -days 1 \
  -in "${work_dir}/admin-server.csr" \
  -CA "${work_dir}/admin-server-ca.crt" \
  -CAkey "${work_dir}/admin-server-ca.key" \
  -CAcreateserial \
  -extfile "${work_dir}/admin-server.ext" \
  -out "${work_dir}/admin-server.crt" \
  >/dev/null 2>&1

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=OxiBelt test Admin client CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "${work_dir}/admin-client-ca.key" \
  -out "${work_dir}/admin-client-ca.crt" \
  >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -subj '/CN=OxiBelt test Admin client' \
  -keyout "${work_dir}/admin-client.key" \
  -out "${work_dir}/admin-client.csr" \
  >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' \
  >"${work_dir}/admin-client.ext"
openssl x509 -req -sha256 -days 1 \
  -in "${work_dir}/admin-client.csr" \
  -CA "${work_dir}/admin-client-ca.crt" \
  -CAkey "${work_dir}/admin-client-ca.key" \
  -CAcreateserial \
  -extfile "${work_dir}/admin-client.ext" \
  -out "${work_dir}/admin-client.crt" \
  >/dev/null 2>&1
openssl rand -hex 32 >"${work_dir}/admin-token"
{
  printf 'Authorization: Bearer '
  tr -d '\r\n' <"${work_dir}/admin-token"
  printf '\n'
} >"${work_dir}/admin-headers.txt"

kube -n "${namespace}" create secret generic oxibelt-admin-server \
  --from-file=tls.crt="${work_dir}/admin-server.crt" \
  --from-file=tls.key="${work_dir}/admin-server.key" \
  >/dev/null
kube -n "${namespace}" create secret generic oxibelt-admin-client-ca \
  --from-file=ca.crt="${work_dir}/admin-client-ca.crt" \
  >/dev/null
kube -n "${namespace}" create secret generic oxibelt-admin-token \
  --from-file=token="${work_dir}/admin-token" \
  >/dev/null

kube -n "${namespace}" apply -f - >/dev/null <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: backend
spec:
  ports:
  - name: http
    port: 8080
    targetPort: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: http
    protocol: HTTP
    port: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: backend
spec:
  parentRefs:
  - name: edge
    sectionName: http
  hostnames:
  - app.example.test
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
    backendRefs:
    - name: backend
      port: 8080
EOF

helm upgrade --install "${data_release}" "${repo_root}/deploy/helm/oxibelt" \
  --namespace "${namespace}" \
  -f "${image_values}" \
  -f "${repo_root}/deploy/helm/oxibelt/examples/admin-mtls-values.yaml" \
  --set "replicaCount=3" \
  --set "service.type=ClusterIP" \
  --set-string "admin.tls.serverNames[0]=${admin_server_name}" \
  --set-string "configRollout.mode=kubernetes_immutable" \
  --set-string "configRollout.managedConfigPath=${managed_config_path}"

helm upgrade --install "${controller_release}" "${repo_root}/deploy/helm/oxibelt-gateway-controller" \
  --namespace "${namespace}" \
  -f "${image_values}" \
  --set-string "managedConfigPath=${managed_config_path}" \
  --set-string "watchNamespace=${namespace}" \
  --set-string "rollout.target.namespace=${namespace}" \
  --set-string "rollout.target.kind=deployment" \
  --set-string "rollout.target.name=${workload_name}" \
  --set-string "rollout.target.containerName=oxibelt" \
  --set-string "rollout.volumeName=gateway-config" \
  --set "rollout.timeoutSeconds=300" \
  --set-string "rollout.configMapPrefix=oxibelt-gateway-config" \
  --wait \
  --timeout "${rollout_timeout_seconds}s"

kube -n "${namespace}" rollout status "deployment/${workload_name}" \
  --timeout "${rollout_timeout_seconds}s"
wait_for "committed immutable workload state" "${rollout_timeout_seconds}" deployment_is_committed
wait_for "Gateway Programmed=True after full rollout convergence" "${rollout_timeout_seconds}" gateway_is_programmed

deployment_json="$(kube -n "${namespace}" get deployment "${workload_name}" -o json)"
revision="$(jq -r '.spec.template.metadata.annotations["oxibelt.dev/config-revision"] // empty' <<<"${deployment_json}")"
digest="$(jq -r '.spec.template.metadata.annotations["oxibelt.dev/config-digest"] // empty' <<<"${deployment_json}")"
[[ "${revision}" =~ ^oxibelt-gateway-config-deployment-oxibelt-[a-f0-9]{64}$ ]] \
  || die "workload did not receive a deterministic immutable ConfigMap revision"
[[ "${digest}" =~ ^[a-f0-9]{64}$ ]] \
  || die "workload did not receive a lower-case raw SHA-256 config digest"

admin_service_json="$(kube -n "${namespace}" get service "${admin_service_name}" -o json)"
jq -e '
  .spec.type == "ClusterIP"
    and (.spec.ports | length) == 1
    and .spec.ports[0].name == "admin"
    and .spec.ports[0].targetPort == "admin"
' >/dev/null <<<"${admin_service_json}" \
  || die "Admin Service must stay ClusterIP and target only the Admin container port"

jq -e '
  any(.spec.template.spec.containers[]?;
    .name == "oxibelt"
      and any(.volumeMounts[]?;
        .name == "tls"
          and .mountPath == "/etc/oxibelt/cert"
          and .readOnly == true))
  and any(.spec.template.spec.volumes[]?;
    .name == "tls"
      and .projected.defaultMode == 288
      and any(.projected.sources[]?;
        .secret.name == "oxibelt-admin-server"
          and any(.secret.items[]?;
            .key == "tls.crt" and .path == "admin-server/tls.crt")
          and any(.secret.items[]?;
            .key == "tls.key" and .path == "admin-server/tls.key"))
      and any(.projected.sources[]?;
        .secret.name == "oxibelt-admin-client-ca"
          and any(.secret.items[]?;
            .key == "ca.crt" and .path == "admin-client-ca/ca.crt")))
' >/dev/null <<<"${deployment_json}" \
  || die "Admin identity and client-CA Secrets must be read-only projected certificate files"

jq -e --arg revision "${revision}" --arg managed_path "${managed_config_path}" '
  any(.spec.template.spec.volumes[]?;
    .name == "gateway-config" and .configMap.name == $revision and .configMap.items == [
      {"key": "gateway-api.generated.toml", "path": $managed_path}
    ])
  and any(.spec.template.spec.containers[]?;
    .name == "oxibelt" and any(.volumeMounts[]?;
      .name == "gateway-config" and .mountPath == ("/etc/oxibelt/config/" + $managed_path) and .readOnly == true))
' >/dev/null <<<"${deployment_json}" \
  || die "workload does not mount exactly the controller-owned immutable config file"

config_map_json="$(kube -n "${namespace}" get configmap "${revision}" -o json)"
jq -e --arg revision "${revision}" --arg digest "${digest}" --arg managed_path "${managed_config_path}" '
  .metadata.name == $revision
    and .immutable == true
    and .metadata.labels["app.kubernetes.io/managed-by"] == "oxibelt-gateway-controller"
    and .metadata.labels["oxibelt.dev/rollout-target"] == "oxibelt"
    and .metadata.labels["oxibelt.dev/rollout-target-kind"] == "deployment"
    and .metadata.annotations["oxibelt.dev/config-digest"] == $digest
    and .metadata.annotations["oxibelt.dev/gateway-config-managed-path"] == $managed_path
    and (.data["gateway-api.generated.toml"] | type == "string" and length > 0)
' >/dev/null <<<"${config_map_json}" \
  || die "controller-owned ConfigMap did not satisfy its immutable identity contract"

kube -n "${namespace}" get configmap "${revision}" \
  -o jsonpath='{.data.gateway-api\.generated\.toml}' >"${work_dir}/gateway-api.generated.toml"
actual_digest="$(sha256sum "${work_dir}/gateway-api.generated.toml" | awk '{print $1}')"
[[ "${actual_digest}" == "${digest}" ]] \
  || die "ConfigMap raw bytes do not match the Pod-assigned digest"

pods_json="$(kube -n "${namespace}" get pods -l "${selector}" -o json)"
jq -e --arg revision "${revision}" --arg digest "${digest}" '
  [.items[] | select(.metadata.deletionTimestamp == null)] as $pods
  | ($pods | length) == 3
  and all($pods[];
    ((.status.conditions // []) | any(.type == "Ready" and .status == "True"))
    and .metadata.annotations["oxibelt.dev/config-revision"] == $revision
    and .metadata.annotations["oxibelt.dev/config-digest"] == $digest)
' >/dev/null <<<"${pods_json}" \
  || die "all three Ready Pods must carry the exact assigned revision and digest"

mapfile -t pods < <(jq -r '
  .items
  | map(select(.metadata.deletionTimestamp == null))
  | sort_by(.metadata.name)
  | .[].metadata.name
' <<<"${pods_json}")
[[ "${#pods[@]}" == "3" ]] || die "expected exactly three non-terminating data-plane Pods"
for index in "${!pods[@]}"; do
  check_pod_runtime_proof "${pods[${index}]}" "$((21000 + RANDOM % 10000 + index))" "${revision}" "${digest}"
done
verify_admin_mtls "$((25000 + RANDOM % 10000))"

echo "Kubernetes immutable three-replica rollout passed"
