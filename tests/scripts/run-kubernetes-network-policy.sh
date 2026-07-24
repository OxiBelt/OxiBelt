#!/usr/bin/env bash
# Prove the Helm NetworkPolicy contract on a CNI that enforces policy. This
# creates one uniquely named Minikube profile and only test-labelled Docker
# containers; cleanup never prunes shared Docker or Kubernetes resources.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/oxibelt"
admin_values="${chart_dir}/examples/admin-mtls-values.yaml"
temp_root="${TMPDIR:-/tmp}"
work_dir=""
profile_name=""
external_allowed_container=""
external_denied_container=""
external_allowed_ip=""
external_denied_ip=""

# Kubernetes publishes agnhost 2.52. The multi-architecture manifest
# digest keeps the fixture portable while remaining immutable.
agnhost_image="registry.k8s.io/e2e-test-images/agnhost:2.52@sha256:b173c7d0ffe3d805d49f4dfe48375169b7b8d2e1feb81783efd61eb9d08042e6"
curl_image="quay.io/cilium/alpine-curl:v1.10.0@sha256:913e8c9f3d960dde03882defa0edd3a919d529c2eb167caa7f54194528bde364"
coredns_image="registry.k8s.io/coredns/coredns:v1.14.6@sha256:900f9c109f7a33545d3c811516e8376df9019147b750f5ce3e254468769176ea"

die() {
  echo "Kubernetes NetworkPolicy check: $*" >&2
  exit 1
}

require_command() {
  local command="$1"
  command -v "${command}" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
}

kubectl_cmd() {
  kubectl --kubeconfig "${KUBECONFIG}" "$@"
}

is_ipv4_address() {
  local address="$1"
  local octet
  local -a octets

  [[ "${address}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<<"${address}"
  for octet in "${octets[@]}"; do
    (( 10#${octet} <= 255 )) || return 1
  done
}

docker_network_ipv4() {
  local network="$1"
  local container="$2"

  docker network inspect "${network}" \
    --format '{{range .Containers}}{{println .Name .IPv4Address}}{{end}}' |
    awk -v expected_container="${container}" '
      $1 == expected_container {
        sub(/\/.*/, "", $2)
        print $2
        exit
      }
    '
}

wait_for_distinct_docker_network_ipv4s() {
  local network="$1"
  local allowed_container="$2"
  local denied_container="$3"
  local allowed_ip
  local denied_ip
  local attempt

  for attempt in {1..10}; do
    allowed_ip="$(docker_network_ipv4 "${network}" "${allowed_container}" 2>/dev/null || true)"
    denied_ip="$(docker_network_ipv4 "${network}" "${denied_container}" 2>/dev/null || true)"
    if is_ipv4_address "${allowed_ip}" \
      && is_ipv4_address "${denied_ip}" \
      && [[ "${allowed_ip}" != "${denied_ip}" ]]; then
      external_allowed_ip="${allowed_ip}"
      external_denied_ip="${denied_ip}"
      return 0
    fi
    sleep 1
  done

  die "Cilium FQDN fixtures did not receive distinct IPv4 addresses on Minikube Docker network"
}

diagnose() {
  set +e
  echo "--- Kubernetes NetworkPolicy diagnostics ---" >&2
  kubectl_cmd get pods --all-namespaces -o wide >&2
  kubectl_cmd get networkpolicy --all-namespaces >&2
  kubectl_cmd get ciliumnetworkpolicy --all-namespaces >&2
  kubectl_cmd get events --all-namespaces --sort-by=.lastTimestamp >&2
  if [[ "${cni}" == "calico" ]]; then
    kubectl_cmd -n kube-system logs -l k8s-app=calico-node --all-containers=true --tail=120 >&2
  else
    kubectl_cmd -n kube-system logs -l k8s-app=cilium --all-containers=true --tail=120 >&2
  fi
}

cleanup() {
  local status="$?"
  set +e

  if [[ "${status}" -ne 0 && -n "${profile_name}" ]]; then
    diagnose
  fi

  if [[ -n "${external_allowed_container}" ]]; then
    docker rm --force "${external_allowed_container}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${external_denied_container}" ]]; then
    docker rm --force "${external_denied_container}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${profile_name}" ]]; then
    minikube delete --profile "${profile_name}" >/dev/null 2>&1 || true
  fi

  case "${work_dir}" in
    "${temp_root%/}"/oxibelt-kubernetes-network-policy.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected Kubernetes NetworkPolicy work directory: ${work_dir}" >&2
      ;;
  esac

  exit "${status}"
}
trap cleanup EXIT

expect_allowed() {
  local description="$1"
  shift
  local attempt

  for attempt in 1 2 3 4 5 6; do
    if "$@"; then
      return 0
    fi
    sleep 2
  done

  die "${description} remained unavailable after policy propagation"
}

expect_denied() {
  local description="$1"
  shift
  local attempt

  # Require consecutive drops so a transient start-up failure is not treated as
  # policy enforcement. A later positive control proves the destination lives.
  for attempt in 1 2 3; do
    if "$@"; then
      die "${description} unexpectedly succeeded"
    fi
    sleep 1
  done
}

wait_for_policy_denial() {
  local description="$1"
  shift
  local attempt
  local consecutive_denials=0

  # CNI policy application is asynchronous. Tolerate initial successful probes,
  # but accept convergence only after three consecutive denials so a transient
  # destination failure cannot satisfy the policy assertion.
  for attempt in {1..12}; do
    if "$@"; then
      consecutive_denials=0
    else
      consecutive_denials="$((consecutive_denials + 1))"
      if ((consecutive_denials == 3)); then
        return 0
      fi
    fi
    sleep 1
  done

  die "${description} remained reachable after policy propagation"
}

wait_for_pod() {
  local namespace="$1"
  local name="$2"
  kubectl_cmd -n "${namespace}" wait --for=condition=Ready "pod/${name}" --timeout="${timeout_seconds}s"
}

run_client_curl() {
  local namespace="$1"
  local pod="$2"
  local url="$3"
  kubectl_cmd -n "${namespace}" exec "${pod}" -c client -- \
    curl --fail --silent --show-error --connect-timeout 2 --max-time 6 "${url}" >/dev/null
}

run_udp_dial() {
  local namespace="$1"
  local pod="$2"
  local host="$3"
  local port="$4"
  kubectl_cmd -n "${namespace}" exec "${pod}" -c client -- \
    curl --fail --silent --show-error --connect-timeout 2 --max-time 6 \
    "http://127.0.0.1:18080/dial?host=${host}&port=${port}&protocol=udp&request=hostname" >/dev/null
}

create_client_pod() {
  local namespace="$1"
  local name="$2"
  local label_key="$3"
  local label_value="$4"
  local with_udp_dialer="$5"
  local dns_server="$6"

  kubectl_cmd -n "${namespace}" apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  labels:
    ${label_key}: ${label_value}
spec:
  restartPolicy: Never
$(if [[ -n "${dns_server}" ]]; then cat <<DNS
  dnsPolicy: None
  dnsConfig:
    nameservers:
    - ${dns_server}
    searches:
    - ${data_namespace}.svc.cluster.local
    - svc.cluster.local
    - cluster.local
    options:
    - name: ndots
      value: "1"
DNS
fi)
  containers:
  - name: client
    image: ${curl_image}
    command: ["/bin/sh", "-c", "sleep 3600"]
$(if [[ "${with_udp_dialer}" == "true" ]]; then cat <<DIALER
  - name: udp-dialer
    image: ${agnhost_image}
    command: ["/agnhost", "netexec", "--http-port=18080", "--udp-port=-1"]
DIALER
fi)
EOF
  wait_for_pod "${namespace}" "${name}"
}

if [[ "$#" -ne 2 || "$1" != "--cni" ]]; then
  die "usage: $0 --cni <calico|cilium>"
fi
cni="$2"
case "${cni}" in
  calico|cilium)
    ;;
  *)
    die "CNI must be calico or cilium"
    ;;
esac

timeout_seconds="${OXIBELT_NETWORK_POLICY_TIMEOUT_SECONDS:-420}"
if ! [[ "${timeout_seconds}" =~ ^[0-9]+$ ]] \
  || (( timeout_seconds < 120 || timeout_seconds > 900 )); then
  die "OXIBELT_NETWORK_POLICY_TIMEOUT_SECONDS must be a decimal value from 120 through 900"
fi

for command in docker helm kubectl minikube mktemp grep awk tail; do
  require_command "${command}"
done
[[ -f "${chart_dir}/Chart.yaml" ]] || die "chart is unavailable: ${chart_dir}"
[[ -f "${admin_values}" ]] || die "Admin values are unavailable: ${admin_values}"

# The devcontainer invokes tests as UID 0 while exposing a host-rootless Docker
# daemon. Minikube rejects the Docker driver solely because of that client UID.
# Permit its compatibility flag only after the selected daemon positively
# identifies as rootless; never fall back to a rootful daemon for this check.
minikube_root_compatibility=()
if [[ "${EUID}" -eq 0 ]]; then
  docker info --format '{{json .SecurityOptions}}' | grep -Fq '"name=rootless"' \
    || die "refusing Minikube Docker-driver test as root unless Docker reports rootless mode"
  minikube_root_compatibility=(--force)
fi

work_dir="$(mktemp -d "${temp_root%/}/oxibelt-kubernetes-network-policy.XXXXXX")"
export MINIKUBE_HOME="${work_dir}/minikube-home"
export KUBECONFIG="${work_dir}/kubeconfig"
mkdir -p "${MINIKUBE_HOME}"

run_id="${RANDOM}${RANDOM}"
profile_name="oxibelt-np-${run_id}"
data_namespace="oxibelt-np-data-${run_id}"
public_namespace="oxibelt-np-public-${run_id}"
monitoring_namespace="oxibelt-np-monitor-${run_id}"
management_namespace="oxibelt-np-management-${run_id}"
controller_namespace="oxibelt-np-controller-${run_id}"
backend_namespace="oxibelt-np-backend-${run_id}"
arbitrary_namespace="oxibelt-np-arbitrary-${run_id}"
dns_namespace="oxibelt-np-dns-${run_id}"

minikube_start_log="${work_dir}/minikube-start.log"
if ! minikube start \
  --profile "${profile_name}" \
  --driver=docker \
  --container-runtime=containerd \
  --cni="${cni}" \
  --kubernetes-version=v1.34.8 \
  --output=json \
  --wait=all \
  --wait-timeout="${timeout_seconds}s" \
  "${minikube_root_compatibility[@]}" >"${minikube_start_log}" 2>&1; then
  tail -n 160 "${minikube_start_log}" >&2 || true
  die "Minikube did not start with the requested ${cni} CNI"
fi

kubectl_cmd wait --for=condition=Ready node --all --timeout="${timeout_seconds}s"
if [[ "${cni}" == "calico" ]]; then
  kubectl_cmd -n kube-system wait --for=condition=Ready pod -l k8s-app=calico-node --timeout="${timeout_seconds}s"
else
  kubectl_cmd -n kube-system wait --for=condition=Ready pod -l k8s-app=cilium --timeout="${timeout_seconds}s"
  kubectl_cmd get crd ciliumnetworkpolicies.cilium.io >/dev/null
fi

for namespace in \
  "${data_namespace}" \
  "${public_namespace}" \
  "${monitoring_namespace}" \
  "${management_namespace}" \
  "${controller_namespace}" \
  "${backend_namespace}" \
  "${arbitrary_namespace}"; do
  kubectl_cmd create namespace "${namespace}"
done

if [[ "${cni}" == "cilium" ]]; then
  cilium_enabled=true
  dns_policy_namespace="${dns_namespace}"
  dns_policy_label_key="app"
  dns_policy_label_value="oxibelt-policy-dns"
else
  cilium_enabled=false
  dns_policy_namespace="kube-system"
  dns_policy_label_key="k8s-app"
  dns_policy_label_value="kube-dns"
fi

if [[ "${cni}" == "cilium" ]]; then
  kubectl_cmd create namespace "${dns_namespace}"
  minikube_network="$(docker inspect "${profile_name}" --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' | awk 'NF { print; exit }')"
  [[ -n "${minikube_network}" ]] || die "could not determine the Minikube Docker network"

  external_allowed_container="${profile_name}-allowed"
  external_denied_container="${profile_name}-denied"
  # agnhost has an exec-form /agnhost entrypoint, so Docker appends only the
  # netexec subcommand here. The Kubernetes fixture below uses command because
  # that field replaces an image entrypoint.
  "${script_dir}/retry-docker-pull.sh" "${agnhost_image}"
  docker run --detach \
    --pull=never \
    --name "${external_allowed_container}" \
    --network "${minikube_network}" \
    --label "oxibelt.network-policy-test=${run_id}" \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
    "${agnhost_image}" netexec --http-port=8080 --udp-port=-1 >/dev/null
  docker run --detach \
    --pull=never \
    --name "${external_denied_container}" \
    --network "${minikube_network}" \
    --label "oxibelt.network-policy-test=${run_id}" \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
    "${agnhost_image}" netexec --http-port=8080 --udp-port=-1 >/dev/null

  wait_for_distinct_docker_network_ipv4s \
    "${minikube_network}" \
    "${external_allowed_container}" \
    "${external_denied_container}"
  allowed_ip="${external_allowed_ip}"
  denied_ip="${external_denied_ip}"
  allowed_name="allowed-${run_id}.oxibelt.test"
  denied_name="denied-${run_id}.oxibelt.test"

  kubectl_cmd -n "${dns_namespace}" apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: policy-dns
data:
  Corefile: |
    .:53 {
        errors
        health
        ready
        hosts {
            ${allowed_ip} ${allowed_name}
            ${denied_ip} ${denied_name}
            fallthrough
        }
        forward . /etc/resolv.conf
        cache 30
    }
---
apiVersion: v1
kind: Pod
metadata:
  name: policy-dns
  labels:
    ${dns_policy_label_key}: ${dns_policy_label_value}
spec:
  restartPolicy: Never
  containers:
  - name: coredns
    image: ${coredns_image}
    args: ["-conf", "/etc/coredns/Corefile"]
    ports:
    - name: dns-udp
      containerPort: 53
      protocol: UDP
    - name: dns-tcp
      containerPort: 53
      protocol: TCP
    volumeMounts:
    - name: config
      mountPath: /etc/coredns
      readOnly: true
  volumes:
  - name: config
    configMap:
      name: policy-dns
---
apiVersion: v1
kind: Service
metadata:
  name: policy-dns
spec:
  selector:
    ${dns_policy_label_key}: ${dns_policy_label_value}
  ports:
  - name: dns-udp
    port: 53
    targetPort: dns-udp
    protocol: UDP
  - name: dns-tcp
    port: 53
    targetPort: dns-tcp
    protocol: TCP
EOF
  wait_for_pod "${dns_namespace}" policy-dns
  dns_service_ip="$(kubectl_cmd -n "${dns_namespace}" get service policy-dns -o jsonpath='{.spec.clusterIP}')"
  [[ -n "${dns_service_ip}" && "${dns_service_ip}" != "None" ]] \
    || die "policy DNS Service must have a ClusterIP"
else
  allowed_name=""
  denied_name=""
  dns_service_ip=""
fi

kubectl_cmd -n "${data_namespace}" apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: target
  labels:
    app.kubernetes.io/name: oxibelt
    app.kubernetes.io/instance: network-policy
spec:
  restartPolicy: Never
  containers:
  - name: public-http
    image: ${agnhost_image}
    command: ["/agnhost", "netexec", "--http-port=8080", "--udp-port=-1"]
    ports:
    - name: http
      containerPort: 8080
      protocol: TCP
  - name: public-https
    image: ${agnhost_image}
    command: ["/agnhost", "netexec", "--http-port=8443", "--udp-port=-1"]
    ports:
    - name: https
      containerPort: 8443
      protocol: TCP
  - name: public-http3
    image: ${agnhost_image}
    command: ["/agnhost", "netexec", "--http-port=18081", "--udp-port=8443"]
    ports:
    - name: http3
      containerPort: 8443
      protocol: UDP
  - name: metrics
    image: ${agnhost_image}
    command: ["/agnhost", "netexec", "--http-port=9090", "--udp-port=-1"]
    ports:
    - name: metrics
      containerPort: 9090
      protocol: TCP
  - name: admin
    image: ${agnhost_image}
    command: ["/agnhost", "netexec", "--http-port=9092", "--udp-port=-1"]
    ports:
    - name: admin
      containerPort: 9092
      protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: target
spec:
  selector:
    app.kubernetes.io/name: oxibelt
    app.kubernetes.io/instance: network-policy
  ports:
  - name: http
    port: 8080
    targetPort: http
    protocol: TCP
  - name: https
    port: 8443
    targetPort: https
    protocol: TCP
  - name: http3
    port: 8443
    targetPort: http3
    protocol: UDP
  - name: metrics
    port: 9090
    targetPort: metrics
    protocol: TCP
  - name: admin
    port: 9092
    targetPort: admin
    protocol: TCP
---
apiVersion: v1
kind: Pod
metadata:
  name: data-probe
  labels:
    app.kubernetes.io/name: oxibelt
    app.kubernetes.io/instance: network-policy
spec:
  restartPolicy: Never
$(if [[ "${cni}" == "cilium" ]]; then cat <<DNS
  dnsPolicy: None
  dnsConfig:
    nameservers:
    - ${dns_service_ip}
    searches:
    - ${data_namespace}.svc.cluster.local
    - svc.cluster.local
    - cluster.local
    options:
    - name: ndots
      value: "1"
DNS
fi)
  containers:
  - name: client
    image: ${curl_image}
    command: ["/bin/sh", "-c", "sleep 3600"]
EOF

kubectl_cmd -n "${backend_namespace}" apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: allowed-upstream
  labels:
    app.kubernetes.io/name: allowed-upstream
spec:
  restartPolicy: Never
  containers:
  - name: server
    image: ${agnhost_image}
    command: ["/agnhost", "netexec", "--http-port=8080", "--udp-port=-1"]
---
apiVersion: v1
kind: Service
metadata:
  name: allowed-upstream
spec:
  selector:
    app.kubernetes.io/name: allowed-upstream
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
EOF

kubectl_cmd -n "${arbitrary_namespace}" apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: arbitrary-service
  labels:
    app.kubernetes.io/name: arbitrary-service
spec:
  restartPolicy: Never
  containers:
  - name: server
    image: ${agnhost_image}
    command: ["/agnhost", "netexec", "--http-port=8080", "--udp-port=-1"]
---
apiVersion: v1
kind: Service
metadata:
  name: arbitrary-service
spec:
  selector:
    app.kubernetes.io/name: arbitrary-service
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
EOF

wait_for_pod "${data_namespace}" target
wait_for_pod "${data_namespace}" data-probe
wait_for_pod "${backend_namespace}" allowed-upstream
wait_for_pod "${arbitrary_namespace}" arbitrary-service

create_client_pod "${public_namespace}" public-client \
  app.kubernetes.io/name public-client true ""
create_client_pod "${monitoring_namespace}" monitoring-client \
  app.kubernetes.io/name prometheus false ""
create_client_pod "${management_namespace}" management-client \
  app.kubernetes.io/name management-client false ""
create_client_pod "${controller_namespace}" controller-client \
  app.kubernetes.io/name oxibelt-gateway-controller false ""

policy_values="${work_dir}/policy-values.yaml"
cat >"${policy_values}" <<EOF
networkPolicy:
  enabled: true
  ingress:
    public:
      allowAll: true
      from: []
    metrics:
      from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ${monitoring_namespace}
        podSelector:
          matchLabels:
            app.kubernetes.io/name: prometheus
    admin:
      from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ${management_namespace}
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ${controller_namespace}
        podSelector:
          matchLabels:
            app.kubernetes.io/name: oxibelt-gateway-controller
  egress:
    dns:
      enabled: true
      to:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ${dns_policy_namespace}
        podSelector:
          matchLabels:
            ${dns_policy_label_key}: ${dns_policy_label_value}
    destinations:
    - name: allowed-upstream
      category: upstream
      to:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ${backend_namespace}
        podSelector:
          matchLabels:
            app.kubernetes.io/name: allowed-upstream
      ports:
      - port: 8080
        protocol: TCP
  cilium:
    enabled: ${cilium_enabled}
EOF

if [[ "${cni}" == "cilium" ]]; then
  cat >>"${policy_values}" <<EOF
    dns:
      toEndpoints:
      - matchLabels:
          k8s:io.kubernetes.pod.namespace: ${dns_namespace}
          k8s:${dns_policy_label_key}: ${dns_policy_label_value}
    fqdnDestinations:
    - name: allowed-external
      category: external-dependency
      matchNames:
      - ${allowed_name}
      ports:
      - port: 8080
        protocol: TCP
EOF
fi

helm_show_only=(--show-only templates/networkpolicy.yaml)
if [[ "${cni}" == "cilium" ]]; then
  helm_show_only+=(--show-only templates/ciliumnetworkpolicy.yaml)
fi

helm template network-policy "${chart_dir}" \
  --namespace "${data_namespace}" \
  -f "${admin_values}" \
  -f "${policy_values}" \
  "${helm_show_only[@]}" >"${work_dir}/policies.yaml"

target_host="target.${data_namespace}.svc.cluster.local"
backend_host="allowed-upstream.${backend_namespace}.svc.cluster.local"
arbitrary_host="arbitrary-service.${arbitrary_namespace}.svc.cluster.local"

# Prove the target is reachable before policy application so the first denial
# cannot be mistaken for an unavailable destination. Then wait for the CNI to
# converge before exercising strict trust-boundary assertions.
expect_allowed "pre-policy public source reaching metrics" \
  run_client_curl "${public_namespace}" public-client "http://${target_host}:9090/"
kubectl_cmd -n "${data_namespace}" apply -f "${work_dir}/policies.yaml"
wait_for_policy_denial "public source reaching metrics" \
  run_client_curl "${public_namespace}" public-client "http://${target_host}:9090/"

# Exercise every trust boundary from Pod-originated traffic rather than
# node/hostNetwork traffic. Later negative assertions remain immediately strict.
expect_allowed "public HTTP" \
  run_client_curl "${public_namespace}" public-client "http://${target_host}:8080/"
expect_allowed "public HTTPS listener TCP port" \
  run_client_curl "${public_namespace}" public-client "http://${target_host}:8443/"
expect_allowed "public HTTP/3 UDP port" \
  run_udp_dial "${public_namespace}" public-client "${target_host}" 8443
expect_denied "public source reaching Admin" \
  run_client_curl "${public_namespace}" public-client "http://${target_host}:9092/"
expect_allowed "monitoring identity reaching metrics" \
  run_client_curl "${monitoring_namespace}" monitoring-client "http://${target_host}:9090/"
expect_denied "monitoring identity reaching Admin" \
  run_client_curl "${monitoring_namespace}" monitoring-client "http://${target_host}:9092/"
expect_allowed "management namespace reaching Admin" \
  run_client_curl "${management_namespace}" management-client "http://${target_host}:9092/"
expect_allowed "Gateway Controller identity reaching Admin" \
  run_client_curl "${controller_namespace}" controller-client "http://${target_host}:9092/"
expect_allowed "declared data-plane upstream egress" \
  run_client_curl "${data_namespace}" data-probe "http://${backend_host}:8080/"
expect_denied "arbitrary cluster Service egress" \
  run_client_curl "${data_namespace}" data-probe "http://${arbitrary_host}:8080/"

if [[ "${cni}" == "cilium" ]]; then
  expect_allowed "exact Cilium FQDN egress" \
    run_client_curl "${data_namespace}" data-probe "http://${allowed_name}:8080/"
  expect_denied "undeclared Cilium FQDN egress" \
    run_client_curl "${data_namespace}" data-probe "http://${denied_name}:8080/"
fi

echo "Kubernetes NetworkPolicy check passed for ${cni}"
