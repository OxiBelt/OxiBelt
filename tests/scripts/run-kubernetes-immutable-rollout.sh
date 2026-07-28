#!/usr/bin/env bash
# Exercise the Kubernetes-native immutable Gateway API rollout using only a
# short-lived Kind cluster. It uses the normal `docker` CLI through Kind and
# removes only the uniquely named cluster it created.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

gateway_api_version="v1.6.1"
gateway_api_url="https://github.com/kubernetes-sigs/gateway-api/releases/download/${gateway_api_version}/standard-install.yaml"
gateway_api_sha256="24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73"
redis_source_image="valkey/valkey:9-alpine@sha256:3fe38a705227d29534a199e876b38d5474dec4d3baca980ac6894df539416562"
redis_source_digest="${redis_source_image##*@sha256:}"
redis_kind_image=""
# The scheduled qualification matrix may select only these reviewed Kind node
# manifests. Arbitrary environment-provided images are rejected before Docker
# or Kind creates resources.
kind_node_image="${OXIBELT_KUBERNETES_KIND_NODE_IMAGE:-kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256}"
case "${kind_node_image}" in
  "kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256" | \
  "kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95" | \
  "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5")
    ;;
  *)
    echo "kubernetes immutable rollout test: unapproved Kind node image: ${kind_node_image}" >&2
    exit 1
    ;;
esac
rollout_timeout_seconds="${OXIBELT_KUBERNETES_ROLLOUT_TIMEOUT_SECONDS:-420}"

run_id=""
cluster_name=""
namespace=""
outside_namespace=""
work_dir=""

data_release="oxibelt-data"
controller_release="oxibelt-gateway-controller"
workload_name="oxibelt"
selector="app.kubernetes.io/name=oxibelt,app.kubernetes.io/instance=${data_release}"
managed_config_path="conf.d/gateway-api.generated.toml"
empty_config_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
port_forward_pid=""
udp_flow_probe_pid=""
cluster_created=0
redis_kind_image_created=0
admin_server_name=""
admin_service_name="${workload_name}-admin"
controller_selector="app.kubernetes.io/name=oxibelt-gateway-controller"
leader_lease_name="oxibelt-gateway-controller"
controller_readiness_revocation_timeout_seconds=45

die() {
  echo "kubernetes immutable rollout test: $*" >&2
  exit 1
}

require_command() {
  local command="$1"
  command -v "${command}" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
}

print_admin_probe_diagnostics() {
  local phase
  local log

  [[ -n "${work_dir}" ]] || return 0
  for phase in authenticated-before-rejection no-client-certificate authenticated-after-rejection; do
    log="${work_dir}/admin-port-forward-${phase}.log"
    if [[ -f "${log}" ]]; then
      echo "Admin ${phase} port-forward diagnostics:" >&2
      tail -n 80 -- "${log}" >&2
    fi
  done
  if [[ -f "${work_dir}/admin-no-client-certificate-curl.log" ]]; then
    echo "Admin no-client-certificate curl diagnostics:" >&2
    tail -n 80 -- "${work_dir}/admin-no-client-certificate-curl.log" >&2
  fi
}

kube() {
  kubectl --context "kind-${cluster_name}" "$@"
}

cleanup() {
  local status="$?"
  local controller_pod
  set +e

  if [[ -n "${port_forward_pid}" ]]; then
    kill "${port_forward_pid}" >/dev/null 2>&1 || true
    wait "${port_forward_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${udp_flow_probe_pid}" ]]; then
    kill "${udp_flow_probe_pid}" >/dev/null 2>&1 || true
    wait "${udp_flow_probe_pid}" >/dev/null 2>&1 || true
  fi

  if ((status != 0)); then
    print_admin_probe_diagnostics
  fi

  if ((status != 0 && cluster_created == 1)); then
    echo "Kubernetes immutable rollout diagnostics for ${cluster_name}/${namespace}:" >&2
    kube -n "${namespace}" get deployments,replicasets,pods --ignore-not-found >&2 || true
    kube -n "${namespace}" get events --sort-by=.metadata.creationTimestamp >&2 || true
    while IFS= read -r controller_pod; do
      [[ -n "${controller_pod}" ]] || continue
      kube -n "${namespace}" logs "${controller_pod}" \
        --all-containers=true --prefix --tail=200 >&2 || true
      kube -n "${namespace}" logs "${controller_pod}" \
        --all-containers=true --prefix --previous --tail=200 >&2 || true
    done < <(kube -n "${namespace}" get pods -l "${controller_selector}" \
      -o name 2>/dev/null)
    kube -n "${namespace}" logs -l "${selector}" \
      --all-containers=true --prefix --tail=200 >&2 || true
    kube -n "${namespace}" logs -l "${selector}" \
      --all-containers=true --prefix --previous --tail=200 >&2 || true
    kube -n "${namespace}" logs deployment/oxibelt-udp-flow-redis \
      --all-containers=true --prefix --tail=120 >&2 || true
    kube -n "${namespace}" logs deployment/oxibelt-udp-flow-redis \
      --all-containers=true --prefix --previous --tail=120 >&2 || true
    kube -n "${namespace}" logs -l 'oxibelt.dev/test=stale-config' \
      --all-containers=true --prefix --tail=80 >&2 || true
    kube -n "${outside_namespace}" get deployments,pods --ignore-not-found >&2 || true
    kube -n "${outside_namespace}" get events --sort-by=.metadata.creationTimestamp >&2 || true
    kube -n "${outside_namespace}" logs deployment/tcp-backend \
      --all-containers=true --prefix --tail=80 >&2 || true
    kube -n "${outside_namespace}" logs deployment/udp-backend \
      --all-containers=true --prefix --tail=80 >&2 || true
  fi

  if ((cluster_created == 1)); then
    # The Kind cluster is named from this invocation only. Do not run broad
    # Docker or Kubernetes cleanup commands here.
    kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
  fi
  if ((redis_kind_image_created == 1)); then
    docker image rm --no-prune "${redis_kind_image}" >/dev/null 2>&1 || true
  fi

  case "${work_dir}" in
    "${repo_root}"/tests/.tmp/kubernetes-immutable-rollout-*)
      rm -rf -- "${work_dir}"
      ;;
    "")
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

deployment_committed_revision_changed() {
  local previous_revision="$1"
  local deployment

  deployment="$(kube -n "${namespace}" get deployment "${workload_name}" -o json 2>/dev/null)" \
    || return 1
  jq -e --arg previous "${previous_revision}" '
    .metadata.annotations["oxibelt.dev/gateway-config-phase"] == "Committed"
      and (.metadata.annotations["oxibelt.dev/gateway-config-desired"] | type == "string" and length > 0)
      and (.metadata.annotations["oxibelt.dev/gateway-config-committed"]
        == .metadata.annotations["oxibelt.dev/gateway-config-desired"])
      and .metadata.annotations["oxibelt.dev/gateway-config-committed"] != $previous
  ' >/dev/null <<<"${deployment}"
}

gateway_is_programmed() {
  local gateway
  gateway="$(kube -n "${namespace}" get gateway edge -o json 2>/dev/null)" || return 1
  jq -e \
    'any(.status.conditions[]?; .type == "Programmed" and .status == "True")' \
    >/dev/null <<<"${gateway}"
}

route_conditions_match() {
  local resource="$1"
  local name="$2"
  local resolved="$3"
  local programmed="$4"
  local resolved_reason="$5"
  local route

  route="$(kube -n "${namespace}" get "${resource}" "${name}" -o json 2>/dev/null)" \
    || return 1
  jq -e \
    --arg controller "oxibelt.dev/gateway-controller" \
    --arg resolved "${resolved}" \
    --arg programmed "${programmed}" \
    --arg resolved_reason "${resolved_reason}" '
    .metadata.generation as $generation
    | any(.status.parents[]?;
        .controllerName == $controller
          and any(.conditions[]?;
            .type == "Accepted"
              and .status == "True"
              and .observedGeneration == $generation)
          and any(.conditions[]?;
            .type == "ResolvedRefs"
              and .status == $resolved
              and .reason == $resolved_reason
              and .observedGeneration == $generation)
          and any(.conditions[]?;
            .type == "Programmed"
              and .status == $programmed
              and .observedGeneration == $generation))
  ' >/dev/null <<<"${route}"
}

l4_routes_are_programmed() {
  route_conditions_match tcproutes.gateway.networking.k8s.io tcp-probe True True ResolvedRefs \
    && route_conditions_match udproutes.gateway.networking.k8s.io udp-probe True True ResolvedRefs
}

l4_routes_are_unresolved() {
  route_conditions_match tcproutes.gateway.networking.k8s.io tcp-probe False False RefNotPermitted \
    && route_conditions_match udproutes.gateway.networking.k8s.io udp-probe False False RefNotPermitted
}

verify_kind_node_l4_probe_runtime() {
  local node="${cluster_name}-control-plane"

  docker exec "${node}" /usr/bin/perl \
    -MIO::Socket::IP \
    -MIO::Select \
    -MSocket=AI_NUMERICHOST,SOCK_DGRAM,SOCK_STREAM,getaddrinfo \
    -e 'exit 0' \
    || die "Kind control-plane node lacks the package-free Perl L4 probe runtime"
}

probe_l4_round_trips() {
  local expected_namespace="$1"
  local expected_udp_backend="${2:-single}"
  local expected_udp_services
  local node="${cluster_name}-control-plane"
  local tcp_response
  local udp_response

  case "${expected_udp_backend}" in
    paired)
      expected_udp_services='["udp-backend-a","udp-backend-b"]'
      ;;
    single)
      expected_udp_services='["udp-backend"]'
      ;;
    *)
      die "refusing unexpected UDP backend probe mode: ${expected_udp_backend}"
      ;;
  esac

  tcp_response="$(
    docker exec \
      --env OXIBELT_L4_ADDRESS="${status_service_address}" \
      "${node}" /usr/bin/perl \
      -MIO::Socket::IP \
      -MIO::Select \
      -MSocket=SOCK_STREAM \
      -e '
use strict;
use warnings;

sub read_bounded_line {
    my ($connection, $selector, $timeout, $label) = @_;
    my $deadline = time() + $timeout;
    my $buffer = "";

    while (length($buffer) < 4096) {
        my $remaining = $deadline - time();
        $remaining > 0 && $selector->can_read($remaining)
            or die "$label timed out\n";
        my $read = sysread($connection, my $byte, 1);
        defined $read or die "$label read failed: $!\n";
        $read > 0 or die "$label ended before newline\n";
        $buffer .= $byte;
        return $buffer if $byte eq "\n";
    }

    die "$label exceeded 4096 bytes\n";
}

my $connection = IO::Socket::IP->new(
    PeerHost => $ENV{OXIBELT_L4_ADDRESS},
    PeerPort => 9300,
    Type => SOCK_STREAM,
    Timeout => 5,
) or die "TCP probe connection failed: $!\n";
my $selector = IO::Select->new($connection);
my $welcome = read_bounded_line($connection, $selector, 5, "TCP probe welcome");
$welcome eq "Gateway API Test TCP Server\n"
    or die "unexpected TCP probe response\n";

my $request = "TEST\n";
my $written = syswrite($connection, $request);
defined $written && $written == length($request)
    or die "TCP probe request write failed: $!\n";
my $response = read_bounded_line($connection, $selector, 5, "TCP probe response");
print STDOUT $response;
'
  )" || return 1
  OXIBELT_L4_EXPECTED_NAMESPACE="${expected_namespace}" \
    jq -s -e '
      length == 1
        and .[0].namespace == env.OXIBELT_L4_EXPECTED_NAMESPACE
        and .[0].service == "tcp-backend"
    ' >/dev/null <<<"${tcp_response}" || return 1

  udp_response="$(
    docker exec \
      --env OXIBELT_L4_ADDRESS="${status_service_address}" \
      "${node}" /usr/bin/perl \
      -MIO::Socket::IP \
      -MIO::Select \
      -MSocket=SOCK_DGRAM \
      -e '
use strict;
use warnings;

my $connection = IO::Socket::IP->new(
    PeerHost => $ENV{OXIBELT_L4_ADDRESS},
    PeerPort => 5300,
    Type => SOCK_DGRAM,
    Timeout => 5,
) or die "UDP probe socket creation failed: $!\n";
my $request = "oxibelt-udp-probe";
my $written = $connection->send($request);
defined $written && $written == length($request)
    or die "UDP probe request write failed: $!\n";
my $selector = IO::Select->new($connection);
$selector->can_read(5) or die "UDP probe response timed out\n";
my $peer = $connection->recv(my $response, 4096);
defined $peer or die "UDP probe response read failed: $!\n";
length($response) > 0 or die "UDP probe response was empty\n";
print STDOUT $response;
'
  )" || return 1
  OXIBELT_L4_EXPECTED_NAMESPACE="${expected_namespace}" \
    jq -s -e --argjson expected_services "${expected_udp_services}" '
      length == 1
        and .[0].request == "oxibelt-udp-probe"
        and .[0].namespace == env.OXIBELT_L4_EXPECTED_NAMESPACE
        and (.[0].service as $service | $expected_services | index($service) != null)
    ' >/dev/null <<<"${udp_response}" || return 1
}

l4_ports_fail_closed() {
  local node="${cluster_name}-control-plane"

  docker exec \
    --env OXIBELT_L4_ADDRESS="${status_service_address}" \
    "${node}" /usr/bin/perl \
    -MIO::Socket::IP \
    -MIO::Select \
    -MSocket=SOCK_STREAM,SOCK_DGRAM \
    -e '
use strict;
use warnings;

my $address = $ENV{OXIBELT_L4_ADDRESS};
my $tcp = IO::Socket::IP->new(
    PeerHost => $address,
    PeerPort => 9300,
    Type => SOCK_STREAM,
    Timeout => 2,
);
die "TCP listener remained reachable without ReferenceGrant\n" if defined $tcp;

my $udp = IO::Socket::IP->new(
    PeerHost => $address,
    PeerPort => 5300,
    Type => SOCK_DGRAM,
    Timeout => 2,
) or die "UDP denied-probe socket creation failed: $!\n";
my $request = "oxibelt-udp-denied-probe";
my $written = $udp->send($request);
exit 0 unless defined $written;
$written == length($request)
    or die "UDP denied-probe request write was incomplete\n";
my $selector = IO::Select->new($udp);
exit 0 unless $selector->can_read(2);
my $peer = $udp->recv(my $response, 4096);
exit 0 unless defined $peer;
die "UDP listener remained reachable without ReferenceGrant\n";
'
}

udp_flow_probe_first_response_ready() {
  if [[ -z "${udp_flow_probe_pid}" ]] || ! kill -0 "${udp_flow_probe_pid}" 2>/dev/null; then
    [[ -f "${work_dir}/udp-flow-restart-probe.log" ]] \
      && tail -n 40 -- "${work_dir}/udp-flow-restart-probe.log" >&2
    die "same-socket UDP flow probe exited before its first response"
  fi
  grep -q $'^SOURCE\t' "${work_dir}/udp-flow-restart-probe.log" \
    && grep -q $'^FIRST\t{' "${work_dir}/udp-flow-restart-probe.log"
}

udp_flow_probe_finished() {
  [[ -n "${udp_flow_probe_pid}" ]] && ! kill -0 "${udp_flow_probe_pid}" 2>/dev/null
}

data_plane_pods_replaced() {
  local old_uids="$1"
  local pods

  pods="$(kube -n "${namespace}" get pods -l "${selector}" -o json 2>/dev/null)" || return 1
  jq -e --argjson old_uids "${old_uids}" '
    [.items[] | select(.metadata.deletionTimestamp == null)] as $pods
    | ($pods | length) == 3
      and all($pods[];
        ((.status.conditions // []) | any(.type == "Ready" and .status == "True"))
          and (.metadata.uid as $uid | $old_uids | index($uid) == null))
  ' >/dev/null <<<"${pods}"
}

metrics_port_forward_is_ready() {
  local port="$1"
  local log="$2"

  [[ -n "${port_forward_pid}" ]] \
    && kill -0 "${port_forward_pid}" 2>/dev/null \
    && grep -Fq "Forwarding from 127.0.0.1:${port} -> 9090" "${log}"
}

data_plane_pod_logged_udp_peer() {
  local pod="$1"
  local peer="$2"
  local logs

  logs="$(kube -n "${namespace}" logs "pod/${pod}" -c oxibelt --tail=200 2>/dev/null)" \
    || return 1
  grep -F "UDP stream flow started" <<<"${logs}" | grep -Fq -- "${peer}"
}

pod_has_udp_restore_metric() {
  local pod="$1"
  local port="$2"
  local log="${work_dir}/udp-restore-metric-${pod}.log"
  local metric_log="${work_dir}/udp-restore-metrics-${pod}.log"
  local metrics
  local observed=1

  [[ -z "${port_forward_pid}" ]] || die "a metrics port-forward is already active"
  kubectl --context "kind-${cluster_name}" -n "${namespace}" port-forward \
    --address 127.0.0.1 "pod/${pod}" "${port}:9090" \
    >"${log}" 2>&1 &
  port_forward_pid="$!"
  wait_for "metrics port-forward bind for ${pod}" 30 \
    metrics_port_forward_is_ready "${port}" "${log}"

  if metrics="$(curl --fail --silent --show-error --max-time 5 \
    "http://127.0.0.1:${port}/metrics")"; then
    awk '
      $1 ~ /^oxibelt_stream_udp_(flows_(created|restored)|flow_(persistence_errors|fence_rejections))_total$/ {
        print
      }
    ' <<<"${metrics}" >"${metric_log}"
    if awk '
      $1 == "oxibelt_stream_udp_flows_restored_total" && ($2 + 0) >= 1 {
        found = 1
      }
      END { exit found ? 0 : 1 }
    ' <<<"${metrics}"; then
      observed=0
    fi
  fi

  kill "${port_forward_pid}" >/dev/null 2>&1 || true
  wait "${port_forward_pid}" >/dev/null 2>&1 || true
  port_forward_pid=""
  return "${observed}"
}

verify_udp_restore_metric() {
  local pod="$1"
  local metric_log="${work_dir}/udp-restore-metrics-${pod}.log"

  if pod_has_udp_restore_metric "${pod}" "$((22000 + RANDOM % 7000))"; then
    return 0
  fi
  if [[ -f "${metric_log}" ]]; then
    echo "UDP restore metric diagnostics for ${pod}:" >&2
    tail -n 40 -- "${metric_log}" >&2
  fi
  die "replacement data-plane Pod ${pod} did not report oxibelt_stream_udp_flows_restored_total >= 1"
}

verify_udp_flow_survives_data_plane_rollout() {
  local node="${cluster_name}-control-plane"
  local node_replacement_target_file="/tmp/oxibelt-udp-flow-${run_id}.target"
  local probe_log="${work_dir}/udp-flow-restart-probe.log"
  local old_probe_log="${work_dir}/udp-flow-old-pod.log"
  local replacement_probe_log="${work_dir}/udp-flow-replacement-pod.log"
  local old_pods_json
  local old_uids
  local old_probe_target
  local old_probe_pod
  local old_probe_ip
  local replacement_pods_json
  local replacement_probe_target
  local replacement_probe_pod
  local replacement_probe_ip
  local source_peer
  local first_response
  local second_response

  old_pods_json="$(kube -n "${namespace}" get pods -l "${selector}" -o json)" \
    || die "could not capture data-plane Pod identities before the UDP restart proof"
  old_uids="$(jq -ce '
    [.items[]
      | select(.metadata.deletionTimestamp == null)
      | .metadata.uid]
    | select(length == 3)
  ' <<<"${old_pods_json}")" \
    || die "UDP restart proof requires exactly three live data-plane Pod UIDs"
  old_probe_target="$(jq -er '
    [.items[]
      | select(.metadata.deletionTimestamp == null)
      | select((.status.conditions // []) | any(.type == "Ready" and .status == "True"))
      | select(.status.podIP | type == "string" and test("^[0-9]+([.][0-9]+){3}$"))]
    | sort_by(.metadata.name)
    | select(length > 0)
    | first
    | [.metadata.name, .status.podIP]
    | @tsv
  ' <<<"${old_pods_json}")" \
    || die "could not select a Ready old data-plane Pod with an IPv4 address"
  IFS=$'\t' read -r old_probe_pod old_probe_ip <<<"${old_probe_target}"

  [[ -z "${udp_flow_probe_pid}" ]] || die "a same-socket UDP flow probe is already active"
  docker exec \
    --env OXIBELT_L4_INITIAL_POD_ADDRESS="${old_probe_ip}" \
    --env OXIBELT_L4_REPLACEMENT_TARGET_FILE="${node_replacement_target_file}" \
    --env OXIBELT_L4_RESTART_TIMEOUT="${rollout_timeout_seconds}" \
    "${node}" /usr/bin/perl \
    -MIO::Socket::IP \
    -MIO::Select \
    -MSocket=AI_NUMERICHOST,SOCK_DGRAM,getaddrinfo \
    -e '
use strict;
use warnings;

$| = 1;
my $connection = IO::Socket::IP->new(
    PeerHost => $ENV{OXIBELT_L4_INITIAL_POD_ADDRESS},
    PeerPort => 15300,
    Type => SOCK_DGRAM,
    Timeout => 5,
) or die "UDP restart probe socket creation failed: $!\n";
my $selector = IO::Select->new($connection);
my $source_host = $connection->sockhost;
my $source_port = $connection->sockport;
$source_host =~ /\A[0-9]+(?:[.][0-9]+){3}\z/
    or die "UDP restart probe selected a non-IPv4 source address\n";
$source_port =~ /\A[1-9][0-9]{0,4}\z/ && $source_port <= 65535
    or die "UDP restart probe selected an invalid source port\n";
print STDOUT "SOURCE\t$source_host:$source_port\n";

sub receive_response {
    my ($socket, $readable, $timeout, $label) = @_;
    $readable->can_read($timeout) or die "$label timed out\n";
    my $peer = $socket->recv(my $response, 4096);
    defined $peer or die "$label read failed: $!\n";
    length($response) > 0 or die "$label was empty\n";
    $response =~ s/[\r\n]+\z//;
    return $response;
}

my $first_request = "oxibelt-udp-before-restart";
my $first_written = $connection->send($first_request);
defined $first_written && $first_written == length($first_request)
    or die "UDP restart probe first write failed: $!\n";
my $first_response = receive_response(
    $connection,
    $selector,
    10,
    "UDP restart probe first response",
);
print STDOUT "FIRST\t$first_response\n";

my $target_file = $ENV{OXIBELT_L4_REPLACEMENT_TARGET_FILE};
my $restart_timeout = $ENV{OXIBELT_L4_RESTART_TIMEOUT};
$restart_timeout =~ /\A[1-9][0-9]{1,2}\z/
    or die "invalid UDP restart probe timeout\n";
my $target_deadline = time() + $restart_timeout + 60;
while (!-f $target_file) {
    time() < $target_deadline
        or die "UDP restart probe replacement target timed out\n";
    select undef, undef, undef, 0.1;
}
open my $target_handle, "<", $target_file
    or die "UDP restart probe could not open replacement target: $!\n";
my $replacement_address = <$target_handle>;
defined $replacement_address
    or die "UDP restart probe replacement target was empty\n";
close $target_handle
    or die "UDP restart probe could not close replacement target: $!\n";
unlink $target_file
    or die "UDP restart probe could not remove replacement target: $!\n";
$replacement_address =~ s/[\r\n]+\z//;
my ($address_error, @addresses) = getaddrinfo(
    $replacement_address,
    15300,
    {
        flags => AI_NUMERICHOST,
        socktype => SOCK_DGRAM,
    },
);
$address_error == 0 && @addresses == 1
    or die "UDP restart probe replacement target was not one numeric UDP address\n";
$connection->connect($addresses[0]->{addr})
    or die "UDP restart probe could not select the replacement Pod: $!\n";
$connection->sockhost eq $source_host && $connection->sockport == $source_port
    or die "UDP restart probe source tuple changed across Pod replacement\n";

my $second_request = "oxibelt-udp-after-restart";
my $response_deadline = time() + 90;
while (time() < $response_deadline) {
    my $written = $connection->send($second_request);
    if (defined $written && $written == length($second_request)
        && $selector->can_read(1)) {
        my $peer = $connection->recv(my $response, 4096);
        if (defined $peer && length($response) > 0) {
            $response =~ s/[\r\n]+\z//;
            print STDOUT "SECOND\t$response\n";
            exit 0;
        }
    }
    select undef, undef, undef, 0.1;
}
die "UDP restart probe second response timed out\n";
' >"${probe_log}" 2>&1 &
  udp_flow_probe_pid="$!"

  wait_for "first response on the persistent UDP client socket" 30 \
    udp_flow_probe_first_response_ready
  source_peer="$(awk -F '\t' '$1 == "SOURCE" {print $2; exit}' "${probe_log}")"
  [[ "${source_peer}" =~ ^[0-9]+([.][0-9]+){3}:[1-9][0-9]{0,4}$ ]] \
    || die "same-socket UDP flow probe did not report a bounded IPv4 source tuple"
  wait_for "old data-plane Pod to log the stable UDP peer" 30 \
    data_plane_pod_logged_udp_peer "${old_probe_pod}" "${source_peer}"
  kube -n "${namespace}" logs "pod/${old_probe_pod}" -c oxibelt --tail=200 \
    >"${old_probe_log}" \
    || die "could not capture the old data-plane Pod UDP flow log"

  kube -n "${namespace}" rollout restart "deployment/${workload_name}" >/dev/null
  kube -n "${namespace}" rollout status "deployment/${workload_name}" \
    --timeout "${rollout_timeout_seconds}s"
  wait_for "replacement of every data-plane Pod" "${rollout_timeout_seconds}" \
    data_plane_pods_replaced "${old_uids}"
  wait_for "committed immutable state after data-plane Pod replacement" \
    "${rollout_timeout_seconds}" deployment_is_committed

  replacement_pods_json="$(kube -n "${namespace}" get pods -l "${selector}" -o json)" \
    || die "could not capture replacement data-plane Pod identities for the UDP restart proof"
  replacement_probe_target="$(jq -er --argjson old_uids "${old_uids}" '
    [.items[]
      | select(.metadata.deletionTimestamp == null)
      | select(.metadata.uid as $uid | $old_uids | index($uid) == null)
      | select((.status.conditions // []) | any(.type == "Ready" and .status == "True"))
      | select(.status.podIP | type == "string" and test("^[0-9]+([.][0-9]+){3}$"))]
    | sort_by(.metadata.name)
    | select(length > 0)
    | first
    | [.metadata.name, .status.podIP]
    | @tsv
  ' <<<"${replacement_pods_json}")" \
    || die "could not select a Ready replacement data-plane Pod with an IPv4 address"
  IFS=$'\t' read -r replacement_probe_pod replacement_probe_ip \
    <<<"${replacement_probe_target}"
  docker exec \
    --env OXIBELT_L4_REPLACEMENT_POD_ADDRESS="${replacement_probe_ip}" \
    --env OXIBELT_L4_REPLACEMENT_TARGET_FILE="${node_replacement_target_file}" \
    "${node}" /usr/bin/perl \
    -e '
use strict;
use warnings;

my $target_file = $ENV{OXIBELT_L4_REPLACEMENT_TARGET_FILE};
my $pending_file = "$target_file.pending";
open my $target_handle, ">", $pending_file
    or die "could not create the pending UDP replacement target: $!\n";
print {$target_handle} $ENV{OXIBELT_L4_REPLACEMENT_POD_ADDRESS}, "\n"
    or die "could not write the pending UDP replacement target: $!\n";
close $target_handle
    or die "could not close the pending UDP replacement target: $!\n";
rename $pending_file, $target_file
    or die "could not publish the UDP replacement target: $!\n";
' \
    || die "could not provide the bounded same-socket UDP probe with its replacement target"
  wait_for "second response on the same UDP client socket" 120 udp_flow_probe_finished
  if wait "${udp_flow_probe_pid}"; then
    udp_flow_probe_pid=""
  else
    udp_flow_probe_pid=""
    tail -n 40 -- "${probe_log}" >&2
    die "same-socket UDP flow probe failed after data-plane Pod replacement"
  fi

  first_response="$(awk -F '\t' '$1 == "FIRST" {sub(/^FIRST\t/, ""); print; exit}' \
    "${probe_log}")"
  second_response="$(awk -F '\t' '$1 == "SECOND" {sub(/^SECOND\t/, ""); print; exit}' \
    "${probe_log}")"
  jq -s -e --arg expected_namespace "${namespace}" '
    length == 2
      and .[0].request == "oxibelt-udp-before-restart"
      and .[1].request == "oxibelt-udp-after-restart"
      and .[0].namespace == $expected_namespace
      and .[1].namespace == $expected_namespace
      and (. as $responses
        | ["udp-backend-a", "udp-backend-b"]
        | index($responses[0].service) != null)
      and .[1].service == .[0].service
      and (.[0].pod | type == "string" and length > 0)
      and .[1].pod == .[0].pod
  ' >/dev/null <<<"${first_response}"$'\n'"${second_response}" \
    || die "restored UDP flow did not retain its distinguishable backend Service and Pod identity"

  wait_for "replacement data-plane Pod to log the stable UDP peer" 30 \
    data_plane_pod_logged_udp_peer "${replacement_probe_pod}" "${source_peer}"
  kube -n "${namespace}" logs "pod/${replacement_probe_pod}" -c oxibelt --tail=200 \
    >"${replacement_probe_log}" \
    || die "could not capture the replacement data-plane Pod UDP flow log"
  verify_udp_restore_metric "${replacement_probe_pod}"
  wait_for "Gateway Programmed=True after data-plane Pod replacement" \
    "${rollout_timeout_seconds}" gateway_is_programmed
  wait_for "L4 route programming after data-plane Pod replacement" \
    "${rollout_timeout_seconds}" l4_routes_are_programmed
  wait_for "same-namespace TCP and UDP round trips after data-plane Pod replacement" 60 \
    probe_l4_round_trips "${namespace}" paired
}

controller_has_two_ready_replicas() {
  local deployment
  local pods
  deployment="$(kube -n "${namespace}" get deployment "${controller_release}" -o json 2>/dev/null)" \
    || return 1
  pods="$(kube -n "${namespace}" get pods -l "${controller_selector}" -o json 2>/dev/null)" \
    || return 1
  jq -e '
    .spec.replicas == 2
      and .status.observedGeneration == .metadata.generation
      and .status.replicas == 2
      and .status.updatedReplicas == 2
      and .status.readyReplicas == 2
      and .status.availableReplicas == 2
      and (.status.unavailableReplicas // 0) == 0
      and .spec.strategy.type == "RollingUpdate"
      and .spec.strategy.rollingUpdate.maxUnavailable == 0
      and .spec.strategy.rollingUpdate.maxSurge == 1
  ' >/dev/null <<<"${deployment}" || return 1
  jq -e '
    [.items[] | select(.metadata.deletionTimestamp == null)] as $pods
    | ($pods | length) == 2
      and all($pods[];
        any(.status.conditions[]?;
          .type == "Ready" and .status == "True"))
  ' >/dev/null <<<"${pods}"
}

controller_pod_uids() {
  local pods
  pods="$(kube -n "${namespace}" get pods -l "${controller_selector}" -o json 2>/dev/null)" \
    || return 1
  jq -er '
    [.items[] | select(.metadata.deletionTimestamp == null)] as $pods
    | if (($pods | length) == 2
        and all($pods[];
          any(.status.conditions[]?;
            .type == "Ready" and .status == "True")))
      then ([$pods[].metadata.uid] | sort | join(","))
      else empty
      end
  ' <<<"${pods}"
}

controller_pod_runtime_identities() {
  local pods
  pods="$(kube -n "${namespace}" get pods -l "${controller_selector}" -o json 2>/dev/null)" \
    || return 1
  jq -cer '
    [.items[] | select(.metadata.deletionTimestamp == null)] as $pods
    | [$pods[] as $pod
      | $pod.status.containerStatuses[]?
      | select(.name == "controller")
      | select(.state.running != null)
      | select(.containerID | type == "string" and length > 0)
      | {
          pod_uid: $pod.metadata.uid,
          container_id: .containerID,
          restart_count: .restartCount
        }] as $identities
    | if (($pods | length) == 2
        and all($pods[];
          any(.status.conditions[]?;
            .type == "Ready" and .status == "True"))
        and ($identities | length) == 2)
      then ($identities | sort_by(.pod_uid))
      else empty
      end
  ' <<<"${pods}"
}

controller_replicaset_uids() {
  local deployment_uid="$1"
  local replicasets
  replicasets="$(kube -n "${namespace}" get replicasets -l "${controller_selector}" \
    -o json 2>/dev/null)" || return 1
  jq -er --arg deployment_uid "${deployment_uid}" '
    [.items[]
      | select(.metadata.deletionTimestamp == null)
      | select(any(.metadata.ownerReferences[]?;
          .controller == true and .uid == $deployment_uid))
      | .metadata.uid] as $uids
    | if ($uids | length) >= 1
      then ($uids | sort | join(","))
      else empty
      end
  ' <<<"${replicasets}"
}

lease_holder_pod() {
  local holder
  holder="$(kube -n "${namespace}" get lease "${leader_lease_name}" \
    -o jsonpath='{.spec.holderIdentity}' 2>/dev/null)" || return 1
  [[ -n "${holder}" ]] || return 1
  printf '%s\n' "${holder%%.*}"
}

lease_has_live_unique_holder() {
  local holder_pod
  local live_pods
  holder_pod="$(lease_holder_pod)" || return 1
  live_pods="$(kube -n "${namespace}" get pods -l "${controller_selector}" -o json 2>/dev/null)" \
    || return 1
  jq -e --arg holder "${holder_pod}" '
    [.items[] | select(.metadata.deletionTimestamp == null)] as $pods
    | ($pods | length) == 2
      and ([ $pods[] | select(.metadata.name == $holder) ] | length) == 1
  ' >/dev/null <<<"${live_pods}"
}

lease_holder_changed() {
  local previous="$1"
  local current
  current="$(lease_holder_pod)" || return 1
  [[ "${current}" != "${previous}" ]]
}

controller_pods_are_unready() {
  local expected_runtime_identities="$1"
  local pods
  pods="$(kube -n "${namespace}" get pods -l "${controller_selector}" -o json 2>/dev/null)" \
    || return 1
  jq -e --argjson expected_runtime_identities "${expected_runtime_identities}" '
    [.items[] | select(.metadata.deletionTimestamp == null)] as $pods
    | [$pods[] as $pod
        | $pod.status.containerStatuses[]?
        | select(.name == "controller")
        | select(.state.running != null)
        | select(.containerID | type == "string" and length > 0)
        | {
            pod_uid: $pod.metadata.uid,
            container_id: .containerID,
            restart_count: .restartCount
          }] as $runtime_identities
    | ($pods | length) == 2
      and all($pods[]; all(.status.conditions[]?; .type != "Ready" or .status != "True"))
      and ($runtime_identities | length) == 2
      and (($runtime_identities | sort_by(.pod_uid)) == $expected_runtime_identities)
  ' >/dev/null <<<"${pods}"
}

bootstrap_pods_have_identity() {
  local revision="$1"
  local digest="$2"
  local pods
  pods="$(kube -n "${namespace}" get pods -l "${selector}" -o json 2>/dev/null)" || return 1
  jq -e --arg revision "${revision}" --arg digest "${digest}" '
    [.items[] | select(.metadata.deletionTimestamp == null)] as $pods
    | ($pods | length) == 3
    and all($pods[];
      .metadata.annotations["oxibelt.dev/config-revision"] == $revision
      and .metadata.annotations["oxibelt.dev/config-digest"] == $digest)
  ' >/dev/null <<<"${pods}"
}

external_base_bootstrap_is_unassigned() {
  local workload_kind="$1"
  local template="$2"
  local rendered
  rendered="$(helm template external-base-bootstrap "${repo_root}/deploy/helm/oxibelt" \
    --show-only "${template}" \
    --set-string "workload.kind=${workload_kind}" \
    --set-string "configRollout.mode=kubernetes_immutable" \
    --set "config.create=false" \
    --set-string "config.existingConfigMap=operator-managed-base" \
    --set-string "config.existingConfigMapDigest=1111111111111111111111111111111111111111111111111111111111111111")" \
    || return 1

  grep -F 'oxibelt.dev/immutable-config-rollout: "true"' <<<"${rendered}" >/dev/null \
    || return 1
  if grep -F 'oxibelt.dev/config-revision:' <<<"${rendered}" >/dev/null \
    || grep -F 'oxibelt.dev/config-digest:' <<<"${rendered}" >/dev/null; then
    return 1
  fi
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

admin_get_json() {
  local port="$1"
  local path="$2"
  local output="$3"

  case "${path}" in
    /admin/v1/capabilities | /admin/v1/config/status)
      ;;
    *)
      die "refusing unexpected Admin JSON probe path: ${path}"
      ;;
  esac
  case "${output}" in
    "${work_dir}"/admin-*.json)
      ;;
    *)
      die "refusing unexpected Admin JSON probe output: ${output}"
      ;;
  esac

  curl --fail --silent --show-error --max-time 5 --tlsv1.3 \
    --resolve "${admin_server_name}:${port}:127.0.0.1" \
    --cacert "${work_dir}/admin-server-ca.crt" \
    --cert "${work_dir}/admin-client.crt" \
    --key "${work_dir}/admin-client.key" \
    --header "@${work_dir}/admin-headers.txt" \
    --output "${output}" \
    "https://${admin_server_name}:${port}${path}"
  jq -e 'type == "object"' "${output}" >/dev/null \
    || die "Admin JSON probe did not return an object for ${path}"
}

admin_port_forward_is_ready() {
  local port="$1"
  local log="$2"

  [[ -n "${port_forward_pid}" ]] \
    && kill -0 "${port_forward_pid}" 2>/dev/null \
    && grep -Fq "Forwarding from 127.0.0.1:${port} -> 9092" "${log}"
}

start_admin_port_forward() {
  local pod="$1"
  local port="$2"
  local phase="$3"
  local log

  case "${phase}" in
    authenticated-before-rejection | no-client-certificate | authenticated-after-rejection)
      ;;
    *)
      die "refusing unexpected Admin probe phase: ${phase}"
      ;;
  esac
  [[ -z "${port_forward_pid}" ]] || die "an Admin port-forward is already active"

  log="${work_dir}/admin-port-forward-${phase}.log"
  kubectl --context "kind-${cluster_name}" -n "${namespace}" port-forward \
    --address 127.0.0.1 "pod/${pod}" "${port}:9092" \
    >"${log}" 2>&1 &
  port_forward_pid="$!"

  wait_for "${phase} Admin port-forward bind" 30 \
    admin_port_forward_is_ready "${port}" "${log}"
}

stop_admin_port_forward() {
  [[ -n "${port_forward_pid}" ]] || return 0

  kill "${port_forward_pid}" >/dev/null 2>&1 || true
  wait "${port_forward_pid}" >/dev/null 2>&1 || true
  port_forward_pid=""
}

admin_pod_runtime_identity() {
  local pod="$1"
  local pod_json

  pod_json="$(kube -n "${namespace}" get "pod/${pod}" -o json 2>/dev/null)" || return 1
  jq -er '
    [.status.containerStatuses[]? | select(.name == "oxibelt")] as $containers
    | select(.metadata.deletionTimestamp == null)
    | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
    | select(($containers | length) == 1)
    | $containers[0] as $container
    | select($container.ready == true and $container.state.running != null)
    | select(.metadata.uid | type == "string" and length > 0)
    | select($container.containerID | type == "string" and length > 0)
    | select($container.restartCount | type == "number")
    | [.metadata.uid, $container.containerID, ($container.restartCount | tostring)]
    | @tsv
  ' <<<"${pod_json}"
}

admin_tls_handshake_failure_count() {
  local pod="$1"
  local count
  local logs

  logs="$(kube -n "${namespace}" logs "pod/${pod}" -c oxibelt 2>/dev/null)" || return 1
  count="$(grep -Fc "admin TLS handshake failed" <<<"${logs}" || true)"
  [[ "${count}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${count}"
}

admin_tls_rejection_observed() {
  local pod="$1"
  local before="$2"
  local after

  after="$(admin_tls_handshake_failure_count "${pod}")" || return 1
  ((10#${after} > 10#${before}))
}

verify_admin_immutable_secret_boundary() {
  local port="$1"
  local capabilities="${work_dir}/admin-capabilities.json"
  local status_before="${work_dir}/admin-config-status-before.json"
  local status_after="${work_dir}/admin-config-status-after.json"
  local request="${work_dir}/admin-secret-reference-request.json"
  local response_body="${work_dir}/admin-secret-reference-response.json"
  local response_headers="${work_dir}/admin-secret-reference-response.headers"
  local state_before
  local state_after
  local etag
  local http_status

  admin_get_json "${port}" "/admin/v1/capabilities" "${capabilities}"
  jq -e '.features.atomic_secret_reference_activation == false' "${capabilities}" >/dev/null \
    || die "Admin capabilities must disable atomic secret-reference activation in immutable rollout mode"

  admin_get_json "${port}" "/admin/v1/config/status" "${status_before}"
  state_before="$(jq -cer '
    select(.revision | type == "number")
    | select(.etag | type == "string" and test("^\\\"oxibelt-config-[1-9][0-9]*\\\"$"))
    | select(.rollout.rollout_mode == "kubernetes_immutable")
    | select(.rollout.apply_state == "applied")
    | {
        revision,
        etag,
        rollout: {
          rollout_mode: .rollout.rollout_mode,
          desired_revision: .rollout.desired_revision,
          applied_revision: .rollout.applied_revision,
          digest: .rollout.digest,
          apply_state: .rollout.apply_state
        }
      }
  ' "${status_before}")" \
    || die "Admin config status did not expose a valid applied immutable rollout identity"
  etag="$(jq -er '.etag' "${status_before}")" \
    || die "Admin config status did not expose a strong config ETag"

  jq -n \
    '{
      schema_version: 1,
      field: "tls.remote_signer.token_env",
      reference: "OXIBELT_IMMUTABLE_PROBE_UNUSED"
    }' >"${request}"
  http_status="$(curl --silent --show-error --max-time 5 --tlsv1.3 \
    --resolve "${admin_server_name}:${port}:127.0.0.1" \
    --cacert "${work_dir}/admin-server-ca.crt" \
    --cert "${work_dir}/admin-client.crt" \
    --key "${work_dir}/admin-client.key" \
    --header "@${work_dir}/admin-headers.txt" \
    --header "Content-Type: application/json" \
    --header "If-Match: ${etag}" \
    --request POST \
    --data-binary "@${request}" \
    --dump-header "${response_headers}" \
    --output "${response_body}" \
    --write-out '%{http_code}' \
    "https://${admin_server_name}:${port}/admin/v1/config/secret-references/update")" \
    || die "Admin immutable secret-reference probe did not complete"
  [[ "${http_status}" == "409" ]] \
    || die "immutable secret-reference activation returned HTTP ${http_status}, expected 409"
  jq -e '.error.code == "immutable_rollout_conflict"' "${response_body}" >/dev/null \
    || die "immutable secret-reference activation did not return immutable_rollout_conflict"
  if grep -Fq "OXIBELT_IMMUTABLE_PROBE_UNUSED" "${response_body}" "${response_headers}" \
    || grep -Fq -f "${work_dir}/admin-token" "${response_body}" "${response_headers}"; then
    die "immutable secret-reference rejection leaked request reference or bearer material"
  fi

  admin_get_json "${port}" "/admin/v1/config/status" "${status_after}"
  state_after="$(jq -cer '
    {
      revision,
      etag,
      rollout: {
        rollout_mode: .rollout.rollout_mode,
        desired_revision: .rollout.desired_revision,
        applied_revision: .rollout.applied_revision,
        digest: .rollout.digest,
        apply_state: .rollout.apply_state
      }
    }
  ' "${status_after}")" \
    || die "Admin config status became invalid after immutable mutation rejection"
  [[ "${state_after}" == "${state_before}" ]] \
    || die "immutable secret-reference rejection changed config revision or rollout identity"
}

verify_admin_mtls() {
  local pod="$1"
  local port="$2"
  local url="https://${admin_server_name}:${port}/admin/v1/openapi.json"
  local identity_before
  local identity_after
  local tls_failures_before

  identity_before="$(admin_pod_runtime_identity "${pod}")" \
    || die "selected Admin probe Pod is not Ready with a stable OxiBelt container identity: ${pod}"

  start_admin_port_forward "${pod}" "${port}" authenticated-before-rejection
  admin_endpoint_accepts_client "${port}" \
    || die "Admin listener rejected the configured mTLS client and bearer token before the rejection probe"
  verify_admin_immutable_secret_boundary "${port}"
  stop_admin_port_forward

  tls_failures_before="$(admin_tls_handshake_failure_count "${pod}")" \
    || die "could not read the selected Admin probe Pod logs: ${pod}"
  start_admin_port_forward "${pod}" "${port}" no-client-certificate

  # Deliberately omit --fail: any completed HTTP exchange, including a 4xx,
  # means the unauthenticated client crossed the mTLS trust boundary.
  if curl --silent --show-error --max-time 5 --tlsv1.3 \
    --resolve "${admin_server_name}:${port}:127.0.0.1" \
    --cacert "${work_dir}/admin-server-ca.crt" \
    --header "@${work_dir}/admin-headers.txt" \
    "${url}" \
    >/dev/null 2>"${work_dir}/admin-no-client-certificate-curl.log"; then
    die "Admin listener completed an HTTP exchange without a client certificate"
  fi
  wait_for "Admin TLS handshake rejection without a client certificate" 30 \
    admin_tls_rejection_observed "${pod}" "${tls_failures_before}"
  stop_admin_port_forward

  start_admin_port_forward "${pod}" "${port}" authenticated-after-rejection
  admin_endpoint_accepts_client "${port}" \
    || die "Admin listener did not recover after rejecting a client without a certificate"
  stop_admin_port_forward

  identity_after="$(admin_pod_runtime_identity "${pod}")" \
    || die "selected Admin probe Pod lost its Ready OxiBelt container identity: ${pod}"
  [[ "${identity_after}" == "${identity_before}" ]] \
    || die "Admin mTLS probes changed the selected Pod UID, OxiBelt container ID, or restart count: ${pod}"
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

stale_config_pod_failed_closed() {
  local pod="$1"
  local pod_json
  pod_json="$(kube -n "${namespace}" get pod "${pod}" -o json 2>/dev/null)" || return 1

  jq -e '
    .status.phase == "Failed"
      and all(.status.conditions[]?; .type != "Ready" or .status != "True")
      and any(.status.containerStatuses[]?;
        .name == "oxibelt"
          and (.restartCount // 0) == 0
          and .state.terminated.reason == "Error"
          and (.state.terminated.exitCode // 0) != 0)
  ' >/dev/null <<<"${pod_json}"
}

stale_config_pod_reports_digest_mismatch() {
  local pod="$1"
  local logs

  logs="$(kube -n "${namespace}" logs "pod/${pod}" -c oxibelt 2>/dev/null)" || return 1
  grep -Fq \
    "OXIBELT_CONFIG_DIGEST does not match the exact bytes of OXIBELT_CONFIG_REVISION_FILE" \
    <<<"${logs}"
}

verify_cross_namespace_l4_reference_grants() {
  local denied_revision
  local previous_revision

  # Switch to the chart's explicit cluster-wide mode only after the scoped-RBAC
  # and leader-replacement checks have completed. The controller still has no
  # Secret access and receives only the reads needed for ReferenceGrant.
  helm upgrade "${controller_release}" "${repo_root}/deploy/helm/oxibelt-gateway-controller" \
    --namespace "${namespace}" \
    -f "${controller_image_values}" \
    --set "watchAllNamespaces=true" \
    --set "l4.idleTimeoutMs=3600000" \
    --set-string "l4.udp.flowState=shared_required" \
    --set-string "managedConfigPath=${managed_config_path}" \
    --set-string "statusService=${namespace}/${workload_name}" \
    --set-string "statusAddresses[0]=${status_service_address}" \
    --set-string "rollout.target.namespace=${namespace}" \
    --set-string "rollout.target.kind=deployment" \
    --set-string "rollout.target.name=${workload_name}" \
    --set-string "rollout.target.containerName=oxibelt" \
    --set-string "rollout.volumeName=gateway-config" \
    --set "rollout.timeoutSeconds=300" \
    --set-string "rollout.configMapPrefix=oxibelt-gateway-config" \
    --wait \
    --timeout "${rollout_timeout_seconds}s"

  assert_controller_can_i no get secrets --namespace "${outside_namespace}"
  assert_controller_can_i no list secrets --namespace "${outside_namespace}"

  kube -n "${outside_namespace}" apply -f - >/dev/null <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: tcp-backend
spec:
  selector:
    app: tcp-backend
  ports:
  - name: tcp
    protocol: TCP
    port: 3000
    targetPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: udp-backend
spec:
  selector:
    app: udp-backend
  ports:
  - name: udp
    protocol: UDP
    port: 8080
    targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tcp-backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tcp-backend
  template:
    metadata:
      labels:
        app: tcp-backend
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: echo
        image: registry.k8s.io/gateway-api/echo-basic:v1.6.0-dev.2@sha256:5dd376a93d8ec7cb8c15b46973bdb1c686db48135058d2606f2e0cf30f8dd63d
        imagePullPolicy: IfNotPresent
        env:
        - { name: TCP_ECHO_SERVER, value: "1" }
        - { name: SERVICE_NAME, value: tcp-backend }
        - name: NAMESPACE
          valueFrom: { fieldRef: { fieldPath: metadata.namespace } }
        - name: POD_NAME
          valueFrom: { fieldRef: { fieldPath: metadata.name } }
        securityContext:
          allowPrivilegeEscalation: false
          capabilities: { drop: ["ALL"] }
          readOnlyRootFilesystem: true
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: udp-backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: udp-backend
  template:
    metadata:
      labels:
        app: udp-backend
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: echo
        image: registry.k8s.io/gateway-api/echo-basic:v1.6.0-dev.2@sha256:5dd376a93d8ec7cb8c15b46973bdb1c686db48135058d2606f2e0cf30f8dd63d
        imagePullPolicy: IfNotPresent
        env:
        - { name: UDP_ECHO_SERVER, value: "1" }
        - { name: UDP_PORT, value: "8080" }
        - { name: SERVICE_NAME, value: udp-backend }
        - name: NAMESPACE
          valueFrom: { fieldRef: { fieldPath: metadata.namespace } }
        - name: POD_NAME
          valueFrom: { fieldRef: { fieldPath: metadata.name } }
        securityContext:
          allowPrivilegeEscalation: false
          capabilities: { drop: ["ALL"] }
          readOnlyRootFilesystem: true
EOF

  kube -n "${outside_namespace}" rollout status deployment/tcp-backend --timeout=120s
  kube -n "${outside_namespace}" rollout status deployment/udp-backend --timeout=120s

  previous_revision="$(kube -n "${namespace}" get deployment "${workload_name}" \
    -o jsonpath='{.metadata.annotations.oxibelt\.dev/gateway-config-committed}')"
  [[ "${previous_revision}" =~ ^oxibelt-gateway-config-deployment-oxibelt-[a-f0-9]{64}$ ]] \
    || die "pre-ReferenceGrant rollout did not expose a committed immutable revision"
  kube -n "${namespace}" patch tcproute tcp-probe --type=merge \
    --patch "{\"spec\":{\"rules\":[{\"backendRefs\":[{\"name\":\"tcp-backend\",\"namespace\":\"${outside_namespace}\",\"port\":3000}]}]}}" >/dev/null
  kube -n "${namespace}" patch udproute udp-probe --type=merge \
    --patch "{\"spec\":{\"rules\":[{\"backendRefs\":[{\"name\":\"udp-backend\",\"namespace\":\"${outside_namespace}\",\"port\":8080}]}]}}" >/dev/null
  wait_for "cross-namespace L4 routes rejected without ReferenceGrant" 60 l4_routes_are_unresolved
  wait_for "fail-closed immutable revision without ReferenceGrant" \
    "${rollout_timeout_seconds}" deployment_committed_revision_changed "${previous_revision}"
  wait_for "L4 listeners removed without ReferenceGrant" 60 l4_ports_fail_closed
  denied_revision="$(kube -n "${namespace}" get deployment "${workload_name}" \
    -o jsonpath='{.metadata.annotations.oxibelt\.dev/gateway-config-committed}')"
  [[ "${denied_revision}" =~ ^oxibelt-gateway-config-deployment-oxibelt-[a-f0-9]{64}$ ]] \
    || die "denied ReferenceGrant rollout did not expose a committed immutable revision"

  kube -n "${outside_namespace}" apply -f - >/dev/null <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: ReferenceGrant
metadata:
  name: oxibelt-tcp-probe
spec:
  from:
  - group: gateway.networking.k8s.io
    kind: TCPRoute
    namespace: ${namespace}
  to:
  - group: ""
    kind: Service
    name: tcp-backend
---
apiVersion: gateway.networking.k8s.io/v1
kind: ReferenceGrant
metadata:
  name: oxibelt-udp-probe
spec:
  from:
  - group: gateway.networking.k8s.io
    kind: UDPRoute
    namespace: ${namespace}
  to:
  - group: ""
    kind: Service
    name: udp-backend
EOF

  wait_for "cross-namespace L4 routes programmed by ReferenceGrant" \
    "${rollout_timeout_seconds}" l4_routes_are_programmed
  wait_for "cross-namespace L4 immutable rollout commit" \
    "${rollout_timeout_seconds}" deployment_committed_revision_changed "${denied_revision}"
  kube -n "${namespace}" rollout status "deployment/${workload_name}" \
    --timeout "${rollout_timeout_seconds}s"
  wait_for "cross-namespace TCP and UDP round trips" 60 \
    probe_l4_round_trips "${outside_namespace}"
}

assert_controller_can_i() {
  local expected="$1"
  shift
  local subject="system:serviceaccount:${namespace}:${controller_release}"

  if kube auth can-i --quiet --as="${subject}" "$@"; then
    [[ "${expected}" == "yes" ]] \
      || die "controller ServiceAccount unexpectedly has permission: $*"
  else
    [[ "${expected}" == "no" ]] \
      || die "controller ServiceAccount lacks required permission: $*"
  fi
}

for command in docker kind kubectl helm curl jq openssl sed sha256sum tail tr; do
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
[[ "${redis_source_digest}" =~ ^[a-f0-9]{64}$ ]] \
  || die "the reviewed Valkey source image must use an exact sha256 manifest digest"
redis_kind_image="oxibelt-ci/valkey:sha256-${redis_source_digest}-${run_id}"
[[ "${redis_kind_image}" =~ ^oxibelt-ci/valkey:sha256-[a-f0-9]{64}-[a-f0-9]{24}$ ]] \
  || die "failed to derive a safe Kind-local Valkey image alias"
cluster_name="oxibelt-rollout-${run_id}"
namespace="oxibelt-rollout-${run_id}"
outside_namespace="oxibelt-outside-${run_id}"
work_dir="${repo_root}/tests/.tmp/kubernetes-immutable-rollout-${run_id}"
admin_server_name="${admin_service_name}.${namespace}.svc"

[[ -n "${OXIBELT_DATAPLANE_DOCKER_IMAGE:-}" ]] \
  || die "OXIBELT_DATAPLANE_DOCKER_IMAGE must name the locally loaded data-plane image"
dataplane_image="${OXIBELT_DATAPLANE_DOCKER_IMAGE}"
[[ "${dataplane_image}" =~ ^[a-z0-9][a-z0-9._-]*(:[0-9]{1,5})?(/[a-z0-9][a-z0-9._-]*)*:[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || die "OXIBELT_DATAPLANE_DOCKER_IMAGE must be a lower-case local repository:tag without Helm metacharacters"
dataplane_image_repository="${dataplane_image%:*}"
dataplane_image_tag="${dataplane_image##*:}"
[[ -n "${dataplane_image_repository}" && -n "${dataplane_image_tag}" ]] \
  || die "OXIBELT_DATAPLANE_DOCKER_IMAGE must include non-empty repository and tag"

[[ -n "${OXIBELT_GATEWAY_CONTROLLER_DOCKER_IMAGE:-}" ]] \
  || die "OXIBELT_GATEWAY_CONTROLLER_DOCKER_IMAGE must name the locally loaded controller image"
controller_image="${OXIBELT_GATEWAY_CONTROLLER_DOCKER_IMAGE}"
[[ "${controller_image}" =~ ^[a-z0-9][a-z0-9._-]*(:[0-9]{1,5})?(/[a-z0-9][a-z0-9._-]*)*:[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || die "OXIBELT_GATEWAY_CONTROLLER_DOCKER_IMAGE must be a lower-case local repository:tag without Helm metacharacters"
controller_image_repository="${controller_image%:*}"
controller_image_tag="${controller_image##*:}"
[[ -n "${controller_image_repository}" && -n "${controller_image_tag}" ]] \
  || die "OXIBELT_GATEWAY_CONTROLLER_DOCKER_IMAGE must include non-empty repository and tag"
[[ "${dataplane_image}" != "${controller_image}" ]] \
  || die "data-plane and controller tests require distinct role image references"

# This verifies the configured Docker endpoint before Kind delegates image and
# cluster lifecycle operations to the normal `docker` command.
docker version --format '{{.Server.Version}}' >/dev/null
docker image inspect "${dataplane_image}" >/dev/null
docker image inspect "${controller_image}" >/dev/null
docker pull "${redis_source_image}" >/dev/null
docker image inspect "${redis_source_image}" >/dev/null
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${redis_source_image}" \
  | grep -Fqx "valkey/valkey@${redis_source_image##*@}" \
  || die "rootless Docker did not retain the exact reviewed Valkey repo digest"
[[ "$(docker image inspect --format '{{.Architecture}}/{{.Os}}' "${redis_source_image}")" == "amd64/linux" ]] \
  || die "the Kubernetes qualification requires the reviewed linux/amd64 Valkey image"
redis_source_image_id="$(docker image inspect --format '{{.Id}}' "${redis_source_image}")"
if docker image inspect "${redis_kind_image}" >/dev/null 2>&1; then
  die "refusing to reuse an existing Kind-local Valkey image alias: ${redis_kind_image}"
fi
redis_kind_image_created=1
docker tag "${redis_source_image}" "${redis_kind_image}"
[[ "$(docker image inspect --format '{{.Id}}' "${redis_kind_image}")" == "${redis_source_image_id}" ]] \
  || die "rootless Docker did not create the reviewed Valkey Kind alias"
dataplane_effective_version="$(docker image inspect \
  --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' \
  "${dataplane_image}")"
controller_effective_version="$(docker image inspect \
  --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' \
  "${controller_image}")"
semver_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
[[ "${dataplane_effective_version}" =~ ${semver_pattern} ]] \
  || die "data-plane image must declare a valid org.opencontainers.image.version SemVer label"
[[ "${controller_effective_version}" =~ ${semver_pattern} ]] \
  || die "controller image must declare a valid org.opencontainers.image.version SemVer label"
[[ "${dataplane_effective_version}" == "${controller_effective_version}" ]] \
  || die "exact compatibility mode requires identical data-plane and controller image versions"

if kind get clusters | grep -Fqx "${cluster_name}"; then
  die "refusing to reuse an existing Kind cluster named ${cluster_name}"
fi

mkdir -p "${work_dir}"
gateway_api_manifest="${work_dir}/gateway-api-${gateway_api_version}.yaml"
dataplane_image_values="${work_dir}/dataplane-image-values.yaml"
controller_image_values="${work_dir}/controller-image-values.yaml"
printf 'effectiveVersion: "%s"\nimage:\n  repository: "%s"\n  tag: "%s"\n  pullPolicy: "IfNotPresent"\n' \
  "${dataplane_effective_version}" "${dataplane_image_repository}" "${dataplane_image_tag}" \
  >"${dataplane_image_values}"
printf 'effectiveVersion: "%s"\nimage:\n  repository: "%s"\n  tag: "%s"\n  pullPolicy: "IfNotPresent"\n' \
  "${controller_effective_version}" "${controller_image_repository}" "${controller_image_tag}" \
  >"${controller_image_values}"

external_base_bootstrap_is_unassigned Deployment templates/deployment.yaml \
  || die "external ConfigMap Deployment bootstrap must remain unassigned until controller reconciliation"
external_base_bootstrap_is_unassigned DaemonSet templates/daemonset.yaml \
  || die "external ConfigMap DaemonSet bootstrap must remain unassigned until controller reconciliation"

kind create cluster \
  --name "${cluster_name}" \
  --image "${kind_node_image}" \
  --wait 120s
cluster_created=1
verify_kind_node_l4_probe_runtime

kind load docker-image --name "${cluster_name}" \
  "${dataplane_image}" "${controller_image}" "${redis_kind_image}"
docker exec "${cluster_name}-control-plane" \
  crictl inspecti "docker.io/${redis_kind_image}" >/dev/null \
  || die "Kind CRI did not retain the reviewed Valkey image alias"

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
  crd/referencegrants.gateway.networking.k8s.io \
  crd/tcproutes.gateway.networking.k8s.io \
  crd/udproutes.gateway.networking.k8s.io \
  crd/backendtlspolicies.gateway.networking.k8s.io

kube create namespace "${namespace}" >/dev/null
kube create namespace "${outside_namespace}" >/dev/null
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
openssl rand -hex 32 | tr -d '\r\n' >"${work_dir}/admin-token"
grep -Eq '^[a-f0-9]{64}$' "${work_dir}/admin-token" \
  || die "failed to generate a safe Admin token"
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

openssl rand -base64 32 | tr -d '\r\n' >"${work_dir}/udp-flow-identity-key"
grep -Eq '^[A-Za-z0-9+/]{43}=$' "${work_dir}/udp-flow-identity-key" \
  || die "failed to generate an exact 32-byte base64 UDP flow identity key"
kube -n "${namespace}" create secret generic oxibelt-udp-flow-state \
  --from-file=identity-key="${work_dir}/udp-flow-identity-key" \
  >/dev/null

sed "s|OXIBELT_REDIS_KIND_IMAGE|${redis_kind_image}|g" <<'EOF' \
  | kube -n "${namespace}" apply -f - >/dev/null
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
apiVersion: v1
kind: Service
metadata:
  name: tcp-backend
spec:
  selector:
    app: tcp-backend
  ports:
  - name: tcp
    protocol: TCP
    port: 3000
    targetPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: oxibelt-udp-flow-redis
spec:
  selector:
    app: oxibelt-udp-flow-redis
  ports:
  - name: redis
    protocol: TCP
    port: 6379
    targetPort: redis
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oxibelt-udp-flow-redis
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: oxibelt-udp-flow-redis
  template:
    metadata:
      labels:
        app: oxibelt-udp-flow-redis
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 999
        runAsGroup: 999
        fsGroup: 999
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: redis
        image: OXIBELT_REDIS_KIND_IMAGE
        imagePullPolicy: Never
        command: ["valkey-server"]
        args:
        - --save
        - ""
        - --appendonly
        - "no"
        - --maxmemory
        - 32mb
        - --maxmemory-policy
        - noeviction
        - --protected-mode
        - "no"
        ports:
        - { name: redis, containerPort: 6379, protocol: TCP }
        startupProbe:
          tcpSocket: { port: redis }
          periodSeconds: 1
          failureThreshold: 60
        readinessProbe:
          tcpSocket: { port: redis }
          periodSeconds: 2
          failureThreshold: 3
        livenessProbe:
          tcpSocket: { port: redis }
          periodSeconds: 10
          failureThreshold: 3
        resources:
          requests: { cpu: 25m, memory: 32Mi }
          limits: { cpu: 250m, memory: 96Mi }
        securityContext:
          allowPrivilegeEscalation: false
          capabilities: { drop: ["ALL"] }
          readOnlyRootFilesystem: true
        volumeMounts:
        - { name: data, mountPath: /data }
      volumes:
      - name: data
        emptyDir: { sizeLimit: 16Mi }
---
apiVersion: v1
kind: Service
metadata:
  name: udp-backend-a
spec:
  selector:
    app: udp-backend-a
  ports:
  - name: udp
    protocol: UDP
    port: 8080
    targetPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: udp-backend-b
spec:
  selector:
    app: udp-backend-b
  ports:
  - name: udp
    protocol: UDP
    port: 8080
    targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tcp-backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tcp-backend
  template:
    metadata:
      labels:
        app: tcp-backend
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: echo
        image: registry.k8s.io/gateway-api/echo-basic:v1.6.0-dev.2@sha256:5dd376a93d8ec7cb8c15b46973bdb1c686db48135058d2606f2e0cf30f8dd63d
        imagePullPolicy: IfNotPresent
        env:
        - { name: TCP_ECHO_SERVER, value: "1" }
        - { name: SERVICE_NAME, value: tcp-backend }
        - name: NAMESPACE
          valueFrom: { fieldRef: { fieldPath: metadata.namespace } }
        - name: POD_NAME
          valueFrom: { fieldRef: { fieldPath: metadata.name } }
        securityContext:
          allowPrivilegeEscalation: false
          capabilities: { drop: ["ALL"] }
          readOnlyRootFilesystem: true
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: udp-backend-a
spec:
  replicas: 1
  selector:
    matchLabels:
      app: udp-backend-a
  template:
    metadata:
      labels:
        app: udp-backend-a
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: echo
        image: registry.k8s.io/gateway-api/echo-basic:v1.6.0-dev.2@sha256:5dd376a93d8ec7cb8c15b46973bdb1c686db48135058d2606f2e0cf30f8dd63d
        imagePullPolicy: IfNotPresent
        env:
        - { name: UDP_ECHO_SERVER, value: "1" }
        - { name: UDP_PORT, value: "8080" }
        - { name: SERVICE_NAME, value: udp-backend-a }
        - name: NAMESPACE
          valueFrom: { fieldRef: { fieldPath: metadata.namespace } }
        - name: POD_NAME
          valueFrom: { fieldRef: { fieldPath: metadata.name } }
        securityContext:
          allowPrivilegeEscalation: false
          capabilities: { drop: ["ALL"] }
          readOnlyRootFilesystem: true
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: udp-backend-b
spec:
  replicas: 1
  selector:
    matchLabels:
      app: udp-backend-b
  template:
    metadata:
      labels:
        app: udp-backend-b
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: echo
        image: registry.k8s.io/gateway-api/echo-basic:v1.6.0-dev.2@sha256:5dd376a93d8ec7cb8c15b46973bdb1c686db48135058d2606f2e0cf30f8dd63d
        imagePullPolicy: IfNotPresent
        env:
        - { name: UDP_ECHO_SERVER, value: "1" }
        - { name: UDP_PORT, value: "8080" }
        - { name: SERVICE_NAME, value: udp-backend-b }
        - name: NAMESPACE
          valueFrom: { fieldRef: { fieldPath: metadata.namespace } }
        - name: POD_NAME
          valueFrom: { fieldRef: { fieldPath: metadata.name } }
        securityContext:
          allowPrivilegeEscalation: false
          capabilities: { drop: ["ALL"] }
          readOnlyRootFilesystem: true
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
  - name: tcp-probe
    protocol: TCP
    port: 9300
  - name: udp-probe
    protocol: UDP
    port: 5300
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
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata:
  name: tcp-probe
spec:
  parentRefs:
  - name: edge
    sectionName: tcp-probe
  rules:
  - backendRefs:
    - name: tcp-backend
      port: 3000
---
apiVersion: gateway.networking.k8s.io/v1
kind: UDPRoute
metadata:
  name: udp-probe
spec:
  parentRefs:
  - name: edge
    sectionName: udp-probe
  rules:
  - backendRefs:
    - name: udp-backend-a
      port: 8080
    - name: udp-backend-b
      port: 8080
EOF

kube -n "${namespace}" rollout status deployment/oxibelt-udp-flow-redis --timeout=120s
kube -n "${namespace}" rollout status deployment/tcp-backend --timeout=120s
kube -n "${namespace}" rollout status deployment/udp-backend-a --timeout=120s
kube -n "${namespace}" rollout status deployment/udp-backend-b --timeout=120s

helm upgrade --install "${data_release}" "${repo_root}/deploy/helm/oxibelt" \
  --namespace "${namespace}" \
  -f "${dataplane_image_values}" \
  -f "${repo_root}/deploy/helm/oxibelt/examples/admin-mtls-values.yaml" \
  -f "${repo_root}/tests/fixtures/gateway-api-l4-values.yaml" \
  --set "replicaCount=3" \
  --set "service.type=ClusterIP" \
  --set-string "admin.tls.serverNames[0]=${admin_server_name}" \
  --set-string "configRollout.mode=kubernetes_immutable" \
  --set-string "configRollout.managedConfigPath=${managed_config_path}"

# Prove the chart-owned bootstrap identity before the controller exists. The
# default Gateway base config intentionally has no routes, so these Pods may
# remain unready until the controller assigns generated configuration; that
# fail-closed behavior must not be weakened by the rollout harness.
bootstrap_deployment_json="$(kube -n "${namespace}" get deployment "${workload_name}" -o json)"
jq -e '
  any(.spec.template.spec.containers[]?;
    .name == "oxibelt"
      and ([.env[]? | select(.name == "OXIBELT_UDP_FLOW_IDENTITY_KEY")] | length) == 1
      and any(.env[]?;
        .name == "OXIBELT_UDP_FLOW_IDENTITY_KEY"
          and (has("value") | not)
          and .valueFrom.secretKeyRef.name == "oxibelt-udp-flow-state"
          and .valueFrom.secretKeyRef.key == "identity-key"))
' >/dev/null <<<"${bootstrap_deployment_json}" \
  || die "data-plane workload must receive the UDP flow identity only through the focused Secret reference"
bootstrap_revision="$(jq -r '.spec.template.metadata.annotations["oxibelt.dev/config-revision"] // empty' \
  <<<"${bootstrap_deployment_json}")"
bootstrap_digest="$(jq -r '.spec.template.metadata.annotations["oxibelt.dev/config-digest"] // empty' \
  <<<"${bootstrap_deployment_json}")"
[[ "${bootstrap_revision}" =~ ^oxibelt-config-[a-f0-9]{12}$ ]] \
  || die "bootstrap workload did not identify the chart-owned immutable base ConfigMap"
[[ "${bootstrap_digest}" == "${empty_config_digest}" ]] \
  || die "bootstrap workload digest must prove the empty managed configuration placeholder"

jq -e \
  --arg revision "${bootstrap_revision}" \
  --arg digest "${empty_config_digest}" \
  --arg managed_path "${managed_config_path}" '
  .spec.template.metadata.annotations["oxibelt.dev/config-revision"] == $revision
  and .spec.template.metadata.annotations["oxibelt.dev/config-digest"] == $digest
  and any(.spec.template.spec.volumes[]?;
    .name == "config"
      and .configMap.name == $revision
      and .configMap.items == [
        {"key": "oxibelt.toml", "path": "oxibelt.toml"},
        {"key": "gateway-config-directory", "path": "conf.d/.keep"},
        {"key": "gateway-config-directory", "path": $managed_path}
      ])
  and any(.spec.template.spec.containers[]?;
    .name == "oxibelt"
      and any(.volumeMounts[]?;
        .name == "config"
          and .mountPath == "/etc/oxibelt/config"
          and .readOnly == true
          and (has("subPath") | not)))
' >/dev/null <<<"${bootstrap_deployment_json}" \
  || die "bootstrap workload must mount the direct immutable base ConfigMap and exact empty placeholder"

jq -e '
  .spec.template.spec.automountServiceAccountToken == false
    and all(.spec.template.spec.volumes[]?; .name != "kube-api-access")
    and all(.spec.template.spec.containers[]?;
      all(.volumeMounts[]?; .name != "kube-api-access"))
' >/dev/null <<<"${bootstrap_deployment_json}" \
  || die "default data-plane Pod template must not mount a Kubernetes API credential"

bootstrap_config_map_json="$(kube -n "${namespace}" get configmap "${bootstrap_revision}" -o json)"
jq -e --arg revision "${bootstrap_revision}" '
  .metadata.name == $revision
    and .immutable == true
    and .data["gateway-config-directory"] == ""
' >/dev/null <<<"${bootstrap_config_map_json}" \
  || die "bootstrap ConfigMap must be immutable and contain the empty compatibility sentinel"

wait_for "three bootstrap Pods with the base revision and empty digest" 60 \
  bootstrap_pods_have_identity "${bootstrap_revision}" "${empty_config_digest}"

status_service_address="$(kube -n "${namespace}" get service "${workload_name}" -o jsonpath='{.spec.clusterIP}')"
[[ "${status_service_address}" =~ ^[0-9a-fA-F:.]+$ ]] \
  || die "data-plane Service did not expose a valid L4 probe address"

helm upgrade --install "${controller_release}" "${repo_root}/deploy/helm/oxibelt-gateway-controller" \
  --namespace "${namespace}" \
  -f "${controller_image_values}" \
  --set "l4.idleTimeoutMs=3600000" \
  --set-string "l4.udp.flowState=shared_required" \
  --set-string "managedConfigPath=${managed_config_path}" \
  --set-string "watchNamespace=${namespace}" \
  --set-string "statusService=${namespace}/${workload_name}" \
  --set-string "statusAddresses[0]=${status_service_address}" \
  --set-string "rollout.target.namespace=${namespace}" \
  --set-string "rollout.target.kind=deployment" \
  --set-string "rollout.target.name=${workload_name}" \
  --set-string "rollout.target.containerName=oxibelt" \
  --set-string "rollout.volumeName=gateway-config" \
  --set "rollout.timeoutSeconds=300" \
  --set-string "rollout.configMapPrefix=oxibelt-gateway-config" \
  --wait \
  --timeout "${rollout_timeout_seconds}s"

controller_deployment_json="$(kube -n "${namespace}" get deployment "${controller_release}" -o json)"
jq -e '
  .spec.template.spec.automountServiceAccountToken == false
    and .spec.template.spec.securityContext.fsGroup == 10001
    and any(.spec.template.spec.containers[]?;
      .name == "controller"
        and any(.volumeMounts[]?;
          .name == "kube-api-access"
            and .mountPath == "/var/run/secrets/kubernetes.io/serviceaccount"
            and .readOnly == true))
    and any(.spec.template.spec.volumes[]?;
      .name == "kube-api-access"
        and .projected.defaultMode == 288
        and any(.projected.sources[]?;
          .serviceAccountToken.expirationSeconds == 3600
            and .serviceAccountToken.path == "token")
        and any(.projected.sources[]?;
          .configMap.name == "kube-root-ca.crt"
            and .configMap.items == [{"key": "ca.crt", "path": "ca.crt"}]))
' >/dev/null <<<"${controller_deployment_json}" \
  || die "controller Pod template must use only the bounded explicit Kubernetes API credential projection"

controller_pod="$(kube -n "${namespace}" get pods -l "${controller_selector}" -o json \
  | jq -r '.items | map(select(.metadata.deletionTimestamp == null)) | .[0].metadata.name // empty')"
[[ -n "${controller_pod}" ]] || die "controller Deployment did not create a live Pod"

# The scoped controller identity has only the reads and status/rollout writes
# exercised by its reconciliation loop. These checks intentionally use API
# authorization rather than inspecting RBAC text so forbidden access cannot
# silently reappear through a binding change.
assert_controller_can_i yes list gatewayclasses.gateway.networking.k8s.io
assert_controller_can_i yes patch gatewayclasses.gateway.networking.k8s.io --subresource=status
assert_controller_can_i yes get "namespaces/${namespace}"
assert_controller_can_i yes list gateways.gateway.networking.k8s.io --namespace "${namespace}"
assert_controller_can_i yes list httproutes.gateway.networking.k8s.io --namespace "${namespace}"
assert_controller_can_i yes list services --namespace "${namespace}"
assert_controller_can_i yes get configmaps --namespace "${namespace}"
assert_controller_can_i yes create configmaps --namespace "${namespace}"
assert_controller_can_i yes list pods --namespace "${namespace}"
assert_controller_can_i yes list replicasets.apps --namespace "${namespace}"
assert_controller_can_i yes get "deployments.apps/${workload_name}" --namespace "${namespace}"
assert_controller_can_i yes patch "deployments.apps/${workload_name}" --namespace "${namespace}"
assert_controller_can_i yes get "leases.coordination.k8s.io/${leader_lease_name}" --namespace "${namespace}"
assert_controller_can_i yes watch "leases.coordination.k8s.io/${leader_lease_name}" --namespace "${namespace}"
assert_controller_can_i yes patch "leases.coordination.k8s.io/${leader_lease_name}" --namespace "${namespace}"
assert_controller_can_i no create leases.coordination.k8s.io --namespace "${namespace}"
assert_controller_can_i no delete "leases.coordination.k8s.io/${leader_lease_name}" --namespace "${namespace}"
assert_controller_can_i no patch leases.coordination.k8s.io/not-the-controller --namespace "${namespace}"
assert_controller_can_i no get "leases.coordination.k8s.io/${leader_lease_name}" --namespace "${outside_namespace}"
assert_controller_can_i no list namespaces
assert_controller_can_i no get "namespaces/${outside_namespace}"
assert_controller_can_i no watch gatewayclasses.gateway.networking.k8s.io
assert_controller_can_i no update gatewayclasses.gateway.networking.k8s.io --subresource=status
assert_controller_can_i no get secrets --namespace "${namespace}"
assert_controller_can_i no list secrets --namespace "${namespace}"
assert_controller_can_i no get services --namespace "${namespace}"
assert_controller_can_i no create services --namespace "${namespace}"
assert_controller_can_i no patch services --namespace "${namespace}"
assert_controller_can_i no update services --namespace "${namespace}"
assert_controller_can_i no delete services --namespace "${namespace}"
assert_controller_can_i no delete configmaps --namespace "${namespace}"
assert_controller_can_i no delete pods --namespace "${namespace}"
assert_controller_can_i no patch deployments.apps/not-the-target --namespace "${namespace}"
assert_controller_can_i no list gateways.gateway.networking.k8s.io --namespace "${outside_namespace}"

kube -n "${namespace}" rollout status "deployment/${workload_name}" \
  --timeout "${rollout_timeout_seconds}s"
wait_for "committed immutable workload state" "${rollout_timeout_seconds}" deployment_is_committed
wait_for "Gateway Programmed=True after full rollout convergence" "${rollout_timeout_seconds}" gateway_is_programmed
wait_for "same-namespace TCPRoute and UDPRoute programming" \
  "${rollout_timeout_seconds}" l4_routes_are_programmed
wait_for "same-namespace TCP and UDP round trips" 60 \
  probe_l4_round_trips "${namespace}" paired
verify_udp_flow_survives_data_plane_rollout
wait_for "two Ready controller replicas" 60 controller_has_two_ready_replicas
wait_for "one live Lease holder among two simultaneous replicas" 60 lease_has_live_unique_holder

pdb_json="$(kube -n "${namespace}" get poddisruptionbudget "${controller_release}" -o json)"
jq -e '
  .spec.minAvailable == 1
    and .status.expectedPods == 2
    and .status.desiredHealthy == 1
' >/dev/null <<<"${pdb_json}" \
  || die "controller PodDisruptionBudget does not preserve one available replica"

# Terminate the active writer and require a distinct live Pod to acquire a
# higher Lease epoch while the immutable rollout and Programmed proof remain
# recoverable from Kubernetes state.
first_leader="$(lease_holder_pod)"
first_epoch="$(kube -n "${namespace}" get lease "${leader_lease_name}" -o jsonpath='{.spec.leaseTransitions}')"
kube -n "${namespace}" delete pod "${first_leader}" --wait=false >/dev/null
wait_for "replacement controller leader" 60 lease_holder_changed "${first_leader}"
wait_for "two Ready replicas after leader termination" 60 controller_has_two_ready_replicas
wait_for "committed rollout recovered after leader termination" "${rollout_timeout_seconds}" deployment_is_committed
wait_for "Programmed proof recovered after leader termination" "${rollout_timeout_seconds}" gateway_is_programmed
next_epoch="$(kube -n "${namespace}" get lease "${leader_lease_name}" -o jsonpath='{.spec.leaseTransitions}')"
((10#${next_epoch} > 10#${first_epoch})) \
  || die "replacement leader did not advance the Lease fencing epoch"

# Exercise the Deployment's RollingUpdate strategy. maxUnavailable=0 plus the
# PDB must keep an election participant available throughout replacement.
kube -n "${namespace}" rollout restart "deployment/${controller_release}" >/dev/null
kube -n "${namespace}" rollout status "deployment/${controller_release}" --timeout=120s
wait_for "two fully updated controller replicas after rolling upgrade" 60 \
  controller_has_two_ready_replicas
wait_for "one leader after rolling controller upgrade" 60 lease_has_live_unique_holder
wait_for "Programmed proof after rolling controller upgrade" "${rollout_timeout_seconds}" gateway_is_programmed

# Reconcile the out-of-band rollout restart while the Lease is healthy. The
# subsequent Helm recovery must recreate only the Lease, not combine fencing
# recovery with another controller rollout.
helm upgrade "${controller_release}" "${repo_root}/deploy/helm/oxibelt-gateway-controller" \
  --namespace "${namespace}" \
  --reuse-values \
  --wait \
  --timeout "${rollout_timeout_seconds}s"
wait_for "two Helm-converged controller replicas before Lease deletion" 60 \
  controller_has_two_ready_replicas
wait_for "one leader after Helm reconciles the controller rollout" 60 \
  lease_has_live_unique_holder
wait_for "committed rollout after Helm reconciles the controller rollout" \
  "${rollout_timeout_seconds}" deployment_is_committed
wait_for "Programmed proof after Helm reconciles the controller rollout" \
  "${rollout_timeout_seconds}" gateway_is_programmed

controller_deployment_before="$(kube -n "${namespace}" get deployment \
  "${controller_release}" -o json)"
jq -e '
  .spec.template.metadata.annotations["kubectl.kubernetes.io/restartedAt"] == null
' >/dev/null <<<"${controller_deployment_before}" \
  || die "Helm did not remove the out-of-band controller restart annotation"
controller_deployment_uid="$(jq -er '.metadata.uid' <<<"${controller_deployment_before}")"
controller_generation_before="$(jq -er '.metadata.generation' <<<"${controller_deployment_before}")"
controller_template_digest_before="$(
  jq -cS '.spec.template' <<<"${controller_deployment_before}" | sha256sum
)"
controller_template_digest_before="${controller_template_digest_before%% *}"
controller_pod_uids_before="$(controller_pod_uids)" \
  || die "could not capture exactly two controller Pod UIDs before Lease deletion"
controller_pod_runtime_identities_before="$(controller_pod_runtime_identities)" \
  || die "could not capture two running controller container identities before Lease deletion"
controller_replicaset_uids_before="$(controller_replicaset_uids "${controller_deployment_uid}")" \
  || die "could not capture controller ReplicaSet UIDs before Lease deletion"

# Deleting the selected Lease revokes both writers. The controller lacks create
# permission, so only reapplying the Helm release can recreate the exact object.
# Kubernetes' default readiness probe budget is 30 seconds. Keep a bounded
# propagation margin for the kubelet to publish both failed Pod conditions.
old_lease_uid="$(kube -n "${namespace}" get lease "${leader_lease_name}" -o jsonpath='{.metadata.uid}')"
kube -n "${namespace}" delete lease "${leader_lease_name}" --wait=true >/dev/null
wait_for "controller readiness revocation after Lease deletion" \
  "${controller_readiness_revocation_timeout_seconds}" controller_pods_are_unready \
  "${controller_pod_runtime_identities_before}"
helm upgrade "${controller_release}" "${repo_root}/deploy/helm/oxibelt-gateway-controller" \
  --namespace "${namespace}" \
  --reuse-values \
  --wait \
  --timeout "${rollout_timeout_seconds}s"
wait_for "two unchanged controller replicas after Lease recreation" 60 \
  controller_has_two_ready_replicas
wait_for "leadership after Helm recreates the exact Lease" 60 lease_has_live_unique_holder
new_lease_uid="$(kube -n "${namespace}" get lease "${leader_lease_name}" -o jsonpath='{.metadata.uid}')"
[[ "${new_lease_uid}" != "${old_lease_uid}" ]] \
  || die "recreated Lease did not receive a new UID fencing domain"
controller_deployment_after="$(kube -n "${namespace}" get deployment \
  "${controller_release}" -o json)"
controller_generation_after="$(jq -er '.metadata.generation' <<<"${controller_deployment_after}")"
controller_template_digest_after="$(
  jq -cS '.spec.template' <<<"${controller_deployment_after}" | sha256sum
)"
controller_template_digest_after="${controller_template_digest_after%% *}"
controller_pod_uids_after="$(controller_pod_uids)" \
  || die "could not capture exactly two controller Pod UIDs after Lease recreation"
controller_pod_runtime_identities_after="$(controller_pod_runtime_identities)" \
  || die "could not capture two running controller container identities after Lease recreation"
controller_replicaset_uids_after="$(controller_replicaset_uids "${controller_deployment_uid}")" \
  || die "could not capture controller ReplicaSet UIDs after Lease recreation"
[[ "${controller_generation_after}" == "${controller_generation_before}" ]] \
  || die "Lease recreation unexpectedly changed the controller Deployment generation"
[[ "${controller_template_digest_after}" == "${controller_template_digest_before}" ]] \
  || die "Lease recreation unexpectedly changed the controller Pod template"
[[ "${controller_pod_uids_after}" == "${controller_pod_uids_before}" ]] \
  || die "Lease recreation unexpectedly replaced a controller Pod"
[[ "${controller_pod_runtime_identities_after}" == "${controller_pod_runtime_identities_before}" ]] \
  || die "Lease recreation unexpectedly restarted a controller container"
[[ "${controller_replicaset_uids_after}" == "${controller_replicaset_uids_before}" ]] \
  || die "Lease recreation unexpectedly changed the controller ReplicaSet set"
wait_for "rollout recovery after Lease recreation" "${rollout_timeout_seconds}" deployment_is_committed
wait_for "Programmed proof after Lease recreation" "${rollout_timeout_seconds}" gateway_is_programmed

verify_cross_namespace_l4_reference_grants

deployment_json="$(kube -n "${namespace}" get deployment "${workload_name}" -o json)"
jq -e '
  any(.spec.template.spec.containers[]?;
    .name == "oxibelt"
      and ([.env[]? | select(.name == "OXIBELT_UDP_FLOW_IDENTITY_KEY")] | length) == 1
      and any(.env[]?;
        .name == "OXIBELT_UDP_FLOW_IDENTITY_KEY"
          and (has("value") | not)
          and .valueFrom.secretKeyRef.name == "oxibelt-udp-flow-state"
          and .valueFrom.secretKeyRef.key == "identity-key"))
' >/dev/null <<<"${deployment_json}" \
  || die "controller rollout must preserve the Secret-backed UDP flow identity reference"
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

jq -e \
  --arg revision "${revision}" \
  --arg bootstrap_revision "${bootstrap_revision}" \
  --arg managed_path "${managed_config_path}" '
  ([.spec.template.spec.volumes[]? | select(.name == "gateway-config")] | length) == 1
  and any(.spec.template.spec.volumes[]?;
    .name == "config"
      and .configMap.name == $bootstrap_revision
      and any(.configMap.items[]?;
        .key == "gateway-config-directory" and .path == $managed_path))
  and any(.spec.template.spec.volumes[]?;
    .name == "gateway-config"
      and (.projected.sources | length) == 2
      and .projected.sources[0].configMap.name == $bootstrap_revision
      and .projected.sources[0].configMap.items == [
        {"key": "oxibelt.toml", "path": "oxibelt.toml"},
        {"key": "gateway-config-directory", "path": "conf.d/.keep"}
      ]
      and all(.projected.sources[0].configMap.items[]?; .path != $managed_path)
      and .projected.sources[1].configMap.name == $revision
      and .projected.sources[1].configMap.items == [
        {"key": "gateway-api.generated.toml", "path": $managed_path}
      ])
  and any(.spec.template.spec.containers[]?;
    .name == "oxibelt"
      and ([.volumeMounts[]? | select(.mountPath == "/etc/oxibelt/config")] | length) == 1
      and any(.volumeMounts[]?;
        .name == "gateway-config"
          and .mountPath == "/etc/oxibelt/config"
          and .readOnly == true
          and (has("subPath") | not)))
' >/dev/null <<<"${deployment_json}" \
  || die "workload does not use the controller-owned projected immutable config root"

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
grep -Fq 'udp_flow_state = "shared_required"' "${work_dir}/gateway-api.generated.toml" \
  || die "focused UDPRoute qualification did not render shared_required flow state"
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
verify_admin_mtls "${pods[0]}" "$((25000 + RANDOM % 10000))"

# A Pod with a valid mounted immutable configuration but a different assigned
# digest must fail before startup. Keep the standalone fixture outside the
# workload selector so it cannot affect controller convergence, Service
# endpoints, or the PDB.
stale_pod="stale-config-${run_id}"
stale_digest="1111111111111111111111111111111111111111111111111111111111111111"
kube -n "${namespace}" get deployment "${workload_name}" -o json \
  | jq --arg pod "${stale_pod}" --arg revision "${revision}" --arg digest "${stale_digest}" '
      {
        apiVersion: "v1",
        kind: "Pod",
        metadata: {
          name: $pod,
          labels: {"oxibelt.dev/test": "stale-config"},
          annotations: (.spec.template.metadata.annotations + {
            "oxibelt.dev/config-revision": $revision,
            "oxibelt.dev/config-digest": $digest
          })
        },
        spec: (.spec.template.spec
          | .restartPolicy = "Never"
          | .terminationGracePeriodSeconds = 1)
      }
    ' \
  | kube -n "${namespace}" create -f - >/dev/null
wait_for "a failed-closed stale-config Pod" 60 \
  stale_config_pod_failed_closed "${stale_pod}"
wait_for "the immutable digest-mismatch log from stale-config Pod" 30 \
  stale_config_pod_reports_digest_mismatch "${stale_pod}"

echo "Kubernetes immutable three-replica rollout and focused Gateway API TCP/UDP integration passed"
