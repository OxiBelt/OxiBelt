#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: run-bounded-http-burst.sh \
  --network NAME --image IMAGE --label KEY=VALUE \
  --target-host NAME --port PORT --scheme http|https \
  --authority HOST --path ORIGIN_FORM --allowed-statuses LIST \
  --concurrency 1..64 --timeout-seconds 1..30 --output FILE \
  [--ca-file FILE]
EOF
}

network=""
image=""
test_label=""
target_host=""
port=""
scheme=""
authority=""
request_path=""
allowed_statuses=""
concurrency=""
timeout_seconds=""
output_file=""
ca_file=""

while (($# > 0)); do
  case "$1" in
    --network) network="${2:-}"; shift 2 ;;
    --image) image="${2:-}"; shift 2 ;;
    --label) test_label="${2:-}"; shift 2 ;;
    --target-host) target_host="${2:-}"; shift 2 ;;
    --port) port="${2:-}"; shift 2 ;;
    --scheme) scheme="${2:-}"; shift 2 ;;
    --authority) authority="${2:-}"; shift 2 ;;
    --path) request_path="${2:-}"; shift 2 ;;
    --allowed-statuses) allowed_statuses="${2:-}"; shift 2 ;;
    --concurrency) concurrency="${2:-}"; shift 2 ;;
    --timeout-seconds) timeout_seconds="${2:-}"; shift 2 ;;
    --output) output_file="${2:-}"; shift 2 ;;
    --ca-file) ca_file="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

if [[ ! "${network}" =~ ^[A-Za-z0-9_.-]{1,128}$ ]] \
  || [[ ! "${image}" =~ ^[A-Za-z0-9_./:@-]{1,255}$ ]] \
  || [[ ! "${test_label}" =~ ^[A-Za-z0-9_.-]{1,128}=[A-Za-z0-9_.:-]{1,128}$ ]] \
  || [[ ! "${target_host}" =~ ^[A-Za-z0-9_.-]{1,253}$ ]] \
  || [[ ! "${port}" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)) \
  || [[ "${scheme}" != "http" && "${scheme}" != "https" ]] \
  || [[ -z "${authority}" || "${authority}" =~ [[:space:]] ]] \
  || [[ "${authority}" == *$'\r'* || "${authority}" == *$'\n'* ]] \
  || [[ "${request_path}" != /* || "${request_path}" == //* || "${request_path}" == *#* ]] \
  || [[ "${request_path}" == *$'\r'* || "${request_path}" == *$'\n'* ]] \
  || [[ ! "${allowed_statuses}" =~ ^[1-5][0-9]{2}(,[1-5][0-9]{2})*$ ]] \
  || [[ ! "${concurrency}" =~ ^[0-9]+$ ]] || ((concurrency < 1 || concurrency > 64)) \
  || [[ ! "${timeout_seconds}" =~ ^[0-9]+$ ]] || ((timeout_seconds < 1 || timeout_seconds > 30)) \
  || [[ -z "${output_file}" || "${output_file}" == *$'\r'* || "${output_file}" == *$'\n'* ]]; then
  usage
  exit 2
fi
if [[ "${scheme}" == "https" && ! -f "${ca_file}" ]]; then
  echo "--ca-file must name a readable CA file for HTTPS bursts" >&2
  exit 2
fi

burst_id="${BASHPID:-$$}-${RANDOM}-$(date +%s%N)"
work_dir="$(mktemp -d /tmp/oxibelt-http-burst.XXXXXX)"
containers=()
pids=()

cleanup() {
  local container
  for container in "${containers[@]}"; do
    docker rm -f "${container}" >/dev/null 2>&1 || true
  done
  rm -rf "${work_dir}"
}
trap cleanup EXIT

for index in $(seq 1 "${concurrency}"); do
  container="oxibelt-http-burst-${burst_id}-${index}"
  containers+=("${container}")
  create_args=(
    create
    --name "${container}"
    --label "${test_label}"
    --label "oxibelt.test.burst=${burst_id}"
    --network "${network}"
    --entrypoint python
    "${image}"
    /opt/mock_upstream/client.py
    --target-host "${target_host}"
    --scheme "${scheme}"
    --path "${request_path}"
    --host "${authority}"
    --port "${port}"
    --method GET
    --body ""
    --dump-response-json
    --timeout "${timeout_seconds}"
  )
  if [[ "${scheme}" == "https" ]]; then
    create_args+=(--ca-file /tmp/proxy-ca.pem)
  fi
  docker "${create_args[@]}" >/dev/null
  if [[ "${scheme}" == "https" ]]; then
    docker cp "${ca_file}" "${container}:/tmp/proxy-ca.pem"
  fi
done

# Every client container exists before any is started. This provides a bounded
# synchronized launch without shell evaluation or unbounded process creation.
for index in $(seq 1 "${concurrency}"); do
  container="${containers[index - 1]}"
  timeout --foreground "$((timeout_seconds + 2))s" \
    docker start -a "${container}" \
    >"${work_dir}/${index}.json" 2>"${work_dir}/${index}.stderr" &
  pids+=("$!")
done

for index in $(seq 1 "${concurrency}"); do
  wait "${pids[index - 1]}" || true
done

for index in $(seq 1 "${concurrency}"); do
  response_file="${work_dir}/${index}.json"
  if ! jq -e --arg allowed ",${allowed_statuses}," '
    .status as $status
    | ($status | type == "number")
      and ($allowed | contains("," + ($status | tostring) + ","))
  ' "${response_file}" >/dev/null 2>&1; then
    echo "bounded HTTP burst request ${index} failed or returned a disallowed status" >&2
    jq -c '{status, reason}' "${response_file}" >&2 2>/dev/null || true
    if [[ -s "${work_dir}/${index}.stderr" ]]; then
      sed -n '1,20p' "${work_dir}/${index}.stderr" >&2
    fi
    exit 1
  fi
done

mkdir -p "$(dirname -- "${output_file}")"
jq -s 'to_entries | map(.value + {burst_index: (.key + 1)})' \
  "${work_dir}"/*.json >"${output_file}"
