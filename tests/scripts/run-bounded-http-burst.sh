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
container="oxibelt-http-burst-${burst_id}"
response_file="${work_dir}/responses.json"
stderr_file="${work_dir}/burst.stderr"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf "${work_dir}"
}
trap cleanup EXIT

create_args=(
  create
  --name "${container}"
  --label "${test_label}"
  --label "oxibelt.test.burst=${burst_id}"
  --network "${network}"
  --entrypoint python
  "${image}"
  /opt/mock_upstream/burst_client.py
  --target-host "${target_host}"
  --scheme "${scheme}"
  --path "${request_path}"
  --host "${authority}"
  --port "${port}"
  --concurrency "${concurrency}"
  --timeout "${timeout_seconds}"
)
if [[ "${scheme}" == "https" ]]; then
  create_args+=(--ca-file /tmp/proxy-ca.pem)
fi
docker "${create_args[@]}" >/dev/null
if [[ "${scheme}" == "https" ]]; then
  docker cp "${ca_file}" "${container}:/tmp/proxy-ca.pem"
fi

# The in-container client preconnects every TCP/TLS socket before its barrier
# releases any HTTP request. The outer timeout covers both bounded socket phases.
start_status=0
if timeout --foreground "$((timeout_seconds * 2 + 5))s" \
  docker start -a "${container}" >"${response_file}" 2>"${stderr_file}"; then
  :
else
  start_status=$?
fi

valid_output=1
if ! jq -e \
  --arg allowed ",${allowed_statuses}," \
  --argjson concurrency "${concurrency}" '
    type == "array"
    and length == $concurrency
    and ([.[].burst_index] | sort) == [range(1; $concurrency + 1)]
    and all(.[];
      (has("error") | not)
      and (.status | type == "number")
      and (.status as $status
        | ($allowed | contains("," + ($status | tostring) + ",")))
    )
  ' "${response_file}" >/dev/null 2>&1; then
  valid_output=0
fi

if ((start_status != 0 || valid_output != 1)); then
  echo "bounded HTTP burst failed or returned a disallowed response set" >&2
  if jq -e 'type == "array"' "${response_file}" >/dev/null 2>&1; then
    jq -c '.[] | {burst_index, status, reason, error}' \
      "${response_file}" 2>/dev/null | sed -n '1,20p' >&2 || true
  elif [[ -s "${response_file}" ]]; then
    sed -n '1,20p' "${response_file}" >&2
  fi
  if [[ -s "${stderr_file}" ]]; then
    sed -n '1,20p' "${stderr_file}" >&2
  fi
  exit 1
fi

mkdir -p "$(dirname -- "${output_file}")"
jq 'sort_by(.burst_index)' "${response_file}" >"${output_file}"
