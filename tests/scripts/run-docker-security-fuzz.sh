#!/usr/bin/env bash
# Bounded Docker security-fuzz orchestrator.  Target adapters are deliberately
# external to this driver: the driver owns deterministic replay, timeouts,
# cleanup, and failure-only artifact handling; adapters own protocol topology
# and security oracles.  An absent adapter is a failure, never a skipped pass.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage:
  run-docker-security-fuzz.sh smoke <target> [--seed N]
  run-docker-security-fuzz.sh replay <target> --seed N --case N
  run-docker-security-fuzz.sh replay-session <target> --seed N --case N
  run-docker-security-fuzz.sh campaign <target> [seconds] [--seed N]

OXIBELT_SECURITY_FUZZ_EXECUTOR may override the repository executor. An
executor must support start, case, recovery, and stop, and return zero only
after exercising the named target's catalog oracle against OxiBelt.
EOF
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
matrix_bin=()
run_id="$(date +%s)-${BASHPID:-$$}-${RANDOM}"
label="oxibelt.security-fuzz.run=${run_id}"
tmp_root="${repo_root}/tests/.tmp"
mkdir -p "${tmp_root}"
work_dir="$(mktemp -d "${tmp_root}/security-fuzz.XXXXXXXX")"
chmod 0700 "${work_dir}"
artifact_dir="${OXIBELT_TEST_ARTIFACT_DIR:-${work_dir}/artifacts}"
keep_artifacts="${KEEP_TEST_ARTIFACTS:-0}"
rollover_stop_timeout_seconds=10
rollover_start_timeout_seconds=60

cleanup() {
  if [[ -n "${executor:-}" && -x "${executor}" && -f "${work_dir}/session-started" ]]; then
    env OXIBELT_SECURITY_FUZZ_RUN_ID="${run_id}" \
      OXIBELT_SECURITY_FUZZ_LABEL="${label}" \
      OXIBELT_SECURITY_FUZZ_TARGET="${target:-unknown}" \
      OXIBELT_SECURITY_FUZZ_WORK_DIR="${work_dir}" \
      timeout --foreground 10s "${executor}" stop >/dev/null 2>&1 || true
  fi
  docker ps -aq --filter "label=${label}" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker volume ls -q --filter "label=${label}" | xargs -r docker volume rm >/dev/null 2>&1 || true
  docker network ls -q --filter "label=${label}" | xargs -r docker network rm >/dev/null 2>&1 || true
  # Reproducer bundles never need ephemeral CA or server private keys. Remove
  # those fixtures even when failure evidence is intentionally retained.
  rm -f "${work_dir}/cert/ca.key" "${work_dir}/cert/privkey.pem" \
    "${work_dir}/cert/upstream.key" "${work_dir}/config/privkey.pem" \
    "${work_dir}/credentials/admin.token" "${work_dir}/credentials/denied.token" \
    "${work_dir}/credentials/turn.username" "${work_dir}/credentials/turn.password" \
    "${work_dir}/credentials/postgres.password" \
    "${work_dir}/credentials/mutation-signer.ed25519.pem" >/dev/null 2>&1 || true
  if [[ "${keep_artifacts}" != "1" && ! -s "${work_dir}/failed" ]]; then
    rm -rf "${work_dir}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

prepare_matrix_bin() {
  local build_receipt="${work_dir}/matrix-build.jsonl"
  local matrix_artifact matrix_executable

  if ! (
    cd "${repo_root}"
    cargo build --quiet --locked -p oxibelt --bin oxibelt-docker-integration-matrix \
      --message-format=json-render-diagnostics >"${build_receipt}"
  ); then
    jq -r 'select(.reason == "compiler-message") | .message.rendered // empty' \
      "${build_receipt}" >&2 2>/dev/null || true
    echo "failed to build the Docker integration matrix helper" >&2
    return 1
  fi

  matrix_artifact="$(
    jq -ces '
      map(select(
        .reason == "compiler-artifact"
        and .target.name == "oxibelt-docker-integration-matrix"
        and ((.target.kind? // []) | index("bin") != null)
        and ((.executable? // null) | type == "string")
      ))
      | if length == 1 then .[0]
        else error("expected exactly one Docker integration matrix executable")
        end
    ' "${build_receipt}"
  )" || {
    echo "Cargo did not report exactly one Docker integration matrix executable" >&2
    return 1
  }
  matrix_executable="$(jq -er '.executable' <<<"${matrix_artifact}")" || {
    echo "Cargo reported an invalid Docker integration matrix executable" >&2
    return 1
  }
  if [[ ! -f "${matrix_executable}" || ! -x "${matrix_executable}" ]]; then
    echo "Cargo reported a Docker integration matrix path that is not an executable file" >&2
    return 1
  fi
  matrix_bin=("${matrix_executable}")
}

parse_positive_u64() {
  local name="$1" value="$2" maximum="$3"
  if [[ ! "${value}" =~ ^[0-9]+$ ]] || (( ${#value} > 19 )) \
    || (( 10#${value} == 0 || 10#${value} > maximum )); then
    echo "${name} must be an integer from 1 through ${maximum}" >&2
    exit 2
  fi
}

case_seed() {
  local commit="$1" target="$2" schema="$3" run_seed="$4" case_index="$5"
  printf '%s\0%s\0%s\0%s\0%s' "${commit}" "${target}" "${schema}" "${run_seed}" "${case_index}" \
    | sha256sum | awk '{print $1}'
}

write_failure_artifacts() {
  local target="$1" case_index="$2" seed="$3" output_file="$4"
  local replay_command="${5:-tests/scripts/run-docker-security-fuzz.sh replay ${target} --seed ${run_seed} --case ${case_index}}"
  mkdir -p "${artifact_dir}"
  local destination="${artifact_dir}/${target}-case-${case_index}-${seed}.log"
  local primary_log_max_bytes=$((failure_artifact_max_bytes / 2))
  # `head -c` applies the catalog cap before any copy, including hostile probe
  # output.  The marker makes truncation auditable without preserving excess.
  head -c "${primary_log_max_bytes}" "${output_file}" >"${destination}" || true
  if [[ "$(wc -c <"${output_file}")" -gt "${primary_log_max_bytes}" ]]; then
    printf '\n[truncated at %s bytes]\n' "${primary_log_max_bytes}" >>"${destination}"
  fi
  cp "${work_dir}/case-${case_index}.bin" "${artifact_dir}/${target}-case-${case_index}-${seed}.input" 2>/dev/null || true
  cp "${repo_root}/tests/docker/security_fuzz/targets.toml" \
    "${artifact_dir}/${target}-case-${case_index}-${seed}.catalog.toml"
  local raw_wire_dir raw_wire_file raw_wire_base raw_wire_digest raw_wire_metadata
  raw_wire_dir="${work_dir}/raw-wire"
  if [[ -d "${raw_wire_dir}" && ! -L "${raw_wire_dir}" ]]; then
    shopt -s nullglob
    for raw_wire_file in "${raw_wire_dir}/${case_index}-"*.bin; do
      [[ -f "${raw_wire_file}" && ! -L "${raw_wire_file}" ]] || continue
      raw_wire_base="$(basename -- "${raw_wire_file}")"
      [[ "${raw_wire_base}" != *.original.bin ]] || continue
      raw_wire_digest="$(sha256sum "${raw_wire_file}" | awk '{print $1}')"
      head -c 131072 "${raw_wire_file}" \
        >"${artifact_dir}/${target}-case-${case_index}-${seed}.wire-${raw_wire_base}" || true
      chmod 0600 "${artifact_dir}/${target}-case-${case_index}-${seed}.wire-${raw_wire_base}"
      raw_wire_metadata="${raw_wire_file%.bin}.json"
      jq -n --arg source_name "${raw_wire_base}" --arg copied_sha256 "${raw_wire_digest}" \
        --argjson source "$(cat "${raw_wire_metadata}" 2>/dev/null || printf '{}')" \
        '{source_name: $source_name, copied_sha256: $copied_sha256, source: $source}' \
        >"${artifact_dir}/${target}-case-${case_index}-${seed}.wire-${raw_wire_base}.json"
    done
    shopt -u nullglob
  fi
  local input_digest
  input_digest="$(sha256sum "${work_dir}/case-${case_index}.bin" | awk '{print $1}')"
  jq -n \
    --arg target "${target}" \
    --argjson case "${case_index}" \
    --arg case_seed "${seed}" \
    --arg input_sha256 "${input_digest}" \
    --arg source_revision "${commit_sha}" \
    --argjson schema_version "${schema_version}" \
    --arg oracle "${target_oracle}" \
    --argjson protocols "${target_protocols}" \
    --argjson meaning_preserving_transforms "${target_transforms}" \
    --argjson max_concurrent_sessions "${target_max_concurrent_sessions}" \
    --argjson required_helpers "${target_required_helpers}" \
    --arg replay "${replay_command}" \
    '{target: $target, case: $case, case_seed: $case_seed, input_sha256: $input_sha256,
      source_revision: $source_revision, schema_version: $schema_version, oracle: $oracle,
      protocols: $protocols, meaning_preserving_transforms: $meaning_preserving_transforms,
      max_concurrent_sessions: $max_concurrent_sessions, required_helpers: $required_helpers,
      replay: $replay}' \
    >"${artifact_dir}/${target}-case-${case_index}-${seed}.metadata.json"
  local observation observation_name
  for observation_name in \
    path-case.json tls-quic-case.json framing-case.json waf-case.json \
    auth-case.json session-case.json turn-case.json turn-edge-malformed.json \
    turn-edge-allocation.json admin-case.json admin-recovery.json \
    admin-admission-context.json \
    mutation.json recovery.json recovery-clean.json recovery-valid.json \
    runtime-introspection.json; do
    observation="${work_dir}/${observation_name}"
    if [[ -f "${observation}" && ! -L "${observation}" ]]; then
      head -c 262144 "${observation}" \
        >"${artifact_dir}/${target}-case-${case_index}-${seed}.observation.${observation_name}" || true
    fi
  done
  docker ps -a --filter "label=${label}" --format '{{.Names}} {{.Status}}' \
    >"${artifact_dir}/${target}-case-${case_index}-${seed}.containers.txt" 2>/dev/null || true
  docker ps -aq --filter "label=${label}" | while read -r container; do
    docker inspect --format '{{json .State}}' "${container}" 2>/dev/null || true
  done >"${artifact_dir}/${target}-case-${case_index}-${seed}.states.jsonl"
  mapfile -t diagnostic_containers < <(docker ps -aq --filter "label=${label}")
  mapfile -t running_containers < <(docker ps -q --filter "label=${label}")
  if ((${#running_containers[@]})); then
    docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}} {{.NetIO}}' \
      "${running_containers[@]}" \
      >"${artifact_dir}/${target}-case-${case_index}-${seed}.resources.txt" 2>/dev/null || true
  fi
  local container container_name diagnostic_log_max_bytes
  diagnostic_log_max_bytes=$((failure_artifact_max_bytes / 4 / (${#diagnostic_containers[@]} + 1)))
  for container in "${diagnostic_containers[@]}"; do
    container_name="$(docker inspect --format '{{.Name}}' "${container}" 2>/dev/null \
      | tr -cd 'A-Za-z0-9_.-')"
    [[ -n "${container_name}" ]] || container_name="${container}"
    docker logs "${container}" 2>&1 \
      | head -c "${diagnostic_log_max_bytes}" \
      >"${artifact_dir}/${target}-case-${case_index}-${seed}.${container_name}.log" || true
  done
  printf 'failed\n' >"${work_dir}/failed"
}

load_target() {
  local target="$1" description
  description="$(cd "${repo_root}" && "${matrix_bin[@]}" security-fuzz describe --target "${target}")"
  schema_version="$(jq -er '.schema_version' <<<"${description}")"
  replay_schema_version="$(jq -er '.replay_schema_version' <<<"${description}")"
  pr_max_cases="$(jq -er '.pr_max_cases' <<<"${description}")"
  pr_max_seconds="$(jq -er '.pr_max_seconds' <<<"${description}")"
  sustained_default_seconds="$(jq -er '.sustained_default_seconds' <<<"${description}")"
  sustained_max_cases="$(jq -er '.sustained_max_cases' <<<"${description}")"
  case_timeout_seconds="$(jq -er '.case_timeout_seconds' <<<"${description}")"
  recovery_timeout_seconds="$(jq -er '.recovery_timeout_seconds' <<<"${description}")"
  input_timeout_seconds="${case_timeout_seconds}"
  complete_case_budget_seconds=$((input_timeout_seconds + case_timeout_seconds + recovery_timeout_seconds))
  failure_artifact_max_bytes="$(jq -er '.failure_artifact_max_bytes' <<<"${description}")"
  target_payload_max_bytes="$(jq -er '.payload_max_bytes' <<<"${description}")"
  target_session_max_cases="$(jq -er '.session_max_cases' <<<"${description}")"
  target_max_concurrent_sessions="$(jq -er '.max_concurrent_sessions' <<<"${description}")"
  target_required_helpers="$(jq -cer '.required_helpers' <<<"${description}")"
  target_oracle="$(jq -er '.oracle' <<<"${description}")"
  target_protocols="$(jq -cer '.protocols' <<<"${description}")"
  target_transforms="$(jq -cer '.meaning_preserving_transforms' <<<"${description}")"
  [[ "${schema_version}" == "1" && "${replay_schema_version}" == "1" ]] || {
    echo "unsupported security-fuzz replay schema" >&2; exit 1;
  }
}

run_adapter_case() {
  local target="$1" case_index="$2" seed="$3" deadline="$4"
  local output_file="${work_dir}/case-${case_index}.log"
  local case_started_at now remaining case_budget recovery_budget
  local input_status case_status recovery_status
  # The executor receives a deterministic, target-bounded binary case through
  # a file rather than a command argument, preventing shell parsing changes.
  local input_file="${work_dir}/case-${case_index}.bin"
  : >"${output_file}"
  input_status=0
  (
    cd "${repo_root}"
    timeout --foreground "${input_timeout_seconds}s" \
      "${matrix_bin[@]}" security-fuzz materialize-input \
        --target "${target}" --seed "${seed}" --output "${input_file}"
  ) >>"${output_file}" 2>&1 || input_status=$?
  if ((input_status != 0)); then
    printf 'security-fuzz executor phase=input exit_status=%s budget_seconds=%s\n' \
      "${input_status}" "${input_timeout_seconds}" >>"${output_file}"
    [[ -e "${input_file}" || -L "${input_file}" ]] || : >"${input_file}"
    write_failure_artifacts "${target}" "${case_index}" "${seed}" "${output_file}"
    cat "${output_file}" >&2 || true
    return 1
  fi
  now="$(date +%s)"
  remaining=$((deadline - now))
  if ((remaining < case_timeout_seconds + recovery_timeout_seconds)); then
    adapter_case_started=0
    rm -f "${input_file}"
    return 0
  fi
  adapter_case_started=1
  case_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  case_budget="${case_timeout_seconds}"
  case_status=0
  timeout --foreground "${case_budget}s" \
    env \
      OXIBELT_SECURITY_FUZZ_RUN_ID="${run_id}" \
      OXIBELT_SECURITY_FUZZ_LABEL="${label}" \
      OXIBELT_SECURITY_FUZZ_TARGET="${target}" \
      OXIBELT_SECURITY_FUZZ_CASE="${case_index}" \
      OXIBELT_SECURITY_FUZZ_CASE_SEED="${seed}" \
      OXIBELT_SECURITY_FUZZ_INPUT_FILE="${input_file}" \
      OXIBELT_SECURITY_FUZZ_WORK_DIR="${work_dir}" \
      OXIBELT_SECURITY_FUZZ_PAYLOAD_MAX_BYTES="${target_payload_max_bytes}" \
      OXIBELT_SECURITY_FUZZ_SESSION_MAX_CASES="${target_session_max_cases}" \
      OXIBELT_SECURITY_FUZZ_MAX_CONCURRENT_SESSIONS="${target_max_concurrent_sessions}" \
      OXIBELT_SECURITY_FUZZ_PROTOCOLS="${target_protocols}" \
      OXIBELT_SECURITY_FUZZ_ORACLE="${target_oracle}" \
      OXIBELT_SECURITY_FUZZ_MEANING_PRESERVING_TRANSFORMS="${target_transforms}" \
      OXIBELT_SECURITY_FUZZ_RECOVERY_TIMEOUT_SECONDS="${recovery_timeout_seconds}" \
      OXIBELT_SECURITY_FUZZ_DEADLINE_EPOCH_SECONDS="${deadline}" \
      "${executor}" case >"${output_file}" 2>&1 || case_status=$?
  if ((case_status != 0)); then
    printf 'security-fuzz executor phase=case exit_status=%s budget_seconds=%s\n' \
      "${case_status}" "${case_budget}" >>"${output_file}"
    write_failure_artifacts "${target}" "${case_index}" "${seed}" "${output_file}"
    cat "${output_file}" >&2 || true
    return 1
  fi
  recovery_budget="${recovery_timeout_seconds}"
  recovery_status=0
  timeout --foreground "${recovery_budget}s" \
    env OXIBELT_SECURITY_FUZZ_RUN_ID="${run_id}" \
      OXIBELT_SECURITY_FUZZ_LABEL="${label}" \
      OXIBELT_SECURITY_FUZZ_TARGET="${target}" \
      OXIBELT_SECURITY_FUZZ_CASE="${case_index}" \
      OXIBELT_SECURITY_FUZZ_CASE_SEED="${seed}" \
      OXIBELT_SECURITY_FUZZ_INPUT_FILE="${input_file}" \
      OXIBELT_SECURITY_FUZZ_WORK_DIR="${work_dir}" \
      "${executor}" recovery >>"${output_file}" 2>&1 || recovery_status=$?
  if ((recovery_status != 0)); then
    printf 'security-fuzz executor phase=recovery exit_status=%s budget_seconds=%s\n' \
      "${recovery_status}" "${recovery_budget}" >>"${output_file}"
    write_failure_artifacts "${target}" "${case_index}" "${seed}" "${output_file}"
    return 1
  fi
  local container state
  while read -r container; do
    [[ -n "${container}" ]] || continue
    state="$(docker inspect --format '{{.State.Running}} {{.State.OOMKilled}}' "${container}" 2>/dev/null || true)"
    if [[ "${state}" != "true false" ]]; then
      echo "case container exited or was OOM-killed" >>"${output_file}"
      write_failure_artifacts "${target}" "${case_index}" "${seed}" "${output_file}"
      return 1
    fi
    if docker logs --since "${case_started_at}" "${container}" 2>&1 \
      | grep -Eiq '(^|[^[:alpha:]])(panic|panicked|abort|aborted|fatal)([^[:alpha:]]|$)'; then
      echo "fatal runtime marker appeared in a case container log" >>"${output_file}"
      write_failure_artifacts "${target}" "${case_index}" "${seed}" "${output_file}"
      return 1
    fi
  done < <(docker ps -aq --filter "label=${label}")
}

start_executor_session() {
  local start_timeout="${1:-60}" start_status=0
  timeout --foreground "${start_timeout}s" \
    env \
      OXIBELT_SECURITY_FUZZ_RUN_ID="${run_id}" \
      OXIBELT_SECURITY_FUZZ_LABEL="${label}" \
      OXIBELT_SECURITY_FUZZ_TARGET="${target}" \
      OXIBELT_SECURITY_FUZZ_WORK_DIR="${work_dir}" \
      OXIBELT_SECURITY_FUZZ_PROTOCOLS="${target_protocols}" \
      OXIBELT_SECURITY_FUZZ_ORACLE="${target_oracle}" \
      OXIBELT_SECURITY_FUZZ_MAX_CONCURRENT_SESSIONS="${target_max_concurrent_sessions}" \
      OXIBELT_SECURITY_FUZZ_RECOVERY_TIMEOUT_SECONDS="${recovery_timeout_seconds}" \
      "${executor}" start || start_status=$?
  if ((start_status != 0)); then
    printf 'security-fuzz executor phase=start exit_status=%s budget_seconds=%s\n' \
      "${start_status}" "${start_timeout}" >&2
    return "${start_status}"
  fi
  : >"${work_dir}/session-started"
}

stop_executor_session() {
  local stop_timeout="${1:-30}" stop_status=0
  timeout --foreground "${stop_timeout}s" \
    env OXIBELT_SECURITY_FUZZ_RUN_ID="${run_id}" \
      OXIBELT_SECURITY_FUZZ_LABEL="${label}" \
      OXIBELT_SECURITY_FUZZ_TARGET="${target}" \
      OXIBELT_SECURITY_FUZZ_WORK_DIR="${work_dir}" \
      "${executor}" stop || stop_status=$?
  if ((stop_status != 0)); then
    printf 'security-fuzz executor phase=stop exit_status=%s budget_seconds=%s\n' \
      "${stop_status}" "${stop_timeout}" >&2
    return "${stop_status}"
  fi
  rm -f "${work_dir}/session-started"
}

cleanup_failed_executor_start() {
  local lifecycle_log="$1"
  if ! stop_executor_session "${rollover_stop_timeout_seconds}" >>"${lifecycle_log}" 2>&1; then
    printf 'security-fuzz failed-start cleanup did not complete\n' >>"${lifecycle_log}"
    return 1
  fi
}

command="${1:-}"
target="${2:-}"
[[ -n "${command}" && -n "${target}" ]] || { usage; exit 2; }
shift 2
seed=""
case_index=""
campaign_seconds=""
while (($#)); do
  case "$1" in
    --seed) seed="${2:-}"; shift 2 ;;
    --case) case_index="${2:-}"; shift 2 ;;
    *)
      if [[ "${command}" == "campaign" && -z "${campaign_seconds}" ]]; then
        campaign_seconds="$1"; shift
      else
        usage; exit 2
      fi
      ;;
  esac
done

mkdir -p "${work_dir}"
prepare_matrix_bin
load_target "${target}"
rollover_budget_seconds=$((rollover_stop_timeout_seconds \
  + rollover_start_timeout_seconds + complete_case_budget_seconds))
executor="${OXIBELT_SECURITY_FUZZ_EXECUTOR:-${repo_root}/tests/docker/security_fuzz/executor.sh}"
if [[ ! -x "${executor}" ]]; then
  echo "security-fuzz executor is missing or not executable: ${executor}" >&2
  exit 1
fi
commit_sha="$(git -C "${repo_root}" rev-parse HEAD)"
if [[ -z "${seed}" ]]; then
  # Keep the externally visible run seed decimal while binding it to the exact
  # revision.  Fifteen hex digits remain below Bash's signed integer limit.
  seed="$((16#${commit_sha:0:15}))"
fi
parse_positive_u64 "seed" "${seed}" 9223372036854775807
run_seed="${seed}"

case "${command}" in
  smoke)
    [[ -z "${case_index}" && -z "${campaign_seconds}" ]] || { usage; exit 2; }
    max_cases="${pr_max_cases}"
    duration="${pr_max_seconds}"
    ;;
  replay|replay-session)
    [[ -n "${case_index}" && -z "${campaign_seconds}" ]] || { usage; exit 2; }
    parse_positive_u64 "case" "${case_index}" "${sustained_max_cases}"
    if [[ "${command}" == "replay" ]]; then
      max_cases=1
      duration="${complete_case_budget_seconds}"
    else
      max_cases="${case_index}"
      duration="${sustained_default_seconds}"
    fi
    ;;
  campaign)
    [[ -z "${case_index}" ]] || { usage; exit 2; }
    duration="${campaign_seconds:-${sustained_default_seconds}}"
    parse_positive_u64 "campaign seconds" "${duration}" "${sustained_default_seconds}"
    max_cases="${sustained_max_cases}"
    ;;
  *) usage; exit 2 ;;
esac

# Cold image/container setup is intentionally outside the per-mutation budget;
# once started, input materialization, mutation, and recovery each receive a
# complete catalog-derived budget.
startup_log="${work_dir}/startup.log"
if ! start_executor_session >"${startup_log}" 2>&1; then
  if ! cleanup_failed_executor_start "${startup_log}"; then
    printf 'security-fuzz topology may remain after failed startup\n' >>"${startup_log}"
  fi
  startup_case=1
  startup_seed="$(case_seed "${commit_sha}" "${target}" "${schema_version}" "${run_seed}" "${startup_case}")"
  : >"${work_dir}/case-${startup_case}.bin"
  write_failure_artifacts "${target}" "${startup_case}" "${startup_seed}" "${startup_log}"
  cat "${startup_log}" >&2 || true
  echo "security-fuzz topology startup did not complete" >&2
  exit 1
fi
deadline=$(( $(date +%s) + duration ))
first_case=1
[[ "${command}" == "replay" ]] && first_case="${case_index}"
executed=0
index="${first_case}"
while ((executed < max_cases)); do
  now="$(date +%s)"
  remaining=$((deadline - now))
  ((remaining >= complete_case_budget_seconds)) || break
  derived_seed="$(case_seed "${commit_sha}" "${target}" "${schema_version}" "${run_seed}" "${index}")"
  adapter_case_started=0
  run_adapter_case "${target}" "${index}" "${derived_seed}" "${deadline}"
  ((adapter_case_started == 1)) || break
  executed=$((executed + 1))
  index=$((index + 1))
  now="$(date +%s)"
  if ((executed % target_session_max_cases == 0 \
    && executed < max_cases \
    && now < deadline)); then
    remaining=$((deadline - now))
    # End after the completed session unless a bounded stop, start, and next
    # complete case all fit with scheduling slack.
    ((remaining > rollover_budget_seconds)) || break
    lifecycle_log="${work_dir}/session-rollover.log"
    if ! stop_executor_session "${rollover_stop_timeout_seconds}" >"${lifecycle_log}" 2>&1; then
      lifecycle_seed="$(case_seed "${commit_sha}" "${target}" "${schema_version}" "${run_seed}" "${index}")"
      : >"${work_dir}/case-${index}.bin"
      write_failure_artifacts "${target}" "${index}" "${lifecycle_seed}" "${lifecycle_log}" \
        "tests/scripts/run-docker-security-fuzz.sh replay-session ${target} --seed ${run_seed} --case ${index}"
      cat "${lifecycle_log}" >&2 || true
      exit 1
    fi
    if ! start_executor_session "${rollover_start_timeout_seconds}" >"${lifecycle_log}" 2>&1; then
      if ! cleanup_failed_executor_start "${lifecycle_log}"; then
        printf 'security-fuzz topology may remain after failed rollover startup\n' \
          >>"${lifecycle_log}"
      fi
      lifecycle_seed="$(case_seed "${commit_sha}" "${target}" "${schema_version}" "${run_seed}" "${index}")"
      : >"${work_dir}/case-${index}.bin"
      write_failure_artifacts "${target}" "${index}" "${lifecycle_seed}" "${lifecycle_log}" \
        "tests/scripts/run-docker-security-fuzz.sh replay-session ${target} --seed ${run_seed} --case ${index}"
      cat "${lifecycle_log}" >&2 || true
      exit 1
    fi
  fi
done
if (( executed == 0 )); then
  echo "security-fuzz budget elapsed before a case could run" >&2
  exit 1
fi
final_case=$((index - 1))
final_seed="$(case_seed "${commit_sha}" "${target}" "${schema_version}" "${run_seed}" "${final_case}")"
final_replay="tests/scripts/run-docker-security-fuzz.sh replay-session ${target} --seed ${run_seed} --case ${final_case}"
if [[ "${command}" == "replay" ]]; then
  final_replay="tests/scripts/run-docker-security-fuzz.sh replay ${target} --seed ${run_seed} --case ${final_case}"
fi
final_lifecycle_log="${work_dir}/session-final-stop.log"
if ! stop_executor_session 10 >"${final_lifecycle_log}" 2>&1; then
  write_failure_artifacts "${target}" "${final_case}" "${final_seed}" "${final_lifecycle_log}" \
    "${final_replay}"
  cat "${final_lifecycle_log}" >&2 || true
  exit 1
fi
printf 'security-fuzz %s target=%s cases=%s run-seed=%s schema=%s\n' \
  "${command}" "${target}" "${executed}" "${run_seed}" "${schema_version}"
