#!/usr/bin/env bash
set -euo pipefail

# Run a deliberately local, immutable-input performance campaign.  This is a
# wrapper around run-proxy-performance.sh; workload definitions and thresholds
# remain owned by that runner and oxibelt-performance-aggregate.
umask 077

usage() {
  cat >&2 <<'USAGE'
usage: tests/scripts/run-local-performance-campaign.sh --phase smoke|benchmark|aggregate|all --inputs <images.json> [options]

Options:
  --target-cpu x86-64-v2|x86-64-v3  Restrict a collection phase (repeatable).
  --group NAME                      Restrict a collection phase (repeatable).
                                      NAME is reverse-proxy, static-files,
                                      oxibelt-features, remote-signer, or
                                      oxibelt-soak-stress.
  --campaign-dir DIR                New campaign directory, or an existing
                                      one only for --phase aggregate.
  --source-root DIR                 Checked-out source revision represented by
                                      the supplied OxiBelt images and runner.
  --baseline-report PATH            Prior passing primary report, or a prior
                                      campaign root containing both reports.
  --aggregate-bin PATH              Prebuilt `oxibelt-performance-aggregate`
                                      executable. Defaults to
                                      `$OXIBELT_PERF_AGGREGATE_COMMAND` or the
                                      source-root release binary.
  -h, --help                        Show this help.

The inputs file is JSON with this shape:
{
  "schema_version": 1,
  "common": {
    "perf_probe_image": "…",
    "external_benchmark_image": "…"
  },
  "targets": {
    "x86-64-v2": {
      "oxibelt_image": "…", "keysigner_image": "…",
      "oxibelt_contract": "…", "keysigner_contract": "…",
      "nginx_image": "…", "caddy_image": "…", "openresty_image": "…"
    },
    "x86-64-v3": { "…": "…" }
  }
}

Each collection phase creates new attempt directories. It never overwrites an
attempt: make a new --campaign-dir for a rerun. --phase aggregate reads an
existing campaign and creates reports for both primary targets.
USAGE
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
source_root="${repo_root}"
runner=""
aggregate_bin="${OXIBELT_PERF_AGGREGATE_COMMAND:-}"
docker_command="${OXIBELT_DOCKER_COMMAND:-docker}"

# These ceilings bound orchestration failures without shortening any measured
# workload. They are intentionally fixed so two campaign manifests describe
# the same admission policy.
readonly smoke_attempt_timeout_seconds=1500
readonly benchmark_attempt_timeout_seconds=3600
readonly aggregate_timeout_seconds=900
readonly input_inspect_timeout_seconds=60
readonly smoke_campaign_timeout_seconds=7200
readonly benchmark_campaign_timeout_seconds=72000
readonly all_campaign_timeout_seconds=75600
readonly timeout_kill_after_seconds=120

phase=""
inputs_file=""
campaign_dir=""
baseline_report=""
declare -a selected_targets=()
declare -a selected_groups=()

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --phase)
      phase="${2:-}"
      shift 2
      ;;
    --inputs)
      inputs_file="${2:-}"
      shift 2
      ;;
    --target-cpu)
      selected_targets+=("${2:-}")
      shift 2
      ;;
    --group)
      selected_groups+=("${2:-}")
      shift 2
      ;;
    --campaign-dir)
      campaign_dir="${2:-}"
      shift 2
      ;;
    --source-root)
      source_root="${2:-}"
      shift 2
      ;;
    --baseline-report)
      baseline_report="${2:-}"
      shift 2
      ;;
    --aggregate-bin)
      aggregate_bin="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 64
      ;;
  esac
done

case "${phase}" in
  smoke|benchmark|aggregate|all) ;;
  *)
    usage
    exit 64
    ;;
esac

if [[ -z "${campaign_dir}" ]]; then
  campaign_dir="${repo_root}/tests/.tmp/local-performance-campaign-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
campaign_parent="$(dirname -- "${campaign_dir}")"
mkdir -p "${campaign_parent}"
campaign_dir="$(cd -- "${campaign_parent}" && pwd)/$(basename -- "${campaign_dir}")"
manifest="${campaign_dir}/campaign-manifest.json"

if [[ ! -d "${source_root}" ]]; then
  echo "--source-root is not a directory: ${source_root}" >&2
  exit 64
fi
source_root="$(cd -- "${source_root}" && pwd)"
runner="${source_root}/tests/scripts/run-proxy-performance.sh"
if [[ "${phase}" != "aggregate" && ! -x "${runner}" ]]; then
  echo "source-root does not provide an executable performance runner: ${runner}" >&2
  exit 66
fi
if [[ -z "${aggregate_bin}" ]]; then
  aggregate_bin="${source_root}/source/target/release/oxibelt-performance-aggregate"
fi
if [[ "${phase}" == "benchmark" || "${phase}" == "aggregate" || "${phase}" == "all" ]] && [[ ! -x "${aggregate_bin}" ]]; then
  echo "aggregate executable is unavailable; build it before measuring and pass --aggregate-bin" >&2
  exit 66
fi

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command is unavailable: $1" >&2
    exit 69
  }
}

for required_command in git jq flock sha256sum stat awk find timeout "${docker_command}"; do
  require_command "${required_command}"
done

# Collection policy is fixed here.  Letting inherited tuning or fixture knobs
# reach the runner would make a manifest look comparable when it is not.
while IFS= read -r inherited_override; do
  case "${inherited_override}" in
    OXIBELT_PERF_AGGREGATE_COMMAND) ;;
    OXIBELT_PERF_*|OXIBELT_EXTERNAL_*)
      echo "local performance campaigns reject inherited ${inherited_override}; use the documented fixed campaign policy" >&2
      exit 64
      ;;
  esac
done < <(compgen -v)

if [[ "${phase}" != "aggregate" || -n "${inputs_file}" ]]; then
  [[ -n "${inputs_file}" && -f "${inputs_file}" ]] || {
    echo "--inputs must name a readable immutable-image manifest" >&2
    exit 64
  }
fi

if [[ -n "${baseline_report}" && ! -f "${baseline_report}" && ! -d "${baseline_report}" ]]; then
  echo "--baseline-report does not exist: ${baseline_report}" >&2
  exit 64
fi

validate_target() {
  case "$1" in
    x86-64-v2|x86-64-v3) ;;
    *) echo "unsupported target CPU: $1" >&2; exit 64 ;;
  esac
}

validate_group() {
  case "$1" in
    reverse-proxy|static-files|oxibelt-features|remote-signer|oxibelt-soak-stress) ;;
    *) echo "unsupported campaign group: $1" >&2; exit 64 ;;
  esac
}

if [[ "${#selected_targets[@]}" == 0 ]]; then
  selected_targets=(x86-64-v2 x86-64-v3)
fi
if [[ "${#selected_groups[@]}" == 0 ]]; then
  selected_groups=(reverse-proxy static-files oxibelt-features remote-signer oxibelt-soak-stress)
fi
for target in "${selected_targets[@]}"; do validate_target "${target}"; done
for group in "${selected_groups[@]}"; do validate_group "${group}"; done

prepare_campaign_directory() {
  local mode
  if [[ -L "${campaign_dir}" ]]; then
    echo "campaign directory must not be a symlink: ${campaign_dir}" >&2
    exit 73
  fi
  if [[ -e "${campaign_dir}" ]]; then
    [[ -d "${campaign_dir}" && -O "${campaign_dir}" ]] || {
      echo "campaign directory must be an owned directory: ${campaign_dir}" >&2
      exit 73
    }
  else
    mkdir -m 0700 "${campaign_dir}"
  fi
  mode="$(stat -c '%a' "${campaign_dir}")"
  if (( (8#${mode} & 8#077) != 0 )); then
    echo "campaign directory must not grant group or other access: ${campaign_dir}" >&2
    exit 73
  fi
}

prepare_campaign_directory

existing_campaign_symlink="$(find -P "${campaign_dir}" -type l -print -quit)"
if [[ -n "${existing_campaign_symlink}" ]]; then
  echo "campaign artifacts must not contain symlinks: ${existing_campaign_symlink}" >&2
  exit 73
fi

# The host lock serializes the current dedicated benchmark user across distinct
# campaign directories. Its private directory makes append-open safe and avoids
# following a sibling campaign path controlled outside this campaign root.
host_lock_dir="${XDG_RUNTIME_DIR:-/tmp}/oxibelt-local-performance-${UID}"
if [[ -L "${host_lock_dir}" ]]; then
  echo "performance campaign runtime directory must not be a symlink: ${host_lock_dir}" >&2
  exit 73
fi
if [[ -e "${host_lock_dir}" ]]; then
  [[ -d "${host_lock_dir}" && -O "${host_lock_dir}" ]] || {
    echo "performance campaign runtime directory must be an owned directory: ${host_lock_dir}" >&2
    exit 73
  }
else
  mkdir -m 0700 "${host_lock_dir}"
fi
host_lock_mode="$(stat -c '%a' "${host_lock_dir}")"
if (( (8#${host_lock_mode} & 8#077) != 0 )); then
  echo "performance campaign runtime directory must not grant group or other access: ${host_lock_dir}" >&2
  exit 73
fi
host_lock_file="${host_lock_dir}/campaign.lock"
if [[ -L "${host_lock_file}" ]]; then
  echo "performance campaign lock must be an owned regular file: ${host_lock_file}" >&2
  exit 73
fi
if [[ -e "${host_lock_file}" ]] && { [[ ! -f "${host_lock_file}" ]] || [[ ! -O "${host_lock_file}" ]]; }; then
  echo "performance campaign lock must be an owned regular file: ${host_lock_file}" >&2
  exit 73
fi
exec 8>>"${host_lock_file}"
if ! flock -n 8; then
  echo "another local performance campaign is active for this user" >&2
  exit 75
fi

case "${phase}" in
  smoke) campaign_timeout_seconds="${smoke_campaign_timeout_seconds}" ;;
  benchmark) campaign_timeout_seconds="${benchmark_campaign_timeout_seconds}" ;;
  all) campaign_timeout_seconds="${all_campaign_timeout_seconds}" ;;
  aggregate) campaign_timeout_seconds=0 ;;
esac
readonly campaign_timeout_seconds
readonly campaign_started_seconds="${SECONDS}"

source_revision="$(git -C "${source_root}" rev-parse HEAD)"
source_tree="$(git -C "${source_root}" rev-parse 'HEAD^{tree}')"
if ! git -C "${source_root}" diff --quiet --ignore-submodules -- ||
   ! git -C "${source_root}" diff --cached --quiet --ignore-submodules --; then
  echo "local performance campaigns require a clean tracked source tree" >&2
  exit 65
fi

utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

write_json_atomically() {
  local destination="$1"
  local temporary
  temporary="$(mktemp "${destination}.tmp.XXXXXX")"
  cat >"${temporary}"
  mv -- "${temporary}" "${destination}"
}

image_identity() {
  local reference="$1"
  local budget_status=0 inspect_status=0 inspect_output
  local budget_record effective_timeout_seconds timeout_scope campaign_remaining_seconds
  budget_record="$(timeout_budget_for "${input_inspect_timeout_seconds}" input)" || budget_status=$?
  [[ "${budget_status}" == 0 ]] || return "${budget_status}"
  IFS=$'\t' read -r effective_timeout_seconds timeout_scope campaign_remaining_seconds <<<"${budget_record}"
  inspect_output="$(
    timeout --signal=TERM --kill-after="${timeout_kill_after_seconds}s" "${effective_timeout_seconds}s" \
      "${docker_command}" image inspect "${reference}" 2>/dev/null
  )" || inspect_status=$?
  [[ "${inspect_status}" == 0 ]] || return "${inspect_status}"
  jq -ce --arg reference "${reference}" '
      .[0] | {
        reference: $reference,
        image_id: .Id,
        descriptor: (.Descriptor // null),
        repo_digests: (.RepoDigests // []),
        created: .Created,
        os: .Os,
        architecture: .Architecture,
        labels: (.Config.Labels // {})
      }
      | select(.image_id | type == "string" and startswith("sha256:"))
      | select(.os == "linux" and .architecture == "amd64")
    ' <<<"${inspect_output}"
}

resolve_inputs() {
  local target key reference identity identity_status contract_reference contract_path contract_json contract_sha256 contract_role
  jq -e '
    . as $inputs |
    $inputs.schema_version == 1 and
    ($inputs.common.perf_probe_image | type == "string" and length > 0) and
    ($inputs.common.external_benchmark_image | type == "string" and length > 0) and
    all(["x86-64-v2", "x86-64-v3"][]; . as $target |
      ($inputs.targets[$target] | type == "object") and
      all(["oxibelt_image", "keysigner_image", "keysigner_contract", "oxibelt_contract", "nginx_image", "caddy_image", "openresty_image"][];
        . as $key | ($inputs.targets[$target][$key] | type == "string" and length > 0)
      )
    )
  ' "${inputs_file}" >/dev/null || {
    echo "inputs manifest has an invalid campaign image shape: ${inputs_file}" >&2
    exit 65
  }

  local resolved="${campaign_dir}/resolved-inputs.json"
  local tooling="${campaign_dir}/tooling-identity.json"
  local raw_resolved raw_status=0
  jq -n \
    --arg wrapper "${script_dir}/$(basename -- "${BASH_SOURCE[0]}")" \
    --arg wrapper_sha256 "$(sha256sum "${script_dir}/$(basename -- "${BASH_SOURCE[0]}")" | awk '{print $1}')" \
    --arg runner "${runner}" \
    --arg runner_sha256 "$(sha256sum "${runner}" | awk '{print $1}')" \
    --arg aggregate_bin "${aggregate_bin}" \
    --arg aggregate_sha256 "$(if [[ -f "${aggregate_bin}" ]]; then sha256sum "${aggregate_bin}" | awk '{print $1}'; else echo unavailable; fi)" \
    '{wrapper: {path: $wrapper, sha256: $wrapper_sha256}, runner: {path: $runner, sha256: $runner_sha256}, aggregate: {path: $aggregate_bin, sha256: $aggregate_sha256}}' \
    | write_json_atomically "${tooling}"
  raw_resolved="$(mktemp "${campaign_dir}/.resolved-inputs.XXXXXX.json")"
  (
    printf '{"schema_version":1,"source":{"revision":"%s","tree":"%s"},"common":{' \
      "${source_revision}" "${source_tree}"
    for key in perf_probe_image external_benchmark_image; do
      reference="$(jq -r --arg key "${key}" '.common[$key]' "${inputs_file}")"
      identity_status=0
      identity="$(image_identity "${reference}")" || identity_status=$?
      if [[ "${identity_status}" != 0 ]]; then
        if [[ "${identity_status}" == 124 || "${identity_status}" == 137 ]]; then
          echo "inspection timed out for required common image ${key}: ${reference}" >&2
          exit "${identity_status}"
        fi
        echo "cannot inspect required common image ${key}: ${reference}" >&2
        exit 69
      fi
      printf '%s"%s":%s' "${common_separator:-}" "${key}" "${identity}"
      common_separator=,
    done
    printf '},"targets":{'
    local target_separator=""
    for target in x86-64-v2 x86-64-v3; do
      printf '%s"%s":{' "${target_separator}" "${target}"
      local key_separator=""
      for key in oxibelt_image keysigner_image nginx_image caddy_image openresty_image; do
        reference="$(jq -r --arg target "${target}" --arg key "${key}" '.targets[$target][$key]' "${inputs_file}")"
        identity_status=0
        identity="$(image_identity "${reference}")" || identity_status=$?
        if [[ "${identity_status}" != 0 ]]; then
          if [[ "${identity_status}" == 124 || "${identity_status}" == 137 ]]; then
            echo "inspection timed out for required ${target} image ${key}: ${reference}" >&2
            exit "${identity_status}"
          fi
          echo "cannot inspect required ${target} image ${key}: ${reference}" >&2
          exit 69
        fi
        case "${key}" in
          oxibelt_image|keysigner_image)
            jq -e --arg revision "${source_revision}" \
              '.labels["org.opencontainers.image.revision"] == $revision' <<<"${identity}" >/dev/null || {
                echo "${target} ${key} does not identify source revision ${source_revision}" >&2
                exit 65
              }
            ;;
          nginx_image|caddy_image|openresty_image)
            comparator="${key%_image}"
            jq -e --arg comparator "${comparator}" --arg target "${target}" \
              '.labels["org.oxibelt.performance.comparator"] == $comparator and .labels["org.oxibelt.performance.amd64_target_cpu"] == $target' \
              <<<"${identity}" >/dev/null || {
                echo "${target} ${key} lacks the expected comparator and target labels" >&2
                exit 65
              }
            ;;
        esac
        if [[ "${key}" == "oxibelt_image" || "${key}" == "keysigner_image" ]]; then
          contract_reference="$(jq -r --arg target "${target}" --arg key "${key%_image}_contract" '.targets[$target][$key]' "${inputs_file}")"
          if [[ "${contract_reference}" = /* ]]; then
            contract_path="${contract_reference}"
          else
            contract_path="$(dirname -- "${inputs_file}")/${contract_reference}"
          fi
          [[ -f "${contract_path}" ]] || {
            echo "missing ${target} ${key} artifact contract: ${contract_path}" >&2
            exit 65
          }
          contract_role="standalone"
          [[ "${key}" == "keysigner_image" ]] && contract_role="keysigner"
          contract_json="$(jq -ce --arg revision "${source_revision}" --arg tree "${source_tree}" \
            --arg target "${target}" --arg role "${contract_role}" --arg image_id "$(jq -r '.image_id' <<<"${identity}")" \
            --argjson descriptor "$(jq -c '.descriptor' <<<"${identity}")" '
              select(
                (keys | sort) == [
                  "artifact_arch", "binaries", "build_kind", "build_metadata", "build_parameters",
                  "cargo_builds", "config_digest", "created", "descriptor_digest", "docker_architecture",
                  "docker_target", "image_digest", "image_tar", "image_tar_sha256", "layers",
                  "normalized_config_sha256", "platform", "ref_name", "revision", "role", "rust_target",
                  "schema", "source", "source_dirty", "source_inputs", "source_inputs_sha256",
                  "source_ref", "source_tree", "target_cpu", "version"
                ] and
                .schema == 3 and
                ([.revision, .source, .source_tree, .version, .ref_name, .source_ref, .source_dirty,
                  .build_kind, .created, .role, .platform, .artifact_arch, .docker_architecture,
                  .rust_target, .target_cpu, .docker_target, .source_inputs_sha256, .image_tar,
                  .image_tar_sha256, .build_metadata, .config_digest, .normalized_config_sha256,
                  .descriptor_digest, .image_digest] | all(type == "string")) and
                (.cargo_builds | type == "array") and (.build_parameters | type == "object") and
                (.source_inputs | type == "object") and (.layers | type == "array") and
                (.binaries | type == "array") and
                .revision == $revision and .source_tree == $tree and
                .source_dirty == "clean" and .target_cpu == $target and
                .role == $role and
                (
                  .config_digest == $image_id or
                  (
                    ($descriptor | type == "object") and
                    $descriptor.mediaType == "application/vnd.oci.image.manifest.v1+json" and
                    $descriptor.digest == $image_id and
                    .descriptor_digest == $image_id and
                    .image_digest == $image_id
                  )
                )
              )
            ' "${contract_path}")" || {
              echo "${target} ${key} artifact contract or inspected descriptor does not bind its image and source identity" >&2
              exit 65
            }
          contract_sha256="$(sha256sum "${contract_path}" | awk '{print $1}')"
          identity="$(jq -c --arg path "${contract_path}" --arg sha256 "${contract_sha256}" \
            --slurpfile contract <(printf '%s\n' "${contract_json}") \
            '. + {artifact_contract: {path: $path, sha256: $sha256, document: $contract[0]}}' <<<"${identity}")"
        fi
        printf '%s"%s":%s' "${key_separator}" "${key}" "${identity}"
        key_separator=,
      done
      printf '}'
      target_separator=,
    done
    printf '}}\n'
  ) >"${raw_resolved}" || raw_status=$?
  if [[ "${raw_status}" != 0 ]]; then
    rm -f -- "${raw_resolved}"
    return "${raw_status}"
  fi

  jq -S . "${raw_resolved}" | write_json_atomically "${resolved}" || raw_status=$?
  rm -f -- "${raw_resolved}"
  return "${raw_status}"
}

initialize_campaign() {
  if [[ -f "${manifest}" ]]; then
    jq -e --arg revision "${source_revision}" --arg tree "${source_tree}" '
      .schema_version == 1 and .source.revision == $revision and .source.tree == $tree
    ' "${manifest}" >/dev/null || {
      echo "campaign source identity differs from the existing manifest" >&2
      exit 65
    }
    jq -e --slurpfile resolved "${campaign_dir}/resolved-inputs.json" \
      '.inputs == $resolved[0]' "${manifest}" >/dev/null || {
      echo "campaign image identities differ from the existing manifest" >&2
      exit 65
    }
    jq -e --slurpfile tooling "${campaign_dir}/tooling-identity.json" '
      .tooling.wrapper == $tooling[0].wrapper and
      .tooling.runner == $tooling[0].runner and
      (
        .tooling.aggregate == $tooling[0].aggregate or
        (.tooling.aggregate.sha256 == "unavailable" and $tooling[0].aggregate.sha256 != "unavailable")
      )
    ' "${manifest}" >/dev/null || {
      echo "campaign wrapper or runner identity differs from the existing manifest" >&2
      exit 65
    }
    if jq -e --slurpfile tooling "${campaign_dir}/tooling-identity.json" \
      '.tooling.aggregate.sha256 == "unavailable" and $tooling[0].aggregate.sha256 != "unavailable"' \
      "${manifest}" >/dev/null; then
      tooling_temporary="$(mktemp "${manifest}.tmp.XXXXXX")"
      jq --slurpfile tooling "${campaign_dir}/tooling-identity.json" \
        '.tooling.aggregate = $tooling[0].aggregate' "${manifest}" >"${tooling_temporary}"
      mv -- "${tooling_temporary}" "${manifest}"
    fi
    return
  fi
  if [[ -e "${campaign_dir}" && -n "$(find "${campaign_dir}" -mindepth 1 -maxdepth 1 ! -name resolved-inputs.json ! -name tooling-identity.json -print -quit)" ]]; then
    echo "campaign directory already contains data; choose a new --campaign-dir" >&2
    exit 73
  fi
  jq -n \
    --arg created_at "$(utc_now)" \
    --arg campaign_id "$(basename -- "${campaign_dir}")" \
    --arg revision "${source_revision}" \
    --arg tree "${source_tree}" \
    --argjson smoke_attempt_timeout_seconds "${smoke_attempt_timeout_seconds}" \
    --argjson benchmark_attempt_timeout_seconds "${benchmark_attempt_timeout_seconds}" \
    --argjson aggregate_timeout_seconds "${aggregate_timeout_seconds}" \
    --argjson input_inspect_timeout_seconds "${input_inspect_timeout_seconds}" \
    --argjson smoke_campaign_timeout_seconds "${smoke_campaign_timeout_seconds}" \
    --argjson benchmark_campaign_timeout_seconds "${benchmark_campaign_timeout_seconds}" \
    --argjson all_campaign_timeout_seconds "${all_campaign_timeout_seconds}" \
    --argjson timeout_kill_after_seconds "${timeout_kill_after_seconds}" \
    --slurpfile inputs "${campaign_dir}/resolved-inputs.json" \
    --slurpfile tooling "${campaign_dir}/tooling-identity.json" '
      {
        schema_version: 1,
        campaign_id: $campaign_id,
        created_at: $created_at,
        status: "collecting",
        source: {revision: $revision, tree: $tree},
        inputs: $inputs[0],
        tooling: $tooling[0],
        policy: {
          smoke_iterations: 1,
          benchmark_iterations: 5,
          expected_shards: 1,
          nginx_h3_mode: "required",
          runner_regression_gate_mode: "fail",
          external_benchmark_gate_mode: "warn",
          timeout_seconds: {
            attempt: {
              smoke: $smoke_attempt_timeout_seconds,
              benchmark: $benchmark_attempt_timeout_seconds
            },
            aggregate: $aggregate_timeout_seconds,
            input_inspect: $input_inspect_timeout_seconds,
            campaign: {
              smoke: $smoke_campaign_timeout_seconds,
              benchmark: $benchmark_campaign_timeout_seconds,
              all: $all_campaign_timeout_seconds
            },
            kill_after: $timeout_kill_after_seconds
          }
        },
        planned: {smoke: [], benchmark: []},
        attempts: [],
        aggregates: []
      }
    ' | write_json_atomically "${manifest}"
}

verify_manifest_source_identity() {
  local manifest_revision manifest_tree current_revision current_tree
  manifest_revision="$(jq -r '.source.revision // empty' "${manifest}")"
  manifest_tree="$(jq -r '.source.tree // empty' "${manifest}")"
  [[ "${manifest_revision}" =~ ^[0-9a-f]{40}$ && "${manifest_tree}" =~ ^[0-9a-f]{40}$ ]] || {
    echo "campaign manifest has an invalid source identity" >&2
    return 65
  }
  current_revision="$(git -C "${source_root}" rev-parse HEAD)"
  current_tree="$(git -C "${source_root}" rev-parse 'HEAD^{tree}')"
  if [[ "${manifest_revision}" != "${current_revision}" || "${manifest_tree}" != "${current_tree}" ]] ||
     ! git -C "${source_root}" diff --quiet --ignore-submodules -- ||
     ! git -C "${source_root}" diff --cached --quiet --ignore-submodules --; then
    echo "campaign source manifest identity does not match the clean source root" >&2
    return 65
  fi
  jq -e --arg revision "${manifest_revision}" --arg tree "${manifest_tree}" \
    --slurpfile resolved "${campaign_dir}/resolved-inputs.json" '
      .inputs == $resolved[0] and
      .inputs.source.revision == $revision and .inputs.source.tree == $tree
    ' "${manifest}" >/dev/null || {
      echo "campaign resolved inputs do not bind the manifest source identity" >&2
      return 65
    }
  source_revision="${manifest_revision}"
  source_tree="${manifest_tree}"
}

verify_recorded_tooling_identity() {
  local wrapper_path
  local wrapper_sha runner_sha aggregate_sha
  wrapper_path="${script_dir}/$(basename -- "${BASH_SOURCE[0]}")"
  wrapper_sha="$(sha256sum "${wrapper_path}" | awk '{print $1}')"
  runner_sha="$(sha256sum "${runner}" | awk '{print $1}')"
  aggregate_sha="$(sha256sum "${aggregate_bin}" | awk '{print $1}')"
  jq -e --arg wrapper_path "${wrapper_path}" --arg wrapper_sha "${wrapper_sha}" \
    --arg runner_path "${runner}" --arg runner_sha "${runner_sha}" \
    --arg aggregate_path "${aggregate_bin}" --arg aggregate_sha "${aggregate_sha}" '
      .tooling.wrapper.path == $wrapper_path and
      .tooling.wrapper.sha256 == $wrapper_sha and
      .tooling.runner.path == $runner_path and
      .tooling.runner.sha256 == $runner_sha and
      .tooling.aggregate.path == $aggregate_path and
      .tooling.aggregate.sha256 == $aggregate_sha
    ' "${manifest}" >/dev/null || {
      echo "campaign tooling identity no longer matches the recorded wrapper, runner, or aggregate binary" >&2
      return 65
    }
}

append_manifest_attempt() {
  local record="$1"
  local temporary
  temporary="$(mktemp "${manifest}.tmp.XXXXXX")"
  jq --slurpfile record "${record}" '.attempts += $record' "${manifest}" >"${temporary}"
  mv -- "${temporary}" "${manifest}"
}

set_manifest_status() {
  local status="$1"
  local temporary
  temporary="$(mktemp "${manifest}.tmp.XXXXXX")"
  jq --arg status "${status}" --arg updated_at "$(utc_now)" \
    '.status = $status | .updated_at = $updated_at' "${manifest}" >"${temporary}"
  mv -- "${temporary}" "${manifest}"
}

comparators_for_group() {
  case "$1" in
    reverse-proxy|static-files) echo "oxibelt,nginx,caddy,openresty" ;;
    *) echo "oxibelt" ;;
  esac
}

declare_collection_plan() {
  local profile="$1" iteration_count="$2" plan_file target group iteration relative_path temporary
  plan_file="$(mktemp "${campaign_dir}/.planned-${profile}.XXXXXX.json")"
  for target in "${selected_targets[@]}"; do
    for group in "${selected_groups[@]}"; do
      for ((iteration = 1; iteration <= iteration_count; iteration++)); do
        relative_path="${profile}-input/oxibelt-docker-performance-${profile}-${group}-shard-1/${target}/run-${iteration}"
        jq -n --arg target_cpu "${target}" --arg group "${group}" \
          --arg artifact_dir "${relative_path}" --argjson iteration "${iteration}" \
          '{target_cpu: $target_cpu, group: $group, iteration: $iteration, artifact_dir: $artifact_dir}' >>"${plan_file}"
      done
    done
  done
  temporary="$(mktemp "${manifest}.tmp.XXXXXX")"
  if ! jq -s . "${plan_file}" | jq --arg profile "${profile}" --slurpfile plan /dev/stdin '
    if (.planned[$profile] | length) != 0 then
      error("planned collection phase already exists; use a new campaign")
    else
      .planned[$profile] = $plan[0]
    end
  ' "${manifest}" >"${temporary}"; then
    rm -f -- "${plan_file}" "${temporary}"
    echo "campaign already contains a ${profile} plan; rerun in an explicit new campaign" >&2
    return 73
  fi
  rm -f -- "${plan_file}"
  mv -- "${temporary}" "${manifest}"
}

remove_attempt_secret() {
  local artifact_dir="$1" receipt_jsonl="$2" secret_file="$3"
  local secret_sha256 secret_bytes secret_path
  [[ -e "${secret_file}" ]] || return 0
  if [[ -L "${secret_file}" || ! -f "${secret_file}" ]]; then
    echo "copied campaign secret must be a regular non-symlink file: ${secret_file}" >&2
    return 1
  fi
  secret_sha256="$(sha256sum "${secret_file}" | awk '{print $1}')"
  secret_bytes="$(stat -c '%s' "${secret_file}")"
  secret_path="${secret_file#"${artifact_dir}"/}"
  rm -f -- "${secret_file}" || return 1
  jq -n --arg path "${secret_path}" --arg sha256 "${secret_sha256}" --argjson bytes "${secret_bytes}" \
    '{path: $path, sha256: $sha256, bytes: $bytes}' >>"${receipt_jsonl}"
}

cleanup_attempt_secrets() {
  local artifact_dir="$1" receipt
  local receipt_jsonl secret_file cleanup_status=0
  receipt="${artifact_dir}/restricted-receipt.json"
  receipt_jsonl="$(mktemp "${artifact_dir}/.restricted-receipt.XXXXXX.jsonl")"
  for secret_file in \
    "${artifact_dir}/proxy-tls/privkey.pem" \
    "${artifact_dir}/proxy-tls/quic-host-key.b64" \
    "${artifact_dir}/proxy-tls/keysigner-token.b64"
  do
    remove_attempt_secret "${artifact_dir}" "${receipt_jsonl}" "${secret_file}" || cleanup_status=1
  done
  if [[ -d "${artifact_dir}/configs" ]]; then
    while IFS= read -r -d '' secret_file; do
      remove_attempt_secret "${artifact_dir}" "${receipt_jsonl}" "${secret_file}" || cleanup_status=1
    done < <(find -P "${artifact_dir}/configs" -type f \( \
      -path '*/cert/privkey.pem' -o \
      -path '*/cert/quic-host-key.b64' -o \
      -path '*/cert/keysigner-token.b64' \
    \) -print0)
  fi
  jq -s --arg status "$(if [[ "${cleanup_status}" == 0 ]]; then echo removed; else echo failed; fi)" \
    '{schema_version: 1, status: $status, removed: .}' "${receipt_jsonl}" | write_json_atomically "${receipt}"
  rm -f -- "${receipt_jsonl}"
  return "${cleanup_status}"
}

timeout_budget_for() {
  local requested_seconds="$1" default_scope="$2"
  local elapsed_seconds remaining_seconds effective_seconds scope
  effective_seconds="${requested_seconds}"
  remaining_seconds=-1
  scope="${default_scope}"
  if (( campaign_timeout_seconds > 0 )); then
    elapsed_seconds=$((SECONDS - campaign_started_seconds))
    remaining_seconds=$((campaign_timeout_seconds - elapsed_seconds))
    if (( remaining_seconds <= 0 )); then
      printf '0\tcampaign\t0\n'
      return 124
    fi
    if (( remaining_seconds < effective_seconds )); then
      effective_seconds="${remaining_seconds}"
      scope=campaign
    fi
  fi
  printf '%s\t%s\t%s\n' "${effective_seconds}" "${scope}" "${remaining_seconds}"
}

last_attempt_timeout_scope=""

run_attempt() {
  local profile="$1" target="$2" group="$3" iteration="$4"
  local artifact_dir="${campaign_dir}/${profile}-input/oxibelt-docker-performance-${profile}-${group}-shard-1/${target}/run-${iteration}"
  local record="${artifact_dir}/campaign-attempt.json"
  local inputs="${campaign_dir}/resolved-inputs.json"
  local status=0 runner_status=0 cleanup_status=0 budget_status=0 timed_out=0
  local started_at started_seconds duration_seconds timeout_limit_seconds
  local budget_record effective_timeout_seconds timeout_scope campaign_remaining_seconds
  started_at="$(utc_now)"
  started_seconds="${SECONDS}"
  last_attempt_timeout_scope=""

  case "${profile}" in
    smoke) timeout_limit_seconds="${smoke_attempt_timeout_seconds}" ;;
    benchmark) timeout_limit_seconds="${benchmark_attempt_timeout_seconds}" ;;
    *) echo "unsupported timeout profile: ${profile}" >&2; return 64 ;;
  esac

  if [[ -e "${artifact_dir}" || -L "${artifact_dir}" ]]; then
    echo "attempt already exists (${artifact_dir}); rerun in an explicit new campaign" >&2
    return 73
  fi
  mkdir -p "${artifact_dir}"

  budget_record="$(timeout_budget_for "${timeout_limit_seconds}" attempt)" || budget_status=$?
  IFS=$'\t' read -r effective_timeout_seconds timeout_scope campaign_remaining_seconds <<<"${budget_record}"
  if [[ "${budget_status}" != 0 ]]; then
    runner_status=124
    printf 'Campaign timeout exhausted before this attempt could start.\n' >"${artifact_dir}/runner.log"
  else
    OXIBELT_DOCKER_IMAGE="$(jq -r --arg target "${target}" '.targets[$target].oxibelt_image.image_id' "${inputs}")" \
    OXIBELT_KEYSIGNER_DOCKER_IMAGE="$(jq -r --arg target "${target}" '.targets[$target].keysigner_image.image_id' "${inputs}")" \
    OXIBELT_NGINX_IMAGE="$(jq -r --arg target "${target}" '.targets[$target].nginx_image.image_id' "${inputs}")" \
    OXIBELT_CADDY_IMAGE="$(jq -r --arg target "${target}" '.targets[$target].caddy_image.image_id' "${inputs}")" \
    OXIBELT_OPENRESTY_IMAGE="$(jq -r --arg target "${target}" '.targets[$target].openresty_image.image_id' "${inputs}")" \
    OXIBELT_PERF_PROBE_IMAGE="$(jq -r '.common.perf_probe_image.image_id' "${inputs}")" \
    OXIBELT_EXTERNAL_BENCHMARK_IMAGE="$(jq -r '.common.external_benchmark_image.image_id' "${inputs}")" \
    OXIBELT_AMD64_TARGET_CPU="${target}" \
    OXIBELT_TEST_ARTIFACT_DIR="${artifact_dir}" \
    OXIBELT_PERF_REGRESSION_GATE_MODE=fail \
    OXIBELT_NGINX_H3_MODE=required \
    OXIBELT_EXTERNAL_BENCHMARK_GATE_MODE=warn \
    KEEP_TEST_ARTIFACTS=0 \
      timeout --signal=TERM --kill-after="${timeout_kill_after_seconds}s" "${effective_timeout_seconds}s" \
        "${runner}" --profile "${profile}" --serving-type "${group}" \
        --comparators "$(comparators_for_group "${group}")" \
        </dev/null >"${artifact_dir}/runner.log" 2>&1 || runner_status=$?
  fi
  cleanup_attempt_secrets "${artifact_dir}" || cleanup_status=$?
  if [[ "${runner_status}" == 124 || "${runner_status}" == 137 ]]; then
    timed_out=1
    last_attempt_timeout_scope="${timeout_scope}"
  fi
  status="${runner_status}"
  if [[ "${status}" == 0 && "${cleanup_status}" != 0 ]]; then
    status="${cleanup_status}"
  fi
  duration_seconds=$((SECONDS - started_seconds))

  jq -n \
    --arg profile "${profile}" --arg target_cpu "${target}" --arg group "${group}" \
    --arg artifact_dir "${artifact_dir#"${campaign_dir}"/}" --arg started_at "${started_at}" \
    --arg receipt "${artifact_dir#"${campaign_dir}"/}/restricted-receipt.json" \
    --arg finished_at "$(utc_now)" --arg timeout_scope "${timeout_scope}" \
    --arg campaign_remaining_seconds_at_start "${campaign_remaining_seconds}" \
    --argjson iteration "${iteration}" --argjson exit_code "${status}" \
    --argjson runner_exit_code "${runner_status}" --argjson cleanup_exit_code "${cleanup_status}" \
    --argjson timeout_limit_seconds "${timeout_limit_seconds}" \
    --argjson timeout_seconds "${effective_timeout_seconds}" \
    --argjson timeout_kill_after_seconds "${timeout_kill_after_seconds}" \
    --argjson duration_seconds "${duration_seconds}" --argjson timed_out "${timed_out}" '
      {
        profile: $profile, target_cpu: $target_cpu, group: $group,
        iteration: $iteration, artifact_dir: $artifact_dir,
        started_at: $started_at, finished_at: $finished_at, exit_code: $exit_code,
        runner_exit_code: $runner_exit_code, cleanup_exit_code: $cleanup_exit_code,
        duration_seconds: $duration_seconds,
        timeout_limit_seconds: $timeout_limit_seconds,
        timeout_seconds: $timeout_seconds,
        timeout_kill_after_seconds: $timeout_kill_after_seconds,
        campaign_remaining_seconds_at_start: (
          if $campaign_remaining_seconds_at_start == "-1" then null
          else ($campaign_remaining_seconds_at_start | tonumber)
          end
        ),
        timed_out: ($timed_out == 1),
        timeout_scope: (if $timed_out == 1 then $timeout_scope else null end),
        restricted_receipt: $receipt,
        status: (if $exit_code == 0 then "pass" elif $timed_out == 1 then "timeout" else "fail" end)
      }
    ' | write_json_atomically "${record}"
  append_manifest_attempt "${record}"
  return "${status}"
}

run_collection_phase() {
  local profile="$1" iteration_count="$2" already_declared="${3:-0}" failures=0
  local target group iteration attempt_status
  if [[ "${already_declared}" != 1 ]]; then
    declare_collection_plan "${profile}" "${iteration_count}" || return $?
  fi
  for target in "${selected_targets[@]}"; do
    for group in "${selected_groups[@]}"; do
      for ((iteration = 1; iteration <= iteration_count; iteration++)); do
        attempt_status=0
        run_attempt "${profile}" "${target}" "${group}" "${iteration}" || attempt_status=$?
        if [[ "${attempt_status}" != 0 ]]; then
          failures=1
          if [[ "${profile}" == "smoke" || "${last_attempt_timeout_scope}" == "campaign" ]]; then
            set_manifest_status "collection-failed"
            return 1
          fi
        fi
      done
    done
  done
  if [[ "${failures}" == 0 ]]; then
    set_manifest_status "collected"
  else
    set_manifest_status "collection-failed"
  fi
  return "${failures}"
}

baseline_for_primary_target() {
  local primary_target="$1" candidate
  [[ -n "${baseline_report}" ]] || return 0
  if [[ -d "${baseline_report}" ]]; then
    candidate="${baseline_report}/reports/benchmark-primary-${primary_target}/performance-comparison.json"
  else
    candidate="${baseline_report}"
  fi
  [[ -f "${candidate}" ]] || {
    echo "--baseline-report lacks the ${primary_target} primary report: ${candidate}" >&2
    return 65
  }
  jq -e --arg primary_target "${primary_target}" '
    .schema_version == 33 and
    .profile == "benchmark" and
    .quorum.status == "pass" and
    (.quorum.violations | type == "array" and length == 0) and
    .regression_gates.status == "pass" and
    (.regression_gates.violations | type == "array" and length == 0) and
    .regression_gates.accepted_regression.status == "inactive" and
    .primary_target_cpu == $primary_target
  ' "${candidate}" >/dev/null || {
    echo "--baseline-report is not a passing, unaccepted schema-33 ${primary_target} aggregate: ${candidate}" >&2
    return 65
  }
  printf '%s\n' "${candidate}"
}

require_intended_benchmark_paths() {
  local planned_count target group iteration artifact_dir attempt_status result_path
  planned_count="$(jq '[.planned.benchmark[]] | length' "${manifest}")"
  if [[ "${planned_count}" == 0 ]]; then
    echo "campaign has no intended benchmark attempts to aggregate" >&2
    return 65
  fi
  while IFS=$'\t' read -r target group iteration artifact_dir attempt_status; do
    result_path="${campaign_dir}/${artifact_dir}/results.json"
    if [[ "${attempt_status}" != "0" || -L "${campaign_dir}/${artifact_dir}" || -L "${result_path}" || ! -s "${result_path}" ]]; then
      echo "missing successful intended benchmark result: ${artifact_dir}/results.json" >&2
      return 65
    fi
    if ! jq -e --arg revision "${source_revision}" --arg target "${target}" --arg group "${group}" \
      --slurpfile inputs "${campaign_dir}/resolved-inputs.json" '
      type == "array" and length > 0 and
      all(.[];
        .amd64_target_cpu == $target and
        .benchmark_identity.source_sha == $revision and
        .benchmark_identity.source_dirty == false and
        .benchmark_identity.profile == "benchmark" and
        .benchmark_identity.serving_type == $group and
        .benchmark_identity.images.perf_probe.image_id == $inputs[0].common.perf_probe_image.image_id and
        .benchmark_identity.images.oxibelt.image_id == $inputs[0].targets[$target].oxibelt_image.image_id and
        .benchmark_identity.images.nginx.image_id == $inputs[0].targets[$target].nginx_image.image_id and
        .benchmark_identity.images.caddy.image_id == $inputs[0].targets[$target].caddy_image.image_id and
        .benchmark_identity.images.openresty.image_id == $inputs[0].targets[$target].openresty_image.image_id
      )
    ' "${campaign_dir}/${artifact_dir}/results.json" >/dev/null; then
      echo "benchmark identity metadata is invalid for ${artifact_dir}/results.json" >&2
      return 65
    fi
  done < <(
    jq -r '
      . as $manifest |
      .planned.benchmark[] | . as $planned |
      ([$manifest.attempts[]? | select(
          .profile == "benchmark" and
          .target_cpu == $planned.target_cpu and
          .group == $planned.group and
          .iteration == $planned.iteration and
          .artifact_dir == $planned.artifact_dir
        ) | .exit_code]
       | if length == 1 then .[0] else "missing" end) as $exit_code |
      [$planned.target_cpu, $planned.group, $planned.iteration, $planned.artifact_dir, $exit_code] | @tsv
    ' "${manifest}"
  )
}

aggregate_campaign() {
  local primary_target report_dir report_json aggregate_status=0 aggregate_command_status=0
  local overall_status=0 baseline_for_primary expected_targets_csv full_campaign=0 reports_root
  local budget_status budget_record effective_timeout_seconds timeout_scope
  local campaign_remaining_seconds timed_out aggregate_started_seconds aggregate_duration_seconds
  verify_manifest_source_identity || return $?
  verify_recorded_tooling_identity || return $?
  require_intended_benchmark_paths || return $?
  mapfile -t aggregate_targets < <(jq -r '.planned.benchmark[].target_cpu' "${manifest}" | sort -u)
  expected_targets_csv="$(IFS=,; echo "${aggregate_targets[*]}")"
  # Validate every selected primary before emitting either report. A single
  # target-primary baseline cannot qualify a dual-target candidate campaign.
  for primary_target in "${aggregate_targets[@]}"; do
    baseline_for_primary_target "${primary_target}" >/dev/null || return $?
  done
  if [[ "${expected_targets_csv}" == "x86-64-v2,x86-64-v3" ]] && jq -e '
    def expected_attempts:
      ["x86-64-v2", "x86-64-v3"][] as $target |
      ["reverse-proxy", "static-files", "oxibelt-features", "remote-signer", "oxibelt-soak-stress"][] as $group |
      range(1; 6) as $iteration |
      {
        target_cpu: $target,
        group: $group,
        iteration: $iteration,
        artifact_dir: ("benchmark-input/oxibelt-docker-performance-benchmark-" + $group + "-shard-1/" + $target + "/run-" + ($iteration | tostring))
      };
    (.planned.benchmark | sort_by([.target_cpu, .group, .iteration, .artifact_dir])) ==
      ([expected_attempts] | sort_by([.target_cpu, .group, .iteration, .artifact_dir]))
  ' "${manifest}" >/dev/null; then
    full_campaign=1
  fi
  reports_root="${campaign_dir}/reports"
  if [[ -L "${reports_root}" ]]; then
    echo "campaign reports directory must not be a symlink: ${reports_root}" >&2
    return 73
  fi
  for primary_target in "${aggregate_targets[@]}"; do
    baseline_for_primary="$(baseline_for_primary_target "${primary_target}")" || return $?
    report_dir="${campaign_dir}/reports/benchmark-primary-${primary_target}"
    report_json="${report_dir}/performance-comparison.json"
    if [[ -e "${report_dir}" || -L "${report_dir}" ]]; then
      echo "aggregate report directory already exists; rerun in an explicit new campaign: ${report_dir}" >&2
      return 73
    fi
    mkdir -p "${report_dir}"
    aggregate_args=(
      "${aggregate_bin}"
      --input-dir "${campaign_dir}/benchmark-input"
      --output-dir "${report_dir}"
      --profile benchmark
      --expected-runs 5
      --expected-shards 1
      --expected-target-cpus "${expected_targets_csv}"
      --primary-target-cpu "${primary_target}"
    )
    if [[ -n "${baseline_for_primary}" ]]; then
      aggregate_args+=(--baseline-report "${baseline_for_primary}")
    fi
    budget_status=0
    budget_record="$(timeout_budget_for "${aggregate_timeout_seconds}" aggregate)" || budget_status=$?
    IFS=$'\t' read -r effective_timeout_seconds timeout_scope campaign_remaining_seconds <<<"${budget_record}"
    aggregate_started_seconds="${SECONDS}"
    aggregate_command_status=0
    aggregate_status=0
    timed_out=0
    if [[ "${budget_status}" != 0 ]]; then
      aggregate_command_status=124
      printf 'Campaign timeout exhausted before this aggregate could start.\n' >"${report_dir}/aggregate.log"
    else
      timeout --signal=TERM --kill-after="${timeout_kill_after_seconds}s" "${effective_timeout_seconds}s" \
        "${aggregate_args[@]}" </dev/null >"${report_dir}/aggregate.log" 2>&1 || aggregate_command_status=$?
    fi
    aggregate_status="${aggregate_command_status}"
    if [[ "${aggregate_command_status}" == 124 || "${aggregate_command_status}" == 137 ]]; then
      timed_out=1
    fi
    if [[ "${aggregate_status}" != 0 || ! -f "${report_json}" ]] || ! jq -e '.schema_version == 33' "${report_json}" >/dev/null; then
      echo "aggregate gate failed for ${primary_target}; see ${report_dir}/aggregate.log" >&2
      if [[ "${aggregate_status}" == 0 ]]; then
        aggregate_status=1
      fi
      overall_status=1
    elif [[ "${full_campaign}" == 1 ]] && ! jq -e --arg primary_target "${primary_target}" '
      .profile == "benchmark" and
      .quorum.status == "pass" and
      (.quorum.violations | type == "array" and length == 0) and
      .regression_gates.status == "pass" and
      (.regression_gates.violations | type == "array" and length == 0) and
      .regression_gates.accepted_regression.status == "inactive" and
      .primary_target_cpu == $primary_target
    ' "${report_json}" >/dev/null; then
      echo "aggregate gate failed for ${primary_target}; see ${report_dir}/aggregate.log" >&2
      aggregate_status=1
      overall_status=1
    fi
    aggregate_duration_seconds=$((SECONDS - aggregate_started_seconds))
    local aggregate_record="${report_dir}/campaign-aggregate.json"
    jq -n --arg primary_target "${primary_target}" --arg report_dir "${report_dir#"${campaign_dir}"/}" \
      --arg finished_at "$(utc_now)" --arg timeout_scope "${timeout_scope}" \
      --arg campaign_remaining_seconds_at_start "${campaign_remaining_seconds}" \
      --argjson exit_code "${aggregate_status}" --argjson command_exit_code "${aggregate_command_status}" \
      --argjson full_campaign "${full_campaign}" --argjson timed_out "${timed_out}" \
      --argjson duration_seconds "${aggregate_duration_seconds}" \
      --argjson timeout_seconds "${effective_timeout_seconds}" \
      --argjson timeout_limit_seconds "${aggregate_timeout_seconds}" \
      --argjson timeout_kill_after_seconds "${timeout_kill_after_seconds}" '
      {
        primary_target: $primary_target,
        report_dir: $report_dir,
        finished_at: $finished_at,
        exit_code: $exit_code,
        command_exit_code: $command_exit_code,
        duration_seconds: $duration_seconds,
        timeout_limit_seconds: $timeout_limit_seconds,
        timeout_seconds: $timeout_seconds,
        timeout_kill_after_seconds: $timeout_kill_after_seconds,
        campaign_remaining_seconds_at_start: (
          if $campaign_remaining_seconds_at_start == "-1" then null
          else ($campaign_remaining_seconds_at_start | tonumber)
          end
        ),
        timed_out: ($timed_out == 1),
        timeout_scope: (if $timed_out == 1 then $timeout_scope else null end),
        status: (
          if $timed_out == 1 then "timeout"
          elif $full_campaign == 0 then "diagnostic"
          elif $exit_code == 0 then "pass"
          else "fail"
          end
        )
      }' \
      | write_json_atomically "${aggregate_record}"
    local temporary
    temporary="$(mktemp "${manifest}.tmp.XXXXXX")"
    jq --slurpfile record "${aggregate_record}" '.aggregates += $record' "${manifest}" >"${temporary}"
    mv -- "${temporary}" "${manifest}"
    if [[ "${timed_out}" == 1 && "${timeout_scope}" == "campaign" ]]; then
      break
    fi
  done
  if [[ "${full_campaign}" == 0 ]]; then
    set_manifest_status "diagnostic"
  elif [[ "${overall_status}" == 0 ]]; then
    set_manifest_status "passed"
  else
    set_manifest_status "aggregate-failed"
  fi
  return "${overall_status}"
}

final_status=0
if [[ "${phase}" == "aggregate" ]]; then
  [[ -f "${manifest}" ]] || { echo "campaign manifest does not exist: ${manifest}" >&2; exit 66; }
  source_revision="$(jq -r '.source.revision' "${manifest}")"
  source_tree="$(jq -r '.source.tree' "${manifest}")"
  aggregate_campaign || final_status=1
else
  resolve_inputs
  initialize_campaign
  collection_status=0
  case "${phase}" in
    smoke) run_collection_phase smoke 1 || collection_status=1 ;;
    benchmark) run_collection_phase benchmark 5 || collection_status=1 ;;
    all)
      declare_collection_plan smoke 1 || collection_status=1
      declare_collection_plan benchmark 5 || collection_status=1
      if [[ "${collection_status}" == 0 ]]; then
        run_collection_phase smoke 1 1 || collection_status=1
      fi
      if [[ "${collection_status}" == 0 ]]; then
        run_collection_phase benchmark 5 1 || collection_status=1
      fi
      if [[ "${collection_status}" == 0 ]]; then
        aggregate_campaign || collection_status=1
      fi
      ;;
  esac
  if [[ "${collection_status}" != 0 ]]; then
    set_manifest_status "failed"
    final_status=1
  fi
fi

jq '{campaign_id, status, source, planned, attempts: (.attempts | length), aggregates}' "${manifest}"
exit "${final_status}"
