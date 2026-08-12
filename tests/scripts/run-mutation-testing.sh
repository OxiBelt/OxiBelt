#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

fail() {
  echo "run-mutation-testing: $*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
repo_root="$(cd -- "${script_dir}/../.." && pwd -P)"
readonly repo_root
readonly config="${repo_root}/mewt.toml"
readonly runner_temp_base="${RUNNER_TEMP:-/tmp}"
readonly artifact_dir="${OXIBELT_MUTATION_ARTIFACT_DIR:-${runner_temp_base}/oxibelt-mutation-testing}"
readonly database="${artifact_dir}/mewt.sqlite"
readonly status_json="${artifact_dir}/status.json"
readonly results_json="${artifact_dir}/results.json"
readonly results_sarif="${artifact_dir}/results.sarif"

[[ "${runner_temp_base}" = /* && "${artifact_dir}" = /* ]] \
  || fail "RUNNER_TEMP and the mutation artifact directory must be absolute"
[[ -f "${config}" && ! -L "${config}" ]] || fail "missing canonical mewt.toml"
[[ "$(mewt --version)" == "mewt 4.0.0" ]] || fail "mewt 4.0.0 is required"

[[ ! -e "${artifact_dir}" && ! -L "${artifact_dir}" ]] \
  || fail "mutation artifact directory must start absent"
mkdir -m 0700 -- "${artifact_dir}"
[[ -d "${artifact_dir}" && -O "${artifact_dir}" \
  && "$(stat -c '%a' -- "${artifact_dir}")" == "700" ]] \
  || fail "mutation artifact directory must be owned by the current user with mode 0700"

cd -- "${repo_root}"
mewt --config "${config}" --db "${database}" mutate
mewt --config "${config}" --db "${database}" run
mewt --config "${config}" --db "${database}" status --format json \
  >"${status_json}"
mewt --config "${config}" --db "${database}" results --all --format json \
  >"${results_json}"
mewt --config "${config}" --db "${database}" results --all --format sarif \
  >"${results_sarif}"

jq -e '
  .campaign.total_mutants > 0
    and .campaign.tested == .campaign.total_mutants
    and .campaign.untested == 0
    and .campaign.skipped == 0
    and .campaign.timeout == 0
' "${status_json}" >/dev/null || {
  jq -r '.campaign | "total=\(.total_mutants) tested=\(.tested) untested=\(.untested) skipped=\(.skipped) timeout=\(.timeout)"' \
    "${status_json}" >&2
  fail "the complete configured mutation inventory must be tested without skips or timeouts"
}

jq -e --argjson tested "$(jq -r '.campaign.tested' "${status_json}")" '
  (.results | length) > 0
    and (.results | length) == $tested
    and all(.results[]; .outcome.status == "TestFail")
' "${results_json}" >/dev/null || {
  jq -r '
    if (.results | length) == 0 then
      "no mutation outcomes were produced"
    else
      .results[]
      | select(.outcome.status != "TestFail")
      | "\(.outcome.status): \(.target.path):\((.mutant.line_offset // 0) + 1) [\(.mutant.mutation_slug)]"
    end
  ' "${results_json}" >&2
  fail "every configured mutant must be caught without skips, timeouts, or unknown outcomes"
}

printf 'mutation testing passed with %s caught mutants\n' \
  "$(jq -r '.results | length' "${results_json}")"
