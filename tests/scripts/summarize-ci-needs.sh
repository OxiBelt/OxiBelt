#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <needs-json> <summary-json> <summary-markdown>" >&2
}

if [[ "$#" -ne 3 ]]; then
  usage
  exit 2
fi

needs_json="$1"
summary_json="$2"
summary_markdown="$3"

required_jobs=(
  source-structure
  test
  rust-advisory-checks
  fuzz-smoke
  unsafe-validation
  check-riscv64-cross
  generate-test-matrices
  linux-target-builds
  docker-alpine-musl-image-amd64
  docker-alpine-musl-role-image-amd64
  docker-alpine-musl-role-image-other
  docker-alpine-musl-image-other
  docker-alpine-musl-image-riscv64
  docker-image-trivy-scan
  docker-integration-helper-images
  admin-mutation-postgres
  admin-operation-postgres
  admin-audit-anchor-postgres
  kubernetes-immutable-rollout
  kubernetes-pod-lifecycle
  kubernetes-network-policy
  kubernetes-current-compatibility
  docker-integration-config-runtime
  docker-integration-proxy
  docker-integration-protocol
  docker-integration-waf
  docker-integration-cache
  docker-integration-state-data
  docker-integration-ops
  docker-integration-security
  remote-signer-dos-docker
  browser-webdriver
)

if [[ ! -f "${needs_json}" ]]; then
  echo "needs JSON does not exist: ${needs_json}" >&2
  exit 2
fi

mkdir -p -- "$(dirname -- "${summary_json}")" "$(dirname -- "${summary_markdown}")"

temporary_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "${temporary_dir}"
}
trap cleanup EXIT

printf '%s\n' "${required_jobs[@]}" | LC_ALL=C sort | jq -Rsc 'split("\n") | map(select(length > 0))' >"${temporary_dir}/expected.json"

if ! jq -e '
  type == "object" and
  all(to_entries[]; (.value | type) == "object" and (.value.result | type) == "string")
' "${needs_json}" >/dev/null; then
  echo "needs JSON must map every job ID to an object with a string result" >&2
  exit 2
fi

jq -c 'keys | sort' "${needs_json}" >"${temporary_dir}/actual.json"
jq -c '
  [
    to_entries[]
    | {id: .key, result: .value.result}
  ]
  | sort_by(.id)
' "${needs_json}" >"${temporary_dir}/jobs.json"

jq -n -c \
  --slurpfile expected "${temporary_dir}/expected.json" \
  --slurpfile actual "${temporary_dir}/actual.json" \
  '$expected[0] - $actual[0]' >"${temporary_dir}/missing.json"
jq -n -c \
  --slurpfile expected "${temporary_dir}/expected.json" \
  --slurpfile actual "${temporary_dir}/actual.json" \
  '$actual[0] - $expected[0]' >"${temporary_dir}/extra.json"
jq -c '[.[] | select(.result != "success")]' "${temporary_dir}/jobs.json" >"${temporary_dir}/unexpected.json"

overall="success"
if [[ "$(jq 'length' "${temporary_dir}/missing.json")" -ne 0 ||
      "$(jq 'length' "${temporary_dir}/extra.json")" -ne 0 ||
      "$(jq 'length' "${temporary_dir}/unexpected.json")" -ne 0 ]]; then
  overall="failure"
fi

jq -n \
  --arg repository "${GITHUB_REPOSITORY:-local}" \
  --arg event "${GITHUB_EVENT_NAME:-local}" \
  --arg sha "${GITHUB_SHA:-local}" \
  --arg ref "${GITHUB_REF:-local}" \
  --arg run_id "${GITHUB_RUN_ID:-local}" \
  --arg run_attempt "${GITHUB_RUN_ATTEMPT:-local}" \
  --arg overall "${overall}" \
  --slurpfile jobs "${temporary_dir}/jobs.json" \
  --slurpfile unexpected "${temporary_dir}/unexpected.json" \
  --slurpfile missing "${temporary_dir}/missing.json" \
  --slurpfile extra "${temporary_dir}/extra.json" \
  '{
    schema: 1,
    repository: $repository,
    event: $event,
    sha: $sha,
    ref: $ref,
    run_id: $run_id,
    run_attempt: $run_attempt,
    overall: $overall,
    jobs: $jobs[0],
    unexpected: $unexpected[0],
    missing_jobs: $missing[0],
    extra_jobs: $extra[0]
  }' >"${temporary_dir}/summary.json"

mv -- "${temporary_dir}/summary.json" "${summary_json}"

jq -r '
  def cell: tostring | gsub("[|\\r\\n]"; " ");
  "## Non-benchmark validation summary\n",
  "- Overall: `\(.overall | cell)`",
  "- Commit: `\(.sha | cell)`",
  "- Event: `\(.event | cell)`\n",
  "| Required job | Result |",
  "| --- | --- |",
  (.jobs[] | "| `\(.id | cell)` | `\(.result | cell)` |"),
  (if (.missing_jobs | length) > 0 then "\nMissing jobs: `\(.missing_jobs | join(", ") | cell)`" else empty end),
  (if (.extra_jobs | length) > 0 then "\nUnexpected jobs: `\(.extra_jobs | join(", ") | cell)`" else empty end)
' "${summary_json}" >"${summary_markdown}"

if [[ "${overall}" != "success" ]]; then
  echo "one or more required non-benchmark jobs did not succeed" >&2
  exit 1
fi
