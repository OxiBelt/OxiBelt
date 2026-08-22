#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tests/scripts/check-github-release-tag-ruleset.sh --visibility <public|authenticated>
EOF
}

if [[ "$#" -ne 2 || "$1" != "--visibility" || ("$2" != "public" && "$2" != "authenticated") ]]; then
  usage
  exit 2
fi

visibility="$2"
repo_root="$(git rev-parse --show-toplevel)"
binding="${repo_root}/devops/config/github-release-tag-ruleset-binding.json"
[[ -f "${binding}" && ! -L "${binding}" ]] \
  || { echo "release-tag ruleset binding must be a regular non-symlink file" >&2; exit 1; }
repository="$(jq -er '.repository | select(type == "string")' "${binding}")"
ruleset_id="$(jq -er '.rulesetId | select(type == "number" and . > 0)' "${binding}")"
work_dir="$(mktemp -d)"

cleanup() {
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT

chmod 700 "${work_dir}"
index="${work_dir}/rulesets-index.json"
ruleset="${work_dir}/release-tag-ruleset.json"

if [[ "${visibility}" == "authenticated" ]]; then
  identity="$(gh api user --jq '[.login, .id, .type] | @tsv')"
  identity_pattern=$'^[^[:space:]]+\t[1-9][0-9]*\tUser$'
  [[ "${identity}" =~ ${identity_pattern} ]] \
    || { echo "authenticated GitHub identity is not a canonical user" >&2; exit 1; }
fi

gh api --paginate --slurp \
  "repos/${repository}/rulesets?includes_parents=true&per_page=100" >"${index}"
gh api \
  "repos/${repository}/rulesets/${ruleset_id}?includes_parents=true" >"${ruleset}"
chmod 600 "${index}" "${ruleset}"

pnpm run release-tag-ruleset:check \
  --workspace-path "${repo_root}" \
  --index "${index}" \
  --ruleset "${ruleset}" \
  --visibility "${visibility}"

printf 'release-tag ruleset %s visibility check passed for %s/%s\n' \
  "${visibility}" "${repository}" "${ruleset_id}"
