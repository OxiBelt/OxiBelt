#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
generated="$(mktemp)"
trap 'rm -f -- "${generated}"' EXIT

cd "${repo_root}"
cargo run \
  --quiet \
  --package oxibelt \
  --example generate-native-config-schema \
  --features config-tooling \
  --locked \
  -- "${generated}"

if ! cmp --silent "${generated}" source/assets/oxibelt-config-v1.schema.json; then
  echo "native configuration schema drifted; regenerate it with:" >&2
  echo "cargo run -p oxibelt --example generate-native-config-schema --features config-tooling -- source/assets/oxibelt-config-v1.schema.json" >&2
  diff --unified source/assets/oxibelt-config-v1.schema.json "${generated}" || true
  exit 1
fi

echo "Native configuration schema is current."
