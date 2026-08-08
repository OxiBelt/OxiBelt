#!/usr/bin/env bash
set -euo pipefail

script_path="$(readlink -f "${BASH_SOURCE[0]}")"
script_dir="$(dirname "${script_path}")"
repo_root="$(git -C "${script_dir}/../.." rev-parse --show-toplevel)"
repo_root="$(readlink -f "${repo_root}")"
[[ "$(git -C "${repo_root}" rev-parse --is-inside-work-tree)" == "true" ]] \
  && [[ "$(git -C "${repo_root}" rev-parse --show-toplevel)" == "${repo_root}" ]] \
  || {
    printf 'error: checker script must reside under the Git repository top-level\n' >&2
    exit 1
  }
canonical_fixture_dir="${repo_root}/tests/fixtures/owned-embedded-runtime-api"
fixture_dir="${OXIBELT_OWNED_EMBEDDED_RUNTIME_API_FIXTURE:-${canonical_fixture_dir}}"
root_lock="${OXIBELT_OWNED_EMBEDDED_RUNTIME_API_ROOT_LOCK:-${repo_root}/Cargo.lock}"
actual_snapshot=""
work_dir=""

cleanup() {
  [[ -z "${actual_snapshot}" ]] || rm -f -- "${actual_snapshot}"
  [[ -z "${work_dir}" ]] || rm -rf -- "${work_dir}"
}
trap cleanup EXIT

validate_fixture_inventory() {
  local candidate="$1"
  local expected=("Cargo.toml" "lifecycle-api.snapshot" "src" "src/main.rs")
  local actual=()

  [[ -d "${candidate}" && ! -L "${candidate}" ]] || {
    printf 'error: fixture root must be a real non-symlink directory\n' >&2
    exit 1
  }
  [[ -f "${candidate}/Cargo.toml" && ! -L "${candidate}/Cargo.toml" ]] || {
    printf 'error: fixture Cargo.toml must be a regular non-symlink file\n' >&2
    exit 1
  }
  [[ -f "${candidate}/lifecycle-api.snapshot" && ! -L "${candidate}/lifecycle-api.snapshot" ]] || {
    printf 'error: fixture lifecycle-api.snapshot must be a regular non-symlink file\n' >&2
    exit 1
  }
  [[ -d "${candidate}/src" && ! -L "${candidate}/src" ]] || {
    printf 'error: fixture src must be a real non-symlink directory\n' >&2
    exit 1
  }
  [[ -f "${candidate}/src/main.rs" && ! -L "${candidate}/src/main.rs" ]] || {
    printf 'error: fixture src/main.rs must be a regular non-symlink file\n' >&2
    exit 1
  }

  mapfile -t actual < <(find -P "${candidate}" -mindepth 1 -printf '%P\n' | LC_ALL=C sort)
  if ((${#actual[@]} != ${#expected[@]})); then
    printf 'error: fixture inventory contains an unexpected entry\n' >&2
    exit 1
  fi
  for index in "${!expected[@]}"; do
    [[ "${actual[index]}" == "${expected[index]}" ]] || {
      printf 'error: fixture inventory contains an unexpected entry\n' >&2
      exit 1
    }
  done
}

copy_regular_no_follow() {
  local source="$1"
  local destination="$2"

  python3 - "${source}" "${destination}" <<'PY'
import os
import stat
import sys

source_path, destination_path = sys.argv[1:]
source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
destination_flags = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
)
source_fd = os.open(source_path, source_flags)
try:
    if not stat.S_ISREG(os.fstat(source_fd).st_mode):
        raise SystemExit("error: source must be a regular file")
    destination_fd = os.open(destination_path, destination_flags, 0o600)
    try:
        while chunk := os.read(source_fd, 1024 * 1024):
            offset = 0
            while offset < len(chunk):
                offset += os.write(destination_fd, chunk[offset:])
    finally:
        os.close(destination_fd)
finally:
    os.close(source_fd)
PY
}

validate_fixture_inventory "${fixture_dir}"
validate_fixture_inventory "${canonical_fixture_dir}"
[[ -f "${root_lock}" && ! -L "${root_lock}" ]] || {
  printf 'error: root lockfile must be a regular non-symlink file\n' >&2
  exit 1
}

actual_snapshot="$(mktemp)"
work_dir="$(mktemp -d)"
work_fixture_dir="${work_dir}/tests/fixtures/owned-embedded-runtime-api"
generated_lock="${work_fixture_dir}/Cargo.lock"
root_lock_snapshot="${work_dir}/root.Cargo.lock"
canonical_fixture_snapshot_dir="${work_dir}/canonical-fixture"
canonical_manifest_snapshot="${canonical_fixture_snapshot_dir}/Cargo.toml"
canonical_lifecycle_snapshot="${canonical_fixture_snapshot_dir}/lifecycle-api.snapshot"
canonical_source_snapshot="${canonical_fixture_snapshot_dir}/src/main.rs"

mkdir -p "$(dirname "${work_fixture_dir}")"
mkdir -p "${work_fixture_dir}/src"
mkdir -p "${canonical_fixture_snapshot_dir}/src"
copy_regular_no_follow "${fixture_dir}/Cargo.toml" "${work_fixture_dir}/Cargo.toml"
copy_regular_no_follow "${fixture_dir}/lifecycle-api.snapshot" "${work_fixture_dir}/lifecycle-api.snapshot"
copy_regular_no_follow "${fixture_dir}/src/main.rs" "${work_fixture_dir}/src/main.rs"
copy_regular_no_follow "${canonical_fixture_dir}/Cargo.toml" "${canonical_manifest_snapshot}"
copy_regular_no_follow "${canonical_fixture_dir}/lifecycle-api.snapshot" "${canonical_lifecycle_snapshot}"
copy_regular_no_follow "${canonical_fixture_dir}/src/main.rs" "${canonical_source_snapshot}"
cmp -s -- "${work_fixture_dir}/Cargo.toml" "${canonical_manifest_snapshot}" || {
  printf 'error: fixture Cargo.toml must match the canonical fixture manifest\n' >&2
  exit 1
}
cmp -s -- "${work_fixture_dir}/lifecycle-api.snapshot" "${canonical_lifecycle_snapshot}" || {
  printf 'error: fixture lifecycle-api.snapshot must match the canonical fixture snapshot\n' >&2
  exit 1
}
ln -s "${repo_root}/Cargo.toml" "${work_dir}/Cargo.toml"
ln -s "${repo_root}/docs" "${work_dir}/docs"
ln -s "${repo_root}/fuzz" "${work_dir}/fuzz"
ln -s "${repo_root}/source" "${work_dir}/source"
ln -s "${repo_root}/tests/unsafe_harness" "${work_dir}/tests/unsafe_harness"
copy_regular_no_follow "${root_lock}" "${root_lock_snapshot}"
copy_regular_no_follow "${root_lock_snapshot}" "${generated_lock}"

if grep -Eq 'cfg_attr|#[[:space:]]*\[[[:space:]]*cfg' "${work_fixture_dir}/src/main.rs"; then
  printf 'error: fixture source must not contain cfg attributes\n' >&2
  exit 1
fi

awk '
  /^(async )?fn surface_/ {
    name = $0
    sub(/^(async )?fn surface_/, "", name)
    sub(/\(.*/, "", name)
    sub(/__/, "::", name)
    print name
  }
' "${work_fixture_dir}/src/main.rs" >"${actual_snapshot}"
diff -u "${canonical_lifecycle_snapshot}" "${actual_snapshot}"
cmp -s -- "${work_fixture_dir}/src/main.rs" "${canonical_source_snapshot}" || {
  printf 'error: fixture src/main.rs must match the canonical fixture source\n' >&2
  exit 1
}

# The external fixture is not a root-workspace member. Resolve it once offline
# from the checked-in lock, then reject any package version, source, checksum,
# duplicate, or added dependency edge that is not already present in the root
# resolution. The external graph may prune root-only optional edges.
cargo metadata --offline --format-version 1 --manifest-path "${work_fixture_dir}/Cargo.toml" >/dev/null
python3 - "${root_lock_snapshot}" "${generated_lock}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
import tomllib

root_path = pathlib.Path(sys.argv[1])
generated_path = pathlib.Path(sys.argv[2])

def load(path):
    with path.open("rb") as source:
        return tomllib.load(source)

def package_key(record):
    return (record.get("name"), record.get("version"), record.get("source"))

def resolution_record(record):
    return {
        "name": record.get("name"),
        "version": record.get("version"),
        "source": record.get("source"),
        "checksum": record.get("checksum"),
    }

def record_hash(records):
    encoded = [
        json.dumps(record, sort_keys=True, separators=(",", ":"))
        for record in records
    ]
    return hashlib.sha256("\n".join(sorted(encoded)).encode()).hexdigest()

def normalized_dependencies(record, package_index, label):
    dependencies = set()
    for dependency in record.get("dependencies", []):
        parts = dependency.split()
        name = parts[0]
        candidates = [key for key in package_index if key[0] == name]
        if len(parts) > 1 and re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", parts[1]):
            candidates = [key for key in candidates if key[1] == parts[1]]
        if len(parts) > 2 and parts[2].startswith("(") and parts[-1].endswith(")"):
            source = " ".join(parts[2:])[1:-1]
            candidates = [key for key in candidates if key[2] == source]
        if len(candidates) != 1:
            raise SystemExit(
                f"error: {label} dependency {dependency!r} does not resolve to one locked package"
            )
        dependencies.add(candidates[0])
    return dependencies

root = load(root_path)
generated = load(generated_path)
root_packages = root.get("package", [])
generated_packages = generated.get("package", [])

fixture_name = "oxibelt-owned-embedded-runtime-api-fixture"
fixture_records = [
    record for record in generated_packages if record.get("name") == fixture_name
]
if len(fixture_records) != 1:
    raise SystemExit("error: offline fixture resolution must add exactly one fixture package record")
fixture = fixture_records[0]
expected_fixture = {
    "name": fixture_name,
    "version": "0.0.0",
    "dependencies": ["anyhow", "oxibelt", "tokio"],
}
if fixture != expected_fixture:
    raise SystemExit("error: offline fixture resolution has an unexpected local dependency set")

root_by_key = {}
for record in root_packages:
    key = package_key(record)
    if key in root_by_key:
        raise SystemExit("error: checked-in root lockfile has a duplicate package identity")
    root_by_key[key] = record

temporary_packages = [
    record for record in generated_packages if record.get("name") != fixture_name
]
temporary_by_key = {}
for record in temporary_packages:
    key = package_key(record)
    if key in temporary_by_key:
        raise SystemExit("error: temporary lockfile has a duplicate package identity")
    temporary_by_key[key] = record

root_resolution = []
temporary_resolution = []
for record in temporary_packages:
    key = package_key(record)
    root_record = root_by_key.get(key)
    if root_record is None:
        raise SystemExit("error: temporary lockfile selects a package absent from the checked-in root lockfile")
    if record.get("checksum") != root_record.get("checksum"):
        raise SystemExit("error: temporary lockfile changes a checked-in package checksum")
    temporary_edges = normalized_dependencies(record, temporary_by_key, "temporary lockfile")
    root_edges = normalized_dependencies(root_record, root_by_key, "checked-in root lockfile")
    if not temporary_edges.issubset(root_edges):
        raise SystemExit("error: temporary lockfile introduces a dependency edge absent from the root lockfile")
    temporary_resolution.append(resolution_record(record))
    root_resolution.append(resolution_record(root_record))

if record_hash(temporary_resolution) != record_hash(root_resolution):
    raise SystemExit("error: dependency-package lock resolution differs from the checked-in root lockfile")
PY

CARGO_TARGET_DIR="${work_dir}/target" \
  cargo check --quiet --manifest-path "${work_fixture_dir}/Cargo.toml" --locked --offline
