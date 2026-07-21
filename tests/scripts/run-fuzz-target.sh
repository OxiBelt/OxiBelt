#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly FUZZ_NIGHTLY="nightly-2026-07-16"
readonly MAX_SEED_FILES=128
readonly MAX_SEED_BYTES=524288
readonly MAX_CORPUS_FILES=2048
readonly MAX_CORPUS_BYTES=67108864
readonly MAX_ARTIFACT_FILES=8
readonly FUZZ_TIMEOUT_SECONDS=10
readonly FUZZ_RSS_LIMIT_MB=3072
readonly FUZZ_MALLOC_LIMIT_MB=512

usage() {
  echo "Usage: $0 <smoke|campaign|cmin|coverage|minimize|report> <target> [seconds]" >&2
  exit 64
}

fail() {
  echo "run-fuzz-target: $*" >&2
  exit 1
}

[[ $# -ge 2 && $# -le 3 ]] || usage

readonly mode="$1"
readonly target="$2"
readonly duration_seconds="${3:-900}"

case "$mode" in
  smoke|campaign|cmin|coverage|minimize|report) ;;
  *) usage ;;
esac

[[ "$target" =~ ^[a-z0-9_]+$ ]] || fail "invalid target name: $target"
[[ "$duration_seconds" =~ ^[1-9][0-9]*$ ]] || fail "duration must be a positive integer"
(( duration_seconds <= 86400 )) || fail "duration must not exceed 86400 seconds"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
readonly repo_root
readonly fuzz_root="$repo_root/fuzz"
readonly catalog="$fuzz_root/targets.toml"
readonly coverage_dir="$fuzz_root/coverage/$target"

[[ -f "$catalog" && ! -L "$catalog" ]] || fail "missing canonical fuzz target catalog"

max_input_bytes="$({
  awk -v wanted="$target" '
    /^\[\[target\]\]$/ { selected = 0; next }
    /^name = "[a-z0-9_]+"$/ {
      name = $0
      sub(/^name = "/, "", name)
      sub(/"$/, "", name)
      selected = (name == wanted)
      next
    }
    selected && /^max_input_bytes = [0-9]+$/ {
      value = $0
      sub(/^max_input_bytes = /, "", value)
      print value
      exit
    }
  ' "$catalog"
} || true)"
[[ "$max_input_bytes" =~ ^[1-9][0-9]*$ ]] || fail "target is absent from the catalog or has no valid input limit: $target"
readonly max_input_bytes

catalog_string_value() {
  local field="$1"
  awk -v wanted="$target" -v wanted_field="$field" '
    /^\[\[target\]\]$/ { selected = 0; next }
    /^name = "[a-z0-9_]+"$/ {
      name = $0
      sub(/^name = "/, "", name)
      sub(/"$/, "", name)
      selected = (name == wanted)
      next
    }
    selected && index($0, wanted_field " = \"") == 1 {
      value = $0
      sub("^" wanted_field " = \\\"", "", value)
      sub(/"$/, "", value)
      print value
      exit
    }
  ' "$catalog"
}

catalog_array_values() {
  local field="$1"
  awk -v wanted="$target" -v wanted_field="$field" '
    /^\[\[target\]\]$/ { selected = 0; next }
    /^name = "[a-z0-9_]+"$/ {
      name = $0
      sub(/^name = "/, "", name)
      sub(/"$/, "", name)
      selected = (name == wanted)
      next
    }
    selected && index($0, wanted_field " = [") == 1 {
      prefix = wanted_field " = [\""
      value = substr($0, length(prefix) + 1)
      sub(/"\][[:space:]]*$/, "", value)
      count = split(value, items, /",[[:space:]]*"/)
      for (item_index = 1; item_index <= count; item_index += 1) {
        print items[item_index]
      }
      exit
    }
  ' "$catalog"
}

seed_relative="$(catalog_string_value seed_dir)"
readonly seed_relative
[[ "$seed_relative" == "fuzz/seeds/$target" ]] || fail "catalog seed path must be target-local"
readonly seed_dir="$repo_root/$seed_relative"

dictionary_relative="$(catalog_string_value dictionary)"
readonly dictionary_relative
if [[ -n "$dictionary_relative" ]]; then
  [[ "$dictionary_relative" =~ ^fuzz/dictionaries/[a-z0-9_.-]+\.dict$ ]] \
    || fail "catalog dictionary path is outside fuzz/dictionaries"
  dictionary="$repo_root/$dictionary_relative"
else
  dictionary=""
fi
readonly dictionary

readonly runner_temp_base="${RUNNER_TEMP:-/tmp}"
[[ "$runner_temp_base" = /* ]] || fail "RUNNER_TEMP must be an absolute path"
mkdir -p -- "$runner_temp_base"
[[ -d "$runner_temp_base" && ! -L "$runner_temp_base" ]] || fail "RUNNER_TEMP must be a real directory"
runner_temp="$(cd -- "$runner_temp_base" && pwd -P)"
readonly runner_temp
readonly persistent_corpus="$runner_temp/oxibelt-fuzz-corpus/$target"
readonly artifact_dir="$runner_temp/oxibelt-fuzz-artifacts/$target"
readonly failure_dir="$runner_temp/oxibelt-fuzz-failures/$target"

assert_no_symlinks() {
  local directory="$1"
  [[ -d "$directory" ]] || return 0
  if find "$directory" -type l -print -quit | grep -q .; then
    fail "symlinks are forbidden below $directory"
  fi
}

directory_stats() {
  local directory="$1"
  if [[ ! -d "$directory" ]]; then
    echo "0 0"
    return
  fi
  find "$directory" -type f -printf '%s\n' \
    | awk '{ files += 1; bytes += $1 } END { print files + 0, bytes + 0 }'
}

validate_seed_corpus() {
  [[ -d "$seed_dir" && ! -L "$seed_dir" ]] || fail "missing reviewed seed directory: $seed_dir"
  assert_no_symlinks "$seed_dir"
  if find "$seed_dir" -mindepth 2 -type f -print -quit | grep -q .; then
    fail "seed files must be direct children of $seed_dir"
  fi
  if find "$seed_dir" -type f -size "+${max_input_bytes}c" -print -quit | grep -q .; then
    fail "a reviewed seed exceeds the target input limit"
  fi

  local seed_files seed_bytes
  read -r seed_files seed_bytes < <(directory_stats "$seed_dir")
  (( seed_files > 0 )) || fail "reviewed seed corpus is empty: $seed_dir"
  (( seed_files <= MAX_SEED_FILES )) || fail "reviewed seed corpus exceeds $MAX_SEED_FILES files"
  (( seed_bytes <= MAX_SEED_BYTES )) || fail "reviewed seed corpus exceeds $MAX_SEED_BYTES bytes"
}

validate_working_corpus() {
  local directory="$1"
  [[ -d "$directory" && ! -L "$directory" ]] || fail "missing mutable corpus: $directory"
  assert_no_symlinks "$directory"
  if find "$directory" -mindepth 2 -type f -print -quit | grep -q .; then
    fail "mutable corpus files must be direct children of $directory"
  fi
  if find "$directory" -type f -size "+${max_input_bytes}c" -print -quit | grep -q .; then
    fail "a corpus entry exceeds the target input limit"
  fi

  local corpus_files corpus_bytes
  read -r corpus_files corpus_bytes < <(directory_stats "$directory")
  (( corpus_files > 0 )) || fail "mutable corpus is empty: $directory"
  (( corpus_bytes <= MAX_CORPUS_BYTES )) || fail "corpus exceeds $MAX_CORPUS_BYTES bytes"
}

validate_cached_corpus() {
  local directory="$1"
  validate_working_corpus "$directory"

  local corpus_files corpus_bytes
  read -r corpus_files corpus_bytes < <(directory_stats "$directory")
  (( corpus_files <= MAX_CORPUS_FILES )) || fail "corpus exceeds $MAX_CORPUS_FILES files"
}

copy_reviewed_seeds() {
  local destination="$1"
  mkdir -p -- "$destination"
  while IFS= read -r -d '' seed; do
    cp -- "$seed" "$destination/$(basename -- "$seed")"
  done < <(find "$seed_dir" -maxdepth 1 -type f -print0 | sort -z)
}

copy_corpus_files() {
  local source="$1"
  local destination="$2"
  while IFS= read -r -d '' corpus_file; do
    cp -- "$corpus_file" "$destination/$(basename -- "$corpus_file")"
  done < <(find "$source" -maxdepth 1 -type f -print0 | sort -z)
}

dictionary_argument=()
if [[ -n "$dictionary" ]]; then
  [[ -f "$dictionary" && ! -L "$dictionary" ]] || fail "catalog dictionary must be a regular, non-symlink file"
  [[ -s "$dictionary" ]] || fail "catalog dictionary must not be empty"
  (( $(wc -c <"$dictionary") <= 65536 )) || fail "catalog dictionary exceeds 65536 bytes"
  dictionary_argument=("-dict=$dictionary")
fi

common_fuzzer_arguments=(
  "-max_len=$max_input_bytes"
  "-timeout=$FUZZ_TIMEOUT_SECONDS"
  "-rss_limit_mb=$FUZZ_RSS_LIMIT_MB"
  "-malloc_limit_mb=$FUZZ_MALLOC_LIMIT_MB"
  "-print_final_stats=1"
)

configure_sanitizer_environment() {
  local detect_leaks="$1"
  export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=$detect_leaks:halt_on_error=1:abort_on_error=1"
  export LSAN_OPTIONS="${LSAN_OPTIONS:+$LSAN_OPTIONS:}detect_leaks=$detect_leaks"
}

mkdir -p -- "$artifact_dir" "$failure_dir"
assert_no_symlinks "$artifact_dir"

cd -- "$repo_root"

case "$mode" in
  smoke)
    configure_sanitizer_environment 0
    validate_seed_corpus
    temporary_corpus="$(mktemp -d "$runner_temp/oxibelt-fuzz-${target}.XXXXXX")"
    cleanup_temporary_corpus() {
      case "$temporary_corpus" in
        "$runner_temp/oxibelt-fuzz-$target."??????)
          [[ -d "$temporary_corpus" && ! -L "$temporary_corpus" ]] \
            && rm -rf -- "$temporary_corpus"
          ;;
        *) fail "refusing to clean an unexpected temporary corpus path" ;;
      esac
    }
    trap cleanup_temporary_corpus EXIT
    copy_reviewed_seeds "$temporary_corpus"
    cargo "+$FUZZ_NIGHTLY" fuzz run --sanitizer address "$target" "$temporary_corpus" -- \
      -runs=256 \
      -detect_leaks=0 \
      "${common_fuzzer_arguments[@]}" \
      "${dictionary_argument[@]}" \
      "-artifact_prefix=$artifact_dir/"
    ;;

  campaign)
    configure_sanitizer_environment 1
    validate_seed_corpus
    mkdir -p -- "$persistent_corpus"
    assert_no_symlinks "$persistent_corpus"
    copy_reviewed_seeds "$persistent_corpus"
    validate_cached_corpus "$persistent_corpus"
    cargo "+$FUZZ_NIGHTLY" fuzz run --sanitizer address "$target" "$persistent_corpus" -- \
      "-max_total_time=$duration_seconds" \
      -detect_leaks=1 \
      "${common_fuzzer_arguments[@]}" \
      "${dictionary_argument[@]}" \
      "-artifact_prefix=$artifact_dir/"
    ;;

  cmin)
    configure_sanitizer_environment 1
    validate_working_corpus "$persistent_corpus"

    cmin_staging="$(mktemp -d "$fuzz_root/.cmin-${target}.XXXXXX")"
    cmin_replacement="$(mktemp -d "$runner_temp/oxibelt-fuzz-cmin-${target}.XXXXXX")"
    cmin_backup="$(mktemp -d "$runner_temp/oxibelt-fuzz-backup-${target}.XXXXXX")"
    preserve_cmin_backup=0
    cleanup_cmin_directories() {
      case "$cmin_staging" in
        "$fuzz_root/.cmin-$target."??????)
          [[ ! -e "$cmin_staging" || -d "$cmin_staging" && ! -L "$cmin_staging" ]] \
            || fail "refusing to clean an unexpected cmin staging path"
          rm -rf -- "$cmin_staging"
          ;;
        *) fail "refusing to clean an unexpected cmin staging path" ;;
      esac
      case "$cmin_replacement" in
        "$runner_temp/oxibelt-fuzz-cmin-$target."??????)
          [[ ! -e "$cmin_replacement" || -d "$cmin_replacement" && ! -L "$cmin_replacement" ]] \
            || fail "refusing to clean an unexpected cmin replacement path"
          rm -rf -- "$cmin_replacement"
          ;;
        *) fail "refusing to clean an unexpected cmin replacement path" ;;
      esac
      if (( preserve_cmin_backup == 0 )); then
        case "$cmin_backup" in
          "$runner_temp/oxibelt-fuzz-backup-$target."??????)
            [[ ! -e "$cmin_backup" || -d "$cmin_backup" && ! -L "$cmin_backup" ]] \
              || fail "refusing to clean an unexpected cmin backup path"
            rm -rf -- "$cmin_backup"
            ;;
          *) fail "refusing to clean an unexpected cmin backup path" ;;
        esac
      fi
    }
    trap cleanup_cmin_directories EXIT

    copy_corpus_files "$persistent_corpus" "$cmin_staging"
    validate_working_corpus "$cmin_staging"
    cargo "+$FUZZ_NIGHTLY" fuzz cmin --sanitizer address "$target" "$cmin_staging" -- \
      "-max_len=$max_input_bytes" \
      "-timeout=$FUZZ_TIMEOUT_SECONDS" \
      -detect_leaks=1 \
      "${dictionary_argument[@]}"
    validate_cached_corpus "$cmin_staging"

    copy_corpus_files "$cmin_staging" "$cmin_replacement"
    validate_cached_corpus "$cmin_replacement"
    mv -- "$persistent_corpus" "$cmin_backup/original"
    preserve_cmin_backup=1
    if ! mv -- "$cmin_replacement" "$persistent_corpus"; then
      if mv -- "$cmin_backup/original" "$persistent_corpus"; then
        preserve_cmin_backup=0
        fail "failed to install minimized corpus; the original corpus was restored"
      fi
      fail "failed to install minimized corpus; the original is retained in $cmin_backup"
    fi
    validate_cached_corpus "$persistent_corpus"
    preserve_cmin_backup=0
    ;;

  coverage)
    configure_sanitizer_environment 1
    validate_cached_corpus "$persistent_corpus"
    cargo "+$FUZZ_NIGHTLY" fuzz coverage --sanitizer address "$target" "$persistent_corpus" -- \
      "-max_len=$max_input_bytes" \
      "-timeout=$FUZZ_TIMEOUT_SECONDS" \
      -detect_leaks=1

    readonly profdata="$coverage_dir/coverage.profdata"
    [[ -s "$profdata" && ! -L "$profdata" ]] || fail "cargo-fuzz did not create coverage.profdata"

    command -v jq >/dev/null 2>&1 || fail "jq is required to locate and validate coverage"
    cargo_target_dir="$(
      cargo "+$FUZZ_NIGHTLY" metadata --no-deps --format-version 1 \
        | jq -er '.target_directory | select(type == "string" and startswith("/"))'
    )"
    readonly cargo_target_dir
    [[ "$cargo_target_dir" == "$repo_root"/* && -d "$cargo_target_dir" && ! -L "$cargo_target_dir" ]] \
      || fail "Cargo target directory must be a real directory inside the repository"

    coverage_search_roots=("$cargo_target_dir")
    for coverage_candidate in "$repo_root/target" "$fuzz_root/target"; do
      [[ -d "$coverage_candidate" && ! -L "$coverage_candidate" ]] || continue
      coverage_candidate="$(cd -- "$coverage_candidate" && pwd -P)"
      [[ "$coverage_candidate" == "$repo_root"/* ]] \
        || fail "coverage search roots must stay inside the repository"
      coverage_candidate_seen=0
      for coverage_search_root in "${coverage_search_roots[@]}"; do
        if [[ "$coverage_search_root" == "$coverage_candidate" ]]; then
          coverage_candidate_seen=1
        fi
      done
      if (( coverage_candidate_seen == 0 )); then
        coverage_search_roots+=("$coverage_candidate")
      fi
    done
    readonly coverage_search_roots
    mapfile -d '' coverage_binaries < <(
      find "${coverage_search_roots[@]}" \
        -type f -path '*/coverage/*/release/*' -name "$target" -perm -u+x -print0 2>/dev/null \
        | sort -z
    )
    (( ${#coverage_binaries[@]} == 1 )) || fail "expected exactly one instrumented coverage binary"
    readonly coverage_binary="${coverage_binaries[0]}"
    target_libdir="$(rustc "+$FUZZ_NIGHTLY" --print target-libdir)"
    readonly target_libdir
    llvm_bin="$(dirname -- "$target_libdir")/bin"
    readonly llvm_bin
    readonly llvm_cov="$llvm_bin/llvm-cov"
    [[ -x "$llvm_cov" && ! -L "$llvm_cov" ]] || fail "missing pinned llvm-cov component"

    "$llvm_cov" report "$coverage_binary" "-instr-profile=$profdata" \
      >"$coverage_dir/summary.txt"
    "$llvm_cov" export "$coverage_binary" "-instr-profile=$profdata" \
      >"$coverage_dir/coverage.json"
    "$llvm_cov" export -format=lcov "$coverage_binary" "-instr-profile=$profdata" \
      >"$coverage_dir/coverage.lcov"
    "$llvm_cov" show "$coverage_binary" "-instr-profile=$profdata" \
      -format=html "-output-dir=$coverage_dir/html"

    : >"$coverage_dir/landmarks.txt"
    while IFS= read -r landmark; do
      [[ "$landmark" =~ ^[a-zA-Z0-9_./-]+\.rs:[a-zA-Z0-9_:]+$ ]] \
        || fail "invalid coverage landmark in catalog: $landmark"
      source_path="${landmark%%:*}"
      symbol="${landmark#*:}"
      if ! jq -e --arg source_path "/$source_path" '
        [.data[]?.files[]?
          | select(.filename | endswith($source_path))
          | .segments[]?
          | select(.[3] == true)
          | .[2]]
        | any(. > 0)
      ' "$coverage_dir/coverage.json" >/dev/null; then
        fail "coverage landmark source has no executed regions: $landmark"
      fi

      if ! jq -e --arg source_path "/$source_path" --arg symbol "$symbol" '
        [.data[]?.functions[]?
          | select(any(.filenames[]?; endswith($source_path)))
          | select(.name | contains($symbol))
          | .regions[]?
          | .[4]]
        | any(. > 0)
      ' "$coverage_dir/coverage.json" >/dev/null; then
        fail "coverage landmark function has no executed regions: $landmark"
      fi
      printf '%s function-hit\n' "$landmark" >>"$coverage_dir/landmarks.txt"
    done < <(catalog_array_values coverage_landmarks)
    ;;

  minimize)
    configure_sanitizer_environment 1
    assert_no_symlinks "$artifact_dir"
    mapfile -d '' failing_inputs < <(
      find "$artifact_dir" -maxdepth 1 -type f \
        \( -name 'crash-*' -o -name 'timeout-*' -o -name 'oom-*' -o -name 'leak-*' \) \
        -print0 | sort -z | head -z -n "$MAX_ARTIFACT_FILES"
    )
    for failing_input in "${failing_inputs[@]}"; do
      if ! timeout --signal=TERM --kill-after=15s 300s \
        cargo "+$FUZZ_NIGHTLY" fuzz tmin --sanitizer address -r 255 "$target" "$failing_input" -- \
          "-max_len=$max_input_bytes" \
          "-timeout=$FUZZ_TIMEOUT_SECONDS" \
          "-rss_limit_mb=$FUZZ_RSS_LIMIT_MB" \
          "-malloc_limit_mb=$FUZZ_MALLOC_LIMIT_MB" \
          -detect_leaks=1 \
          >>"$failure_dir/tmin.log" 2>&1; then
        printf 'Minimization failed or timed out; retaining raw input: %s\n' \
          "$(basename -- "$failing_input")" >>"$failure_dir/tmin.log"
      fi
    done
    ;;

  report)
    assert_no_symlinks "$artifact_dir"
    mkdir -p -- "$failure_dir/artifacts"
    while IFS= read -r -d '' artifact; do
      cp -- "$artifact" "$failure_dir/artifacts/$(basename -- "$artifact")"
    done < <(find "$artifact_dir" -maxdepth 1 -type f -print0 | sort -z)

    {
      echo "commit_sha=$(git rev-parse HEAD)"
      echo "target=$target"
      echo "toolchain=$FUZZ_NIGHTLY"
      echo "cargo_fuzz_version=0.13.2"
      echo "sanitizer=address+leak"
      echo "max_input_bytes=$max_input_bytes"
      echo "timeout_seconds=$FUZZ_TIMEOUT_SECONDS"
      echo "rss_limit_mb=$FUZZ_RSS_LIMIT_MB"
      echo "malloc_limit_mb=$FUZZ_MALLOC_LIMIT_MB"
      echo "reproduce=tests/scripts/run-fuzz-target.sh campaign $target $duration_seconds"
      if [[ -d "$persistent_corpus" ]]; then
        read -r corpus_files corpus_bytes < <(directory_stats "$persistent_corpus")
        echo "corpus_files=$corpus_files"
        echo "corpus_bytes=$corpus_bytes"
        find "$persistent_corpus" -maxdepth 1 -type f -print0 \
          | sort -z | xargs -0 -r sha256sum --
      fi
      find "$failure_dir/artifacts" -maxdepth 1 -type f -print0 \
        | sort -z | xargs -0 -r sha256sum --
    } >"$failure_dir/reproduction.txt"
    ;;
esac
