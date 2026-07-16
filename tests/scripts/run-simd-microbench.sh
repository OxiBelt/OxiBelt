#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <x86-64-v2|x86-64-v3> [run-count]" >&2
}

target_cpu="${1:-}"
run_count="${2:-2}"
case "${target_cpu}" in
  x86-64-v2|x86-64-v3) ;;
  *)
    usage
    exit 2
    ;;
esac
if [[ ! "${run_count}" =~ ^[1-9][0-9]*$ ]]; then
  usage
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
target_dir="${OXIBELT_SIMD_BENCH_TARGET_DIR:-/tmp/oxibelt-simd-microbench/${target_cpu}}"
rustflags="${RUSTFLAGS:+${RUSTFLAGS} }-Ctarget-cpu=${target_cpu}"

for ((run = 1; run <= run_count; run += 1)); do
  echo "Running safe SIMD microbench ${run}/${run_count} for ${target_cpu}"
  (
    cd -- "${repo_root}"
    CARGO_TARGET_DIR="${target_dir}" \
      OXIBELT_SIMD_BENCH_BASELINE_MODE=none \
      RUSTFLAGS="${rustflags}" \
      cargo test --release --locked -p oxibelt --lib \
        simd_bench::safe_simd_kernels -- \
        --exact --ignored --nocapture --test-threads=1
  )
done

echo "Criterion evidence is under ${target_dir}/criterion"
