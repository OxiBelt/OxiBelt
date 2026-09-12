#!/usr/bin/env bash
set -euo pipefail

# Build the governed native archive through its normal build.rs, then exercise
# that exact archive from a bounded C ownership harness. This is sanitizer
# evidence only; it is neither a performance benchmark nor allocator review.

usage() {
  cat <<'EOF'
Usage: tests/scripts/run-allocator-sanitizers.sh --target gnu|musl --sanitizer address-undefined|thread [--evidence-dir DIR] [--rust-checker]

The archive and C harness use the matching Rust target triple and selected C
compiler. The script requires readelf, the Rust target, and a runnable compiler
sanitizer runtime. GNU supports ASan+UBSan and TSan. Musl supports ASan+UBSan
only when its compiler supplies those runtimes; TSan is rejected for musl.
EOF
}

target_kind=""; sanitizer=""; evidence_dir=""; rust_checker=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --target) target_kind="${2:-}"; shift 2 ;;
    --sanitizer) sanitizer="${2:-}"; shift 2 ;;
    --evidence-dir) evidence_dir="${2:-}"; shift 2 ;;
    --rust-checker) rust_checker=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
case "$target_kind" in
  gnu)
    target_triple="x86_64-unknown-linux-gnu"
    compiler="${OXIBELT_ALLOCATOR_SANITIZER_CC:-cc}"
    ;;
  musl)
    target_triple="x86_64-unknown-linux-musl"
    compiler="${OXIBELT_ALLOCATOR_SANITIZER_CC:-musl-gcc}"
    ;;
  *) usage >&2; exit 2 ;;
esac
case "$sanitizer" in
  address-undefined) native_sanitizers="address,undefined" ;;
  thread)
    test "$target_kind" = gnu || { printf '%s\n' 'TSan is supported on GNU only.' >&2; exit 2; }
    native_sanitizers="thread"
    ;;
  *) usage >&2; exit 2 ;;
esac
command -v "$compiler" >/dev/null || { printf 'required compiler not found: %s\n' "$compiler" >&2; exit 1; }
command -v readelf >/dev/null || { printf '%s\n' 'readelf is required to verify the selected compiler target.' >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ -z "$evidence_dir" ]; then evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/oxibelt-allocator-sanitizer.XXXXXX")"; else mkdir -p "$evidence_dir"; fi
target_dir="$(mktemp -d "${TMPDIR:-/tmp}/oxibelt-allocator-target.XXXXXX")"
cleanup() { rm -rf "$target_dir"; }
trap cleanup EXIT
target_key="${target_triple//-/_}"

# Inspect a binary emitted by the selected compiler instead of trusting
# -dumpmachine: musl-gcc commonly reports a GNU-style compiler triple while
# linking against musl. This probe fails before Cargo can create mislabeled
# sanitizer evidence with the wrong architecture or libc.
cat > "$evidence_dir/compiler-target-probe.c" <<'EOF'
int main(void) { return 0; }
EOF
if ! "$compiler" -std=c11 "$evidence_dir/compiler-target-probe.c" \
  -o "$evidence_dir/compiler-target-probe" \
  > "$evidence_dir/compiler-target-build.stdout" 2> "$evidence_dir/compiler-target-build.stderr"; then
  printf 'selected compiler cannot link a target identity probe for %s.\n' "$target_triple" >&2
  exit 1
fi
if ! LC_ALL=C readelf --file-header --wide "$evidence_dir/compiler-target-probe" \
  > "$evidence_dir/compiler-target-elf-header.txt"; then
  printf 'selected compiler did not emit a readable ELF target probe for %s.\n' "$target_triple" >&2
  exit 1
fi
if ! grep -Eq '^[[:space:]]*Class:[[:space:]]*ELF64$' "$evidence_dir/compiler-target-elf-header.txt" \
  || ! grep -Eq '^[[:space:]]*Machine:[[:space:]]*Advanced Micro Devices X86-64$' "$evidence_dir/compiler-target-elf-header.txt"; then
  printf 'selected compiler did not emit an x86-64 ELF64 target probe for %s.\n' "$target_triple" >&2
  exit 1
fi
if ! LC_ALL=C readelf --program-headers --wide "$evidence_dir/compiler-target-probe" \
  > "$evidence_dir/compiler-target-program-headers.txt"; then
  printf 'selected compiler target probe has unreadable program headers for %s.\n' "$target_triple" >&2
  exit 1
fi
compiler_interpreter="$(sed -n 's/.*Requesting program interpreter: \(.*\)]/\1/p' "$evidence_dir/compiler-target-program-headers.txt")"
case "$target_kind:$compiler_interpreter" in
  gnu:*/ld-linux-x86-64.so.2|musl:*/ld-musl-x86_64.so.1) ;;
  *)
    printf 'selected compiler emitted interpreter "%s" for "%s"; expected the matching x86-64 %s loader.\n' \
      "${compiler_interpreter:-none}" "$target_triple" "$target_kind" >&2
    exit 1
    ;;
esac

command -v rustup >/dev/null || { printf '%s\n' 'rustup is required to verify the selected Rust target.' >&2; exit 1; }
command -v rustc >/dev/null || { printf '%s\n' 'rustc is required to verify the selected target runtime.' >&2; exit 1; }
command -v cargo >/dev/null || { printf '%s\n' 'cargo is required to build the native archive.' >&2; exit 1; }
if ! rustup target list --installed > "$evidence_dir/rustup-targets.txt"; then
  printf '%s\n' 'failed to inspect installed Rust targets.' >&2
  exit 1
fi
if ! grep -Fxq "$target_triple" "$evidence_dir/rustup-targets.txt"; then
  printf 'required Rust target is not installed: %s\n' "$target_triple" >&2
  exit 1
fi
target_libdir="$(rustc --print target-libdir --target "$target_triple")"
if [ ! -d "$target_libdir" ]; then
  printf 'Rust target runtime is missing: %s\n' "$target_libdir" >&2
  exit 1
fi
if compiler_triple="$("$compiler" -dumpmachine 2>/dev/null)"; then :; else compiler_triple="unknown"; fi
compiler_version="$("$compiler" --version | head -n 1)"
rustc_version="$(rustc --version)"
commit="$(git -C "$repo_root" rev-parse HEAD)"
printf 'target_kind=%s\ntarget_triple=%s\nsanitizer=%s\ncompiler=%s\ncompiler_version=%s\ncompiler_triple=%s\ncompiler_elf_class=ELF64\ncompiler_elf_machine=x86-64\ncompiler_interpreter=%s\nrustc=%s\nrust_target_libdir=%s\ncommit=%s\n' \
  "$target_kind" "$target_triple" "$sanitizer" "$compiler" "$compiler_version" "$compiler_triple" \
  "$compiler_interpreter" "$rustc_version" "$target_libdir" "$commit" > "$evidence_dir/invocation.txt"

# CFLAGS instruments the governed C archive. The harness below is separately
# compiled and linked with the same selected target compiler and flags, so
# support cannot silently disappear between the archive and its harness.
native_flags="-fsanitize=${native_sanitizers} -fno-omit-frame-pointer"
export CC="$compiler"
export "CC_${target_key}=$compiler"
export CFLAGS="${CFLAGS:-} ${native_flags}"
export "CFLAGS_${target_key}=$CFLAGS"
export CXXFLAGS="${CXXFLAGS:-} ${native_flags}"
export CARGO_TARGET_DIR="$target_dir"

# Verify the selected compiler can link and run its sanitizer runtime before
# invoking Cargo. This catches missing target runtimes without building first.
cat > "$evidence_dir/sanitizer-runtime-probe.c" <<'EOF'
int main(void) { return 0; }
EOF
if ! "$compiler" -std=c11 -fsanitize="$native_sanitizers" -fno-omit-frame-pointer \
  "$evidence_dir/sanitizer-runtime-probe.c" \
  -o "$evidence_dir/sanitizer-runtime-probe" \
  > "$evidence_dir/sanitizer-runtime-build.stdout" 2> "$evidence_dir/sanitizer-runtime-build.stderr"; then
  printf 'selected compiler cannot link the %s sanitizer runtime for %s.\n' "$sanitizer" "$target_triple" >&2
  exit 1
fi
if ! timeout 10s "$evidence_dir/sanitizer-runtime-probe" \
  > "$evidence_dir/sanitizer-runtime.stdout" 2> "$evidence_dir/sanitizer-runtime.stderr"; then
  printf 'selected compiler sanitizer runtime cannot execute for %s.\n' "$target_triple" >&2
  exit 1
fi

timeout 120s cargo check --locked --target "$target_triple" -p oxibelt-allocator --features native-mimalloc \
  > "$evidence_dir/archive-build.stdout" 2> "$evidence_dir/archive-build.stderr"
archive="$(find "$target_dir" -type f -name liboxibelt_mimalloc.a -print -quit)"
test -n "$archive" || { printf '%s\n' 'native archive was not produced' >&2; exit 1; }
nm -g --defined-only "$archive" > "$evidence_dir/archive-symbols.txt"
if rg -q ' [TDB] (malloc|calloc|realloc|free|aligned_alloc|posix_memalign)$' "$evidence_dir/archive-symbols.txt"; then printf '%s\n' 'native archive exports a forbidden process allocator symbol' >&2; exit 1; fi

cat > "$evidence_dir/allocator-stress.c" <<'EOF'
#include <mimalloc.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
enum { THREADS = 4, ITERATIONS = 256, BYTES = 4096 };
static void *shared[THREADS];
static pthread_barrier_t barrier;
static atomic_int failed;

static void mark_failed(void) {
  atomic_store_explicit(&failed, 1, memory_order_relaxed);
}

static void wait_for_all(void) {
  int status = pthread_barrier_wait(&barrier);
  if (status != 0 && status != PTHREAD_BARRIER_SERIAL_THREAD) abort();
}

static void *worker(void *arg) {
  uintptr_t id = (uintptr_t)arg;
  for (size_t it = 0; it < ITERATIONS; it++) {
    unsigned char *owned = mi_zalloc_aligned(BYTES, 4096);
    if (!owned || ((uintptr_t)owned % 4096)) mark_failed();
    if (owned) {
      for (size_t i = 0; i < BYTES; i++) {
        if (owned[i] != 0) mark_failed();
        owned[i] = (unsigned char)(id + i);
      }
    }
    shared[id] = owned;
    wait_for_all();

    unsigned char *foreign = shared[(id + THREADS - 1) % THREADS];
    if (!foreign) {
      mark_failed();
    } else {
      unsigned char *grown = mi_realloc_aligned(foreign, BYTES * 2, 4096);
      if (!grown) {
        mark_failed();
        mi_free(foreign);
      } else {
        uintptr_t foreign_id = (id + THREADS - 1) % THREADS;
        for (size_t i = 0; i < BYTES; i++) {
          if (grown[i] != (unsigned char)(foreign_id + i)) mark_failed();
        }
        mi_free(grown);
      }
    }
    wait_for_all();
    if (atomic_load_explicit(&failed, memory_order_relaxed)) break;
  }
  return atomic_load_explicit(&failed, memory_order_relaxed) ? (void *)1 : NULL;
}

int main(void) {
  pthread_t threads[THREADS];
  if (pthread_barrier_init(&barrier, NULL, THREADS) != 0) return 1;
  for (uintptr_t i = 0; i < THREADS; i++) {
    if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0) abort();
  }
  for (size_t i = 0; i < THREADS; i++) {
    void *result = NULL;
    if (pthread_join(threads[i], &result) != 0 || result != NULL) mark_failed();
  }
  pthread_barrier_destroy(&barrier);
  if (atomic_load_explicit(&failed, memory_order_relaxed)) {
    fputs("allocator native sanitizer harness: FAIL\n", stderr);
    return 1;
  }
  puts("allocator native sanitizer harness: PASS");
  return 0;
}
EOF
"$compiler" -std=c11 -D_XOPEN_SOURCE=700 -Wall -Wextra -Werror -I "$repo_root/source/third_party/mimalloc-3.5.1/include" -fsanitize="$native_sanitizers" -fno-omit-frame-pointer "$evidence_dir/allocator-stress.c" "$archive" -pthread -o "$evidence_dir/allocator-stress"
ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1}" UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1:second_deadlock_stack=1}" timeout 60s "$evidence_dir/allocator-stress" > "$evidence_dir/harness.stdout" 2> "$evidence_dir/harness.stderr"

# This optional result is deliberately separate: it checks the Rust binding but
# does not claim sanitizer coverage of the complete proxy dependency graph.
if [ "$rust_checker" = true ]; then
  env -u CFLAGS -u CXXFLAGS -u CARGO_TARGET_DIR -u CC -u "CC_${target_key}" -u "CFLAGS_${target_key}" \
    timeout 180s cargo run --quiet --locked -p oxibelt --bin oxibelt-allocator-check \
      --no-default-features --features admin-runtime,allocator-mimalloc-experiment \
      > "$evidence_dir/rust-checker.stdout" 2> "$evidence_dir/rust-checker.stderr"
fi
printf 'allocator sanitizer evidence: %s\n' "$evidence_dir"
