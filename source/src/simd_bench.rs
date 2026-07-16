//! Ignored release-mode benchmarks for safe SIMD-backed byte kernels.
//!
//! These benchmarks live inside the library test crate so they can compare
//! production `pub(crate)` helpers with their scalar predecessors without
//! exposing benchmark-only public APIs.

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput};

use crate::proxy::http::fast_path::direct_h1::delimiters::find_delimiter;
use crate::turn::protocol::crc32;

const SEARCH_SIZES: [usize; 3] = [64, 4 * 1024, 64 * 1024];
const CRC_SIZES: [usize; 3] = [64, 512, 1500];

fn configured_criterion() -> Criterion {
  let criterion = Criterion::default()
    .without_plots()
    .sample_size(40)
    .warm_up_time(Duration::from_millis(500))
    .measurement_time(Duration::from_secs(1));
  let Ok(mode) = std::env::var("OXIBELT_SIMD_BENCH_BASELINE_MODE") else {
    return criterion;
  };
  if mode == "none" {
    return criterion;
  }
  let baseline =
    std::env::var("OXIBELT_SIMD_BENCH_BASELINE").unwrap_or_else(|_| "oxibelt-simd".to_string());
  assert!(
    !baseline.is_empty()
      && baseline
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
    "OXIBELT_SIMD_BENCH_BASELINE must contain only ASCII alphanumerics, '-' or '_'"
  );
  match mode.as_str() {
    "save" => criterion.save_baseline(baseline),
    "compare" => criterion.retain_baseline(baseline, true),
    _ => panic!("OXIBELT_SIMD_BENCH_BASELINE_MODE must be none, save, or compare"),
  }
}

fn tail_match_haystack(len: usize, needle: &[u8]) -> Vec<u8> {
  let mut haystack = vec![b'a'; len.max(needle.len())];
  let start = haystack.len() - needle.len();
  haystack[start..].copy_from_slice(needle);
  haystack
}

fn scalar_find(buffer: &[u8], delimiter: &[u8]) -> Option<usize> {
  if delimiter.is_empty() {
    return Some(0);
  }
  buffer
    .windows(delimiter.len())
    .position(|window| window == delimiter)
}

fn scalar_crc32(bytes: &[u8]) -> u32 {
  let mut crc = 0xffff_ffff_u32;
  for byte in bytes {
    crc ^= u32::from(*byte);
    for _ in 0..8 {
      let mask = 0_u32.wrapping_sub(crc & 1);
      crc = (crc >> 1) ^ (0xedb8_8320 & mask);
    }
  }
  !crc
}

fn bench_delimiter_search(criterion: &mut Criterion) {
  let delimiter = b"\r\n\r\n";
  let mut group = criterion.benchmark_group("safe_simd/delimiter_search");
  for size in SEARCH_SIZES {
    let haystack = tail_match_haystack(size, delimiter);
    group.throughput(Throughput::Bytes(haystack.len() as u64));
    group.bench_with_input(
      BenchmarkId::new("scalar_windows", size),
      &haystack,
      |bencher, haystack| bencher.iter(|| scalar_find(black_box(haystack), black_box(delimiter))),
    );
    group.bench_with_input(
      BenchmarkId::new("memmem", size),
      &haystack,
      |bencher, haystack| {
        bencher.iter(|| find_delimiter(black_box(haystack), black_box(delimiter)))
      },
    );
  }
  group.finish();
}

fn bench_text_contains(criterion: &mut Criterion) {
  let needle = "needle-at-tail";
  let mut group = criterion.benchmark_group("safe_simd/text_contains_candidate");
  for size in SEARCH_SIZES {
    let bytes = tail_match_haystack(size, needle.as_bytes());
    let text = String::from_utf8(bytes).expect("ASCII benchmark input must be UTF-8");
    group.throughput(Throughput::Bytes(text.len() as u64));
    group.bench_with_input(
      BenchmarkId::new("str_contains", size),
      &text,
      |bencher, text| bencher.iter(|| black_box(text).contains(black_box(needle))),
    );
    group.bench_with_input(BenchmarkId::new("memmem", size), &text, |bencher, text| {
      bencher.iter(|| {
        memchr::memmem::find(black_box(text.as_bytes()), black_box(needle.as_bytes())).is_some()
      })
    });
  }
  group.finish();
}

fn bench_crc32(criterion: &mut Criterion) {
  let mut group = criterion.benchmark_group("safe_simd/turn_crc32");
  for size in CRC_SIZES {
    let bytes = (0..size)
      .map(|index| ((index * 31 + 17) & 0xff) as u8)
      .collect::<Vec<_>>();
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
      BenchmarkId::new("scalar_bitwise", size),
      &bytes,
      |bencher, bytes| bencher.iter(|| scalar_crc32(black_box(bytes))),
    );
    group.bench_with_input(
      BenchmarkId::new("crc32fast", size),
      &bytes,
      |bencher, bytes| bencher.iter(|| crc32(black_box(bytes))),
    );
  }
  group.finish();
}

#[test]
#[ignore = "release-mode performance evidence; run through tests/scripts/run-simd-microbench.sh"]
fn safe_simd_kernels() {
  let mut criterion = configured_criterion();
  bench_delimiter_search(&mut criterion);
  bench_text_contains(&mut criterion);
  bench_crc32(&mut criterion);
  criterion.final_summary();
}
