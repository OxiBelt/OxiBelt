//! Ignored release-mode benchmarks for safe SIMD-backed byte kernels.
//!
//! These benchmarks live inside the library test crate so they can compare
//! production `pub(crate)` helpers with their scalar predecessors without
//! exposing benchmark-only public APIs.

use std::hint::black_box;
use std::time::Duration;

use aho_corasick::AhoCorasick;
use criterion::{BenchmarkId, Criterion, Throughput};
use memchr::{memchr, memchr_iter, memmem};

use crate::proxy::http::fast_path::direct_h1::delimiters::find_delimiter;
use crate::turn::protocol::crc32;

const SEARCH_SIZES: [usize; 4] = [64, 4 * 1024, 64 * 1024, 1024 * 1024];
const CRC_SIZES: [usize; 3] = [64, 512, 1500];
const AHO_PATTERN_COUNTS: [usize; 4] = [2, 8, 32, 64];

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

fn positioned_haystack(len: usize, needle: &[u8], placement: &str) -> Vec<u8> {
  let mut haystack = vec![b'a'; len.max(needle.len())];
  let start = match placement {
    "start" => 0,
    "middle" => (haystack.len() - needle.len()) / 2,
    "tail" => haystack.len() - needle.len(),
    "miss" => return haystack,
    _ => panic!("unknown search placement: {placement}"),
  };
  haystack[start..start + needle.len()].copy_from_slice(needle);
  haystack
}

fn overlapping_haystack(len: usize) -> Vec<u8> {
  (0..len.max(3))
    .map(|index| if index % 2 == 0 { b'a' } else { b'b' })
    .collect()
}

fn scalar_find(buffer: &[u8], delimiter: &[u8]) -> Option<usize> {
  if delimiter.is_empty() {
    return Some(0);
  }
  buffer
    .windows(delimiter.len())
    .position(|window| window == delimiter)
}

fn scalar_byte_find(buffer: &[u8], needle: u8) -> Option<usize> {
  buffer.iter().position(|byte| *byte == needle)
}

fn scalar_byte_count(buffer: &[u8], needle: u8) -> usize {
  buffer.iter().filter(|byte| **byte == needle).count()
}

fn aho_patterns(count: usize) -> Vec<String> {
  (0..count)
    .map(|index| match index {
      0 => "aba".to_owned(),
      1 => "bab".to_owned(),
      _ => format!("search-pattern-{index:02}-at-tail"),
    })
    .collect()
}

fn naive_any_pattern(haystack: &[u8], patterns: &[String]) -> bool {
  patterns
    .iter()
    .any(|pattern| scalar_find(haystack, pattern.as_bytes()).is_some())
}

fn bench_byte_search(criterion: &mut Criterion) {
  let needle = b'\n';
  let mut group = criterion.benchmark_group("safe_simd/byte_search");
  for size in SEARCH_SIZES {
    for placement in ["start", "middle", "tail", "miss"] {
      let haystack = positioned_haystack(size, &[needle], placement);
      group.throughput(Throughput::Bytes(haystack.len() as u64));
      group.bench_with_input(
        BenchmarkId::new(format!("scalar_find/{placement}"), size),
        &haystack,
        |bencher, haystack| {
          bencher.iter(|| scalar_byte_find(black_box(haystack), black_box(needle)))
        },
      );
      group.bench_with_input(
        BenchmarkId::new(format!("memchr/{placement}"), size),
        &haystack,
        |bencher, haystack| bencher.iter(|| memchr(black_box(needle), black_box(haystack))),
      );
    }

    let dense = (0..size)
      .map(|index| if index % 31 == 0 { needle } else { b'a' })
      .collect::<Vec<_>>();
    group.bench_with_input(
      BenchmarkId::new("scalar_count/dense", size),
      &dense,
      |bencher, haystack| {
        bencher.iter(|| scalar_byte_count(black_box(haystack), black_box(needle)))
      },
    );
    group.bench_with_input(
      BenchmarkId::new("memchr_iter/dense", size),
      &dense,
      |bencher, haystack| {
        bencher.iter(|| memchr_iter(black_box(needle), black_box(haystack)).count())
      },
    );
  }
  group.finish();
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
  let finder = memmem::Finder::new(needle.as_bytes());
  let mut group = criterion.benchmark_group("safe_simd/text_contains_candidate");
  for size in SEARCH_SIZES {
    for placement in ["start", "middle", "tail", "miss"] {
      let bytes = positioned_haystack(size, needle.as_bytes(), placement);
      let text = String::from_utf8(bytes).expect("ASCII benchmark input must be UTF-8");
      group.throughput(Throughput::Bytes(text.len() as u64));
      group.bench_with_input(
        BenchmarkId::new(format!("str_contains/{placement}"), size),
        &text,
        |bencher, text| bencher.iter(|| black_box(text).contains(black_box(needle))),
      );
      group.bench_with_input(
        BenchmarkId::new(format!("memmem_find/{placement}"), size),
        &text,
        |bencher, text| {
          bencher.iter(|| {
            memmem::find(black_box(text.as_bytes()), black_box(needle.as_bytes())).is_some()
          })
        },
      );
      group.bench_with_input(
        BenchmarkId::new(format!("memmem_finder/{placement}"), size),
        &text,
        |bencher, text| bencher.iter(|| finder.find(black_box(text.as_bytes())).is_some()),
      );
    }

    let overlap_needle = b"aba";
    let overlap_finder = memmem::Finder::new(overlap_needle);
    let overlap = overlapping_haystack(size);
    group.bench_with_input(
      BenchmarkId::new("scalar_windows/overlap", size),
      &overlap,
      |bencher, haystack| {
        bencher.iter(|| scalar_find(black_box(haystack), black_box(overlap_needle)))
      },
    );
    group.bench_with_input(
      BenchmarkId::new("memmem_finder/overlap", size),
      &overlap,
      |bencher, haystack| bencher.iter(|| overlap_finder.find(black_box(haystack))),
    );
  }
  group.finish();
}

fn bench_aho_corasick(criterion: &mut Criterion) {
  let mut construction = criterion.benchmark_group("safe_simd/aho_corasick_construction");
  for count in AHO_PATTERN_COUNTS {
    let patterns = aho_patterns(count);
    construction.bench_with_input(
      BenchmarkId::from_parameter(count),
      &patterns,
      |bencher, input| {
        bencher
          .iter(|| AhoCorasick::new(black_box(input)).expect("benchmark patterns must compile"))
      },
    );
  }
  construction.finish();

  let mut scan = criterion.benchmark_group("safe_simd/aho_corasick_scan");
  for count in AHO_PATTERN_COUNTS {
    let patterns = aho_patterns(count);
    let automaton = AhoCorasick::new(&patterns).expect("benchmark patterns must compile");
    let tail_needle = patterns.last().expect("pattern list must not be empty");
    let mut duplicate_patterns = patterns.clone();
    duplicate_patterns.push(patterns[0].clone());
    let duplicate_automaton =
      AhoCorasick::new(&duplicate_patterns).expect("duplicate benchmark patterns must compile");

    for size in SEARCH_SIZES {
      for placement in ["start", "middle", "tail", "miss"] {
        let haystack = positioned_haystack(size, tail_needle.as_bytes(), placement);
        scan.throughput(Throughput::Bytes(haystack.len() as u64));
        scan.bench_with_input(
          BenchmarkId::new(format!("naive/{count}/{placement}"), size),
          &haystack,
          |bencher, haystack| {
            bencher.iter(|| naive_any_pattern(black_box(haystack), black_box(&patterns)))
          },
        );
        scan.bench_with_input(
          BenchmarkId::new(format!("automaton/{count}/{placement}"), size),
          &haystack,
          |bencher, haystack| bencher.iter(|| automaton.is_match(black_box(haystack))),
        );
      }

      let overlap = overlapping_haystack(size);
      scan.bench_with_input(
        BenchmarkId::new(format!("automaton/{count}/overlap"), size),
        &overlap,
        |bencher, haystack| bencher.iter(|| automaton.is_match(black_box(haystack))),
      );
      scan.bench_with_input(
        BenchmarkId::new(format!("automaton/{count}/duplicate"), size),
        &overlap,
        |bencher, haystack| bencher.iter(|| duplicate_automaton.is_match(black_box(haystack))),
      );
    }
  }
  scan.finish();
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
  bench_byte_search(&mut criterion);
  bench_delimiter_search(&mut criterion);
  bench_text_contains(&mut criterion);
  bench_aho_corasick(&mut criterion);
  bench_crc32(&mut criterion);
  criterion.final_summary();
}
