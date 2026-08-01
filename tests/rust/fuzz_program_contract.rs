use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

const EXPECTED_TARGETS: &[&str] = &[
  "admin_json_mutations",
  "admin_mutation_envelope",
  "cache_metadata_key",
  "cluster_rollout_state",
  "compio_h1_response",
  "gateway_api_translation",
  "http3_webtransport",
  "http_body_coding",
  "http_semantics",
  "native_config",
  "oxirule_expression",
  "syscall_boundaries",
  "tls_certificate_metadata",
  "tls_client_hello",
  "turn_protocol",
  "upstream_dns_resolution",
  "webrtc_turn",
  "websocket_frame",
];

#[derive(Debug)]
struct Target {
  name: String,
  owner: String,
  max_input_bytes: u64,
  input_contract: String,
  invariants: Vec<String>,
  unsupported_states: Vec<String>,
  seed_dir: String,
  dictionary: Option<String>,
  coverage_landmarks: Vec<String>,
  regression_path: String,
  leak_policy: String,
}

#[derive(Debug)]
struct Seed {
  target: String,
  path: String,
  sha256: String,
  origin: String,
  license: String,
  classification: String,
}

fn repo_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source crate should live below the repository root")
    .to_path_buf()
}

fn read_repo_file(path: &str) -> String {
  fs::read_to_string(repo_root().join(path))
    .unwrap_or_else(|error| panic!("{path} should be readable: {error}"))
}

fn parse_repo_toml(path: &str) -> toml::Value {
  toml::from_str(&read_repo_file(path))
    .unwrap_or_else(|error| panic!("{path} should contain valid TOML: {error}"))
}

fn required_string(table: &toml::Table, field: &str, context: &str) -> String {
  table
    .get(field)
    .and_then(toml::Value::as_str)
    .filter(|value| !value.trim().is_empty())
    .unwrap_or_else(|| panic!("{context} must define nonempty `{field}`"))
    .to_string()
}

fn required_strings(table: &toml::Table, field: &str, context: &str) -> Vec<String> {
  let values = table
    .get(field)
    .and_then(toml::Value::as_array)
    .unwrap_or_else(|| panic!("{context} must define array `{field}`"));
  assert!(!values.is_empty(), "{context} `{field}` must not be empty");
  values
    .iter()
    .map(|value| {
      value
        .as_str()
        .filter(|item| !item.trim().is_empty())
        .unwrap_or_else(|| panic!("{context} `{field}` entries must be nonempty strings"))
        .to_string()
    })
    .collect()
}

fn catalog() -> (toml::Table, BTreeMap<String, Target>) {
  let document = parse_repo_toml("fuzz/targets.toml");
  assert_eq!(
    document.get("version").and_then(toml::Value::as_integer),
    Some(1),
    "fuzz/targets.toml must use catalog version 1"
  );
  let program = document
    .get("program")
    .and_then(toml::Value::as_table)
    .expect("fuzz/targets.toml must define [program]")
    .clone();
  let tables = document
    .get("target")
    .and_then(toml::Value::as_array)
    .expect("fuzz/targets.toml must define [[target]] entries");
  let mut targets = BTreeMap::new();
  for value in tables {
    let table = value
      .as_table()
      .expect("each [[target]] entry must be a table");
    let name = required_string(table, "name", "fuzz target");
    let context = format!("fuzz target {name}");
    let target = Target {
      name: name.clone(),
      owner: required_string(table, "owner", &context),
      max_input_bytes: table
        .get("max_input_bytes")
        .and_then(toml::Value::as_integer)
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or_else(|| panic!("{context} must define positive `max_input_bytes`")),
      input_contract: required_string(table, "input_contract", &context),
      invariants: required_strings(table, "invariants", &context),
      unsupported_states: required_strings(table, "unsupported_states", &context),
      seed_dir: required_string(table, "seed_dir", &context),
      dictionary: table
        .get("dictionary")
        .map(|_| required_string(table, "dictionary", &context)),
      coverage_landmarks: required_strings(table, "coverage_landmarks", &context),
      regression_path: required_string(table, "regression_path", &context),
      leak_policy: required_string(table, "leak_policy", &context),
    };
    assert!(
      targets.insert(name.clone(), target).is_none(),
      "duplicate fuzz target {name}"
    );
  }
  (program, targets)
}

fn seed_manifest() -> Vec<Seed> {
  let document = parse_repo_toml("fuzz/seeds/manifest.toml");
  assert_eq!(
    document.get("version").and_then(toml::Value::as_integer),
    Some(1),
    "fuzz/seeds/manifest.toml must use version 1"
  );
  document
    .get("seed")
    .and_then(toml::Value::as_array)
    .expect("fuzz/seeds/manifest.toml must define [[seed]] entries")
    .iter()
    .map(|value| {
      let table = value.as_table().expect("each [[seed]] must be a table");
      let path = required_string(table, "path", "fuzz seed");
      let context = format!("fuzz seed {path}");
      Seed {
        target: required_string(table, "target", &context),
        path,
        sha256: required_string(table, "sha256", &context),
        origin: required_string(table, "origin", &context),
        license: required_string(table, "license", &context),
        classification: required_string(table, "classification", &context),
      }
    })
    .collect()
}

fn string_set<'a>(items: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
  items.map(str::to_string).collect()
}

fn assert_safe_relative_path(path: &str, context: &str) {
  let path = Path::new(path);
  assert!(!path.is_absolute(), "{context} must be repository-relative");
  assert!(
    path
      .components()
      .all(|component| matches!(component, Component::Normal(_))),
    "{context} must not contain empty, current, parent, root, or prefix components"
  );
}

fn table_integer(program: &toml::Table, key: &str) -> i64 {
  program
    .get(key)
    .and_then(toml::Value::as_integer)
    .unwrap_or_else(|| panic!("fuzz program must define integer `{key}`"))
}

#[test]
fn catalog_defines_the_complete_bounded_program() {
  let (program, targets) = catalog();
  assert_eq!(
    targets.keys().cloned().collect::<BTreeSet<_>>(),
    string_set(EXPECTED_TARGETS.iter().copied()),
    "the fuzz catalog must preserve all eighteen registered targets"
  );

  assert_eq!(table_integer(&program, "max_seed_files_per_target"), 128);
  assert_eq!(
    table_integer(&program, "max_seed_bytes_per_target"),
    524_288
  );
  assert_eq!(
    table_integer(&program, "max_working_corpus_files_per_target"),
    16_384
  );
  assert_eq!(
    table_integer(&program, "max_cached_corpus_files_per_target"),
    8_192
  );
  assert_eq!(
    table_integer(&program, "max_cached_corpus_bytes_per_target"),
    67_108_864
  );
  assert_eq!(table_integer(&program, "pr_runs"), 256);
  assert_eq!(table_integer(&program, "campaign_seconds"), 900);
  assert_eq!(table_integer(&program, "input_timeout_seconds"), 10);
  assert_eq!(table_integer(&program, "rss_limit_mb"), 3_072);
  assert_eq!(table_integer(&program, "allocation_limit_mb"), 512);
  assert_eq!(
    program
      .get("pr_leak_detection")
      .and_then(toml::Value::as_bool),
    Some(false)
  );
  assert_eq!(
    program
      .get("campaign_leak_detection")
      .and_then(toml::Value::as_bool),
    Some(true)
  );

  for target in targets.values() {
    assert_eq!(target.name.trim(), target.name);
    assert!(
      target
        .name
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
      "target {} must use a shell-safe lowercase name",
      target.name
    );
    assert!(
      (1..=131_072).contains(&target.max_input_bytes),
      "target {} must have a bounded input at or below 128 KiB",
      target.name
    );
    assert!(
      target.owner.len() >= 12,
      "target {} must identify an owner",
      target.name
    );
    assert!(
      target.input_contract.len() >= 24,
      "target {} must document its input contract",
      target.name
    );
    assert!(
      target.invariants.len() >= 2,
      "target {} must document multiple invariants",
      target.name
    );
    assert!(
      target.unsupported_states.len() >= 2,
      "target {} must document unsupported states",
      target.name
    );
    assert_eq!(target.seed_dir, format!("fuzz/seeds/{}", target.name));
    assert_eq!(
      target.regression_path,
      format!("tests/fixtures/fuzz-regressions/{}", target.name)
    );
    assert_eq!(
      target.leak_policy, "enabled",
      "campaign leak detection exceptions require rationale, expiry, and tracking issue metadata"
    );
    for landmark in &target.coverage_landmarks {
      let (source_path, symbol) = landmark
        .split_once(':')
        .unwrap_or_else(|| panic!("coverage landmark {landmark} must use path:symbol"));
      assert_safe_relative_path(source_path, "coverage landmark path");
      assert!(
        repo_root().join(source_path).is_file(),
        "coverage landmark source {source_path} should exist"
      );
      assert!(
        !symbol.trim().is_empty(),
        "coverage landmark symbol must not be empty"
      );
    }
    if let Some(dictionary) = &target.dictionary {
      assert_safe_relative_path(dictionary, "dictionary path");
      assert!(dictionary.starts_with("fuzz/dictionaries/"));
      assert!(dictionary.ends_with(".dict"));
    }
  }
}

#[test]
fn cargo_bins_and_ci_matrices_match_the_catalog() {
  let (_, targets) = catalog();
  let expected = targets.keys().cloned().collect::<BTreeSet<_>>();
  let cargo = parse_repo_toml("fuzz/Cargo.toml");
  let bins = cargo
    .get("bin")
    .and_then(toml::Value::as_array)
    .expect("fuzz/Cargo.toml should define [[bin]] entries");
  let cargo_names = bins
    .iter()
    .map(|value| {
      let table = value.as_table().expect("fuzz bin should be a table");
      let name = required_string(table, "name", "fuzz bin");
      assert_eq!(
        required_string(table, "path", &format!("fuzz bin {name}")),
        format!("fuzz_targets/{name}.rs")
      );
      assert_eq!(
        table.get("test").and_then(toml::Value::as_bool),
        Some(false)
      );
      assert_eq!(table.get("doc").and_then(toml::Value::as_bool), Some(false));
      assert_eq!(
        table.get("bench").and_then(toml::Value::as_bool),
        Some(false)
      );
      name
    })
    .collect::<BTreeSet<_>>();
  assert_eq!(
    cargo_names, expected,
    "fuzz Cargo bins must match the catalog"
  );

  let check_workflow = read_repo_file(".github/workflows/check-oxibelt.yml");
  let sustained_workflow = read_repo_file(".github/workflows/fuzz-sustained.yml");
  assert_eq!(
    job_matrix_targets(&check_workflow, "fuzz-smoke"),
    expected,
    "pull-request fuzz matrix must match the catalog"
  );
  assert_eq!(
    job_matrix_targets(&sustained_workflow, "fuzz-sustained"),
    targets.keys().cloned().collect(),
    "sustained fuzz matrix must match the catalog"
  );
}

fn job_block<'a>(workflow: &'a str, job: &str) -> &'a str {
  let marker = format!("\n  {job}:\n");
  let start = workflow
    .find(&marker)
    .unwrap_or_else(|| panic!("workflow should define job `{job}`"))
    + 1;
  let remainder = &workflow[start..];
  let end = remainder
    .match_indices("\n  ")
    .find_map(|(offset, _)| {
      let line = remainder[offset + 1..].lines().next()?;
      (line.starts_with("  ")
        && !line.starts_with("   ")
        && line.ends_with(':')
        && !line.trim_start().starts_with('-'))
      .then_some(offset)
    })
    .unwrap_or(remainder.len());
  &remainder[..end]
}

fn job_matrix_targets(workflow: &str, job: &str) -> BTreeSet<String> {
  let block = job_block(workflow, job);
  let marker = "        fuzz_target:\n";
  let start = block
    .find(marker)
    .unwrap_or_else(|| panic!("job `{job}` should define matrix.fuzz_target"))
    + marker.len();
  block[start..]
    .lines()
    .take_while(|line| line.starts_with("          - "))
    .map(|line| line.trim_start_matches("          - ").trim().to_string())
    .collect()
}

#[test]
fn reviewed_seeds_are_complete_bounded_and_non_secret() {
  let (program, targets) = catalog();
  let max_files = usize::try_from(table_integer(&program, "max_seed_files_per_target"))
    .expect("seed file limit should fit usize");
  let max_bytes = u64::try_from(table_integer(&program, "max_seed_bytes_per_target"))
    .expect("seed byte limit should be positive");
  let seeds = seed_manifest();
  let mut paths = BTreeSet::new();
  let mut by_target: BTreeMap<String, (usize, u64)> = BTreeMap::new();

  for seed in &seeds {
    let target = targets.get(&seed.target).unwrap_or_else(|| {
      panic!(
        "seed {} references unknown target {}",
        seed.path, seed.target
      )
    });
    assert_safe_relative_path(&seed.path, "seed path");
    assert!(
      seed.path.starts_with(&format!("{}/", target.seed_dir)),
      "seed {} must stay in {}",
      seed.path,
      target.seed_dir
    );
    assert!(
      paths.insert(seed.path.clone()),
      "duplicate seed path {}",
      seed.path
    );
    let metadata = fs::symlink_metadata(repo_root().join(&seed.path))
      .unwrap_or_else(|error| panic!("seed {} should exist: {error}", seed.path));
    assert!(
      !metadata.file_type().is_symlink(),
      "seed {} must not be a symlink",
      seed.path
    );
    assert!(
      metadata.is_file(),
      "seed {} must be a regular file",
      seed.path
    );
    assert!(
      metadata.len() <= target.max_input_bytes,
      "seed {} exceeds target {} input limit",
      seed.path,
      seed.target
    );
    assert_eq!(
      seed.license, "Apache-2.0",
      "seed {} must have a compatible license",
      seed.path
    );
    assert_eq!(
      seed.classification, "non-secret",
      "seed {} must be classified non-secret",
      seed.path
    );
    assert!(
      seed.origin.len() >= 24,
      "seed {} must record meaningful provenance",
      seed.path
    );
    assert!(
      seed.sha256.len() == 64 && seed.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
      "seed {} must record a SHA-256 digest",
      seed.path
    );
    let bytes = fs::read(repo_root().join(&seed.path))
      .unwrap_or_else(|error| panic!("seed {} should be readable: {error}", seed.path));
    let actual = Sha256::digest(&bytes)
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect::<String>();
    assert_eq!(
      actual, seed.sha256,
      "seed {} digest must match reviewed bytes",
      seed.path
    );
    let lower = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
    for forbidden in [
      "begin private key",
      "begin rsa private key",
      "authorization: bearer",
      "aws_secret_access_key",
      "private_token",
    ] {
      assert!(
        !lower.contains(forbidden),
        "seed {} contains forbidden secret marker",
        seed.path
      );
    }
    let summary = by_target.entry(seed.target.clone()).or_default();
    summary.0 += 1;
    summary.1 += metadata.len();
  }

  for target in targets.keys() {
    let (count, bytes) = by_target.get(target).copied().unwrap_or_default();
    assert!(count > 0, "target {target} must have a reviewed seed");
    assert!(
      count <= max_files,
      "target {target} exceeds reviewed seed file limit"
    );
    assert!(
      bytes <= max_bytes,
      "target {target} exceeds reviewed seed byte limit"
    );
  }

  let actual = repository_files_below("fuzz/seeds")
    .into_iter()
    .filter(|path| path != "fuzz/seeds/manifest.toml")
    .collect::<BTreeSet<_>>();
  assert_eq!(
    actual, paths,
    "every reviewed seed file must have manifest provenance"
  );
}

#[test]
fn compio_h1_response_target_preserves_structured_bounds() {
  let (_, targets) = catalog();
  let target = targets
    .get("compio_h1_response")
    .expect("Compio response target should be registered");
  assert_eq!(
    target.max_input_bytes, 131_072,
    "response bytes must remain bounded at the catalog boundary"
  );
  assert!(
    target
      .input_contract
      .contains("thirty-two fragmentation sizes")
      && target.input_contract.contains("nine selectors"),
    "the catalog must document both structured fragmentation and limit inputs"
  );

  let wrapper = read_repo_file("fuzz/fuzz_targets/compio_h1_response.rs");
  for required in [
    "struct CompioH1ResponseInput",
    "const LIMIT_SELECTOR_COUNT: usize = 9;",
    "const MAX_FRAGMENT_SIZES: usize = 32;",
    "limit_selectors: [u8; LIMIT_SELECTOR_COUNT]",
    "exercise_compio_h1_response(",
  ] {
    assert!(
      wrapper.contains(required),
      "Compio response wrapper must preserve structured bound `{required}`"
    );
  }

  let seed_count = seed_manifest()
    .iter()
    .filter(|seed| seed.target == "compio_h1_response")
    .count();
  assert_eq!(
    seed_count, 3,
    "the Compio response target must retain three reviewed framing seeds"
  );
}

#[test]
fn dictionaries_are_small_valid_and_catalogued() {
  let (_, targets) = catalog();
  let expected = targets
    .values()
    .filter_map(|target| target.dictionary.clone())
    .collect::<BTreeSet<_>>();
  let actual = repository_files_below("fuzz/dictionaries");
  assert_eq!(
    actual, expected,
    "dictionary files must be referenced by the target catalog"
  );

  for path in actual {
    assert_safe_relative_path(&path, "dictionary path");
    let metadata = fs::symlink_metadata(repo_root().join(&path))
      .unwrap_or_else(|error| panic!("dictionary {path} should exist: {error}"));
    assert!(
      !metadata.file_type().is_symlink(),
      "dictionary {path} must not be a symlink"
    );
    assert!(
      metadata.is_file(),
      "dictionary {path} must be a regular file"
    );
    assert!(
      metadata.len() <= 65_536,
      "dictionary {path} must not exceed 64 KiB"
    );
    let contents = read_repo_file(&path);
    let mut token_count = 0;
    for (index, line) in contents.lines().enumerate() {
      let line = line.trim();
      if line.is_empty() || line.starts_with('#') {
        continue;
      }
      let (_, token) = line
        .split_once('=')
        .unwrap_or_else(|| panic!("dictionary {path}:{} must use name=\"token\"", index + 1));
      assert!(
        token.starts_with('"') && token.ends_with('"') && token.len() >= 2,
        "dictionary {path}:{} must quote its token",
        index + 1
      );
      token_count += 1;
    }
    assert!(token_count > 0, "dictionary {path} must contain tokens");
  }
}

fn repository_files_below(relative: &str) -> BTreeSet<String> {
  let root = repo_root();
  let start = root.join(relative);
  let mut pending = vec![start];
  let mut files = BTreeSet::new();
  while let Some(directory) = pending.pop() {
    let entries = fs::read_dir(&directory)
      .unwrap_or_else(|error| panic!("{} should be readable: {error}", directory.display()));
    for entry in entries {
      let entry = entry.expect("directory entry should be readable");
      let metadata = fs::symlink_metadata(entry.path())
        .unwrap_or_else(|error| panic!("{} should have metadata: {error}", entry.path().display()));
      assert!(
        !metadata.file_type().is_symlink(),
        "{} must not be a symlink",
        entry.path().display()
      );
      if metadata.is_dir() {
        pending.push(entry.path());
      } else {
        assert!(
          metadata.is_file(),
          "{} must be a regular file",
          entry.path().display()
        );
        files.insert(
          entry
            .path()
            .strip_prefix(&root)
            .expect("file should remain under repository root")
            .to_string_lossy()
            .replace('\\', "/"),
        );
      }
    }
  }
  files
}

#[test]
fn mutable_fuzz_output_is_ignored_but_reviewed_inputs_are_not() {
  let ignored = read_repo_file("fuzz/.gitignore");
  assert_eq!(
    ignored.lines().collect::<BTreeSet<_>>(),
    BTreeSet::from([".cmin-*/", "artifacts/", "corpus/", "coverage/", "target/",]),
    "fuzz/.gitignore must ignore only generated fuzz output"
  );
  for reviewed in ["seeds", "dictionaries", "targets.toml"] {
    assert!(
      !ignored.contains(reviewed),
      "reviewed fuzz input {reviewed} must remain trackable"
    );
  }
}

#[test]
fn workflows_enforce_bounded_least_privilege_profiles() {
  let check = read_repo_file(".github/workflows/check-oxibelt.yml");
  let smoke = job_block(&check, "fuzz-smoke");
  assert_contains_all(
    "fuzz-smoke",
    smoke,
    &[
      "permissions:\n      contents: read",
      "timeout-minutes: 45",
      "name: Fuzz smoke (${{ matrix.fuzz_profile.name }}, ${{ matrix.fuzz_target }})",
      "max-parallel: 16",
      "fuzz_profile:\n          - name: stable\n            toolchain: stable\n          - name: asan\n            toolchain: nightly-2026-07-31",
      "rustup toolchain install \"${{ matrix.fuzz_profile.toolchain }}\" --profile minimal",
      "cargo-fuzz --version 0.13.2",
      "OXIBELT_FUZZ_PROFILE: ${{ matrix.fuzz_profile.name }}",
      "tests/scripts/run-fuzz-target.sh smoke",
      "name: oxibelt-${{ matrix.fuzz_profile.name }}-${{ matrix.fuzz_target }}-fuzz-artifacts",
      "${{ runner.temp }}/oxibelt-fuzz-artifacts/${{ matrix.fuzz_target }}",
      "retention-days: 90",
    ],
  );
  assert!(
    !smoke.contains("ASAN_OPTIONS:") && !smoke.contains("LSAN_OPTIONS:"),
    "the fuzz runner, not the workflow, must configure sanitizer environments by profile"
  );

  let sustained = read_repo_file(".github/workflows/fuzz-sustained.yml");
  assert_contains_all(
    "fuzz-sustained workflow",
    &sustained,
    &[
      "schedule:",
      "cron: \"17 3 * * *\"",
      "workflow_dispatch:",
      "cancel-in-progress: false",
    ],
  );
  let campaign = job_block(&sustained, "fuzz-sustained");
  assert_contains_all(
    "fuzz-sustained job",
    campaign,
    &[
      "permissions:\n      contents: read",
      "max-parallel: 4",
      "timeout-minutes: 120",
      "nightly-2026-07-31",
      "cargo-fuzz --version 0.13.2",
      "tests/scripts/run-fuzz-target.sh campaign",
      "LSAN_OPTIONS: detect_leaks=1",
      "${{ runner.temp }}/oxibelt-fuzz-corpus/${{ matrix.fuzz_target }}",
      "retention-days: 30",
      "retention-days: 90",
    ],
  );
  assert!(
    campaign
      .contains("github.ref == format('refs/heads/{0}', github.event.repository.default_branch)")
      || campaign.contains("github.ref_name == github.event.repository.default_branch"),
    "the sustained campaign must run only for the canonical default branch"
  );

  for (name, contents) in [("fuzz-smoke", smoke), ("fuzz-sustained", campaign)] {
    for forbidden in [
      "contents: write",
      "issues: write",
      "pull-requests: write",
      "git commit",
      "git push",
      "docker ",
      "docker-rootful",
    ] {
      assert!(
        !contents.contains(forbidden),
        "{name} must not contain `{forbidden}`"
      );
    }
  }

  let runner = read_repo_file("tests/scripts/run-fuzz-target.sh");
  assert_contains_all(
    "fuzz runner",
    &runner,
    &[
      "set -Eeuo pipefail",
      "umask 077",
      "readonly FUZZ_ASAN_NIGHTLY=\"nightly-2026-07-31\"",
      "readonly fuzz_profile=\"${OXIBELT_FUZZ_PROFILE:-asan}\"",
      "stable fuzz profile only supports smoke mode",
      "OXIBELT_FUZZ_PROFILE must be one of: asan, stable",
      "fuzz_toolchain=\"stable\"",
      "fuzz_sanitizer=\"none\"",
      "unset ASAN_OPTIONS LSAN_OPTIONS",
      "cargo \"+$fuzz_toolchain\" fuzz run --sanitizer \"$fuzz_sanitizer\"",
      "readonly MAX_SEED_FILES=128",
      "readonly MAX_SEED_BYTES=524288",
      "readonly MAX_WORKING_CORPUS_FILES=16384",
      "readonly MAX_CACHED_CORPUS_FILES=8192",
      "readonly MAX_CORPUS_BYTES=67108864",
      "readonly MAX_ARTIFACT_FILES=8",
      "readonly FUZZ_TIMEOUT_SECONDS=10",
      "readonly FUZZ_RSS_LIMIT_MB=3072",
      "readonly FUZZ_MALLOC_LIMIT_MB=512",
      "-runs=256",
      "-max_total_time=$duration_seconds",
      "-max_len=$max_input_bytes",
      "-timeout=$FUZZ_TIMEOUT_SECONDS",
      "-rss_limit_mb=$FUZZ_RSS_LIMIT_MB",
      "-malloc_limit_mb=$FUZZ_MALLOC_LIMIT_MB",
      "-print_final_stats=1",
      "-detect_leaks=0",
      "-detect_leaks=1",
      "configure_sanitizer_environment 0",
      "configure_sanitizer_environment 1",
      "cargo_target_dir",
      "coverage_search_roots",
      "metadata --no-deps --format-version 1",
      "cmin_staging",
      "cmin_replacement",
      "cmin_backup",
      "-artifact_prefix=$artifact_dir/",
      "readonly artifact_dir=\"$runner_temp/oxibelt-fuzz-artifacts/$target\"",
      "readonly persistent_corpus=\"$runner_temp/oxibelt-fuzz-corpus/$target\"",
      "assert_no_symlinks",
      "mktemp -d",
      "timeout --signal=TERM --kill-after=15s 300s",
    ],
  );
  for forbidden in [
    "eval ",
    "curl ",
    "wget ",
    "docker ",
    "docker-rootful",
    "git commit",
    "git push",
    "gh issue",
  ] {
    assert!(
      !runner.contains(forbidden),
      "fuzz runner must not contain `{forbidden}`"
    );
  }
}

#[cfg(unix)]
#[test]
fn stable_smoke_uses_stable_without_sanitizer_environment() {
  use std::os::unix::fs::PermissionsExt as _;

  let target_dir = repo_root().join("target");
  fs::create_dir_all(&target_dir).expect("Cargo target directory should be creatable");
  let temp_dir = tempfile::Builder::new()
    .prefix("oxibelt-fuzz-stable-smoke-contract-")
    .tempdir_in(target_dir)
    .expect("stable smoke contract temp directory should be creatable");
  let runner_temp = temp_dir.path().join("runner");
  let bin_dir = temp_dir.path().join("bin");
  let called_marker = temp_dir.path().join("stable-smoke-called");
  fs::create_dir_all(&runner_temp).expect("runner temp directory should be creatable");
  fs::create_dir_all(&bin_dir).expect("fake Cargo directory should be creatable");

  let cargo = bin_dir.join("cargo");
  fs::write(
    &cargo,
    r#"#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$#" -ge 9 ]]
[[ "$1" == "+stable" ]]
[[ "$2" == "fuzz" ]]
[[ "$3" == "run" ]]
[[ "$4" == "--sanitizer" ]]
[[ "$5" == "none" ]]
[[ "$6" == "native_config" ]]
[[ -d "$7" && ! -L "$7" ]]
[[ "$8" == "--" ]]
[[ -z "${ASAN_OPTIONS+x}" ]]
[[ -z "${LSAN_OPTIONS+x}" ]]
found_runs=0
for argument in "$@"; do
  if [[ "$argument" == "-runs=256" ]]; then
    found_runs=1
  fi
done
(( found_runs == 1 ))
printf 'stable smoke invoked\n' >"$FAKE_FUZZ_CALLED"
"#,
  )
  .expect("fake Cargo should be writable");
  let mut permissions = fs::metadata(&cargo)
    .expect("fake Cargo should have metadata")
    .permissions();
  permissions.set_mode(0o755);
  fs::set_permissions(&cargo, permissions).expect("fake Cargo should be executable");

  let original_path = std::env::var_os("PATH").unwrap_or_default();
  let path = format!("{}:{}", bin_dir.display(), original_path.to_string_lossy());
  let output = std::process::Command::new("bash")
    .arg(repo_root().join("tests/scripts/run-fuzz-target.sh"))
    .args(["smoke", "native_config"])
    .current_dir(repo_root())
    .env("OXIBELT_FUZZ_PROFILE", "stable")
    .env("RUNNER_TEMP", &runner_temp)
    .env("FAKE_FUZZ_CALLED", &called_marker)
    .env("ASAN_OPTIONS", "caller-value-must-not-leak")
    .env("LSAN_OPTIONS", "caller-value-must-not-leak")
    .env("PATH", path)
    .output()
    .expect("stable smoke contract runner should execute");

  assert!(
    output.status.success(),
    "stable smoke should run without sanitizer instrumentation: {}",
    String::from_utf8_lossy(&output.stderr)
  );
  assert!(
    called_marker.is_file(),
    "stable smoke must invoke cargo with the stable profile"
  );
}

#[cfg(unix)]
#[test]
fn stable_profile_is_smoke_only_and_unknown_profiles_fail_closed() {
  for mode in ["campaign", "cmin", "coverage", "minimize", "report"] {
    let output = std::process::Command::new("bash")
      .arg(repo_root().join("tests/scripts/run-fuzz-target.sh"))
      .args([mode, "native_config", "1"])
      .current_dir(repo_root())
      .env("OXIBELT_FUZZ_PROFILE", "stable")
      .output()
      .expect("stable profile rejection should execute");
    assert!(
      !output.status.success(),
      "stable profile must reject sustained mode {mode}"
    );
    assert!(
      String::from_utf8_lossy(&output.stderr)
        .contains("stable fuzz profile only supports smoke mode"),
      "stable profile should explain the rejected mode {mode}: {}",
      String::from_utf8_lossy(&output.stderr)
    );
  }

  let output = std::process::Command::new("bash")
    .arg(repo_root().join("tests/scripts/run-fuzz-target.sh"))
    .args(["smoke", "native_config"])
    .current_dir(repo_root())
    .env("OXIBELT_FUZZ_PROFILE", "unknown")
    .output()
    .expect("unknown profile rejection should execute");
  assert!(
    !output.status.success(),
    "unknown profiles must fail closed"
  );
  assert!(
    String::from_utf8_lossy(&output.stderr)
      .contains("OXIBELT_FUZZ_PROFILE must be one of: asan, stable"),
    "unknown profile rejection should list the accepted values: {}",
    String::from_utf8_lossy(&output.stderr)
  );
}

#[cfg(unix)]
struct CminHarness {
  _temp_dir: tempfile::TempDir,
  runner_temp: PathBuf,
  corpus: PathBuf,
  called_marker: PathBuf,
  bin_dir: PathBuf,
  input_count: usize,
}

#[cfg(unix)]
impl CminHarness {
  fn new(input_count: usize) -> Self {
    use std::os::unix::fs::PermissionsExt as _;

    let repo = repo_root();
    let target_dir = repo.join("target");
    fs::create_dir_all(&target_dir).expect("Cargo target directory should be creatable");
    let temp_dir = tempfile::Builder::new()
      .prefix("oxibelt-fuzz-cmin-contract-")
      .tempdir_in(target_dir)
      .expect("cmin contract temp directory should be creatable");
    let runner_temp = temp_dir.path().join("runner");
    let corpus = runner_temp.join("oxibelt-fuzz-corpus/native_config");
    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&corpus).expect("working corpus should be creatable");
    fs::create_dir_all(&bin_dir).expect("fake Cargo directory should be creatable");
    for index in 0..input_count {
      fs::write(
        corpus.join(format!("input-{index:05}")),
        [u8::try_from(index % 251).expect("corpus byte should fit")],
      )
      .expect("working corpus entry should be writable");
    }

    let cargo = bin_dir.join("cargo");
    fs::write(
      &cargo,
      r#"#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$#" -ge 7 ]]
[[ "$1" == "+nightly-2026-07-31" ]]
[[ "$2" == "fuzz" ]]
[[ "$3" == "cmin" ]]
[[ "$6" == "native_config" ]]
case "$7" in
  "${EXPECTED_CMIN_PREFIX}".??????) ;;
  *) exit 65 ;;
esac
[[ "$EXPECTED_CMIN_INPUTS" =~ ^[1-9][0-9]*$ ]]
[[ "$FAKE_CMIN_RETAINED" =~ ^[1-9][0-9]*$ ]]
mapfile -d '' corpus_entries < <(find "$7" -maxdepth 1 -type f -print0 | sort -z)
(( ${#corpus_entries[@]} == EXPECTED_CMIN_INPUTS ))
printf '%s\n' "$7" >"$FAKE_CMIN_CALLED"
case "$FAKE_CMIN_MODE" in
  reduce)
    (( FAKE_CMIN_RETAINED <= ${#corpus_entries[@]} ))
    for ((index = FAKE_CMIN_RETAINED; index < ${#corpus_entries[@]}; index += 1)); do
      rm -- "${corpus_entries[$index]}"
    done
    ;;
  noop) ;;
  *) exit 66 ;;
esac
"#,
    )
    .expect("fake Cargo should be writable");
    let mut permissions = fs::metadata(&cargo)
      .expect("fake Cargo should have metadata")
      .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&cargo, permissions).expect("fake Cargo should be executable");

    let called_marker = temp_dir.path().join("cmin-called");
    Self {
      _temp_dir: temp_dir,
      runner_temp,
      corpus,
      called_marker,
      bin_dir,
      input_count,
    }
  }

  fn run(&self, mode: &str, retained_count: usize) -> std::process::Output {
    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!(
      "{}:{}",
      self.bin_dir.display(),
      original_path.to_string_lossy()
    );
    std::process::Command::new("bash")
      .arg(repo_root().join("tests/scripts/run-fuzz-target.sh"))
      .args(["cmin", "native_config", "1"])
      .current_dir(repo_root())
      .env("RUNNER_TEMP", &self.runner_temp)
      .env(
        "EXPECTED_CMIN_PREFIX",
        repo_root().join("fuzz/.cmin-native_config"),
      )
      .env("FAKE_CMIN_CALLED", &self.called_marker)
      .env("FAKE_CMIN_MODE", mode)
      .env("EXPECTED_CMIN_INPUTS", self.input_count.to_string())
      .env("FAKE_CMIN_RETAINED", retained_count.to_string())
      .env("PATH", path)
      .output()
      .expect("cmin contract runner should execute")
  }

  fn expected_snapshot(count: usize) -> BTreeMap<String, Vec<u8>> {
    (0..count)
      .map(|index| {
        (
          format!("input-{index:05}"),
          vec![u8::try_from(index % 251).expect("corpus byte should fit")],
        )
      })
      .collect()
  }

  fn corpus_snapshot(&self) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(&self.corpus)
      .expect("working corpus should be readable")
      .map(|entry| {
        let entry = entry.expect("working corpus entry should be readable");
        let name = entry
          .file_name()
          .into_string()
          .expect("working corpus names should be UTF-8");
        let bytes = fs::read(entry.path()).expect("working corpus bytes should be readable");
        (name, bytes)
      })
      .collect()
  }
}

#[cfg(unix)]
#[test]
fn cmin_accepts_the_exact_http_semantics_regression() {
  let harness = CminHarness::new(2_324);
  let output = harness.run("reduce", 2_102);
  assert!(
    output.status.success(),
    "cmin should retain the complete minimized HTTP corpus: {}",
    String::from_utf8_lossy(&output.stderr)
  );
  assert!(harness.called_marker.is_file(), "fake cmin should run");
  assert_eq!(
    harness.corpus_snapshot(),
    CminHarness::expected_snapshot(2_102)
  );
}

#[cfg(unix)]
#[test]
fn cmin_accepts_the_exact_admin_json_mutations_regression() {
  let harness = CminHarness::new(6_627);
  let output = harness.run("reduce", 5_633);
  assert!(
    output.status.success(),
    "cmin should retain the complete minimized Admin JSON corpus: {}",
    String::from_utf8_lossy(&output.stderr)
  );
  assert!(harness.called_marker.is_file(), "fake cmin should run");
  assert_eq!(
    harness.corpus_snapshot(),
    CminHarness::expected_snapshot(5_633)
  );
}

#[cfg(unix)]
#[test]
fn cmin_accepts_inclusive_working_and_cached_file_limits() {
  let harness = CminHarness::new(16_384);
  let output = harness.run("reduce", 8_192);
  assert!(
    output.status.success(),
    "cmin should accept both inclusive corpus file limits: {}",
    String::from_utf8_lossy(&output.stderr)
  );
  assert!(harness.called_marker.is_file(), "fake cmin should run");
  assert_eq!(
    harness.corpus_snapshot(),
    CminHarness::expected_snapshot(8_192)
  );
}

#[cfg(unix)]
#[test]
fn cmin_rejects_result_above_cached_limit_without_replacing_working_corpus() {
  let harness = CminHarness::new(8_193);
  let original = harness.corpus_snapshot();
  let output = harness.run("noop", 8_193);
  assert!(harness.called_marker.is_file(), "fake cmin should run");
  assert!(
    !output.status.success(),
    "a result above the cached corpus limit must fail"
  );
  assert!(
    String::from_utf8_lossy(&output.stderr).contains("cached corpus exceeds 8192 files"),
    "cmin should explain the retained cache bound: {}",
    String::from_utf8_lossy(&output.stderr)
  );
  assert_eq!(harness.corpus_snapshot(), original);
}

#[cfg(unix)]
#[test]
fn cmin_rejects_working_corpus_above_limit_before_invoking_cargo() {
  let harness = CminHarness::new(16_385);
  let original = harness.corpus_snapshot();
  let output = harness.run("noop", 16_385);
  assert!(
    !harness.called_marker.exists(),
    "fake cmin must not run for an oversized working corpus"
  );
  assert!(
    !output.status.success(),
    "a corpus above the working limit must fail"
  );
  assert!(
    String::from_utf8_lossy(&output.stderr).contains("working corpus exceeds 16384 files"),
    "cmin should explain the transient working bound: {}",
    String::from_utf8_lossy(&output.stderr)
  );
  assert_eq!(harness.corpus_snapshot(), original);
}

#[test]
fn fuzz_target_wrappers_do_not_gain_side_effect_apis() {
  let (_, targets) = catalog();
  let wrappers = repository_files_below("fuzz/fuzz_targets");
  let expected = targets
    .keys()
    .map(|name| format!("fuzz/fuzz_targets/{name}.rs"))
    .collect::<BTreeSet<_>>();
  assert_eq!(
    wrappers, expected,
    "one wrapper must exist for each catalog target"
  );

  for path in wrappers {
    let source = read_repo_file(&path);
    assert!(
      source.contains("fuzz_target!"),
      "{path} must define a libFuzzer entry point"
    );
    for forbidden in [
      "std::fs",
      "tokio::fs",
      "std::process",
      "Command::",
      "TcpStream",
      "TcpListener",
      "UdpSocket",
      "UnixStream",
      "sqlx::",
      "kube::Client",
      "set_var(",
      "remove_var(",
      "libc::",
      "nix::",
      "unsafe {",
      "unsafe fn",
    ] {
      assert!(
        !source.contains(forbidden),
        "{path} must not use side-effect API `{forbidden}`"
      );
    }
  }
}

#[test]
fn fuzzing_documentation_covers_the_operational_lifecycle() {
  let docs = read_repo_file("docs/Fuzzing.md");
  assert_contains_all(
    "docs/Fuzzing.md",
    &docs,
    &[
      "## Program catalog and ownership",
      "## Setup and local runs",
      "## Seeds, dictionaries, and corpus promotion",
      "## Coverage evidence",
      "## Crash triage and regressions",
      "moving `stable`",
      "`nightly-2026-07-31`",
      "OXIBELT_FUZZ_PROFILE=stable",
      "Stable smoke runs use `--sanitizer none`",
      "stable lane supplements rather than replaces",
      "tests/scripts/run-fuzz-target.sh smoke",
      "tests/scripts/run-fuzz-target.sh campaign",
      "tests/fixtures/fuzz-regressions/<target>/",
      "SECURITY.md",
      "Automation never commits a generated corpus or opens a public issue.",
    ],
  );
  for target in EXPECTED_TARGETS {
    assert!(
      docs.contains(&format!("`{target}`")),
      "docs must describe target {target}"
    );
  }
}

fn assert_contains_all(context: &str, contents: &str, needles: &[&str]) {
  for needle in needles {
    assert!(
      contents.contains(needle),
      "{context} must contain `{needle}`"
    );
  }
}
