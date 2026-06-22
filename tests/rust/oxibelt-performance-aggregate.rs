use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_RESULTS_BYTES: u64 = 10 * 1024 * 1024;
const MAX_WARNINGS: usize = 200;
const DEFAULT_H1_KEEPALIVE_MIN_NGINX_RATIO: f64 = 0.80;
const DEFAULT_H1_FAST_PATH_MIN_HIT_RATE: f64 = 0.99;
const DEFAULT_H2_MIN_NGINX_RATIO: f64 = 0.80;
const DEFAULT_H3_MIN_NGINX_RATIO: f64 = 0.80;
const DEFAULT_RATIO_TARGET_NEAR_MISS_TOLERANCE: f64 = 0.005;
const DEFAULT_RATIO_TARGET_COMPARATOR_SHIFT_TOLERANCE: f64 = 0.050;
const DEFAULT_STATIC_16K_H1C_MIN_CADDY_RATIO: f64 = 0.80;
const DEFAULT_STATIC_16K_H1C_MIN_NGINX_RATIO: f64 = 0.90;
const DEFAULT_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO: f64 = 0.90;
const DEFAULT_WAF_ENFORCING_MIN_RPS: f64 = 10000.0;
const DEFAULT_CRS_ENFORCING_MIN_RPS: f64 = 8000.0;
const DEFAULT_WAF_CRS_MAX_ENFORCE_P99_RATIO: f64 = 1.30;
const BASELINE_RPS_REGRESSION_TOLERANCE_PERCENT: f64 = -3.0;
const BASELINE_P99_REGRESSION_TOLERANCE_PERCENT: f64 = 5.0;
const BASELINE_MONITOR_P99_IMPROVEMENT_PERCENT: f64 = -5.0;
const COMPARATOR_RPS_MATERIAL_IMPROVEMENT_PERCENT: f64 = 3.0;
const STAT_BAND_RPS_P10_REGRESSION_TOLERANCE_PERCENT: f64 = -5.0;
const STAT_BAND_P99_P90_REGRESSION_TOLERANCE_PERCENT: f64 = 8.0;
const QUORUM_VALID_SAMPLE_PERCENT: f64 = 0.80;
const QUORUM_SHARD_PERCENT: f64 = 0.80;
const COMPARISON_SCHEMA_VERSION: u32 = 22;
const DELTA_SCHEMA_VERSION: u32 = 2;
const DEFAULT_AMD64_TARGET_CPU: &str = "x86-64-v3";
const UNKNOWN_SERVING_TYPE: &str = "unknown";
const H2LOAD_ZERO_COMPLETED_REQUESTS: &str = "h2load produced no completed requests";
const PERF_RECORD_STATUS_255: &str = "perf record failed with status 255";
const EXTERNAL_CLASSIFICATION_VALIDATION: &str = "external_benchmark_validation";
const EXTERNAL_CLASSIFICATION_INFRA_DIAGNOSTIC: &str = "benchmark_infrastructure_diagnostic";
const PROFILE_CLASSIFICATION_VALIDATION: &str = "diagnostic_profile_validation";
const PROFILE_CLASSIFICATION_ENV_UNAVAILABLE: &str = "profiling_environment_unavailable";
const AMD64_TARGET_CPUS: [&str; 3] = ["x86-64-v2", "x86-64-v3", "x86-64-v4"];
const SERVING_TYPES: [&str; 6] = [
  "reverse-proxy",
  "static-files",
  "oxibelt-features",
  "oxibelt-soak-stress",
  "accept-multipliers",
  "remote-signer",
];

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type AggregateMap = BTreeMap<(String, Comparator, String), AggregateStats>;
type PrimaryAggregateMap = BTreeMap<(Comparator, String), AggregateStats>;

#[derive(Parser)]
#[command(about = "Aggregate OxiBelt Docker performance artifacts")]
struct Args {
  #[arg(long)]
  input_dir: PathBuf,
  #[arg(long)]
  output_dir: PathBuf,
  #[arg(long)]
  profile: Option<String>,
  #[arg(long)]
  expected_runs: Option<usize>,
  #[arg(long)]
  expected_shards: Option<usize>,
  #[arg(long, value_delimiter = ',')]
  expected_target_cpus: Vec<String>,
  #[arg(long, default_value = DEFAULT_AMD64_TARGET_CPU)]
  primary_target_cpu: String,
  #[arg(long)]
  baseline_report: Option<PathBuf>,
  #[arg(long)]
  baseline_context: Option<PathBuf>,
  #[arg(long)]
  accepted_regression_reason: Option<String>,
}

struct AggregateOptions<'a> {
  profile: Option<String>,
  expected_runs: Option<usize>,
  expected_shards: Option<usize>,
  expected_target_cpus: Vec<String>,
  primary_target_cpu: String,
  baseline_report: Option<&'a Path>,
  baseline_context: Option<&'a Path>,
  accepted_regression_reason: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Comparator {
  Oxibelt,
  Nginx,
  Caddy,
  OpenResty,
}

impl Comparator {
  fn as_str(self) -> &'static str {
    match self {
      Self::Oxibelt => "oxibelt",
      Self::Nginx => "nginx",
      Self::Caddy => "caddy",
      Self::OpenResty => "openresty",
    }
  }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
enum ScenarioGroup {
  ReverseProxy,
  StaticFiles,
  AcceptMultipliers,
  RemoteSigner,
  OxibeltOnly,
  #[default]
  Unclassified,
}

impl ScenarioGroup {
  fn as_str(self) -> &'static str {
    match self {
      Self::ReverseProxy => "reverse-proxy",
      Self::StaticFiles => "static-files",
      Self::AcceptMultipliers => "accept-multipliers",
      Self::RemoteSigner => "remote-signer",
      Self::OxibeltOnly => "oxibelt-only",
      Self::Unclassified => "unclassified",
    }
  }
}

#[derive(Default)]
struct WarningBag {
  warnings: Vec<String>,
  omitted: usize,
}

impl WarningBag {
  fn push(&mut self, warning: impl Into<String>) {
    if self.warnings.len() < MAX_WARNINGS {
      self.warnings.push(warning.into());
    } else {
      self.omitted += 1;
    }
  }

  fn finish(self) -> (Vec<String>, usize) {
    (self.warnings, self.omitted)
  }
}

struct DiscoveredFiles {
  results: Vec<PathBuf>,
  external_results: Vec<PathBuf>,
  profile_results: Vec<PathBuf>,
  summary_count: usize,
  docker_stats_count: usize,
  iteration_statuses: Vec<PathBuf>,
  unsupported_cpu_markers: Vec<PathBuf>,
}

#[derive(Serialize)]
struct ArtifactDiscovery {
  results_files: usize,
  external_results_files: usize,
  profile_results_files: usize,
  summary_files: usize,
  docker_stats_files: usize,
  iteration_status_files: usize,
  expected_results_files: Option<usize>,
  missing_expected_paths: Vec<String>,
  unsupported_cpu: UnsupportedCpuDiscovery,
}

#[derive(Default, Serialize)]
struct UnsupportedCpuDiscovery {
  count: usize,
  markers: Vec<String>,
  shards: Vec<String>,
}

#[derive(Clone)]
struct BenchmarkRow {
  source_file: String,
  amd64_target_cpu: String,
  label: String,
  comparator: Comparator,
  scenario: String,
  group: ScenarioGroup,
  result_type: Option<String>,
  protocol_or_mode: Option<String>,
  rps: Option<f64>,
  p50_ms: Option<f64>,
  p90_ms: Option<f64>,
  p95_ms: Option<f64>,
  p99_ms: Option<f64>,
  errors: u64,
  skipped: bool,
  reason: Option<String>,
  fast_path_plain_proxy_h1: Option<FastPathSample>,
  fast_path_plain_proxy_h2: Option<FastPathSample>,
  fast_path_plain_proxy_h3: Option<FastPathSample>,
  fast_path_transport_direct_h1_h1: Option<FastPathSample>,
  fast_path_transport_direct_h1_h2: Option<FastPathSample>,
  fast_path_transport_direct_h1_h3: Option<FastPathSample>,
  fast_path_transport_direct_h2_h1: Option<FastPathSample>,
  fast_path_transport_direct_h2_h2: Option<FastPathSample>,
  fast_path_transport_direct_h2_h3: Option<FastPathSample>,
  direct_h1_pool_events: Option<BTreeMap<String, u64>>,
  direct_h2_pool_events: Option<BTreeMap<String, u64>>,
  static_fast_path_responses: Option<BTreeMap<String, BTreeMap<String, u64>>>,
  fast_path_stage_timing: Option<FastPathStageTimingSamples>,
}

#[derive(Clone)]
struct ExternalBenchmarkSample {
  source_file: String,
  amd64_target_cpu: String,
  serving_type: String,
  label: String,
  tool: String,
  comparator: String,
  scenario: String,
  protocol: String,
  status: String,
  rps: Option<f64>,
  p95_ms: Option<f64>,
  p99_ms: Option<f64>,
  error_rate: Option<f64>,
  requests: Option<f64>,
  reason: Option<String>,
  output_file: Option<String>,
}

#[derive(Clone)]
struct DiagnosticProfileSample {
  source_file: String,
  amd64_target_cpu: String,
  serving_type: String,
  label: String,
  comparator: String,
  scenario: String,
  protocol: String,
  profile_mode: String,
  status: String,
  reason: Option<String>,
  cpu_enabled: bool,
  memory_enabled: bool,
  perf_data: Option<String>,
  perf_report: Option<String>,
  perf_script: Option<String>,
  flamegraph: Option<String>,
  cpu_metadata: Option<String>,
  resource: Option<String>,
  memory_metadata: Option<String>,
  heap_dir: Option<String>,
}

#[derive(Default)]
struct AggregateBuilder {
  amd64_target_cpu: String,
  label: String,
  comparator: Option<Comparator>,
  scenario: String,
  group: ScenarioGroup,
  result_type: Option<String>,
  protocol_or_mode: Option<String>,
  rps_values: Vec<f64>,
  p50_values: Vec<f64>,
  p90_values: Vec<f64>,
  p95_values: Vec<f64>,
  p99_values: Vec<f64>,
  rps_values_by_shard: BTreeMap<String, Vec<f64>>,
  p99_values_by_shard: BTreeMap<String, Vec<f64>>,
  total_errors: u64,
  skipped_count: u64,
  skip_reasons: BTreeSet<String>,
  source_files: BTreeSet<String>,
  fast_path_plain_proxy_h1: FastPathAggregateBuilder,
  fast_path_plain_proxy_h2: FastPathAggregateBuilder,
  fast_path_plain_proxy_h3: FastPathAggregateBuilder,
  fast_path_transport_direct_h1_h1: FastPathAggregateBuilder,
  fast_path_transport_direct_h1_h2: FastPathAggregateBuilder,
  fast_path_transport_direct_h1_h3: FastPathAggregateBuilder,
  fast_path_transport_direct_h2_h1: FastPathAggregateBuilder,
  fast_path_transport_direct_h2_h2: FastPathAggregateBuilder,
  fast_path_transport_direct_h2_h3: FastPathAggregateBuilder,
  direct_h1_pool_events: CounterMapAggregateBuilder,
  direct_h2_pool_events: CounterMapAggregateBuilder,
  static_fast_path_responses: NestedCounterMapAggregateBuilder,
  fast_path_stage_timing: FastPathStageTimingAggregateBuilder,
}

struct AggregateFastPathInput {
  plain_proxy_h1: FastPathAggregateBuilder,
  plain_proxy_h2: FastPathAggregateBuilder,
  plain_proxy_h3: FastPathAggregateBuilder,
  transport_direct_h1_h1: FastPathAggregateBuilder,
  transport_direct_h1_h2: FastPathAggregateBuilder,
  transport_direct_h1_h3: FastPathAggregateBuilder,
  transport_direct_h2_h1: FastPathAggregateBuilder,
  transport_direct_h2_h2: FastPathAggregateBuilder,
  transport_direct_h2_h3: FastPathAggregateBuilder,
  direct_h1_pool: CounterMapAggregateBuilder,
  direct_h2_pool: CounterMapAggregateBuilder,
  static_responses: NestedCounterMapAggregateBuilder,
  stage_timing: FastPathStageTimingAggregateBuilder,
}

#[derive(Clone)]
struct FastPathSample {
  hits: u64,
  misses: u64,
  attempts: u64,
  hit_rate: Option<f64>,
}

type FastPathStageTimingSamples =
  BTreeMap<String, BTreeMap<String, BTreeMap<String, BTreeMap<String, FastPathStageTimingSample>>>>;

#[derive(Clone)]
struct FastPathStageTimingSample {
  count: u64,
  total_ns: u64,
  avg_ns: Option<f64>,
}

#[derive(Default)]
struct FastPathAggregateBuilder {
  sample_count: usize,
  hits: u64,
  misses: u64,
  attempts: u64,
  hit_rates: Vec<f64>,
}

#[derive(Default)]
struct CounterMapAggregateBuilder {
  sample_count: usize,
  values: BTreeMap<String, u64>,
}

#[derive(Default)]
struct NestedCounterMapAggregateBuilder {
  sample_count: usize,
  values: BTreeMap<String, BTreeMap<String, u64>>,
}

#[derive(Default)]
struct FastPathStageTimingAggregateBuilder {
  samples: BTreeMap<(String, String, String, String), FastPathStageTimingSampleAggregateBuilder>,
}

#[derive(Default)]
struct FastPathStageTimingSampleAggregateBuilder {
  sample_count: usize,
  count: u64,
  total_ns: u64,
  avg_ns_values: Vec<f64>,
}

#[derive(Default)]
struct ExternalBenchmarkBuilder {
  amd64_target_cpu: String,
  serving_type: String,
  tool: String,
  comparator: String,
  scenario: String,
  protocol: String,
  labels: BTreeSet<String>,
  rps_values: Vec<f64>,
  p95_values: Vec<f64>,
  p99_values: Vec<f64>,
  error_rate_values: Vec<f64>,
  request_values: Vec<f64>,
  pass_count: usize,
  fail_count: usize,
  skipped_count: usize,
  reasons: BTreeSet<String>,
  source_files: BTreeSet<String>,
  output_files: BTreeSet<String>,
}

#[derive(Default)]
struct DiagnosticProfileBuilder {
  amd64_target_cpu: String,
  serving_type: String,
  comparator: String,
  scenario: String,
  protocol: String,
  profile_mode: String,
  labels: BTreeSet<String>,
  pass_count: usize,
  fail_count: usize,
  skipped_count: usize,
  cpu_enabled_count: usize,
  memory_enabled_count: usize,
  reasons: BTreeSet<String>,
  source_files: BTreeSet<String>,
  artifact_files: BTreeSet<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct AggregateDistribution {
  sample_count: usize,
  shard_count: usize,
  per_shard_median_rps: Vec<f64>,
  per_shard_median_p99_ms: Vec<f64>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct AggregateFastPathStats {
  #[serde(skip_serializing_if = "Option::is_none")]
  plain_proxy_h1: Option<FastPathAggregateStats>,
  #[serde(skip_serializing_if = "Option::is_none")]
  plain_proxy_h2: Option<FastPathAggregateStats>,
  #[serde(skip_serializing_if = "Option::is_none")]
  plain_proxy_h3: Option<FastPathAggregateStats>,
  #[serde(skip_serializing_if = "Option::is_none")]
  transport_direct_h1_h1: Option<FastPathAggregateStats>,
  #[serde(skip_serializing_if = "Option::is_none")]
  transport_direct_h1_h2: Option<FastPathAggregateStats>,
  #[serde(skip_serializing_if = "Option::is_none")]
  transport_direct_h1_h3: Option<FastPathAggregateStats>,
  #[serde(skip_serializing_if = "Option::is_none")]
  transport_direct_h2_h1: Option<FastPathAggregateStats>,
  #[serde(skip_serializing_if = "Option::is_none")]
  transport_direct_h2_h2: Option<FastPathAggregateStats>,
  #[serde(skip_serializing_if = "Option::is_none")]
  transport_direct_h2_h3: Option<FastPathAggregateStats>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  direct_h1_pool: Option<CounterMapAggregateStats>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  direct_h2_pool: Option<CounterMapAggregateStats>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  static_responses: Option<NestedCounterMapAggregateStats>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  stage_timing: Option<FastPathStageTimingAggregateStats>,
}

type FastPathStageTimingAggregateStats = BTreeMap<
  String,
  BTreeMap<String, BTreeMap<String, BTreeMap<String, FastPathStageTimingAggregateSampleStats>>>,
>;

#[derive(Clone, Default, Deserialize, Serialize)]
struct FastPathStageTimingAggregateSampleStats {
  sample_count: usize,
  count: u64,
  total_ns: u64,
  median_avg_ns: Option<f64>,
  max_avg_ns: Option<f64>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct CounterMapAggregateStats {
  sample_count: usize,
  values: BTreeMap<String, u64>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct NestedCounterMapAggregateStats {
  sample_count: usize,
  values: BTreeMap<String, BTreeMap<String, u64>>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct FastPathAggregateStats {
  sample_count: usize,
  hits: u64,
  misses: u64,
  attempts: u64,
  median_hit_rate: Option<f64>,
  min_hit_rate: Option<f64>,
}

#[derive(Clone, Deserialize, Serialize)]
struct AggregateStats {
  #[serde(default = "default_amd64_target_cpu")]
  amd64_target_cpu: String,
  label: String,
  comparator: String,
  scenario: String,
  group: String,
  result_type: Option<String>,
  protocol_or_mode: Option<String>,
  sample_count: usize,
  median_rps: Option<f64>,
  min_rps: Option<f64>,
  max_rps: Option<f64>,
  p25_rps: Option<f64>,
  p75_rps: Option<f64>,
  median_p50_ms: Option<f64>,
  median_p90_ms: Option<f64>,
  median_p95_ms: Option<f64>,
  median_p99_ms: Option<f64>,
  total_errors: u64,
  skipped_count: u64,
  skip_reasons: Vec<String>,
  source_files: Vec<String>,
  #[serde(default)]
  distribution: AggregateDistribution,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  fast_path: Option<AggregateFastPathStats>,
}

#[derive(Clone, Serialize)]
struct ExternalBenchmarkStats {
  amd64_target_cpu: String,
  serving_type: String,
  tool: String,
  comparator: String,
  scenario: String,
  protocol: String,
  sample_count: usize,
  pass_count: usize,
  fail_count: usize,
  skipped_count: usize,
  median_rps: Option<f64>,
  median_p95_ms: Option<f64>,
  median_p99_ms: Option<f64>,
  median_error_rate: Option<f64>,
  total_requests: Option<f64>,
  labels: Vec<String>,
  reasons: Vec<String>,
  source_files: Vec<String>,
  output_files: Vec<String>,
  classification: String,
  diagnostic_reason: Option<String>,
}

#[derive(Clone, Serialize)]
struct DiagnosticProfileStats {
  amd64_target_cpu: String,
  serving_type: String,
  comparator: String,
  scenario: String,
  protocol: String,
  diagnostic_group: String,
  profile_mode: String,
  sample_count: usize,
  pass_count: usize,
  fail_count: usize,
  skipped_count: usize,
  cpu_enabled_count: usize,
  memory_enabled_count: usize,
  labels: Vec<String>,
  reasons: Vec<String>,
  source_files: Vec<String>,
  artifact_files: Vec<String>,
  classification: String,
  diagnostic_reason: Option<String>,
}

#[derive(Clone, Serialize)]
struct RatioResult {
  status: String,
  ratio: Option<f64>,
  percent_of_comparator: Option<f64>,
  text: String,
  reason: Option<String>,
}

#[derive(Clone, Serialize)]
struct ScenarioComparison {
  amd64_target_cpu: String,
  scenario: String,
  group: String,
  oxibelt: Option<AggregateStats>,
  nginx: Option<AggregateStats>,
  caddy: Option<AggregateStats>,
  openresty: Option<AggregateStats>,
  oxibelt_vs_nginx: RatioResult,
  oxibelt_vs_caddy: RatioResult,
  oxibelt_vs_openresty: RatioResult,
}

#[derive(Serialize)]
struct ComparisonGroups {
  reverse_proxy: Vec<ScenarioComparison>,
  static_files: Vec<ScenarioComparison>,
}

#[derive(Clone, Serialize)]
struct AcceptMultiplierRatio {
  status: String,
  ratio: Option<f64>,
  percent_of_accept_0_5: Option<f64>,
  text: String,
  reason: Option<String>,
}

#[derive(Clone, Serialize)]
struct AcceptMultiplierComparison {
  amd64_target_cpu: String,
  scenario: String,
  accept_0_5: Option<AggregateStats>,
  accept_1_0: Option<AggregateStats>,
  accept_1_0_vs_0_5: AcceptMultiplierRatio,
}

#[derive(Clone, Serialize)]
struct RemoteSignerRatio {
  status: String,
  throughput_ratio: Option<f64>,
  throughput_percent_of_local_key: Option<f64>,
  throughput_delta_percent: Option<f64>,
  p99_ratio: Option<f64>,
  p99_percent_of_local_key: Option<f64>,
  p99_delta_percent: Option<f64>,
  text: String,
  reason: Option<String>,
}

#[derive(Clone, Serialize)]
struct RemoteSignerComparison {
  amd64_target_cpu: String,
  scenario: String,
  local_key: Option<AggregateStats>,
  remote_signer: Option<AggregateStats>,
  remote_signer_vs_local_key: RemoteSignerRatio,
}

#[derive(Serialize)]
struct RatioSummary {
  scenario_count: usize,
  valid_comparisons: usize,
  median_ratio: Option<f64>,
  median_percent_of_comparator: Option<f64>,
}

#[derive(Serialize)]
struct GroupSummary {
  scenarios: usize,
  oxibelt_vs_nginx: RatioSummary,
  oxibelt_vs_caddy: RatioSummary,
  oxibelt_vs_openresty: RatioSummary,
}

#[derive(Serialize)]
struct ReportSummary {
  reverse_proxy: GroupSummary,
  static_files: GroupSummary,
  accept_multipliers: AcceptMultiplierSummary,
  remote_signer: RemoteSignerSummary,
  external_benchmark_row_count: usize,
  diagnostic_profile_row_count: usize,
  oxibelt_only_row_count: usize,
}

#[derive(Clone, Copy, Serialize)]
struct RegressionGateThresholds {
  h1_keepalive_min_nginx_ratio: f64,
  h1_fast_path_min_hit_rate: f64,
  h2_min_nginx_ratio: f64,
  h3_min_nginx_ratio: f64,
  static_16k_h1c_min_caddy_ratio: f64,
  static_16k_h1c_min_nginx_ratio: f64,
  remote_signer_handshake_min_local_ratio: f64,
  waf_enforcing_min_rps: f64,
  crs_enforcing_min_rps: f64,
  waf_crs_max_enforce_p99_ratio: f64,
}

#[derive(Serialize)]
struct RegressionGateViolation {
  amd64_target_cpu: String,
  disposition: String,
  gate: String,
  group: String,
  scenario: String,
  metric: String,
  observed: Option<f64>,
  threshold: f64,
  comparator: Option<String>,
  evaluation_mode: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  stat_band: Option<StatBandReport>,
  #[serde(skip_serializing_if = "Option::is_none")]
  baseline_source: Option<String>,
  message: String,
}

#[derive(Serialize)]
struct RegressionGateReport {
  status: String,
  thresholds: RegressionGateThresholds,
  accepted_regression: AcceptedRegressionReport,
  violations: Vec<RegressionGateViolation>,
  advisories: Vec<RegressionGateViolation>,
}

struct RegressionGateFindings {
  violations: Vec<RegressionGateViolation>,
  advisories: Vec<RegressionGateViolation>,
}

#[derive(Serialize)]
struct AcceptedRegressionReport {
  status: String,
  reason: Option<String>,
  accepted_violations: usize,
  remaining_blocking_violations: usize,
}

struct BaselineGateContext {
  report: String,
  schema_version: Option<u32>,
  aggregates: BTreeMap<(String, String), AggregateStats>,
}

enum GateDisposition {
  Blocking {
    reason: String,
    evaluation_mode: String,
    stat_band: Option<StatBandReport>,
    baseline_source: Option<String>,
  },
  Advisory {
    reason: String,
    evaluation_mode: String,
    stat_band: Option<StatBandReport>,
    baseline_source: Option<String>,
  },
}

impl GateDisposition {
  fn blocking(reason: impl Into<String>) -> Self {
    Self::Blocking {
      reason: reason.into(),
      evaluation_mode: "median_baseline".to_owned(),
      stat_band: None,
      baseline_source: None,
    }
  }

  fn threshold_blocking(reason: impl Into<String>) -> Self {
    Self::Blocking {
      reason: reason.into(),
      evaluation_mode: "threshold".to_owned(),
      stat_band: None,
      baseline_source: None,
    }
  }

  fn evidence_blocking(reason: impl Into<String>) -> Self {
    Self::Blocking {
      reason: reason.into(),
      evaluation_mode: "evidence".to_owned(),
      stat_band: None,
      baseline_source: None,
    }
  }

  fn advisory(reason: impl Into<String>) -> Self {
    Self::Advisory {
      reason: reason.into(),
      evaluation_mode: "median_baseline".to_owned(),
      stat_band: None,
      baseline_source: None,
    }
  }

  fn statistical(
    blocking: bool,
    reason: impl Into<String>,
    stat_band: StatBandReport,
    baseline_source: Option<String>,
  ) -> Self {
    let reason = reason.into();
    if blocking {
      Self::Blocking {
        reason,
        evaluation_mode: "statistical_band".to_owned(),
        stat_band: Some(stat_band),
        baseline_source,
      }
    } else {
      Self::Advisory {
        reason,
        evaluation_mode: "statistical_band".to_owned(),
        stat_band: Some(stat_band),
        baseline_source,
      }
    }
  }
}

#[derive(Clone, Serialize)]
struct StatBandReport {
  mode: String,
  status: String,
  baseline_schema_version: Option<u32>,
  baseline_shards: usize,
  current_shards: usize,
  baseline_samples: usize,
  current_samples: usize,
  rps_median_delta_percent: Option<f64>,
  rps_p10_delta_percent: Option<f64>,
  p99_median_delta_percent: Option<f64>,
  p99_p90_delta_percent: Option<f64>,
  rps_median_min_delta_percent: f64,
  rps_p10_min_delta_percent: f64,
  p99_median_max_delta_percent: f64,
  p99_p90_max_delta_percent: f64,
}

#[derive(Serialize)]
struct SampleQuality {
  iteration_status_files: usize,
  ok_iterations: usize,
  diagnostic_warning_iterations: usize,
  failed_iterations: usize,
  diagnostic_warning_samples: Vec<IterationStatusSummary>,
  failed_iteration_samples: Vec<IterationStatusSummary>,
}

#[derive(Serialize)]
struct IterationStatusSummary {
  source_file: String,
  target_cpu: Option<String>,
  serving_type: Option<String>,
  shard: Option<u64>,
  iteration: Option<u64>,
  exit_code: Option<i64>,
  diagnostic_warnings: Option<u64>,
  status: Option<String>,
  reason: Option<String>,
}

#[derive(Deserialize)]
struct IterationStatusFile {
  target_cpu: Option<String>,
  serving_type: Option<String>,
  shard: Option<u64>,
  iteration: Option<u64>,
  exit_code: Option<i64>,
  diagnostic_warnings: Option<u64>,
  status: Option<String>,
  reason: Option<String>,
}

#[derive(Serialize)]
struct QuorumReport {
  status: String,
  policy: String,
  primary_target_cpu: String,
  valid_sample_min_percent: f64,
  shard_min_percent: f64,
  required_sample_count: Option<usize>,
  required_shards: Option<usize>,
  rows: Vec<QuorumRow>,
  warnings: Vec<String>,
  violations: Vec<String>,
}

#[derive(Serialize)]
struct QuorumRow {
  group: String,
  scenario: String,
  comparator: String,
  sample_count: usize,
  shard_count: usize,
  required_sample_count: Option<usize>,
  required_shards: Option<usize>,
  matching_comparator_rows: usize,
  status: String,
  reason: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct BaselineSelectionSource {
  source: Option<String>,
  branch: Option<String>,
  run_id: Option<String>,
  sha: Option<String>,
  artifact_id: Option<String>,
  artifact_name: Option<String>,
  schema_version: Option<u32>,
}

#[derive(Deserialize)]
struct BaselineSelectionFile {
  #[serde(default)]
  fallback_order: Vec<String>,
  #[serde(default)]
  selected: BaselineSelectionSource,
}

#[derive(Serialize)]
struct BaselineContextReport {
  status: String,
  report: Option<String>,
  schema_version: Option<u32>,
  fallback_order: Vec<String>,
  selected: Option<BaselineSelectionSource>,
}

#[derive(Clone, Copy)]
enum GateMetric {
  Rps,
  P99,
}

struct MetricRatioDelta {
  before_ratio: f64,
  after_ratio: f64,
  ratio_delta_percent: f64,
}

#[derive(Clone, Copy)]
struct RegressionGateContext<'a> {
  amd64_target_cpu: &'a str,
  gate: &'a str,
  group: &'a str,
  scenario: &'a str,
  threshold: f64,
}

struct ComparatorRatioGate<'a> {
  gate: &'a str,
  group: ScenarioGroup,
  scenario: &'a str,
  comparator: Comparator,
  threshold: f64,
  allow_baseline_advisory: bool,
  baseline_stable_advisory_policy: Option<BaselineStableRatioAdvisoryPolicy>,
}

#[derive(Clone, Copy)]
struct BaselineStableRatioAdvisoryPolicy {
  near_target_tolerance: f64,
  comparator_shift_tolerance: f64,
}

struct BaselineStableRatioMiss<'a> {
  oxibelt_scenario: &'a str,
  comparator: Comparator,
  comparator_scenario: &'a str,
  threshold: f64,
  policy: BaselineStableRatioAdvisoryPolicy,
  current_ratio: f64,
}

struct P99RatioGate<'a> {
  gate: &'a str,
  monitor_scenario: &'a str,
  enforcing_scenario: &'a str,
  threshold: f64,
}

#[derive(Serialize)]
struct AcceptMultiplierSummary {
  scenario_count: usize,
  valid_comparisons: usize,
  median_ratio: Option<f64>,
  median_percent_of_accept_0_5: Option<f64>,
}

#[derive(Serialize)]
struct RemoteSignerSummary {
  scenario_count: usize,
  valid_comparisons: usize,
  median_throughput_ratio: Option<f64>,
  median_throughput_percent_of_local_key: Option<f64>,
  median_p99_ratio: Option<f64>,
  median_p99_percent_of_local_key: Option<f64>,
}

#[derive(Serialize)]
struct MissingComparatorRow {
  amd64_target_cpu: String,
  group: String,
  scenario: String,
  comparator: String,
  status: String,
  reason: String,
}

#[derive(Serialize)]
struct Amd64IsaComparison {
  scenario: String,
  group: String,
  result_type: Option<String>,
  protocol_or_mode: Option<String>,
  primary_target_cpu: String,
  primary: Option<AggregateStats>,
  variants: Vec<Amd64IsaVariantComparison>,
}

#[derive(Serialize)]
struct Amd64IsaVariantComparison {
  amd64_target_cpu: String,
  target: Option<AggregateStats>,
  rps_ratio_vs_primary: Option<f64>,
  rps_delta_percent_vs_primary: Option<f64>,
  p99_ratio_vs_primary: Option<f64>,
  p99_delta_percent_vs_primary: Option<f64>,
  status: String,
  reason: Option<String>,
  text: String,
}

#[derive(Serialize)]
struct Report {
  schema_version: u32,
  profile: Option<String>,
  primary_target_cpu: String,
  expected_target_cpus: Vec<String>,
  expected_runs: Option<usize>,
  expected_shards: Option<usize>,
  artifact_discovery: ArtifactDiscovery,
  baseline_context: BaselineContextReport,
  sample_quality: SampleQuality,
  quorum: QuorumReport,
  summary: ReportSummary,
  comparisons: ComparisonGroups,
  accept_multiplier_comparisons: Vec<AcceptMultiplierComparison>,
  remote_signer_comparisons: Vec<RemoteSignerComparison>,
  amd64_isa_comparisons: Vec<Amd64IsaComparison>,
  external_benchmarks: Vec<ExternalBenchmarkStats>,
  profiling: Vec<DiagnosticProfileStats>,
  oxibelt_only_results: Vec<AggregateStats>,
  skipped_or_missing_comparator_rows: Vec<MissingComparatorRow>,
  regression_gates: RegressionGateReport,
  aggregates: Vec<AggregateStats>,
  warnings: Vec<String>,
  warnings_omitted: usize,
}

#[derive(Deserialize)]
struct BaselineReport {
  schema_version: Option<u32>,
  aggregates: Vec<AggregateStats>,
}

#[derive(Serialize)]
struct DeltaReport {
  schema_version: u32,
  baseline_report: String,
  summary: DeltaSummary,
  rows: Vec<PerformanceDeltaRow>,
  warnings: Vec<String>,
}

#[derive(Default, Serialize)]
struct DeltaSummary {
  rows: usize,
  oxibelt_regression: usize,
  comparator_shift: usize,
  mixed: usize,
  improvement: usize,
  stable: usize,
  incomplete: usize,
}

#[derive(Serialize)]
struct PerformanceDeltaRow {
  amd64_target_cpu: String,
  group: String,
  scenario: String,
  comparator: String,
  before_oxibelt_rps: Option<f64>,
  after_oxibelt_rps: Option<f64>,
  oxibelt_rps_delta_percent: Option<f64>,
  before_comparator_rps: Option<f64>,
  after_comparator_rps: Option<f64>,
  comparator_rps_delta_percent: Option<f64>,
  before_ratio: Option<f64>,
  after_ratio: Option<f64>,
  ratio_delta_percent: Option<f64>,
  before_oxibelt_p99_ms: Option<f64>,
  after_oxibelt_p99_ms: Option<f64>,
  oxibelt_p99_delta_percent: Option<f64>,
  classification_source: String,
  stat_band: Option<StatBandReport>,
  classification: String,
  reason: String,
}

impl AggregateBuilder {
  fn push(&mut self, row: BenchmarkRow) {
    let source_file = row.source_file.clone();
    let shard_id = shard_id_from_source_file(&source_file);
    if self.amd64_target_cpu.is_empty() {
      self.amd64_target_cpu = row.amd64_target_cpu;
    }
    if self.label.is_empty() {
      self.label = row.label;
    }
    self.comparator = Some(row.comparator);
    self.scenario = row.scenario;
    self.group = row.group;
    merge_text_field(&mut self.result_type, row.result_type);
    merge_text_field(&mut self.protocol_or_mode, row.protocol_or_mode);
    if let Some(rps) = row.rps {
      self.rps_values.push(rps);
      self
        .rps_values_by_shard
        .entry(shard_id.clone())
        .or_default()
        .push(rps);
    }
    if let Some(p50) = row.p50_ms {
      self.p50_values.push(p50);
    }
    if let Some(p90) = row.p90_ms {
      self.p90_values.push(p90);
    }
    if let Some(p95) = row.p95_ms {
      self.p95_values.push(p95);
    }
    if let Some(p99) = row.p99_ms {
      self.p99_values.push(p99);
      self
        .p99_values_by_shard
        .entry(shard_id)
        .or_default()
        .push(p99);
    }
    self.total_errors = self.total_errors.saturating_add(row.errors);
    if row.skipped {
      self.skipped_count = self.skipped_count.saturating_add(1);
      if let Some(reason) = row.reason {
        self.skip_reasons.insert(reason);
      }
    }
    if let Some(fast_path) = row.fast_path_plain_proxy_h1 {
      self.fast_path_plain_proxy_h1.push(fast_path);
    }
    if let Some(fast_path) = row.fast_path_plain_proxy_h2 {
      self.fast_path_plain_proxy_h2.push(fast_path);
    }
    if let Some(fast_path) = row.fast_path_plain_proxy_h3 {
      self.fast_path_plain_proxy_h3.push(fast_path);
    }
    if let Some(fast_path) = row.fast_path_transport_direct_h1_h1 {
      self.fast_path_transport_direct_h1_h1.push(fast_path);
    }
    if let Some(fast_path) = row.fast_path_transport_direct_h1_h2 {
      self.fast_path_transport_direct_h1_h2.push(fast_path);
    }
    if let Some(fast_path) = row.fast_path_transport_direct_h1_h3 {
      self.fast_path_transport_direct_h1_h3.push(fast_path);
    }
    if let Some(fast_path) = row.fast_path_transport_direct_h2_h1 {
      self.fast_path_transport_direct_h2_h1.push(fast_path);
    }
    if let Some(fast_path) = row.fast_path_transport_direct_h2_h2 {
      self.fast_path_transport_direct_h2_h2.push(fast_path);
    }
    if let Some(fast_path) = row.fast_path_transport_direct_h2_h3 {
      self.fast_path_transport_direct_h2_h3.push(fast_path);
    }
    if let Some(events) = row.direct_h1_pool_events {
      self.direct_h1_pool_events.push(events);
    }
    if let Some(events) = row.direct_h2_pool_events {
      self.direct_h2_pool_events.push(events);
    }
    if let Some(responses) = row.static_fast_path_responses {
      self.static_fast_path_responses.push(responses);
    }
    if let Some(stage_timing) = row.fast_path_stage_timing {
      self.fast_path_stage_timing.push(stage_timing);
    }
    self.source_files.insert(source_file);
  }

  fn finish(self) -> AggregateStats {
    let mut rps_values = self.rps_values;
    let mut p50_values = self.p50_values;
    let mut p90_values = self.p90_values;
    let mut p95_values = self.p95_values;
    let mut p99_values = self.p99_values;
    let comparator = self
      .comparator
      .map(Comparator::as_str)
      .unwrap_or("unknown")
      .to_owned();
    let fast_path = aggregate_fast_path_stats(AggregateFastPathInput {
      plain_proxy_h1: self.fast_path_plain_proxy_h1,
      plain_proxy_h2: self.fast_path_plain_proxy_h2,
      plain_proxy_h3: self.fast_path_plain_proxy_h3,
      transport_direct_h1_h1: self.fast_path_transport_direct_h1_h1,
      transport_direct_h1_h2: self.fast_path_transport_direct_h1_h2,
      transport_direct_h1_h3: self.fast_path_transport_direct_h1_h3,
      transport_direct_h2_h1: self.fast_path_transport_direct_h2_h1,
      transport_direct_h2_h2: self.fast_path_transport_direct_h2_h2,
      transport_direct_h2_h3: self.fast_path_transport_direct_h2_h3,
      direct_h1_pool: self.direct_h1_pool_events,
      direct_h2_pool: self.direct_h2_pool_events,
      static_responses: self.static_fast_path_responses,
      stage_timing: self.fast_path_stage_timing,
    });

    AggregateStats {
      amd64_target_cpu: self.amd64_target_cpu,
      label: self.label,
      comparator,
      scenario: self.scenario,
      group: self.group.as_str().to_owned(),
      result_type: self.result_type,
      protocol_or_mode: self.protocol_or_mode,
      sample_count: rps_values.len(),
      median_rps: percentile(&mut rps_values, 50.0),
      min_rps: min_value(&rps_values),
      max_rps: max_value(&rps_values),
      p25_rps: percentile(&mut rps_values, 25.0),
      p75_rps: percentile(&mut rps_values, 75.0),
      median_p50_ms: percentile(&mut p50_values, 50.0),
      median_p90_ms: percentile(&mut p90_values, 50.0),
      median_p95_ms: percentile(&mut p95_values, 50.0),
      median_p99_ms: percentile(&mut p99_values, 50.0),
      total_errors: self.total_errors,
      skipped_count: self.skipped_count,
      skip_reasons: self.skip_reasons.into_iter().collect(),
      source_files: self.source_files.into_iter().collect(),
      distribution: AggregateDistribution {
        sample_count: rps_values.len(),
        shard_count: self.rps_values_by_shard.len(),
        per_shard_median_rps: per_shard_medians(self.rps_values_by_shard),
        per_shard_median_p99_ms: per_shard_medians(self.p99_values_by_shard),
      },
      fast_path,
    }
  }
}

fn aggregate_fast_path_stats(input: AggregateFastPathInput) -> Option<AggregateFastPathStats> {
  let plain_proxy_h1 = input.plain_proxy_h1.finish();
  let plain_proxy_h2 = input.plain_proxy_h2.finish();
  let plain_proxy_h3 = input.plain_proxy_h3.finish();
  let transport_direct_h1_h1 = input.transport_direct_h1_h1.finish();
  let transport_direct_h1_h2 = input.transport_direct_h1_h2.finish();
  let transport_direct_h1_h3 = input.transport_direct_h1_h3.finish();
  let transport_direct_h2_h1 = input.transport_direct_h2_h1.finish();
  let transport_direct_h2_h2 = input.transport_direct_h2_h2.finish();
  let transport_direct_h2_h3 = input.transport_direct_h2_h3.finish();
  let direct_h1_pool = input.direct_h1_pool.finish();
  let direct_h2_pool = input.direct_h2_pool.finish();
  let static_responses = input.static_responses.finish();
  let stage_timing = input.stage_timing.finish();
  if plain_proxy_h1.is_none()
    && plain_proxy_h2.is_none()
    && plain_proxy_h3.is_none()
    && transport_direct_h1_h1.is_none()
    && transport_direct_h1_h2.is_none()
    && transport_direct_h1_h3.is_none()
    && transport_direct_h2_h1.is_none()
    && transport_direct_h2_h2.is_none()
    && transport_direct_h2_h3.is_none()
    && direct_h1_pool.is_none()
    && direct_h2_pool.is_none()
    && static_responses.is_none()
    && stage_timing.is_none()
  {
    return None;
  }
  Some(AggregateFastPathStats {
    plain_proxy_h1,
    plain_proxy_h2,
    plain_proxy_h3,
    transport_direct_h1_h1,
    transport_direct_h1_h2,
    transport_direct_h1_h3,
    transport_direct_h2_h1,
    transport_direct_h2_h2,
    transport_direct_h2_h3,
    direct_h1_pool,
    direct_h2_pool,
    static_responses,
    stage_timing,
  })
}

impl FastPathAggregateBuilder {
  fn push(&mut self, sample: FastPathSample) {
    self.sample_count += 1;
    self.hits = self.hits.saturating_add(sample.hits);
    self.misses = self.misses.saturating_add(sample.misses);
    self.attempts = self.attempts.saturating_add(sample.attempts);
    if let Some(hit_rate) = sample.hit_rate {
      self.hit_rates.push(hit_rate);
    }
  }

  fn finish(self) -> Option<FastPathAggregateStats> {
    if self.sample_count == 0 {
      return None;
    }
    let mut hit_rates = self.hit_rates;
    Some(FastPathAggregateStats {
      sample_count: self.sample_count,
      hits: self.hits,
      misses: self.misses,
      attempts: self.attempts,
      median_hit_rate: percentile(&mut hit_rates, 50.0),
      min_hit_rate: min_value(&hit_rates),
    })
  }
}

impl CounterMapAggregateBuilder {
  fn push(&mut self, values: BTreeMap<String, u64>) {
    self.sample_count += 1;
    for (name, value) in values {
      let entry = self.values.entry(name).or_insert(0);
      *entry = entry.saturating_add(value);
    }
  }

  fn finish(self) -> Option<CounterMapAggregateStats> {
    if self.sample_count == 0 {
      return None;
    }
    Some(CounterMapAggregateStats {
      sample_count: self.sample_count,
      values: self.values,
    })
  }
}

impl NestedCounterMapAggregateBuilder {
  fn push(&mut self, values: BTreeMap<String, BTreeMap<String, u64>>) {
    self.sample_count += 1;
    for (outer, inner_values) in values {
      let inner = self.values.entry(outer).or_default();
      for (name, value) in inner_values {
        let entry = inner.entry(name).or_insert(0);
        *entry = entry.saturating_add(value);
      }
    }
  }

  fn finish(self) -> Option<NestedCounterMapAggregateStats> {
    if self.sample_count == 0 {
      return None;
    }
    Some(NestedCounterMapAggregateStats {
      sample_count: self.sample_count,
      values: self.values,
    })
  }
}

impl FastPathStageTimingAggregateBuilder {
  fn push(&mut self, samples: FastPathStageTimingSamples) {
    for (path, protocols) in samples {
      for (protocol, stages) in protocols {
        for (stage, outcomes) in stages {
          for (outcome, sample) in outcomes {
            self
              .samples
              .entry((path.clone(), protocol.clone(), stage.clone(), outcome))
              .or_default()
              .push(sample);
          }
        }
      }
    }
  }

  fn finish(self) -> Option<FastPathStageTimingAggregateStats> {
    if self.samples.is_empty() {
      return None;
    }
    let mut aggregate = BTreeMap::new();
    for ((path, protocol, stage, outcome), builder) in self.samples {
      aggregate
        .entry(path)
        .or_insert_with(BTreeMap::new)
        .entry(protocol)
        .or_insert_with(BTreeMap::new)
        .entry(stage)
        .or_insert_with(BTreeMap::new)
        .insert(outcome, builder.finish());
    }
    Some(aggregate)
  }
}

impl FastPathStageTimingSampleAggregateBuilder {
  fn push(&mut self, sample: FastPathStageTimingSample) {
    self.sample_count += 1;
    self.count = self.count.saturating_add(sample.count);
    self.total_ns = self.total_ns.saturating_add(sample.total_ns);
    if let Some(avg_ns) = sample.avg_ns {
      self.avg_ns_values.push(avg_ns);
    } else if sample.count > 0 {
      self
        .avg_ns_values
        .push(sample.total_ns as f64 / sample.count as f64);
    }
  }

  fn finish(self) -> FastPathStageTimingAggregateSampleStats {
    let mut avg_ns_values = self.avg_ns_values;
    let max_avg_ns = max_value(&avg_ns_values);
    FastPathStageTimingAggregateSampleStats {
      sample_count: self.sample_count,
      count: self.count,
      total_ns: self.total_ns,
      median_avg_ns: percentile(&mut avg_ns_values, 50.0),
      max_avg_ns,
    }
  }
}

impl ExternalBenchmarkBuilder {
  fn push(&mut self, sample: ExternalBenchmarkSample) {
    if self.amd64_target_cpu.is_empty() {
      self.amd64_target_cpu = sample.amd64_target_cpu;
    }
    if self.serving_type.is_empty() {
      self.serving_type = sample.serving_type;
    }
    if self.tool.is_empty() {
      self.tool = sample.tool;
    }
    if self.comparator.is_empty() {
      self.comparator = sample.comparator;
    }
    if self.scenario.is_empty() {
      self.scenario = sample.scenario;
    }
    if self.protocol.is_empty() {
      self.protocol = sample.protocol;
    }
    self.labels.insert(sample.label);
    match sample.status.as_str() {
      "pass" => self.pass_count += 1,
      "fail" => self.fail_count += 1,
      "skipped" => self.skipped_count += 1,
      _ => self.fail_count += 1,
    }
    if let Some(rps) = sample.rps {
      self.rps_values.push(rps);
    }
    if let Some(p95) = sample.p95_ms {
      self.p95_values.push(p95);
    }
    if let Some(p99) = sample.p99_ms {
      self.p99_values.push(p99);
    }
    if let Some(error_rate) = sample.error_rate {
      self.error_rate_values.push(error_rate);
    }
    if let Some(requests) = sample.requests {
      self.request_values.push(requests);
    }
    if let Some(reason) = sample.reason {
      self.reasons.insert(reason);
    }
    if let Some(output_file) = sample.output_file {
      self.output_files.insert(output_file);
    }
    self.source_files.insert(sample.source_file);
  }

  fn finish(self) -> ExternalBenchmarkStats {
    let mut rps_values = self.rps_values;
    let mut p95_values = self.p95_values;
    let mut p99_values = self.p99_values;
    let mut error_rate_values = self.error_rate_values;
    let total_requests = if self.request_values.is_empty() {
      None
    } else {
      Some(self.request_values.iter().sum())
    };

    ExternalBenchmarkStats {
      amd64_target_cpu: self.amd64_target_cpu,
      serving_type: self.serving_type,
      tool: self.tool,
      comparator: self.comparator,
      scenario: self.scenario,
      protocol: self.protocol,
      sample_count: self.pass_count + self.fail_count + self.skipped_count,
      pass_count: self.pass_count,
      fail_count: self.fail_count,
      skipped_count: self.skipped_count,
      median_rps: percentile(&mut rps_values, 50.0),
      median_p95_ms: percentile(&mut p95_values, 50.0),
      median_p99_ms: percentile(&mut p99_values, 50.0),
      median_error_rate: percentile(&mut error_rate_values, 50.0),
      total_requests,
      labels: self.labels.into_iter().collect(),
      reasons: self.reasons.into_iter().collect(),
      source_files: self.source_files.into_iter().collect(),
      output_files: self.output_files.into_iter().collect(),
      classification: EXTERNAL_CLASSIFICATION_VALIDATION.to_owned(),
      diagnostic_reason: None,
    }
  }
}

impl DiagnosticProfileBuilder {
  fn push(&mut self, sample: DiagnosticProfileSample) {
    if self.amd64_target_cpu.is_empty() {
      self.amd64_target_cpu = sample.amd64_target_cpu;
    }
    if self.serving_type.is_empty() {
      self.serving_type = sample.serving_type;
    }
    if self.comparator.is_empty() {
      self.comparator = sample.comparator;
    }
    if self.scenario.is_empty() {
      self.scenario = sample.scenario;
    }
    if self.protocol.is_empty() {
      self.protocol = sample.protocol;
    }
    if self.profile_mode.is_empty() {
      self.profile_mode = sample.profile_mode;
    }
    self.labels.insert(sample.label);
    match sample.status.as_str() {
      "pass" => self.pass_count += 1,
      "fail" => self.fail_count += 1,
      "skipped" => self.skipped_count += 1,
      _ => self.fail_count += 1,
    }
    if sample.cpu_enabled {
      self.cpu_enabled_count += 1;
    }
    if sample.memory_enabled {
      self.memory_enabled_count += 1;
    }
    if let Some(reason) = sample.reason {
      self.reasons.insert(reason);
    }
    for artifact in [
      sample.perf_data,
      sample.perf_report,
      sample.perf_script,
      sample.flamegraph,
      sample.cpu_metadata,
      sample.resource,
      sample.memory_metadata,
      sample.heap_dir,
    ]
    .into_iter()
    .flatten()
    {
      self.artifact_files.insert(artifact);
    }
    self.source_files.insert(sample.source_file);
  }

  fn finish(self) -> DiagnosticProfileStats {
    DiagnosticProfileStats {
      amd64_target_cpu: self.amd64_target_cpu,
      serving_type: self.serving_type,
      diagnostic_group: comparator_neutral_scenario(&self.comparator, &self.scenario),
      comparator: self.comparator,
      scenario: self.scenario,
      protocol: self.protocol,
      profile_mode: self.profile_mode,
      sample_count: self.pass_count + self.fail_count + self.skipped_count,
      pass_count: self.pass_count,
      fail_count: self.fail_count,
      skipped_count: self.skipped_count,
      cpu_enabled_count: self.cpu_enabled_count,
      memory_enabled_count: self.memory_enabled_count,
      labels: self.labels.into_iter().collect(),
      reasons: self.reasons.into_iter().collect(),
      source_files: self.source_files.into_iter().collect(),
      artifact_files: self.artifact_files.into_iter().collect(),
      classification: PROFILE_CLASSIFICATION_VALIDATION.to_owned(),
      diagnostic_reason: None,
    }
  }
}

fn classify_external_benchmark_diagnostics(rows: &mut [ExternalBenchmarkStats]) {
  let mut groups: BTreeMap<(String, String, String, String, String), BTreeSet<String>> =
    BTreeMap::new();
  for row in rows
    .iter()
    .filter(|row| external_h2load_h3_zero_request(row))
  {
    groups
      .entry((
        row.amd64_target_cpu.clone(),
        row.serving_type.clone(),
        row.tool.clone(),
        row.scenario.clone(),
        row.protocol.clone(),
      ))
      .or_default()
      .insert(row.comparator.clone());
  }

  let diagnostic_groups = groups
    .into_iter()
    .filter_map(|(group, comparators)| {
      if has_all_cross_comparators(&comparators) {
        Some(group)
      } else {
        None
      }
    })
    .collect::<BTreeSet<_>>();

  for row in rows
    .iter_mut()
    .filter(|row| external_h2load_h3_zero_request(row))
  {
    let group = (
      row.amd64_target_cpu.clone(),
      row.serving_type.clone(),
      row.tool.clone(),
      row.scenario.clone(),
      row.protocol.clone(),
    );
    if diagnostic_groups.contains(&group) {
      row.classification = EXTERNAL_CLASSIFICATION_INFRA_DIAGNOSTIC.to_owned();
      row.diagnostic_reason = Some(
                "h2load h3 produced zero completed requests for oxibelt, nginx, and caddy; external benchmark comparator group is invalid in this environment"
                    .to_owned(),
            );
    }
  }
}

fn external_h2load_h3_zero_request(row: &ExternalBenchmarkStats) -> bool {
  row.tool == "h2load"
    && row.protocol == "h3"
    && row.fail_count > 0
    && row.sample_count == row.fail_count
    && row
      .reasons
      .iter()
      .any(|reason| reason == H2LOAD_ZERO_COMPLETED_REQUESTS)
    && row.total_requests.unwrap_or(0.0) == 0.0
}

fn classify_diagnostic_profile_environment_failures(rows: &mut [DiagnosticProfileStats]) {
  let mut groups: BTreeMap<(String, String, String, String, String), BTreeSet<String>> =
    BTreeMap::new();
  for row in rows.iter().filter(|row| diagnostic_profile_perf_255(row)) {
    groups
      .entry((
        row.amd64_target_cpu.clone(),
        row.serving_type.clone(),
        row.diagnostic_group.clone(),
        row.protocol.clone(),
        row.profile_mode.clone(),
      ))
      .or_default()
      .insert(row.comparator.clone());
  }

  let diagnostic_groups = groups
    .into_iter()
    .filter_map(|(group, comparators)| {
      if has_all_cross_comparators(&comparators) {
        Some(group)
      } else {
        None
      }
    })
    .collect::<BTreeSet<_>>();

  for row in rows
    .iter_mut()
    .filter(|row| diagnostic_profile_perf_255(row))
  {
    let group = (
      row.amd64_target_cpu.clone(),
      row.serving_type.clone(),
      row.diagnostic_group.clone(),
      row.protocol.clone(),
      row.profile_mode.clone(),
    );
    if diagnostic_groups.contains(&group) {
      row.classification = PROFILE_CLASSIFICATION_ENV_UNAVAILABLE.to_owned();
      row.diagnostic_reason = Some(
                "perf record failed with status 255 for oxibelt, nginx, and caddy; diagnostic profiling is unavailable in this environment"
                    .to_owned(),
            );
    }
  }
}

fn diagnostic_profile_perf_255(row: &DiagnosticProfileStats) -> bool {
  row.fail_count > 0
    && row.sample_count == row.fail_count
    && row
      .reasons
      .iter()
      .any(|reason| reason == PERF_RECORD_STATUS_255)
}

fn has_all_cross_comparators(comparators: &BTreeSet<String>) -> bool {
  ["oxibelt", "nginx", "caddy"]
    .iter()
    .all(|comparator| comparators.contains(*comparator))
}

fn main() -> Result<()> {
  let args = Args::parse();
  let report = aggregate(
    &args.input_dir,
    AggregateOptions {
      profile: args.profile.clone(),
      expected_runs: args.expected_runs,
      expected_shards: args.expected_shards,
      expected_target_cpus: args.expected_target_cpus.clone(),
      primary_target_cpu: args.primary_target_cpu.clone(),
      baseline_report: args.baseline_report.as_deref(),
      baseline_context: args.baseline_context.as_deref(),
      accepted_regression_reason: args.accepted_regression_reason.as_deref(),
    },
  );
  fs::create_dir_all(&args.output_dir)?;
  fs::write(
    args.output_dir.join("performance-comparison.json"),
    serde_json::to_string_pretty(&report)?,
  )?;
  fs::write(
    args.output_dir.join("performance-comparison.md"),
    render_markdown(&report),
  )?;
  if let Some(baseline_report) = args.baseline_report.as_deref() {
    let delta = build_delta_report(baseline_report, &report);
    fs::write(
      args.output_dir.join("performance-delta.json"),
      serde_json::to_string_pretty(&delta)?,
    )?;
    fs::write(
      args.output_dir.join("performance-delta.md"),
      render_delta_markdown(&delta),
    )?;
  }
  Ok(())
}

fn aggregate(input_dir: &Path, options: AggregateOptions<'_>) -> Report {
  let AggregateOptions {
    profile,
    expected_runs,
    expected_shards,
    expected_target_cpus,
    primary_target_cpu,
    baseline_report,
    baseline_context,
    accepted_regression_reason,
  } = options;
  let mut warnings = WarningBag::default();
  let expected_target_cpus = normalize_expected_target_cpus(expected_target_cpus, &mut warnings);
  let primary_target_cpu = normalize_primary_target_cpu(primary_target_cpu, &mut warnings);
  let regression_gate_thresholds = regression_gate_thresholds(&mut warnings);
  let baseline_gate_context =
    load_baseline_gate_context(baseline_report, &primary_target_cpu, &mut warnings);
  let baseline_context_report = load_baseline_context_report(
    baseline_report,
    baseline_context,
    baseline_gate_context.as_ref(),
    &mut warnings,
  );
  let discovered = discover_files(input_dir, &mut warnings);
  let sample_quality =
    build_sample_quality(input_dir, &discovered.iteration_statuses, &mut warnings);
  let unsupported_artifact_dirs = unsupported_artifact_dirs(&discovered.unsupported_cpu_markers);
  let results = discovered
    .results
    .iter()
    .filter(|path| {
      !unsupported_artifact_dirs
        .iter()
        .any(|unsupported_dir| path.starts_with(unsupported_dir))
    })
    .collect::<Vec<_>>();
  let external_results = discovered
    .external_results
    .iter()
    .filter(|path| {
      !unsupported_artifact_dirs
        .iter()
        .any(|unsupported_dir| path.starts_with(unsupported_dir))
    })
    .collect::<Vec<_>>();
  let profile_results = discovered
    .profile_results
    .iter()
    .filter(|path| {
      !unsupported_artifact_dirs
        .iter()
        .any(|unsupported_dir| path.starts_with(unsupported_dir))
    })
    .collect::<Vec<_>>();
  let mut artifact_discovery = ArtifactDiscovery {
    results_files: results.len(),
    external_results_files: external_results.len(),
    profile_results_files: profile_results.len(),
    summary_files: discovered.summary_count,
    docker_stats_files: discovered.docker_stats_count,
    iteration_status_files: discovered.iteration_statuses.len(),
    expected_results_files: None,
    missing_expected_paths: Vec::new(),
    unsupported_cpu: unsupported_cpu_discovery(
      input_dir,
      profile.as_deref(),
      &discovered.unsupported_cpu_markers,
    ),
  };

  add_expected_artifact_warnings(
    input_dir,
    profile.as_deref(),
    expected_runs,
    expected_shards,
    &expected_target_cpus,
    &mut artifact_discovery,
    &mut warnings,
  );
  if results.is_empty() {
    if artifact_discovery.unsupported_cpu.count > 0 {
      warnings.push(
                "no supported results.json files were discovered; only unsupported CPU marker artifacts were found",
            );
    } else {
      warnings.push("no results.json files were discovered");
    }
  }

  let mut builders: BTreeMap<(String, Comparator, String), AggregateBuilder> = BTreeMap::new();
  for results_path in results {
    for row in parse_results_file(input_dir, results_path, &mut warnings) {
      builders
        .entry((
          row.amd64_target_cpu.clone(),
          row.comparator,
          row.scenario.clone(),
        ))
        .or_default()
        .push(row);
    }
  }

  let mut aggregate_map = BTreeMap::new();
  for (key, builder) in builders {
    aggregate_map.insert(key, builder.finish());
  }

  let mut external_builders: BTreeMap<
    (String, String, String, String, String, String),
    ExternalBenchmarkBuilder,
  > = BTreeMap::new();
  for external_results_path in external_results {
    for sample in parse_external_results_file(input_dir, external_results_path, &mut warnings) {
      external_builders
        .entry((
          sample.amd64_target_cpu.clone(),
          sample.serving_type.clone(),
          sample.tool.clone(),
          sample.comparator.clone(),
          sample.scenario.clone(),
          sample.protocol.clone(),
        ))
        .or_default()
        .push(sample);
    }
  }
  let mut external_benchmarks = external_builders
    .into_values()
    .map(ExternalBenchmarkBuilder::finish)
    .collect::<Vec<_>>();
  classify_external_benchmark_diagnostics(&mut external_benchmarks);

  let mut profile_builders: BTreeMap<
    (String, String, String, String, String, String),
    DiagnosticProfileBuilder,
  > = BTreeMap::new();
  for profile_results_path in profile_results {
    for sample in parse_profile_results_file(input_dir, profile_results_path, &mut warnings) {
      profile_builders
        .entry((
          sample.amd64_target_cpu.clone(),
          sample.serving_type.clone(),
          sample.comparator.clone(),
          sample.scenario.clone(),
          sample.protocol.clone(),
          sample.profile_mode.clone(),
        ))
        .or_default()
        .push(sample);
    }
  }
  let mut profiling = profile_builders
    .into_values()
    .map(DiagnosticProfileBuilder::finish)
    .collect::<Vec<_>>();
  classify_diagnostic_profile_environment_failures(&mut profiling);

  let reverse_proxy = build_group_comparisons(ScenarioGroup::ReverseProxy, &aggregate_map);
  let static_files = build_group_comparisons(ScenarioGroup::StaticFiles, &aggregate_map);
  let accept_multiplier_comparisons = build_accept_multiplier_comparisons(&aggregate_map);
  let remote_signer_comparisons = build_remote_signer_comparisons(&aggregate_map);
  let primary_reverse_proxy = primary_scenario_comparisons(&reverse_proxy, &primary_target_cpu);
  let primary_static_files = primary_scenario_comparisons(&static_files, &primary_target_cpu);
  let primary_accept_multiplier_comparisons =
    primary_accept_multiplier_comparisons(&accept_multiplier_comparisons, &primary_target_cpu);
  let primary_remote_signer_comparisons =
    primary_remote_signer_comparisons(&remote_signer_comparisons, &primary_target_cpu);
  let primary_aggregates = primary_aggregate_map(&aggregate_map, &primary_target_cpu);
  let quorum = build_quorum_report(
    &primary_aggregates,
    expected_runs,
    expected_shards,
    &primary_target_cpu,
  );
  let regression_gates = build_regression_gate_report(
    &primary_aggregates,
    regression_gate_thresholds,
    baseline_gate_context.as_ref(),
    &primary_target_cpu,
    normalize_accepted_regression_reason(accepted_regression_reason, &mut warnings).as_deref(),
  );
  let amd64_isa_comparisons =
    build_amd64_isa_comparisons(&aggregate_map, &expected_target_cpus, &primary_target_cpu);
  let oxibelt_only_results = aggregate_map
    .iter()
    .filter(|((_, comparator, _), aggregate)| {
      *comparator == Comparator::Oxibelt && aggregate.group == ScenarioGroup::OxibeltOnly.as_str()
    })
    .map(|(_, aggregate)| aggregate.clone())
    .collect::<Vec<_>>();
  let skipped_or_missing_comparator_rows = skipped_or_missing_rows(&reverse_proxy, &static_files);
  let aggregates = aggregate_map.into_values().collect::<Vec<_>>();
  let summary = ReportSummary {
    reverse_proxy: summarize_group(&primary_reverse_proxy),
    static_files: summarize_group(&primary_static_files),
    accept_multipliers: summarize_accept_multiplier_comparisons(
      &primary_accept_multiplier_comparisons,
    ),
    remote_signer: summarize_remote_signer_comparisons(&primary_remote_signer_comparisons),
    external_benchmark_row_count: external_benchmarks
      .iter()
      .filter(|row| row.amd64_target_cpu == primary_target_cpu)
      .count(),
    diagnostic_profile_row_count: profiling
      .iter()
      .filter(|row| row.amd64_target_cpu == primary_target_cpu)
      .count(),
    oxibelt_only_row_count: oxibelt_only_results
      .iter()
      .filter(|row| row.amd64_target_cpu == primary_target_cpu)
      .count(),
  };
  let (warnings, warnings_omitted) = warnings.finish();

  Report {
    schema_version: COMPARISON_SCHEMA_VERSION,
    profile,
    primary_target_cpu,
    expected_target_cpus,
    expected_runs,
    expected_shards,
    artifact_discovery,
    baseline_context: baseline_context_report,
    sample_quality,
    quorum,
    summary,
    comparisons: ComparisonGroups {
      reverse_proxy,
      static_files,
    },
    accept_multiplier_comparisons,
    remote_signer_comparisons,
    amd64_isa_comparisons,
    external_benchmarks,
    profiling,
    oxibelt_only_results,
    skipped_or_missing_comparator_rows,
    regression_gates,
    aggregates,
    warnings,
    warnings_omitted,
  }
}

fn default_amd64_target_cpu() -> String {
  DEFAULT_AMD64_TARGET_CPU.to_owned()
}

fn normalize_expected_target_cpus(
  expected_target_cpus: Vec<String>,
  warnings: &mut WarningBag,
) -> Vec<String> {
  let mut normalized = Vec::new();
  for target in expected_target_cpus {
    let target = target.trim();
    if target.is_empty() {
      continue;
    }
    if !is_known_amd64_target_cpu(target) {
      warnings.push(format!(
        "ignoring unknown expected AMD64 target CPU: {target}"
      ));
      continue;
    }
    if !normalized.iter().any(|existing| existing == target) {
      normalized.push(target.to_owned());
    }
  }
  normalized
}

fn normalize_primary_target_cpu(primary_target_cpu: String, warnings: &mut WarningBag) -> String {
  let target = primary_target_cpu.trim();
  if is_known_amd64_target_cpu(target) {
    target.to_owned()
  } else {
    warnings.push(format!(
      "unknown primary AMD64 target CPU {primary_target_cpu:?}; using {DEFAULT_AMD64_TARGET_CPU}"
    ));
    DEFAULT_AMD64_TARGET_CPU.to_owned()
  }
}

fn is_known_amd64_target_cpu(target: &str) -> bool {
  AMD64_TARGET_CPUS.contains(&target)
}

fn primary_aggregate_map(
  aggregates: &AggregateMap,
  primary_target_cpu: &str,
) -> PrimaryAggregateMap {
  aggregates
    .iter()
    .filter(|((target, _, _), _)| target == primary_target_cpu)
    .map(|((_, comparator, scenario), aggregate)| {
      ((*comparator, scenario.clone()), aggregate.clone())
    })
    .collect()
}

fn primary_scenario_comparisons(
  comparisons: &[ScenarioComparison],
  primary_target_cpu: &str,
) -> Vec<ScenarioComparison> {
  comparisons
    .iter()
    .filter(|comparison| comparison.amd64_target_cpu == primary_target_cpu)
    .cloned()
    .collect()
}

fn primary_accept_multiplier_comparisons(
  comparisons: &[AcceptMultiplierComparison],
  primary_target_cpu: &str,
) -> Vec<AcceptMultiplierComparison> {
  comparisons
    .iter()
    .filter(|comparison| comparison.amd64_target_cpu == primary_target_cpu)
    .cloned()
    .collect()
}

fn primary_remote_signer_comparisons(
  comparisons: &[RemoteSignerComparison],
  primary_target_cpu: &str,
) -> Vec<RemoteSignerComparison> {
  comparisons
    .iter()
    .filter(|comparison| comparison.amd64_target_cpu == primary_target_cpu)
    .cloned()
    .collect()
}

fn load_baseline_gate_context(
  baseline_report: Option<&Path>,
  primary_target_cpu: &str,
  warnings: &mut WarningBag,
) -> Option<BaselineGateContext> {
  let Some(path) = baseline_report else {
    warnings.push(
            "baseline performance report was not provided; baseline-aware regression gate classification is unavailable",
        );
    return None;
  };
  let label = path.display().to_string();
  let baseline = match fs::read_to_string(path)
    .map_err(|error| error.to_string())
    .and_then(|raw| serde_json::from_str::<BaselineReport>(&raw).map_err(|error| error.to_string()))
  {
    Ok(report) => report,
    Err(error) => {
      warnings.push(format!(
                "failed to read baseline performance report for regression gates: {error}; baseline-aware regression gate classification is unavailable"
            ));
      return None;
    }
  };
  let aggregates = baseline
    .aggregates
    .into_iter()
    .filter(|aggregate| aggregate.amd64_target_cpu == primary_target_cpu)
    .map(|aggregate| {
      (
        (aggregate.comparator.clone(), aggregate.scenario.clone()),
        aggregate,
      )
    })
    .collect();
  Some(BaselineGateContext {
    report: label,
    schema_version: baseline.schema_version,
    aggregates,
  })
}

fn load_baseline_context_report(
  baseline_report: Option<&Path>,
  baseline_context: Option<&Path>,
  loaded_baseline: Option<&BaselineGateContext>,
  warnings: &mut WarningBag,
) -> BaselineContextReport {
  let mut fallback_order = Vec::new();
  let mut selected = None;
  if let Some(path) = baseline_context {
    match fs::read_to_string(path)
            .map_err(|error| error.to_string())
            .and_then(|raw| {
                serde_json::from_str::<BaselineSelectionFile>(&raw)
                    .map_err(|error| error.to_string())
            }) {
            Ok(context) => {
                fallback_order = context.fallback_order;
                selected = Some(context.selected);
            }
            Err(error) => warnings.push(format!(
                "failed to read baseline context metadata: {error}; selected baseline source metadata is unavailable"
            )),
        }
  }

  match (baseline_report, loaded_baseline) {
    (Some(path), Some(context)) => BaselineContextReport {
      status: "loaded".to_owned(),
      report: Some(path.display().to_string()),
      schema_version: context.schema_version,
      fallback_order,
      selected,
    },
    (Some(path), None) => BaselineContextReport {
      status: "unreadable".to_owned(),
      report: Some(path.display().to_string()),
      schema_version: None,
      fallback_order,
      selected,
    },
    (None, _) => BaselineContextReport {
      status: "unavailable".to_owned(),
      report: None,
      schema_version: None,
      fallback_order,
      selected,
    },
  }
}

fn discover_files(input_dir: &Path, warnings: &mut WarningBag) -> DiscoveredFiles {
  let mut discovered = DiscoveredFiles {
    results: Vec::new(),
    external_results: Vec::new(),
    profile_results: Vec::new(),
    summary_count: 0,
    docker_stats_count: 0,
    iteration_statuses: Vec::new(),
    unsupported_cpu_markers: Vec::new(),
  };

  if !input_dir.exists() {
    warnings.push(format!(
      "input directory does not exist: {}",
      input_dir.display()
    ));
    return discovered;
  }

  let mut stack = vec![input_dir.to_path_buf()];
  while let Some(dir) = stack.pop() {
    let entries = match fs::read_dir(&dir) {
      Ok(entries) => entries,
      Err(error) => {
        warnings.push(format!("failed to read {}: {error}", dir.display()));
        continue;
      }
    };

    for entry in entries {
      let entry = match entry {
        Ok(entry) => entry,
        Err(error) => {
          warnings.push(format!("failed to read directory entry: {error}"));
          continue;
        }
      };
      let file_type = match entry.file_type() {
        Ok(file_type) => file_type,
        Err(error) => {
          warnings.push(format!(
            "failed to inspect {}: {error}",
            entry.path().display()
          ));
          continue;
        }
      };
      if file_type.is_dir() {
        stack.push(entry.path());
        continue;
      }
      if !file_type.is_file() {
        continue;
      }

      match entry.file_name().to_string_lossy().as_ref() {
        "results.json" => discovered.results.push(entry.path()),
        "external-results.json" => discovered.external_results.push(entry.path()),
        "profile-results.json" => discovered.profile_results.push(entry.path()),
        "summary.md" => discovered.summary_count += 1,
        "docker-stats.jsonl" => discovered.docker_stats_count += 1,
        "iteration-status.json" => discovered.iteration_statuses.push(entry.path()),
        "unsupported-cpu.json" => discovered.unsupported_cpu_markers.push(entry.path()),
        _ => {}
      }
    }
  }

  discovered.results.sort();
  discovered.external_results.sort();
  discovered.profile_results.sort();
  discovered.iteration_statuses.sort();
  discovered.unsupported_cpu_markers.sort();
  discovered
}

fn build_sample_quality(
  input_dir: &Path,
  iteration_statuses: &[PathBuf],
  warnings: &mut WarningBag,
) -> SampleQuality {
  let mut quality = SampleQuality {
    iteration_status_files: iteration_statuses.len(),
    ok_iterations: 0,
    diagnostic_warning_iterations: 0,
    failed_iterations: 0,
    diagnostic_warning_samples: Vec::new(),
    failed_iteration_samples: Vec::new(),
  };

  for path in iteration_statuses {
    let rel_path = display_path(input_dir, path);
    let raw = match fs::read_to_string(path) {
      Ok(raw) => raw,
      Err(error) => {
        warnings.push(format!("failed to read {rel_path}: {error}"));
        quality.failed_iterations += 1;
        quality
          .failed_iteration_samples
          .push(IterationStatusSummary {
            source_file: rel_path,
            target_cpu: None,
            serving_type: None,
            shard: None,
            iteration: None,
            exit_code: None,
            diagnostic_warnings: None,
            status: Some("unreadable".to_owned()),
            reason: Some(error.to_string()),
          });
        continue;
      }
    };
    let status = match serde_json::from_str::<IterationStatusFile>(&raw) {
      Ok(status) => status,
      Err(error) => {
        warnings.push(format!("failed to parse {rel_path}: {error}"));
        quality.failed_iterations += 1;
        quality
          .failed_iteration_samples
          .push(IterationStatusSummary {
            source_file: rel_path,
            target_cpu: None,
            serving_type: None,
            shard: None,
            iteration: None,
            exit_code: None,
            diagnostic_warnings: None,
            status: Some("invalid".to_owned()),
            reason: Some(error.to_string()),
          });
        continue;
      }
    };
    let ok = matches!(
      status.status.as_deref(),
      Some("ok") | Some("diagnostic_warning")
    ) && status.exit_code == Some(0);
    if ok {
      quality.ok_iterations += 1;
      if status.status.as_deref() == Some("diagnostic_warning") {
        quality.diagnostic_warning_iterations += 1;
        quality
          .diagnostic_warning_samples
          .push(IterationStatusSummary {
            source_file: rel_path,
            target_cpu: status.target_cpu,
            serving_type: status.serving_type,
            shard: status.shard,
            iteration: status.iteration,
            exit_code: status.exit_code,
            diagnostic_warnings: status.diagnostic_warnings,
            status: status.status,
            reason: status.reason,
          });
      }
      continue;
    }
    quality.failed_iterations += 1;
    quality
      .failed_iteration_samples
      .push(IterationStatusSummary {
        source_file: rel_path,
        target_cpu: status.target_cpu,
        serving_type: status.serving_type,
        shard: status.shard,
        iteration: status.iteration,
        exit_code: status.exit_code,
        diagnostic_warnings: status.diagnostic_warnings,
        status: status.status,
        reason: status.reason,
      });
  }

  quality
}

fn unsupported_cpu_discovery(
  input_dir: &Path,
  profile: Option<&str>,
  markers: &[PathBuf],
) -> UnsupportedCpuDiscovery {
  let mut marker_paths = Vec::new();
  let mut shards = BTreeSet::new();

  for marker in markers {
    marker_paths.push(display_path(input_dir, marker));
    if let Some(shard) = unsupported_shard_id(input_dir, profile, marker) {
      shards.insert(shard);
    }
  }

  UnsupportedCpuDiscovery {
    count: markers.len(),
    markers: marker_paths,
    shards: shards.into_iter().collect(),
  }
}

fn unsupported_artifact_dirs(markers: &[PathBuf]) -> BTreeSet<PathBuf> {
  markers
    .iter()
    .filter_map(|marker| marker.parent().map(Path::to_path_buf))
    .collect()
}

fn unsupported_shard_id(input_dir: &Path, profile: Option<&str>, marker: &Path) -> Option<String> {
  let mut components = marker.strip_prefix(input_dir).ok()?.components();
  let artifact_name = components.next()?;
  let artifact_name = artifact_name.as_os_str().to_string_lossy();
  let artifact_name = artifact_name.as_ref();
  let target_cpu = components.next().and_then(|component| {
    let component = component.as_os_str().to_string_lossy();
    is_known_amd64_target_cpu(component.as_ref()).then(|| component.to_string())
  });

  let remainder = if let Some(profile) = profile {
    let prefix = format!("oxibelt-docker-performance-{profile}-");
    artifact_name.strip_prefix(&prefix)?
  } else {
    artifact_name
  };
  let (serving_type, shard) = remainder.rsplit_once("-shard-")?;
  Some(match target_cpu {
    Some(target_cpu) => format!("{serving_type}/shard-{shard}/{target_cpu}"),
    None => format!("{serving_type}/shard-{shard}"),
  })
}

fn add_expected_artifact_warnings(
  input_dir: &Path,
  profile: Option<&str>,
  expected_runs: Option<usize>,
  expected_shards: Option<usize>,
  expected_target_cpus: &[String],
  artifact_discovery: &mut ArtifactDiscovery,
  warnings: &mut WarningBag,
) {
  let Some(profile) = profile else {
    if expected_runs.is_some() {
      warnings
        .push("--expected-runs was provided without --profile; skipping expected artifact checks");
    }
    return;
  };
  let Some(expected_runs) = expected_runs else {
    return;
  };
  let expected_shards = expected_shards.unwrap_or(5);
  if expected_shards == 0 {
    warnings.push("--expected-shards was 0; skipping expected artifact checks");
    return;
  }

  let mut expected_results_files = 0;
  for serving_type in SERVING_TYPES {
    for shard in 1..=expected_shards {
      let artifact_name =
        format!("oxibelt-docker-performance-{profile}-{serving_type}-shard-{shard}");
      let artifact_dir = input_dir.join(&artifact_name);
      if expected_target_cpus.is_empty() {
        if artifact_dir.join("unsupported-cpu.json").exists() {
          continue;
        }
        expected_results_files += expected_runs;
        if !artifact_dir.exists() {
          artifact_discovery
            .missing_expected_paths
            .push(artifact_name.clone());
          warnings.push(format!(
            "missing expected artifact directory: {artifact_name}"
          ));
          continue;
        }
        for run in 1..=expected_runs {
          let expected = artifact_dir.join(format!("run-{run}/results.json"));
          if !expected.exists() {
            let missing = format!("{artifact_name}/run-{run}/results.json");
            artifact_discovery
              .missing_expected_paths
              .push(missing.clone());
            warnings.push(format!("missing expected results file: {missing}"));
          }
        }
        continue;
      }

      if artifact_dir.join("unsupported-cpu.json").exists() {
        continue;
      }
      for target in expected_target_cpus {
        let target_dir = artifact_dir.join(target);
        if target_dir.join("unsupported-cpu.json").exists() {
          continue;
        }
        expected_results_files += expected_runs;
        if !target_dir.exists() {
          let missing = format!("{artifact_name}/{target}");
          artifact_discovery
            .missing_expected_paths
            .push(missing.clone());
          warnings.push(format!("missing expected artifact directory: {missing}"));
          continue;
        }
        for run in 1..=expected_runs {
          let expected = target_dir.join(format!("run-{run}/results.json"));
          if !expected.exists() {
            let missing = format!("{artifact_name}/{target}/run-{run}/results.json");
            artifact_discovery
              .missing_expected_paths
              .push(missing.clone());
            warnings.push(format!("missing expected results file: {missing}"));
          }
        }
      }
    }
  }
  artifact_discovery.expected_results_files = Some(expected_results_files);
}

#[derive(Clone, Copy)]
struct RequiredQuorumRow {
  group: ScenarioGroup,
  scenario: &'static str,
  comparator: Comparator,
  matching_comparator_rows: usize,
}

fn build_quorum_report(
  aggregates: &PrimaryAggregateMap,
  expected_runs: Option<usize>,
  expected_shards: Option<usize>,
  primary_target_cpu: &str,
) -> QuorumReport {
  let required_sample_count = match (expected_runs, expected_shards) {
    (Some(runs), Some(shards)) => {
      Some(((runs * shards) as f64 * QUORUM_VALID_SAMPLE_PERCENT).ceil() as usize)
    }
    _ => None,
  };
  let required_shards =
    expected_shards.map(|shards| ((shards as f64) * QUORUM_SHARD_PERCENT).ceil() as usize);
  let required_rows = required_quorum_rows();
  let mut rows = Vec::new();
  let mut warnings = Vec::new();
  let mut violations = Vec::new();

  for row in required_rows {
    let aggregate = aggregates.get(&(row.comparator, row.scenario.to_owned()));
    let sample_count = aggregate.map_or(0, |aggregate| aggregate.sample_count);
    let shard_count = aggregate.map_or(0, aggregate_shard_count);
    let mut row_violations = Vec::new();
    if aggregate.is_none() {
      row_violations.push(format!(
        "missing primary {primary_target_cpu} {} {} row",
        row.comparator.as_str(),
        row.scenario
      ));
    }
    if let Some(required) = required_sample_count {
      if sample_count < required {
        row_violations.push(format!("valid samples {sample_count} < quorum {required}"));
      }
    } else if sample_count == 0 {
      row_violations.push("valid samples 0 < quorum 1".to_owned());
    }
    if let Some(required) = required_shards {
      if shard_count < required {
        row_violations.push(format!("valid shards {shard_count} < quorum {required}"));
      }
    } else if shard_count == 0 {
      row_violations.push("valid shards 0 < quorum 1".to_owned());
    }

    let status;
    let reason;
    if row_violations.is_empty() {
      status = "pass".to_owned();
      reason = "quorum satisfied".to_owned();
    } else {
      status = "insufficient_evidence".to_owned();
      reason = row_violations.join("; ");
      violations.push(format!(
        "{} {} {}: {reason}",
        row.group.as_str(),
        row.scenario,
        row.comparator.as_str()
      ));
    }

    rows.push(QuorumRow {
      group: row.group.as_str().to_owned(),
      scenario: row.scenario.to_owned(),
      comparator: row.comparator.as_str().to_owned(),
      sample_count,
      shard_count,
      required_sample_count,
      required_shards,
      matching_comparator_rows: row.matching_comparator_rows,
      status,
      reason,
    });
  }

  if violations.is_empty() {
    warnings.push(
            "missing expected artifact paths are treated as warning evidence when required primary rows satisfy quorum"
                .to_owned(),
        );
  }

  QuorumReport {
    status: if violations.is_empty() {
      "pass".to_owned()
    } else {
      "fail".to_owned()
    },
    policy: "evidence_quorum".to_owned(),
    primary_target_cpu: primary_target_cpu.to_owned(),
    valid_sample_min_percent: QUORUM_VALID_SAMPLE_PERCENT,
    shard_min_percent: QUORUM_SHARD_PERCENT,
    required_sample_count,
    required_shards,
    rows,
    warnings,
    violations,
  }
}

fn required_quorum_rows() -> Vec<RequiredQuorumRow> {
  vec![
    RequiredQuorumRow {
      group: ScenarioGroup::ReverseProxy,
      scenario: "h1-keepalive",
      comparator: Comparator::Oxibelt,
      matching_comparator_rows: 1,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::ReverseProxy,
      scenario: "h1-keepalive",
      comparator: Comparator::Nginx,
      matching_comparator_rows: 1,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::ReverseProxy,
      scenario: "h2",
      comparator: Comparator::Oxibelt,
      matching_comparator_rows: 1,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::ReverseProxy,
      scenario: "h2",
      comparator: Comparator::Nginx,
      matching_comparator_rows: 1,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::ReverseProxy,
      scenario: "h3",
      comparator: Comparator::Oxibelt,
      matching_comparator_rows: 1,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::ReverseProxy,
      scenario: "h3",
      comparator: Comparator::Nginx,
      matching_comparator_rows: 1,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::StaticFiles,
      scenario: "static-16k-h1c",
      comparator: Comparator::Oxibelt,
      matching_comparator_rows: 2,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::StaticFiles,
      scenario: "static-16k-h1c",
      comparator: Comparator::Nginx,
      matching_comparator_rows: 2,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::StaticFiles,
      scenario: "static-16k-h1c",
      comparator: Comparator::Caddy,
      matching_comparator_rows: 2,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::RemoteSigner,
      scenario: "local-key-tls-handshake-h2",
      comparator: Comparator::Oxibelt,
      matching_comparator_rows: 1,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::RemoteSigner,
      scenario: "remote-signer-tls-handshake-h2",
      comparator: Comparator::Oxibelt,
      matching_comparator_rows: 1,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::OxibeltOnly,
      scenario: "waf-monitor",
      comparator: Comparator::Oxibelt,
      matching_comparator_rows: 1,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::OxibeltOnly,
      scenario: "waf-enforcing",
      comparator: Comparator::Oxibelt,
      matching_comparator_rows: 1,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::OxibeltOnly,
      scenario: "crs-monitor",
      comparator: Comparator::Oxibelt,
      matching_comparator_rows: 1,
    },
    RequiredQuorumRow {
      group: ScenarioGroup::OxibeltOnly,
      scenario: "crs-enforcing",
      comparator: Comparator::Oxibelt,
      matching_comparator_rows: 1,
    },
  ]
}

fn aggregate_shard_count(aggregate: &AggregateStats) -> usize {
  if aggregate.distribution.shard_count > 0 {
    aggregate.distribution.shard_count
  } else {
    aggregate.source_files.len()
  }
}

fn parse_results_file(
  input_dir: &Path,
  path: &Path,
  warnings: &mut WarningBag,
) -> Vec<BenchmarkRow> {
  let rel_path = display_path(input_dir, path);
  let metadata = match fs::metadata(path) {
    Ok(metadata) => metadata,
    Err(error) => {
      warnings.push(format!("failed to inspect {rel_path}: {error}"));
      return Vec::new();
    }
  };
  if metadata.len() > MAX_RESULTS_BYTES {
    warnings.push(format!(
      "skipping {rel_path}: results file is larger than {} bytes",
      MAX_RESULTS_BYTES
    ));
    return Vec::new();
  }
  let raw = match fs::read_to_string(path) {
    Ok(raw) => raw,
    Err(error) => {
      warnings.push(format!("failed to read {rel_path}: {error}"));
      return Vec::new();
    }
  };

  match serde_json::from_str::<Value>(&raw) {
    Ok(Value::Array(values)) => values
      .into_iter()
      .enumerate()
      .filter_map(|(index, value)| parse_result_value(value, &rel_path, index + 1, warnings))
      .collect(),
    Ok(value @ Value::Object(_)) => parse_result_value(value, &rel_path, 1, warnings)
      .into_iter()
      .collect(),
    Ok(_) => {
      warnings.push(format!(
        "ignoring {rel_path}: top-level JSON is not an object or array"
      ));
      Vec::new()
    }
    Err(_) => parse_jsonl_results(&raw, &rel_path, warnings),
  }
}

fn parse_external_results_file(
  input_dir: &Path,
  path: &Path,
  warnings: &mut WarningBag,
) -> Vec<ExternalBenchmarkSample> {
  let rel_path = display_path(input_dir, path);
  let metadata = match fs::metadata(path) {
    Ok(metadata) => metadata,
    Err(error) => {
      warnings.push(format!("failed to inspect {rel_path}: {error}"));
      return Vec::new();
    }
  };
  if metadata.len() > MAX_RESULTS_BYTES {
    warnings.push(format!(
      "skipping {rel_path}: external results file is larger than {} bytes",
      MAX_RESULTS_BYTES
    ));
    return Vec::new();
  }
  let raw = match fs::read_to_string(path) {
    Ok(raw) => raw,
    Err(error) => {
      warnings.push(format!("failed to read {rel_path}: {error}"));
      return Vec::new();
    }
  };

  match serde_json::from_str::<Value>(&raw) {
    Ok(Value::Array(values)) => values
      .into_iter()
      .enumerate()
      .filter_map(|(index, value)| {
        parse_external_result_value(value, &rel_path, index + 1, warnings)
      })
      .collect(),
    Ok(value @ Value::Object(_)) => parse_external_result_value(value, &rel_path, 1, warnings)
      .into_iter()
      .collect(),
    Ok(_) => {
      warnings.push(format!(
        "ignoring {rel_path}: external results top-level JSON is not an object or array"
      ));
      Vec::new()
    }
    Err(error) => {
      warnings.push(format!("failed to parse {rel_path} as JSON: {error}"));
      Vec::new()
    }
  }
}

fn parse_external_result_value(
  value: Value,
  source_file: &str,
  row_index: usize,
  warnings: &mut WarningBag,
) -> Option<ExternalBenchmarkSample> {
  let Some(object) = value.as_object() else {
    warnings.push(format!(
      "{source_file} external row {row_index}: expected a JSON object"
    ));
    return None;
  };

  let Some(label) = string_field(object.get("label")) else {
    warnings.push(format!(
      "{source_file} external row {row_index}: missing string field label"
    ));
    return None;
  };
  let Some(tool) = string_field(object.get("tool")) else {
    warnings.push(format!(
      "{source_file} external row {row_index} ({label}): missing string field tool"
    ));
    return None;
  };
  let Some(comparator) = string_field(object.get("comparator")) else {
    warnings.push(format!(
      "{source_file} external row {row_index} ({label}): missing string field comparator"
    ));
    return None;
  };
  let Some(scenario) = string_field(object.get("scenario")) else {
    warnings.push(format!(
      "{source_file} external row {row_index} ({label}): missing string field scenario"
    ));
    return None;
  };
  let Some(protocol) = string_field(object.get("protocol")) else {
    warnings.push(format!(
      "{source_file} external row {row_index} ({label}): missing string field protocol"
    ));
    return None;
  };
  let Some(status) = string_field(object.get("status")) else {
    warnings.push(format!(
      "{source_file} external row {row_index} ({label}): missing string field status"
    ));
    return None;
  };

  if !matches!(tool, "h2load" | "oha" | "wrk") {
    warnings.push(format!(
      "{source_file} external row {row_index} ({label}): unknown tool {tool:?}"
    ));
  }
  if !matches!(comparator, "oxibelt" | "nginx" | "caddy" | "openresty") {
    warnings.push(format!(
      "{source_file} external row {row_index} ({label}): unknown comparator {comparator:?}"
    ));
  }
  if !matches!(status, "pass" | "fail" | "skipped") {
    warnings.push(format!(
      "{source_file} external row {row_index} ({label}): unknown status {status:?}"
    ));
  }

  Some(ExternalBenchmarkSample {
    source_file: source_file.to_owned(),
    amd64_target_cpu: string_field(object.get("amd64_target_cpu"))
      .filter(|target| is_known_amd64_target_cpu(target))
      .map(str::to_owned)
      .or_else(|| infer_amd64_target_cpu_from_path(source_file))
      .unwrap_or_else(default_amd64_target_cpu),
    serving_type: string_field(object.get("serving_type"))
      .map(str::to_owned)
      .or_else(|| infer_serving_type_from_path(source_file))
      .unwrap_or_else(default_serving_type),
    label: label.to_owned(),
    tool: tool.to_owned(),
    comparator: comparator.to_owned(),
    scenario: scenario.to_owned(),
    protocol: protocol.to_owned(),
    status: status.to_owned(),
    rps: numeric_field(object, &["rps"], source_file, row_index, label, warnings),
    p95_ms: numeric_field(object, &["p95_ms"], source_file, row_index, label, warnings),
    p99_ms: numeric_field(object, &["p99_ms"], source_file, row_index, label, warnings),
    error_rate: numeric_field(
      object,
      &["error_rate"],
      source_file,
      row_index,
      label,
      warnings,
    ),
    requests: numeric_field(
      object,
      &["requests"],
      source_file,
      row_index,
      label,
      warnings,
    ),
    reason: string_field(object.get("reason")).map(str::to_owned),
    output_file: string_field(object.get("output_file")).map(str::to_owned),
  })
}

fn parse_profile_results_file(
  input_dir: &Path,
  path: &Path,
  warnings: &mut WarningBag,
) -> Vec<DiagnosticProfileSample> {
  let rel_path = display_path(input_dir, path);
  let metadata = match fs::metadata(path) {
    Ok(metadata) => metadata,
    Err(error) => {
      warnings.push(format!("failed to inspect {rel_path}: {error}"));
      return Vec::new();
    }
  };
  if metadata.len() > MAX_RESULTS_BYTES {
    warnings.push(format!(
      "skipping {rel_path}: profile results file is larger than {} bytes",
      MAX_RESULTS_BYTES
    ));
    return Vec::new();
  }
  let raw = match fs::read_to_string(path) {
    Ok(raw) => raw,
    Err(error) => {
      warnings.push(format!("failed to read {rel_path}: {error}"));
      return Vec::new();
    }
  };

  match serde_json::from_str::<Value>(&raw) {
    Ok(Value::Array(values)) => values
      .into_iter()
      .enumerate()
      .filter_map(|(index, value)| {
        parse_profile_result_value(value, &rel_path, index + 1, warnings)
      })
      .collect(),
    Ok(value @ Value::Object(_)) => parse_profile_result_value(value, &rel_path, 1, warnings)
      .into_iter()
      .collect(),
    Ok(_) => {
      warnings.push(format!(
        "ignoring {rel_path}: profile results top-level JSON is not an object or array"
      ));
      Vec::new()
    }
    Err(error) => {
      warnings.push(format!("failed to parse {rel_path} as JSON: {error}"));
      Vec::new()
    }
  }
}

fn parse_profile_result_value(
  value: Value,
  source_file: &str,
  row_index: usize,
  warnings: &mut WarningBag,
) -> Option<DiagnosticProfileSample> {
  let Some(object) = value.as_object() else {
    warnings.push(format!(
      "{source_file} profile row {row_index}: expected a JSON object"
    ));
    return None;
  };

  let Some(label) = string_field(object.get("label")) else {
    warnings.push(format!(
      "{source_file} profile row {row_index}: missing string field label"
    ));
    return None;
  };
  let Some(comparator) = string_field(object.get("comparator")) else {
    warnings.push(format!(
      "{source_file} profile row {row_index} ({label}): missing string field comparator"
    ));
    return None;
  };
  let Some(scenario) = string_field(object.get("scenario")) else {
    warnings.push(format!(
      "{source_file} profile row {row_index} ({label}): missing string field scenario"
    ));
    return None;
  };
  let Some(protocol) = string_field(object.get("protocol")) else {
    warnings.push(format!(
      "{source_file} profile row {row_index} ({label}): missing string field protocol"
    ));
    return None;
  };
  let Some(profile_mode) = string_field(object.get("profile_mode")) else {
    warnings.push(format!(
      "{source_file} profile row {row_index} ({label}): missing string field profile_mode"
    ));
    return None;
  };
  let Some(status) = string_field(object.get("status")) else {
    warnings.push(format!(
      "{source_file} profile row {row_index} ({label}): missing string field status"
    ));
    return None;
  };

  if !matches!(
    comparator,
    "oxibelt" | "nginx" | "caddy" | "openresty" | "unknown"
  ) {
    warnings.push(format!(
      "{source_file} profile row {row_index} ({label}): unknown comparator {comparator:?}"
    ));
  }
  if !matches!(profile_mode, "cpu" | "memory" | "cpu-memory") {
    warnings.push(format!(
      "{source_file} profile row {row_index} ({label}): unknown profile_mode {profile_mode:?}"
    ));
  }
  if !matches!(status, "pass" | "fail" | "skipped") {
    warnings.push(format!(
      "{source_file} profile row {row_index} ({label}): unknown status {status:?}"
    ));
  }

  let cpu = object.get("cpu").and_then(Value::as_object);
  let memory = object.get("memory").and_then(Value::as_object);
  let cpu_artifacts = cpu
    .and_then(|cpu| cpu.get("artifacts"))
    .and_then(Value::as_object);
  let memory_artifacts = memory
    .and_then(|memory| memory.get("artifacts"))
    .and_then(Value::as_object);

  Some(DiagnosticProfileSample {
    source_file: source_file.to_owned(),
    amd64_target_cpu: string_field(object.get("amd64_target_cpu"))
      .filter(|target| is_known_amd64_target_cpu(target))
      .map(str::to_owned)
      .or_else(|| infer_amd64_target_cpu_from_path(source_file))
      .unwrap_or_else(default_amd64_target_cpu),
    serving_type: string_field(object.get("serving_type"))
      .map(str::to_owned)
      .or_else(|| infer_serving_type_from_path(source_file))
      .unwrap_or_else(default_serving_type),
    label: label.to_owned(),
    comparator: comparator.to_owned(),
    scenario: scenario.to_owned(),
    protocol: protocol.to_owned(),
    profile_mode: profile_mode.to_owned(),
    status: status.to_owned(),
    reason: string_field(object.get("reason")).map(str::to_owned),
    cpu_enabled: cpu
      .and_then(|cpu| cpu.get("enabled"))
      .and_then(Value::as_bool)
      .unwrap_or(false),
    memory_enabled: memory
      .and_then(|memory| memory.get("enabled"))
      .and_then(Value::as_bool)
      .unwrap_or(false),
    perf_data: cpu_artifacts
      .and_then(|artifacts| string_field(artifacts.get("perf_data")))
      .map(str::to_owned),
    perf_report: cpu_artifacts
      .and_then(|artifacts| string_field(artifacts.get("perf_report")))
      .map(str::to_owned),
    perf_script: cpu_artifacts
      .and_then(|artifacts| string_field(artifacts.get("perf_script")))
      .map(str::to_owned),
    flamegraph: cpu_artifacts
      .and_then(|artifacts| string_field(artifacts.get("flamegraph")))
      .map(str::to_owned),
    cpu_metadata: cpu_artifacts
      .and_then(|artifacts| string_field(artifacts.get("metadata")))
      .map(str::to_owned),
    resource: memory_artifacts
      .and_then(|artifacts| string_field(artifacts.get("resource")))
      .map(str::to_owned),
    memory_metadata: memory_artifacts
      .and_then(|artifacts| string_field(artifacts.get("metadata")))
      .map(str::to_owned),
    heap_dir: memory_artifacts
      .and_then(|artifacts| string_field(artifacts.get("heap_dir")))
      .map(str::to_owned),
  })
}

fn parse_jsonl_results(raw: &str, rel_path: &str, warnings: &mut WarningBag) -> Vec<BenchmarkRow> {
  let mut rows = Vec::new();
  for (line_index, line) in raw.lines().enumerate() {
    let line = line.trim();
    if line.is_empty() {
      continue;
    }
    match serde_json::from_str::<Value>(line) {
      Ok(value) => {
        if let Some(row) = parse_result_value(value, rel_path, line_index + 1, warnings) {
          rows.push(row);
        }
      }
      Err(error) => warnings.push(format!(
        "failed to parse {rel_path} line {} as JSON: {error}",
        line_index + 1
      )),
    }
  }
  rows
}

fn parse_result_value(
  value: Value,
  source_file: &str,
  row_index: usize,
  warnings: &mut WarningBag,
) -> Option<BenchmarkRow> {
  let Some(object) = value.as_object() else {
    warnings.push(format!(
      "{source_file} row {row_index}: expected a JSON object"
    ));
    return None;
  };

  let Some(label) = string_field(object.get("label")) else {
    warnings.push(format!(
      "{source_file} row {row_index}: missing string field label"
    ));
    return None;
  };
  let Some((comparator, scenario)) = normalize_label(label) else {
    warnings.push(format!(
            "{source_file} row {row_index}: label {label:?} does not start with oxibelt-, nginx-, caddy-, or openresty-"
        ));
    return None;
  };

  let result_type = string_field(object.get("type")).map(str::to_owned);
  let protocol_or_mode = string_field(object.get("protocol"))
    .or_else(|| string_field(object.get("mode")))
    .map(str::to_owned);
  if protocol_or_mode.is_none() {
    warnings.push(format!(
      "{source_file} row {row_index} ({label}): missing protocol or mode"
    ));
  }

  let skipped = match object.get("skipped") {
    Some(Value::Bool(skipped)) => *skipped,
    Some(_) => {
      warnings.push(format!(
        "{source_file} row {row_index} ({label}): skipped field is not a boolean"
      ));
      false
    }
    None => false,
  };
  let reason = string_field(object.get("reason")).map(str::to_owned);
  if skipped && reason.is_none() {
    warnings.push(format!(
      "{source_file} row {row_index} ({label}): skipped row is missing reason"
    ));
  }

  let rps = numeric_field(
    object,
    &["rps", "handshake_per_sec"],
    source_file,
    row_index,
    label,
    warnings,
  );
  if !skipped && rps.is_none() {
    warnings.push(format!(
      "{source_file} row {row_index} ({label}): missing rps or handshake_per_sec"
    ));
  }
  let errors = integer_field(
    object.get("errors"),
    source_file,
    row_index,
    label,
    "errors",
    warnings,
  )
  .unwrap_or(0);

  let _requests = integer_named_field(
    object,
    &["requests", "handshakes"],
    source_file,
    row_index,
    label,
    warnings,
  );

  Some(BenchmarkRow {
    source_file: source_file.to_owned(),
    amd64_target_cpu: string_field(object.get("amd64_target_cpu"))
      .filter(|target| is_known_amd64_target_cpu(target))
      .map(str::to_owned)
      .or_else(|| infer_amd64_target_cpu_from_path(source_file))
      .unwrap_or_else(default_amd64_target_cpu),
    label: label.to_owned(),
    comparator,
    scenario: scenario.to_owned(),
    group: classify_scenario(comparator, scenario),
    result_type,
    protocol_or_mode,
    rps,
    p50_ms: numeric_field(object, &["p50_ms"], source_file, row_index, label, warnings),
    p90_ms: numeric_field(object, &["p90_ms"], source_file, row_index, label, warnings),
    p95_ms: numeric_field(object, &["p95_ms"], source_file, row_index, label, warnings),
    p99_ms: numeric_field(object, &["p99_ms"], source_file, row_index, label, warnings),
    errors,
    skipped,
    reason,
    fast_path_plain_proxy_h1: parse_fast_path_plain_proxy_h1(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
    fast_path_plain_proxy_h2: parse_fast_path_plain_proxy_h2(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
    fast_path_plain_proxy_h3: parse_fast_path_plain_proxy_h3(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
    fast_path_transport_direct_h1_h1: parse_fast_path_transport_direct_h1_h1(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
    fast_path_transport_direct_h1_h2: parse_fast_path_transport_direct_h1_h2(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
    fast_path_transport_direct_h1_h3: parse_fast_path_transport_direct_h1_h3(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
    fast_path_transport_direct_h2_h1: parse_fast_path_transport_direct_h2_h1(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
    fast_path_transport_direct_h2_h2: parse_fast_path_transport_direct_h2_h2(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
    fast_path_transport_direct_h2_h3: parse_fast_path_transport_direct_h2_h3(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
    direct_h1_pool_events: parse_direct_h1_pool_events(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
    direct_h2_pool_events: parse_direct_h2_pool_events(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
    static_fast_path_responses: parse_static_fast_path_responses(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
    fast_path_stage_timing: parse_fast_path_stage_timing(
      object,
      source_file,
      row_index,
      label,
      warnings,
    ),
  })
}

fn parse_fast_path_plain_proxy_h1(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathSample> {
  parse_fast_path_plain_proxy_protocol(object, "h1", source_file, row_index, label, warnings)
}

fn parse_fast_path_plain_proxy_h2(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathSample> {
  parse_fast_path_plain_proxy_protocol(object, "h2", source_file, row_index, label, warnings)
}

fn parse_fast_path_plain_proxy_h3(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathSample> {
  parse_fast_path_plain_proxy_protocol(object, "h3", source_file, row_index, label, warnings)
}

fn parse_fast_path_plain_proxy_protocol(
  object: &serde_json::Map<String, Value>,
  protocol: &str,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathSample> {
  let sample = object
    .get("fast_path")
    .and_then(Value::as_object)
    .and_then(|fast_path| fast_path.get("plain_proxy"))
    .and_then(Value::as_object)
    .and_then(|plain_proxy| plain_proxy.get(protocol))
    .and_then(Value::as_object)?;
  parse_fast_path_sample(
    sample,
    &format!("fast_path.plain_proxy.{protocol}"),
    source_file,
    row_index,
    label,
    warnings,
  )
}

fn parse_fast_path_transport_direct_h1_h1(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathSample> {
  parse_fast_path_transport_protocol(
    object,
    "direct_h1",
    "h1",
    source_file,
    row_index,
    label,
    warnings,
  )
}

fn parse_fast_path_transport_direct_h1_h2(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathSample> {
  parse_fast_path_transport_protocol(
    object,
    "direct_h1",
    "h2",
    source_file,
    row_index,
    label,
    warnings,
  )
}

fn parse_fast_path_transport_direct_h1_h3(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathSample> {
  parse_fast_path_transport_protocol(
    object,
    "direct_h1",
    "h3",
    source_file,
    row_index,
    label,
    warnings,
  )
}

fn parse_fast_path_transport_direct_h2_h1(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathSample> {
  parse_fast_path_transport_protocol(
    object,
    "direct_h2",
    "h1",
    source_file,
    row_index,
    label,
    warnings,
  )
}

fn parse_fast_path_transport_direct_h2_h2(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathSample> {
  parse_fast_path_transport_protocol(
    object,
    "direct_h2",
    "h2",
    source_file,
    row_index,
    label,
    warnings,
  )
}

fn parse_fast_path_transport_direct_h2_h3(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathSample> {
  parse_fast_path_transport_protocol(
    object,
    "direct_h2",
    "h3",
    source_file,
    row_index,
    label,
    warnings,
  )
}

fn parse_fast_path_transport_protocol(
  object: &serde_json::Map<String, Value>,
  transport_name: &str,
  protocol: &str,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathSample> {
  let sample = object
    .get("fast_path")
    .and_then(Value::as_object)
    .and_then(|fast_path| fast_path.get("transport"))
    .and_then(Value::as_object)
    .and_then(|transport| transport.get(transport_name))
    .and_then(Value::as_object)
    .and_then(|direct_transport| direct_transport.get(protocol))
    .and_then(Value::as_object)?;
  parse_fast_path_sample(
    sample,
    &format!("fast_path.transport.{transport_name}.{protocol}"),
    source_file,
    row_index,
    label,
    warnings,
  )
}

fn parse_fast_path_sample(
  sample: &serde_json::Map<String, Value>,
  path: &str,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathSample> {
  let hits = integer_named_field(sample, &["hits"], source_file, row_index, label, warnings)?;
  let misses = integer_named_field(sample, &["misses"], source_file, row_index, label, warnings)?;
  let attempts = integer_named_field(
    sample,
    &["attempts"],
    source_file,
    row_index,
    label,
    warnings,
  )?;
  let hit_rate = match sample.get("hit_rate") {
    Some(Value::Null) | None => None,
    Some(_) => numeric_field(
      sample,
      &["hit_rate"],
      source_file,
      row_index,
      label,
      warnings,
    ),
  };
  if hits.saturating_add(misses) != attempts {
    warnings.push(format!(
      "{source_file} row {row_index} ({label}): {path} attempts does not equal hits + misses"
    ));
  }
  if let Some(rate) = hit_rate
    && rate > 1.0
  {
    warnings.push(format!(
      "{source_file} row {row_index} ({label}): {path} hit_rate is greater than 1.0"
    ));
  }

  Some(FastPathSample {
    hits,
    misses,
    attempts,
    hit_rate,
  })
}

fn parse_direct_h1_pool_events(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<BTreeMap<String, u64>> {
  let events = object
    .get("fast_path")
    .and_then(Value::as_object)
    .and_then(|fast_path| fast_path.get("pool"))
    .and_then(Value::as_object)
    .and_then(|pool| pool.get("direct_h1"))
    .and_then(Value::as_object)?;
  let mut parsed = BTreeMap::new();
  for (event, value) in events {
    match value.as_u64() {
            Some(count) => {
                parsed.insert(event.clone(), count);
            }
            None => warnings.push(format!(
                "{source_file} row {row_index} ({label}): fast_path.pool.direct_h1.{event} is not an unsigned integer"
            )),
        }
  }
  Some(parsed)
}

fn parse_direct_h2_pool_events(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<BTreeMap<String, u64>> {
  let events = object
    .get("fast_path")
    .and_then(Value::as_object)
    .and_then(|fast_path| fast_path.get("pool"))
    .and_then(Value::as_object)
    .and_then(|pool| pool.get("direct_h2"))
    .and_then(Value::as_object)?;
  let mut parsed = BTreeMap::new();
  for (event, value) in events {
    match value.as_u64() {
      Some(count) => {
        parsed.insert(event.clone(), count);
      }
      None => warnings.push(format!(
        "{source_file} row {row_index} ({label}): fast_path.pool.direct_h2.{event} is not an unsigned integer"
      )),
    }
  }
  Some(parsed)
}

fn parse_static_fast_path_responses(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<BTreeMap<String, BTreeMap<String, u64>>> {
  let responses = object
    .get("fast_path")
    .and_then(Value::as_object)
    .and_then(|fast_path| fast_path.get("static_responses"))
    .and_then(Value::as_object)?;
  let mut parsed = BTreeMap::new();
  for (source, outcomes) in responses {
    let Some(outcomes) = outcomes.as_object() else {
      warnings.push(format!(
                "{source_file} row {row_index} ({label}): fast_path.static_responses.{source} is not an object"
            ));
      continue;
    };
    let mut parsed_outcomes = BTreeMap::new();
    for (outcome, value) in outcomes {
      match value.as_u64() {
                Some(count) => {
                    parsed_outcomes.insert(outcome.clone(), count);
                }
                None => warnings.push(format!(
                    "{source_file} row {row_index} ({label}): fast_path.static_responses.{source}.{outcome} is not an unsigned integer"
                )),
            }
    }
    parsed.insert(source.clone(), parsed_outcomes);
  }
  Some(parsed)
}

fn parse_fast_path_stage_timing(
  object: &serde_json::Map<String, Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<FastPathStageTimingSamples> {
  let stage_timing = object
    .get("fast_path")
    .and_then(Value::as_object)
    .and_then(|fast_path| fast_path.get("stage_timing"))
    .and_then(Value::as_object)?;
  let mut parsed = BTreeMap::new();
  for (path, protocols) in stage_timing {
    let Some(protocols) = protocols.as_object() else {
      warnings.push(format!(
        "{source_file} row {row_index} ({label}): fast_path.stage_timing.{path} is not an object"
      ));
      continue;
    };
    for (protocol, stages) in protocols {
      let Some(stages) = stages.as_object() else {
        warnings.push(format!(
          "{source_file} row {row_index} ({label}): fast_path.stage_timing.{path}.{protocol} is not an object"
        ));
        continue;
      };
      for (stage, outcomes) in stages {
        let Some(outcomes) = outcomes.as_object() else {
          warnings.push(format!(
            "{source_file} row {row_index} ({label}): fast_path.stage_timing.{path}.{protocol}.{stage} is not an object"
          ));
          continue;
        };
        for (outcome, sample) in outcomes {
          let Some(sample) = sample.as_object() else {
            warnings.push(format!(
              "{source_file} row {row_index} ({label}): fast_path.stage_timing.{path}.{protocol}.{stage}.{outcome} is not an object"
            ));
            continue;
          };
          let Some(count) = sample.get("count").and_then(Value::as_u64) else {
            warnings.push(format!(
              "{source_file} row {row_index} ({label}): fast_path.stage_timing.{path}.{protocol}.{stage}.{outcome}.count is not an unsigned integer"
            ));
            continue;
          };
          let Some(total_ns) = sample.get("total_ns").and_then(Value::as_u64) else {
            warnings.push(format!(
              "{source_file} row {row_index} ({label}): fast_path.stage_timing.{path}.{protocol}.{stage}.{outcome}.total_ns is not an unsigned integer"
            ));
            continue;
          };
          let avg_ns = match sample.get("avg_ns") {
            Some(Value::Null) | None => None,
            Some(value) => match value.as_f64() {
              Some(value) => Some(value),
              None => {
                warnings.push(format!(
                  "{source_file} row {row_index} ({label}): fast_path.stage_timing.{path}.{protocol}.{stage}.{outcome}.avg_ns is not numeric"
                ));
                None
              }
            },
          };
          parsed
            .entry(path.clone())
            .or_insert_with(BTreeMap::new)
            .entry(protocol.clone())
            .or_insert_with(BTreeMap::new)
            .entry(stage.clone())
            .or_insert_with(BTreeMap::new)
            .insert(
              outcome.clone(),
              FastPathStageTimingSample {
                count,
                total_ns,
                avg_ns,
              },
            );
        }
      }
    }
  }
  Some(parsed)
}

fn infer_amd64_target_cpu_from_path(path: &str) -> Option<String> {
  path
    .split(['/', '\\'])
    .find(|component| is_known_amd64_target_cpu(component))
    .map(str::to_owned)
}

fn default_serving_type() -> String {
  UNKNOWN_SERVING_TYPE.to_owned()
}

fn infer_serving_type_from_path(path: &str) -> Option<String> {
  for component in path.split(['/', '\\']) {
    let Some(rest) = component.strip_prefix("oxibelt-docker-performance-") else {
      continue;
    };
    for profile in ["smoke", "benchmark", "soak"] {
      let Some(remainder) = rest.strip_prefix(&format!("{profile}-")) else {
        continue;
      };
      let Some((serving_type, _shard)) = remainder.rsplit_once("-shard-") else {
        continue;
      };
      if SERVING_TYPES.contains(&serving_type) {
        return Some(serving_type.to_owned());
      }
    }
  }
  None
}

fn comparator_neutral_scenario(comparator: &str, scenario: &str) -> String {
  let prefix = format!("{comparator}-");
  scenario
    .strip_prefix(&prefix)
    .unwrap_or(scenario)
    .to_owned()
}

fn normalize_label(label: &str) -> Option<(Comparator, &str)> {
  if let Some(scenario) = label.strip_prefix("oxibelt-") {
    Some((Comparator::Oxibelt, scenario))
  } else if let Some(scenario) = label.strip_prefix("nginx-") {
    Some((Comparator::Nginx, scenario))
  } else if let Some(scenario) = label.strip_prefix("caddy-") {
    Some((Comparator::Caddy, scenario))
  } else if let Some(scenario) = label.strip_prefix("openresty-") {
    Some((Comparator::OpenResty, scenario))
  } else {
    None
  }
}

fn classify_scenario(comparator: Comparator, scenario: &str) -> ScenarioGroup {
  if scenario.starts_with("static-") {
    ScenarioGroup::StaticFiles
  } else if accept_multiplier_base_scenario(scenario).is_some() {
    ScenarioGroup::AcceptMultipliers
  } else if remote_signer_base_scenario(scenario).is_some() {
    ScenarioGroup::RemoteSigner
  } else if matches!(scenario, "h1-keepalive" | "h2" | "h3" | "tls-handshake-h2") {
    ScenarioGroup::ReverseProxy
  } else if comparator == Comparator::Oxibelt {
    ScenarioGroup::OxibeltOnly
  } else {
    ScenarioGroup::Unclassified
  }
}

fn accept_multiplier_base_scenario(scenario: &str) -> Option<&str> {
  scenario
    .strip_prefix("accept-0_5-")
    .or_else(|| scenario.strip_prefix("accept-1_0-"))
}

fn remote_signer_base_scenario(scenario: &str) -> Option<&str> {
  scenario
    .strip_prefix("local-key-")
    .or_else(|| scenario.strip_prefix("remote-signer-"))
}

fn string_field(value: Option<&Value>) -> Option<&str> {
  value
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
}

fn numeric_field(
  object: &serde_json::Map<String, Value>,
  names: &[&str],
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<f64> {
  for name in names {
    let Some(value) = object.get(*name) else {
      continue;
    };
    if let Some(number) = value.as_f64()
      && number.is_finite()
      && number >= 0.0
    {
      return Some(number);
    }
    warnings.push(format!(
      "{source_file} row {row_index} ({label}): field {name} is not a finite non-negative number"
    ));
    return None;
  }
  None
}

fn integer_named_field(
  object: &serde_json::Map<String, Value>,
  names: &[&str],
  source_file: &str,
  row_index: usize,
  label: &str,
  warnings: &mut WarningBag,
) -> Option<u64> {
  for name in names {
    if let Some(value) = object.get(*name) {
      return integer_field(Some(value), source_file, row_index, label, name, warnings);
    }
  }
  None
}

fn integer_field(
  value: Option<&Value>,
  source_file: &str,
  row_index: usize,
  label: &str,
  field_name: &str,
  warnings: &mut WarningBag,
) -> Option<u64> {
  let value = value?;
  if let Some(number) = value.as_u64() {
    return Some(number);
  }
  warnings.push(format!(
    "{source_file} row {row_index} ({label}): field {field_name} is not an unsigned integer"
  ));
  None
}

fn build_group_comparisons(
  group: ScenarioGroup,
  aggregates: &AggregateMap,
) -> Vec<ScenarioComparison> {
  let mut scenarios = BTreeSet::new();
  for ((target, comparator, scenario), aggregate) in aggregates {
    if *comparator == Comparator::Oxibelt && aggregate.group == group.as_str() {
      scenarios.insert((target.clone(), scenario.clone()));
    }
  }

  scenarios
    .into_iter()
    .map(|(target, scenario)| {
      let oxibelt = aggregates
        .get(&(target.clone(), Comparator::Oxibelt, scenario.clone()))
        .cloned();
      let nginx = aggregates
        .get(&(target.clone(), Comparator::Nginx, scenario.clone()))
        .cloned();
      let caddy = aggregates
        .get(&(target.clone(), Comparator::Caddy, scenario.clone()))
        .cloned();
      let openresty = aggregates
        .get(&(target.clone(), Comparator::OpenResty, scenario.clone()))
        .cloned();
      let oxibelt_vs_nginx = ratio_result(oxibelt.as_ref(), nginx.as_ref(), Comparator::Nginx);
      let oxibelt_vs_caddy = ratio_result(oxibelt.as_ref(), caddy.as_ref(), Comparator::Caddy);
      let oxibelt_vs_openresty =
        ratio_result(oxibelt.as_ref(), openresty.as_ref(), Comparator::OpenResty);

      ScenarioComparison {
        amd64_target_cpu: target,
        scenario,
        group: group.as_str().to_owned(),
        oxibelt,
        nginx,
        caddy,
        openresty,
        oxibelt_vs_nginx,
        oxibelt_vs_caddy,
        oxibelt_vs_openresty,
      }
    })
    .collect()
}

fn build_accept_multiplier_comparisons(
  aggregates: &AggregateMap,
) -> Vec<AcceptMultiplierComparison> {
  let mut scenarios = BTreeSet::new();
  for ((target, comparator, scenario), aggregate) in aggregates {
    if *comparator == Comparator::Oxibelt
      && aggregate.group == ScenarioGroup::AcceptMultipliers.as_str()
      && let Some(base) = accept_multiplier_base_scenario(scenario)
    {
      scenarios.insert((target.clone(), base.to_owned()));
    }
  }

  scenarios
    .into_iter()
    .map(|(target, scenario)| {
      let accept_0_5 = aggregates
        .get(&(
          target.clone(),
          Comparator::Oxibelt,
          format!("accept-0_5-{scenario}"),
        ))
        .cloned();
      let accept_1_0 = aggregates
        .get(&(
          target.clone(),
          Comparator::Oxibelt,
          format!("accept-1_0-{scenario}"),
        ))
        .cloned();
      let accept_1_0_vs_0_5 = accept_multiplier_ratio(accept_1_0.as_ref(), accept_0_5.as_ref());

      AcceptMultiplierComparison {
        amd64_target_cpu: target,
        scenario,
        accept_0_5,
        accept_1_0,
        accept_1_0_vs_0_5,
      }
    })
    .collect()
}

fn build_remote_signer_comparisons(aggregates: &AggregateMap) -> Vec<RemoteSignerComparison> {
  let mut scenarios = BTreeSet::new();
  for ((target, comparator, scenario), aggregate) in aggregates {
    if *comparator == Comparator::Oxibelt
      && aggregate.group == ScenarioGroup::RemoteSigner.as_str()
      && let Some(base) = remote_signer_base_scenario(scenario)
    {
      scenarios.insert((target.clone(), base.to_owned()));
    }
  }

  scenarios
    .into_iter()
    .map(|(target, scenario)| {
      let local_key = aggregates
        .get(&(
          target.clone(),
          Comparator::Oxibelt,
          format!("local-key-{scenario}"),
        ))
        .cloned();
      let remote_signer = aggregates
        .get(&(
          target.clone(),
          Comparator::Oxibelt,
          format!("remote-signer-{scenario}"),
        ))
        .cloned();
      let remote_signer_vs_local_key =
        remote_signer_ratio(remote_signer.as_ref(), local_key.as_ref());

      RemoteSignerComparison {
        amd64_target_cpu: target,
        scenario,
        local_key,
        remote_signer,
        remote_signer_vs_local_key,
      }
    })
    .collect()
}

fn build_amd64_isa_comparisons(
  aggregates: &AggregateMap,
  expected_target_cpus: &[String],
  primary_target_cpu: &str,
) -> Vec<Amd64IsaComparison> {
  let target_cpus = amd64_isa_target_cpus(aggregates, expected_target_cpus);
  let mut scenarios = BTreeSet::new();
  for ((_, comparator, scenario), aggregate) in aggregates {
    if *comparator == Comparator::Oxibelt {
      scenarios.insert((aggregate.group.clone(), scenario.clone()));
    }
  }

  scenarios
    .into_iter()
    .map(|(group, scenario)| {
      let primary = aggregates
        .get(&(
          primary_target_cpu.to_owned(),
          Comparator::Oxibelt,
          scenario.clone(),
        ))
        .cloned();
      let (result_type, protocol_or_mode) = isa_metadata(primary.as_ref(), aggregates, &scenario);
      let variants = target_cpus
        .iter()
        .filter(|target| target.as_str() != primary_target_cpu)
        .map(|target| {
          let target_stats = aggregates
            .get(&(target.clone(), Comparator::Oxibelt, scenario.clone()))
            .cloned();
          amd64_isa_variant_comparison(target, primary.as_ref(), target_stats)
        })
        .collect();

      Amd64IsaComparison {
        scenario,
        group,
        result_type,
        protocol_or_mode,
        primary_target_cpu: primary_target_cpu.to_owned(),
        primary,
        variants,
      }
    })
    .collect()
}

fn amd64_isa_target_cpus(
  aggregates: &AggregateMap,
  expected_target_cpus: &[String],
) -> Vec<String> {
  if !expected_target_cpus.is_empty() {
    return expected_target_cpus.to_vec();
  }

  let mut targets = BTreeSet::new();
  for (target, comparator, _) in aggregates.keys() {
    if *comparator == Comparator::Oxibelt {
      targets.insert(target.clone());
    }
  }
  targets.into_iter().collect()
}

fn isa_metadata(
  primary: Option<&AggregateStats>,
  aggregates: &AggregateMap,
  scenario: &str,
) -> (Option<String>, Option<String>) {
  if let Some(primary) = primary {
    return (
      primary.result_type.clone(),
      primary.protocol_or_mode.clone(),
    );
  }
  aggregates
    .iter()
    .find(|((_, comparator, aggregate_scenario), _)| {
      *comparator == Comparator::Oxibelt && aggregate_scenario == scenario
    })
    .map(|(_, aggregate)| {
      (
        aggregate.result_type.clone(),
        aggregate.protocol_or_mode.clone(),
      )
    })
    .unwrap_or((None, None))
}

fn amd64_isa_variant_comparison(
  target: &str,
  primary: Option<&AggregateStats>,
  target_stats: Option<AggregateStats>,
) -> Amd64IsaVariantComparison {
  let (status, reason, text, rps_ratio_vs_primary, p99_ratio_vs_primary) =
    match (primary, target_stats.as_ref()) {
      (None, _) => (
        "missing_primary".to_owned(),
        Some("missing primary target row".to_owned()),
        "missing primary target row".to_owned(),
        None,
        None,
      ),
      (Some(_), None) => (
        "missing_target".to_owned(),
        Some("missing target row".to_owned()),
        "missing target row".to_owned(),
        None,
        None,
      ),
      (Some(primary), Some(target_stats)) => {
        let rps_ratio = ratio(target_stats.median_rps, primary.median_rps);
        let p99_ratio = ratio(target_stats.median_p99_ms, primary.median_p99_ms);
        if rps_ratio.is_none() {
          (
            "no_samples".to_owned(),
            Some("missing usable target or primary RPS".to_owned()),
            "missing usable target or primary RPS".to_owned(),
            rps_ratio,
            p99_ratio,
          )
        } else {
          (
            "ok".to_owned(),
            None,
            format!(
              "RPS {}, p99 {} vs primary",
              format_percent(percent_delta(primary.median_rps, target_stats.median_rps)),
              format_percent(percent_delta(
                primary.median_p99_ms,
                target_stats.median_p99_ms
              ))
            ),
            rps_ratio,
            p99_ratio,
          )
        }
      }
    };
  let rps_delta_percent_vs_primary = primary.and_then(|primary| {
    percent_delta(
      primary.median_rps,
      target_stats.as_ref().and_then(|stats| stats.median_rps),
    )
  });
  let p99_delta_percent_vs_primary = primary.and_then(|primary| {
    percent_delta(
      primary.median_p99_ms,
      target_stats.as_ref().and_then(|stats| stats.median_p99_ms),
    )
  });

  Amd64IsaVariantComparison {
    amd64_target_cpu: target.to_owned(),
    target: target_stats,
    rps_ratio_vs_primary,
    rps_delta_percent_vs_primary,
    p99_ratio_vs_primary,
    p99_delta_percent_vs_primary,
    status,
    reason,
    text,
  }
}

fn ratio_result(
  oxibelt: Option<&AggregateStats>,
  comparator: Option<&AggregateStats>,
  comparator_kind: Comparator,
) -> RatioResult {
  let comparator_name = comparator_kind.as_str();
  let Some(oxibelt) = oxibelt else {
    return ratio_status("no_oxibelt", None, "missing OxiBelt row");
  };
  let Some(oxibelt_rps) = oxibelt.median_rps else {
    return ratio_status(
      "no_samples",
      None,
      "OxiBelt row has no non-skipped RPS samples",
    );
  };
  let Some(comparator) = comparator else {
    return ratio_status(
      "missing",
      None,
      format!("missing {comparator_name} row for matching scenario"),
    );
  };
  let Some(comparator_rps) = comparator.median_rps else {
    let reason = if comparator.skipped_count > 0 {
      comparator
        .skip_reasons
        .first()
        .cloned()
        .unwrap_or_else(|| format!("{comparator_name} row was skipped"))
    } else {
      format!("{comparator_name} row has no non-skipped RPS samples")
    };
    let status = if comparator.skipped_count > 0 {
      "skipped"
    } else {
      "no_samples"
    };
    return ratio_status(status, None, reason);
  };
  if comparator_rps == 0.0 {
    return ratio_status(
      "zero_rps",
      None,
      format!("{comparator_name} median RPS is zero"),
    );
  }

  let ratio = oxibelt_rps / comparator_rps;
  RatioResult {
    status: "ok".to_owned(),
    ratio: Some(ratio),
    percent_of_comparator: Some(ratio * 100.0),
    text: format!(
      "{:.1}% of {comparator_name} ({:.2}x {comparator_name})",
      ratio * 100.0,
      ratio
    ),
    reason: None,
  }
}

fn remote_signer_ratio(
  remote_signer: Option<&AggregateStats>,
  local_key: Option<&AggregateStats>,
) -> RemoteSignerRatio {
  let Some(local_key) = local_key else {
    return remote_signer_ratio_status("no_local_key", None, None, "missing local-key row");
  };
  let Some(remote_signer) = remote_signer else {
    return remote_signer_ratio_status("no_remote_signer", None, None, "missing remote-signer row");
  };
  let Some(local_rate) = local_key.median_rps else {
    return remote_signer_ratio_status(
      "no_samples",
      None,
      None,
      "local-key row has no non-skipped rate samples",
    );
  };
  let Some(remote_rate) = remote_signer.median_rps else {
    let reason = if remote_signer.skipped_count > 0 {
      remote_signer
        .skip_reasons
        .first()
        .cloned()
        .unwrap_or_else(|| "remote-signer row was skipped".to_owned())
    } else {
      "remote-signer row has no non-skipped rate samples".to_owned()
    };
    return remote_signer_ratio_status("no_samples", None, None, reason);
  };
  if local_rate == 0.0 {
    return remote_signer_ratio_status(
      "invalid_local_key",
      None,
      None,
      "local-key median rate is zero",
    );
  }

  let throughput_ratio = remote_rate / local_rate;
  let p99_ratio = match (remote_signer.median_p99_ms, local_key.median_p99_ms) {
    (Some(remote_p99), Some(local_p99)) if local_p99 > 0.0 => Some(remote_p99 / local_p99),
    _ => None,
  };
  let text = match p99_ratio {
    Some(p99_ratio) => format!(
      "{:.1}% of local-key throughput ({:+.1}%), p99 {:.1}% of local key ({:+.1}%)",
      throughput_ratio * 100.0,
      (throughput_ratio - 1.0) * 100.0,
      p99_ratio * 100.0,
      (p99_ratio - 1.0) * 100.0
    ),
    None => format!(
      "{:.1}% of local-key throughput ({:+.1}%), p99 unavailable",
      throughput_ratio * 100.0,
      (throughput_ratio - 1.0) * 100.0
    ),
  };

  RemoteSignerRatio {
    status: "ok".to_owned(),
    throughput_ratio: Some(throughput_ratio),
    throughput_percent_of_local_key: Some(throughput_ratio * 100.0),
    throughput_delta_percent: Some((throughput_ratio - 1.0) * 100.0),
    p99_ratio,
    p99_percent_of_local_key: p99_ratio.map(|value| value * 100.0),
    p99_delta_percent: p99_ratio.map(|value| (value - 1.0) * 100.0),
    text,
    reason: None,
  }
}

fn remote_signer_ratio_status(
  status: &str,
  throughput_ratio: Option<f64>,
  p99_ratio: Option<f64>,
  reason: impl Into<String>,
) -> RemoteSignerRatio {
  let reason = reason.into();
  RemoteSignerRatio {
    status: status.to_owned(),
    throughput_ratio,
    throughput_percent_of_local_key: throughput_ratio.map(|value| value * 100.0),
    throughput_delta_percent: throughput_ratio.map(|value| (value - 1.0) * 100.0),
    p99_ratio,
    p99_percent_of_local_key: p99_ratio.map(|value| value * 100.0),
    p99_delta_percent: p99_ratio.map(|value| (value - 1.0) * 100.0),
    text: reason.clone(),
    reason: Some(reason),
  }
}

fn accept_multiplier_ratio(
  accept_1_0: Option<&AggregateStats>,
  accept_0_5: Option<&AggregateStats>,
) -> AcceptMultiplierRatio {
  let Some(accept_1_0) = accept_1_0 else {
    return accept_multiplier_status("missing_1_0", None, "missing accept = 1.0 row");
  };
  let Some(accept_1_0_rps) = accept_1_0.median_rps else {
    return accept_multiplier_status(
      "no_samples_1_0",
      None,
      "accept = 1.0 row has no non-skipped RPS samples",
    );
  };
  let Some(accept_0_5) = accept_0_5 else {
    return accept_multiplier_status("missing_0_5", None, "missing accept = 0.5 row");
  };
  let Some(accept_0_5_rps) = accept_0_5.median_rps else {
    let reason = if accept_0_5.skipped_count > 0 {
      accept_0_5
        .skip_reasons
        .first()
        .cloned()
        .unwrap_or_else(|| "accept = 0.5 row was skipped".to_owned())
    } else {
      "accept = 0.5 row has no non-skipped RPS samples".to_owned()
    };
    let status = if accept_0_5.skipped_count > 0 {
      "skipped_0_5"
    } else {
      "no_samples_0_5"
    };
    return accept_multiplier_status(status, None, reason);
  };
  if accept_0_5_rps == 0.0 {
    return accept_multiplier_status("zero_rps_0_5", None, "accept = 0.5 median RPS is zero");
  }

  let ratio = accept_1_0_rps / accept_0_5_rps;
  AcceptMultiplierRatio {
    status: "ok".to_owned(),
    ratio: Some(ratio),
    percent_of_accept_0_5: Some(ratio * 100.0),
    text: format!("{:.1}% of accept = 0.5 ({:.2}x)", ratio * 100.0, ratio),
    reason: None,
  }
}

fn accept_multiplier_status(
  status: &str,
  ratio: Option<f64>,
  reason: impl Into<String>,
) -> AcceptMultiplierRatio {
  let reason = reason.into();
  AcceptMultiplierRatio {
    status: status.to_owned(),
    ratio,
    percent_of_accept_0_5: ratio.map(|value| value * 100.0),
    text: format!("{status}: {reason}"),
    reason: Some(reason),
  }
}

fn ratio_status(status: &str, ratio: Option<f64>, reason: impl Into<String>) -> RatioResult {
  let reason = reason.into();
  RatioResult {
    status: status.to_owned(),
    ratio,
    percent_of_comparator: ratio.map(|value| value * 100.0),
    text: format!("{status}: {reason}"),
    reason: Some(reason),
  }
}

fn regression_gate_thresholds(warnings: &mut WarningBag) -> RegressionGateThresholds {
  RegressionGateThresholds {
    h1_keepalive_min_nginx_ratio: env_threshold(
      "OXIBELT_PERF_H1_KEEPALIVE_MIN_NGINX_RATIO",
      DEFAULT_H1_KEEPALIVE_MIN_NGINX_RATIO,
      ThresholdKind::NonNegative,
      warnings,
    ),
    h1_fast_path_min_hit_rate: env_threshold(
      "OXIBELT_PERF_H1_FAST_PATH_MIN_HIT_RATE",
      DEFAULT_H1_FAST_PATH_MIN_HIT_RATE,
      ThresholdKind::NonNegative,
      warnings,
    ),
    h2_min_nginx_ratio: env_threshold(
      "OXIBELT_PERF_H2_MIN_NGINX_RATIO",
      DEFAULT_H2_MIN_NGINX_RATIO,
      ThresholdKind::NonNegative,
      warnings,
    ),
    h3_min_nginx_ratio: env_threshold(
      "OXIBELT_PERF_H3_MIN_NGINX_RATIO",
      DEFAULT_H3_MIN_NGINX_RATIO,
      ThresholdKind::NonNegative,
      warnings,
    ),
    static_16k_h1c_min_caddy_ratio: env_threshold(
      "OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO",
      DEFAULT_STATIC_16K_H1C_MIN_CADDY_RATIO,
      ThresholdKind::NonNegative,
      warnings,
    ),
    static_16k_h1c_min_nginx_ratio: env_threshold(
      "OXIBELT_PERF_STATIC_16K_H1C_MIN_NGINX_RATIO",
      DEFAULT_STATIC_16K_H1C_MIN_NGINX_RATIO,
      ThresholdKind::NonNegative,
      warnings,
    ),
    remote_signer_handshake_min_local_ratio: env_threshold(
      "OXIBELT_PERF_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO",
      DEFAULT_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO,
      ThresholdKind::NonNegative,
      warnings,
    ),
    waf_enforcing_min_rps: env_threshold(
      "OXIBELT_PERF_WAF_ENFORCING_MIN_RPS",
      DEFAULT_WAF_ENFORCING_MIN_RPS,
      ThresholdKind::NonNegative,
      warnings,
    ),
    crs_enforcing_min_rps: env_threshold(
      "OXIBELT_PERF_CRS_ENFORCING_MIN_RPS",
      DEFAULT_CRS_ENFORCING_MIN_RPS,
      ThresholdKind::NonNegative,
      warnings,
    ),
    waf_crs_max_enforce_p99_ratio: env_threshold(
      "OXIBELT_PERF_WAF_CRS_MAX_ENFORCE_P99_RATIO",
      DEFAULT_WAF_CRS_MAX_ENFORCE_P99_RATIO,
      ThresholdKind::Positive,
      warnings,
    ),
  }
}

#[derive(Clone, Copy)]
enum ThresholdKind {
  NonNegative,
  Positive,
}

fn env_threshold(name: &str, default: f64, kind: ThresholdKind, warnings: &mut WarningBag) -> f64 {
  let Ok(raw) = env::var(name) else {
    return default;
  };
  let valid = match raw.parse::<f64>() {
    Ok(value) if value.is_finite() => match kind {
      ThresholdKind::NonNegative => value >= 0.0,
      ThresholdKind::Positive => value > 0.0,
    },
    _ => false,
  };
  if !valid {
    warnings.push(format!(
      "{name} must be a finite {} number; using default {default}",
      match kind {
        ThresholdKind::NonNegative => "non-negative",
        ThresholdKind::Positive => "positive",
      }
    ));
    return default;
  }

  raw.parse::<f64>().unwrap_or(default)
}

fn normalize_accepted_regression_reason(
  reason: Option<&str>,
  warnings: &mut WarningBag,
) -> Option<String> {
  let reason = reason?;
  let trimmed = reason.trim();
  if trimmed.is_empty() {
    warnings
      .push("--accepted-regression-reason was empty; regression gate violations remain blocking");
    None
  } else {
    Some(trimmed.to_owned())
  }
}

fn build_regression_gate_report(
  aggregates: &PrimaryAggregateMap,
  thresholds: RegressionGateThresholds,
  baseline: Option<&BaselineGateContext>,
  primary_target_cpu: &str,
  accepted_regression_reason: Option<&str>,
) -> RegressionGateReport {
  let mut findings = RegressionGateFindings {
    violations: Vec::new(),
    advisories: Vec::new(),
  };

  collect_comparator_ratio_regression_gate(
    aggregates,
    baseline,
    primary_target_cpu,
    ComparatorRatioGate {
      gate: "h1_keepalive_min_nginx_ratio",
      group: ScenarioGroup::ReverseProxy,
      scenario: "h1-keepalive",
      comparator: Comparator::Nginx,
      threshold: thresholds.h1_keepalive_min_nginx_ratio,
      allow_baseline_advisory: false,
      baseline_stable_advisory_policy: Some(BaselineStableRatioAdvisoryPolicy {
        near_target_tolerance: DEFAULT_RATIO_TARGET_NEAR_MISS_TOLERANCE,
        comparator_shift_tolerance: DEFAULT_RATIO_TARGET_COMPARATOR_SHIFT_TOLERANCE,
      }),
    },
    &mut findings,
  );
  collect_h1_fast_path_regression_gate(
    aggregates,
    primary_target_cpu,
    thresholds.h1_fast_path_min_hit_rate,
    &mut findings,
  );
  collect_comparator_ratio_regression_gate(
    aggregates,
    baseline,
    primary_target_cpu,
    ComparatorRatioGate {
      gate: "h2_min_nginx_ratio",
      group: ScenarioGroup::ReverseProxy,
      scenario: "h2",
      comparator: Comparator::Nginx,
      threshold: thresholds.h2_min_nginx_ratio,
      allow_baseline_advisory: true,
      baseline_stable_advisory_policy: None,
    },
    &mut findings,
  );
  collect_h2_fast_path_regression_gate(
    aggregates,
    primary_target_cpu,
    thresholds.h1_fast_path_min_hit_rate,
    &mut findings,
  );
  collect_h2_upstream_direct_h2_regression_gate(
    aggregates,
    primary_target_cpu,
    thresholds.h1_fast_path_min_hit_rate,
    &mut findings,
  );
  collect_comparator_ratio_regression_gate(
    aggregates,
    baseline,
    primary_target_cpu,
    ComparatorRatioGate {
      gate: "h3_min_nginx_ratio",
      group: ScenarioGroup::ReverseProxy,
      scenario: "h3",
      comparator: Comparator::Nginx,
      threshold: thresholds.h3_min_nginx_ratio,
      allow_baseline_advisory: true,
      baseline_stable_advisory_policy: None,
    },
    &mut findings,
  );
  collect_h3_fast_path_regression_gate(
    aggregates,
    primary_target_cpu,
    thresholds.h1_fast_path_min_hit_rate,
    &mut findings,
  );
  collect_static_regression_gate(
    aggregates,
    baseline,
    primary_target_cpu,
    thresholds,
    &mut findings,
  );
  collect_comparator_ratio_regression_gate(
    aggregates,
    baseline,
    primary_target_cpu,
    ComparatorRatioGate {
      gate: "static_16k_h1c_min_nginx_ratio",
      group: ScenarioGroup::StaticFiles,
      scenario: "static-16k-h1c",
      comparator: Comparator::Nginx,
      threshold: thresholds.static_16k_h1c_min_nginx_ratio,
      allow_baseline_advisory: true,
      baseline_stable_advisory_policy: None,
    },
    &mut findings,
  );
  collect_remote_signer_handshake_regression_gate(
    aggregates,
    baseline,
    primary_target_cpu,
    thresholds,
    &mut findings,
  );
  collect_min_rps_regression_gate(
    aggregates,
    baseline,
    primary_target_cpu,
    "waf_enforcing_min_rps",
    "waf-enforcing",
    thresholds.waf_enforcing_min_rps,
    &mut findings,
  );
  collect_min_rps_regression_gate(
    aggregates,
    baseline,
    primary_target_cpu,
    "crs_enforcing_min_rps",
    "crs-enforcing",
    thresholds.crs_enforcing_min_rps,
    &mut findings,
  );
  collect_p99_ratio_regression_gate(
    aggregates,
    baseline,
    primary_target_cpu,
    P99RatioGate {
      gate: "waf_enforce_p99_ratio",
      monitor_scenario: "waf-monitor",
      enforcing_scenario: "waf-enforcing",
      threshold: thresholds.waf_crs_max_enforce_p99_ratio,
    },
    &mut findings,
  );
  collect_p99_ratio_regression_gate(
    aggregates,
    baseline,
    primary_target_cpu,
    P99RatioGate {
      gate: "crs_enforce_p99_ratio",
      monitor_scenario: "crs-monitor",
      enforcing_scenario: "crs-enforcing",
      threshold: thresholds.waf_crs_max_enforce_p99_ratio,
    },
    &mut findings,
  );

  let accepted_regression = apply_accepted_regression(&mut findings, accepted_regression_reason);
  let status = if findings.violations.is_empty() {
    "pass"
  } else {
    "fail"
  };
  RegressionGateReport {
    status: status.to_owned(),
    thresholds,
    accepted_regression,
    violations: findings.violations,
    advisories: findings.advisories,
  }
}

fn apply_accepted_regression(
  findings: &mut RegressionGateFindings,
  reason: Option<&str>,
) -> AcceptedRegressionReport {
  let Some(reason) = reason else {
    return AcceptedRegressionReport {
      status: "inactive".to_owned(),
      reason: None,
      accepted_violations: 0,
      remaining_blocking_violations: findings.violations.len(),
    };
  };

  let mut accepted_violations = 0;
  let mut remaining = Vec::new();
  for mut violation in std::mem::take(&mut findings.violations) {
    if accepted_regression_eligible(&violation) {
      violation.disposition = "advisory".to_owned();
      violation.message = format!(
        "{}; accepted regression reason: {reason}",
        violation.message
      );
      findings.advisories.push(violation);
      accepted_violations += 1;
    } else {
      remaining.push(violation);
    }
  }
  findings.violations = remaining;

  AcceptedRegressionReport {
    status: if accepted_violations == 0 {
      "active_no_matches"
    } else {
      "active"
    }
    .to_owned(),
    reason: Some(reason.to_owned()),
    accepted_violations,
    remaining_blocking_violations: findings.violations.len(),
  }
}

fn accepted_regression_eligible(violation: &RegressionGateViolation) -> bool {
  violation.observed.is_some() && violation.evaluation_mode != "evidence"
}

fn collect_static_regression_gate(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  primary_target_cpu: &str,
  thresholds: RegressionGateThresholds,
  findings: &mut RegressionGateFindings,
) {
  let gate = "static_16k_h1c_min_caddy_ratio";
  let scenario = "static-16k-h1c";
  let group = ScenarioGroup::StaticFiles.as_str();
  let threshold = thresholds.static_16k_h1c_min_caddy_ratio;
  let context = RegressionGateContext {
    amd64_target_cpu: primary_target_cpu,
    gate,
    group,
    scenario,
    threshold,
  };
  let Some(oxibelt_rps) = aggregate_median_rps(aggregates, Comparator::Oxibelt, scenario) else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "median_rps",
      Some("oxibelt"),
      "missing OxiBelt static-16k-h1c median RPS; cannot evaluate static regression gate",
    );
    return;
  };
  if oxibelt_rps <= 0.0 {
    push_invalid_regression_gate_metric(
      findings,
      context,
      "median_rps",
      oxibelt_rps,
      Some("oxibelt"),
      format!(
        "OxiBelt static-16k-h1c median RPS must be positive; got {:.3}",
        oxibelt_rps
      ),
    );
    return;
  }
  let Some(caddy_rps) = aggregate_median_rps(aggregates, Comparator::Caddy, scenario) else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "median_rps",
      Some("caddy"),
      "missing Caddy static-16k-h1c median RPS; cannot evaluate static regression gate",
    );
    return;
  };
  if caddy_rps <= 0.0 {
    push_invalid_regression_gate_metric(
      findings,
      context,
      "median_rps",
      caddy_rps,
      Some("caddy"),
      format!(
        "Caddy static-16k-h1c median RPS must be positive; got {:.3}",
        caddy_rps
      ),
    );
    return;
  }

  let ratio = oxibelt_rps / caddy_rps;
  if ratio < threshold {
    let decision = classify_throughput_ratio_threshold_miss(
      aggregates,
      baseline,
      scenario,
      Comparator::Caddy,
      scenario,
      threshold,
      false,
    );
    push_threshold_regression_gate_metric(
      findings,
      RegressionGateFindingInput {
        amd64_target_cpu: primary_target_cpu,
        gate,
        group,
        scenario,
        metric: "median_rps_ratio",
        observed: Some(ratio),
        threshold,
        comparator: Some("caddy"),
        message: format!(
          "OxiBelt static-16k-h1c median RPS ratio {:.4} < {:.4} vs Caddy ({:.3} RPS vs {:.3} RPS)",
          ratio, threshold, oxibelt_rps, caddy_rps
        ),
      },
      decision,
    );
  }
}

fn collect_comparator_ratio_regression_gate(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  primary_target_cpu: &str,
  gate: ComparatorRatioGate<'_>,
  findings: &mut RegressionGateFindings,
) {
  let comparator_name = gate.comparator.as_str();
  let context = RegressionGateContext {
    amd64_target_cpu: primary_target_cpu,
    gate: gate.gate,
    group: gate.group.as_str(),
    scenario: gate.scenario,
    threshold: gate.threshold,
  };
  let Some(oxibelt_rps) = aggregate_median_rps(aggregates, Comparator::Oxibelt, gate.scenario)
  else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "median_rps",
      Some("oxibelt"),
      format!(
        "missing OxiBelt {} median RPS; cannot evaluate {}",
        gate.scenario, gate.gate
      ),
    );
    return;
  };
  if oxibelt_rps <= 0.0 {
    push_invalid_regression_gate_metric(
      findings,
      context,
      "median_rps",
      oxibelt_rps,
      Some("oxibelt"),
      format!(
        "OxiBelt {} median RPS must be positive; got {:.3}",
        gate.scenario, oxibelt_rps
      ),
    );
    return;
  }
  let Some(comparator_rps) = aggregate_median_rps(aggregates, gate.comparator, gate.scenario)
  else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "median_rps",
      Some(comparator_name),
      format!(
        "missing {comparator_name} {} median RPS; cannot evaluate {}",
        gate.scenario, gate.gate
      ),
    );
    return;
  };
  if comparator_rps <= 0.0 {
    push_invalid_regression_gate_metric(
      findings,
      context,
      "median_rps",
      comparator_rps,
      Some(comparator_name),
      format!(
        "{comparator_name} {} median RPS must be positive; got {:.3}",
        gate.scenario, comparator_rps
      ),
    );
    return;
  }

  let ratio = oxibelt_rps / comparator_rps;
  if ratio < gate.threshold {
    let allow_statistical_comparator_shift =
      gate.group == ScenarioGroup::ReverseProxy && gate.comparator == Comparator::Nginx;
    let decision = if gate.allow_baseline_advisory {
      classify_throughput_ratio_threshold_miss(
        aggregates,
        baseline,
        gate.scenario,
        gate.comparator,
        gate.scenario,
        gate.threshold,
        allow_statistical_comparator_shift,
      )
    } else if let Some(policy) = gate.baseline_stable_advisory_policy {
      classify_baseline_stable_ratio_threshold_miss(
        aggregates,
        baseline,
        BaselineStableRatioMiss {
          oxibelt_scenario: gate.scenario,
          comparator: gate.comparator,
          comparator_scenario: gate.scenario,
          threshold: gate.threshold,
          policy,
          current_ratio: ratio,
        },
        allow_statistical_comparator_shift,
      )
    } else {
      GateDisposition::threshold_blocking(
        "target ratio gate requires meeting the configured threshold; baseline-stable advisory pass is disabled for this gate",
      )
    };
    push_threshold_regression_gate_metric(
      findings,
      RegressionGateFindingInput {
        amd64_target_cpu: primary_target_cpu,
        gate: gate.gate,
        group: gate.group.as_str(),
        scenario: gate.scenario,
        metric: "median_rps_ratio",
        observed: Some(ratio),
        threshold: gate.threshold,
        comparator: Some(comparator_name),
        message: format!(
          "OxiBelt {} median RPS ratio {:.4} < {:.4} vs {comparator_name} ({:.3} RPS vs {:.3} RPS)",
          gate.scenario, ratio, gate.threshold, oxibelt_rps, comparator_rps
        ),
      },
      decision,
    );
  }
}

fn collect_remote_signer_handshake_regression_gate(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  primary_target_cpu: &str,
  thresholds: RegressionGateThresholds,
  findings: &mut RegressionGateFindings,
) {
  let gate = "remote_signer_handshake_min_local_ratio";
  let scenario = "tls-handshake-h2";
  let local_scenario = "local-key-tls-handshake-h2";
  let remote_scenario = "remote-signer-tls-handshake-h2";
  let threshold = thresholds.remote_signer_handshake_min_local_ratio;
  let context = RegressionGateContext {
    amd64_target_cpu: primary_target_cpu,
    gate,
    group: ScenarioGroup::RemoteSigner.as_str(),
    scenario,
    threshold,
  };
  let Some(remote_rate) = aggregate_median_rps(aggregates, Comparator::Oxibelt, remote_scenario)
  else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "median_rps",
      Some("remote-signer"),
      format!("missing OxiBelt {remote_scenario} median rate; cannot evaluate {gate}"),
    );
    return;
  };
  if remote_rate <= 0.0 {
    push_invalid_regression_gate_metric(
      findings,
      context,
      "median_rps",
      remote_rate,
      Some("remote-signer"),
      format!(
        "OxiBelt {remote_scenario} median rate must be positive; got {:.3}",
        remote_rate
      ),
    );
    return;
  }
  let Some(local_rate) = aggregate_median_rps(aggregates, Comparator::Oxibelt, local_scenario)
  else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "median_rps",
      Some("local-key"),
      format!("missing OxiBelt {local_scenario} median rate; cannot evaluate {gate}"),
    );
    return;
  };
  if local_rate <= 0.0 {
    push_invalid_regression_gate_metric(
      findings,
      context,
      "median_rps",
      local_rate,
      Some("local-key"),
      format!(
        "OxiBelt {local_scenario} median rate must be positive; got {:.3}",
        local_rate
      ),
    );
    return;
  }

  let ratio = remote_rate / local_rate;
  if ratio < threshold {
    let decision = classify_throughput_ratio_threshold_miss(
      aggregates,
      baseline,
      remote_scenario,
      Comparator::Oxibelt,
      local_scenario,
      threshold,
      false,
    );
    push_threshold_regression_gate_metric(
      findings,
      RegressionGateFindingInput {
        amd64_target_cpu: primary_target_cpu,
        gate,
        group: ScenarioGroup::RemoteSigner.as_str(),
        scenario,
        metric: "median_rps_ratio",
        observed: Some(ratio),
        threshold,
        comparator: Some("local-key"),
        message: format!(
          "OxiBelt remote-signer cold H2 handshake median rate ratio {:.4} < {:.4} vs local key ({:.3} handshakes/s vs {:.3} handshakes/s)",
          ratio, threshold, remote_rate, local_rate
        ),
      },
      decision,
    );
  }
}

fn collect_h1_fast_path_regression_gate(
  aggregates: &PrimaryAggregateMap,
  primary_target_cpu: &str,
  threshold: f64,
  findings: &mut RegressionGateFindings,
) {
  let gate = "h1_fast_path_min_hit_rate";
  let scenario = "h1-keepalive";
  let context = RegressionGateContext {
    amd64_target_cpu: primary_target_cpu,
    gate,
    group: ScenarioGroup::ReverseProxy.as_str(),
    scenario,
    threshold,
  };
  let Some(aggregate) = aggregates.get(&(Comparator::Oxibelt, scenario.to_owned())) else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "min_hit_rate",
      Some("oxibelt"),
      "missing OxiBelt h1-keepalive row; cannot evaluate H1 fast-path hit-rate gate",
    );
    return;
  };
  let Some(fast_path) = aggregate.fast_path.as_ref() else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "min_hit_rate",
      Some("oxibelt"),
      "missing OxiBelt h1-keepalive fast-path evidence; cannot evaluate H1 fast-path hit-rate gate",
    );
    return;
  };
  collect_fast_path_sample_gate(
    fast_path.plain_proxy_h1.as_ref(),
    FastPathSampleGateInput {
      context,
      metric_prefix: "plain_proxy_h1",
      evidence_name: "H1 plain-proxy fast-path",
      missing_message: "missing OxiBelt h1-keepalive plain-proxy fast-path evidence; cannot evaluate H1 fast-path hit-rate gate",
      zero_message: "OxiBelt h1-keepalive plain-proxy fast-path evidence recorded zero attempts",
      missing_rate_message: "missing OxiBelt h1-keepalive plain-proxy fast-path hit-rate value",
      failure_reason: "minimum H1 fast-path evidence must meet the configured threshold",
    },
    findings,
  );
  collect_fast_path_sample_gate(
    fast_path.transport_direct_h1_h1.as_ref(),
    FastPathSampleGateInput {
      context,
      metric_prefix: "transport_direct_h1_h1",
      evidence_name: "direct-H1 transport",
      missing_message: "missing OxiBelt h1-keepalive direct-H1 transport evidence; cannot evaluate H1 direct-H1 transport hit-rate gate",
      zero_message: "OxiBelt h1-keepalive direct-H1 transport evidence recorded zero attempts",
      missing_rate_message: "missing OxiBelt h1-keepalive direct-H1 transport hit-rate value",
      failure_reason: "minimum H1 direct-H1 transport evidence must meet the configured threshold",
    },
    findings,
  );
}

fn collect_h2_fast_path_regression_gate(
  aggregates: &PrimaryAggregateMap,
  primary_target_cpu: &str,
  threshold: f64,
  findings: &mut RegressionGateFindings,
) {
  let gate = "h2_fast_path_min_hit_rate";
  let scenario = "h2";
  let context = RegressionGateContext {
    amd64_target_cpu: primary_target_cpu,
    gate,
    group: ScenarioGroup::ReverseProxy.as_str(),
    scenario,
    threshold,
  };
  let Some(aggregate) = aggregates.get(&(Comparator::Oxibelt, scenario.to_owned())) else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "min_hit_rate",
      Some("oxibelt"),
      "missing OxiBelt h2 row; cannot evaluate H2 fast-path hit-rate gate",
    );
    return;
  };
  let Some(fast_path) = aggregate.fast_path.as_ref() else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "min_hit_rate",
      Some("oxibelt"),
      "missing OxiBelt h2 fast-path evidence; cannot evaluate H2 fast-path hit-rate gate",
    );
    return;
  };
  collect_fast_path_sample_gate(
    fast_path.plain_proxy_h2.as_ref(),
    FastPathSampleGateInput {
      context,
      metric_prefix: "plain_proxy_h2",
      evidence_name: "H2 plain-proxy fast-path",
      missing_message: "missing OxiBelt h2 plain-proxy fast-path evidence; cannot evaluate H2 fast-path hit-rate gate",
      zero_message: "OxiBelt h2 plain-proxy fast-path evidence recorded zero attempts",
      missing_rate_message: "missing OxiBelt h2 plain-proxy fast-path hit-rate value",
      failure_reason: "minimum H2 fast-path evidence must meet the configured threshold",
    },
    findings,
  );
  collect_fast_path_sample_gate(
    fast_path.transport_direct_h1_h2.as_ref(),
    FastPathSampleGateInput {
      context,
      metric_prefix: "transport_direct_h1_h2",
      evidence_name: "H2 direct-H1 transport",
      missing_message: "missing OxiBelt h2 direct-H1 transport evidence; cannot evaluate H2 direct-H1 transport hit-rate gate",
      zero_message: "OxiBelt h2 direct-H1 transport evidence recorded zero attempts",
      missing_rate_message: "missing OxiBelt h2 direct-H1 transport hit-rate value",
      failure_reason: "minimum H2 direct-H1 transport evidence must meet the configured threshold",
    },
    findings,
  );
}

fn collect_h2_upstream_direct_h2_regression_gate(
  aggregates: &PrimaryAggregateMap,
  primary_target_cpu: &str,
  threshold: f64,
  findings: &mut RegressionGateFindings,
) {
  let gate = "h2_upstream_direct_h2_min_hit_rate";
  for scenario in ["h2-upstream-h2c", "h2-upstream-h2"] {
    let Some(aggregate) = aggregates.get(&(Comparator::Oxibelt, scenario.to_owned())) else {
      continue;
    };
    let context = RegressionGateContext {
      amd64_target_cpu: primary_target_cpu,
      gate,
      group: ScenarioGroup::OxibeltOnly.as_str(),
      scenario,
      threshold,
    };
    let Some(fast_path) = aggregate.fast_path.as_ref() else {
      push_missing_regression_gate_metric(
        findings,
        context,
        "transport_direct_h2_h2_min_hit_rate",
        Some("oxibelt"),
        "missing OxiBelt split H2 upstream direct-H2 transport evidence; cannot evaluate direct-H2 transport hit-rate gate",
      );
      continue;
    };
    collect_fast_path_sample_gate(
      fast_path.transport_direct_h2_h2.as_ref(),
      FastPathSampleGateInput {
        context,
        metric_prefix: "transport_direct_h2_h2",
        evidence_name: "split H2 upstream direct-H2 transport",
        missing_message: "missing OxiBelt split H2 upstream direct-H2 transport evidence; cannot evaluate direct-H2 transport hit-rate gate",
        zero_message: "OxiBelt split H2 upstream direct-H2 transport evidence recorded zero attempts",
        missing_rate_message: "missing OxiBelt split H2 upstream direct-H2 transport hit-rate value",
        failure_reason: "minimum split H2 upstream direct-H2 transport evidence must meet the configured threshold",
      },
      findings,
    );
  }
}

fn collect_h3_fast_path_regression_gate(
  aggregates: &PrimaryAggregateMap,
  primary_target_cpu: &str,
  threshold: f64,
  findings: &mut RegressionGateFindings,
) {
  let gate = "h3_fast_path_min_hit_rate";
  let scenario = "h3";
  let context = RegressionGateContext {
    amd64_target_cpu: primary_target_cpu,
    gate,
    group: ScenarioGroup::ReverseProxy.as_str(),
    scenario,
    threshold,
  };
  let Some(aggregate) = aggregates.get(&(Comparator::Oxibelt, scenario.to_owned())) else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "min_hit_rate",
      Some("oxibelt"),
      "missing OxiBelt h3 row; cannot evaluate H3 fast-path hit-rate gate",
    );
    return;
  };
  let Some(fast_path) = aggregate.fast_path.as_ref() else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "min_hit_rate",
      Some("oxibelt"),
      "missing OxiBelt h3 fast-path evidence; cannot evaluate H3 fast-path hit-rate gate",
    );
    return;
  };
  collect_fast_path_sample_gate(
    fast_path.plain_proxy_h3.as_ref(),
    FastPathSampleGateInput {
      context,
      metric_prefix: "plain_proxy_h3",
      evidence_name: "H3 plain-proxy fast-path",
      missing_message: "missing OxiBelt h3 plain-proxy fast-path evidence; cannot evaluate H3 fast-path hit-rate gate",
      zero_message: "OxiBelt h3 plain-proxy fast-path evidence recorded zero attempts",
      missing_rate_message: "missing OxiBelt h3 plain-proxy fast-path hit-rate value",
      failure_reason: "minimum H3 fast-path evidence must meet the configured threshold",
    },
    findings,
  );
  collect_fast_path_sample_gate(
    fast_path.transport_direct_h1_h3.as_ref(),
    FastPathSampleGateInput {
      context,
      metric_prefix: "transport_direct_h1_h3",
      evidence_name: "H3 direct-H1 transport",
      missing_message: "missing OxiBelt h3 direct-H1 transport evidence; cannot evaluate H3 direct-H1 transport hit-rate gate",
      zero_message: "OxiBelt h3 direct-H1 transport evidence recorded zero attempts",
      missing_rate_message: "missing OxiBelt h3 direct-H1 transport hit-rate value",
      failure_reason: "minimum H3 direct-H1 transport evidence must meet the configured threshold",
    },
    findings,
  );
}

struct FastPathSampleGateInput<'a> {
  context: RegressionGateContext<'a>,
  metric_prefix: &'a str,
  evidence_name: &'a str,
  missing_message: &'a str,
  zero_message: &'a str,
  missing_rate_message: &'a str,
  failure_reason: &'a str,
}

fn collect_fast_path_sample_gate(
  fast_path: Option<&FastPathAggregateStats>,
  input: FastPathSampleGateInput<'_>,
  findings: &mut RegressionGateFindings,
) {
  let attempts_metric = format!("{}_attempts", input.metric_prefix);
  let min_hit_rate_metric = format!("{}_min_hit_rate", input.metric_prefix);
  let Some(fast_path) = fast_path else {
    push_missing_regression_gate_metric(
      findings,
      input.context,
      &min_hit_rate_metric,
      Some("oxibelt"),
      input.missing_message,
    );
    return;
  };
  if fast_path.attempts == 0 {
    push_invalid_regression_gate_metric(
      findings,
      input.context,
      &attempts_metric,
      0.0,
      Some("oxibelt"),
      input.zero_message,
    );
    return;
  }
  let Some(min_hit_rate) = fast_path.min_hit_rate else {
    push_missing_regression_gate_metric(
      findings,
      input.context,
      &min_hit_rate_metric,
      Some("oxibelt"),
      input.missing_rate_message,
    );
    return;
  };
  if min_hit_rate < input.context.threshold {
    push_threshold_regression_gate_metric(
      findings,
      RegressionGateFindingInput {
        amd64_target_cpu: input.context.amd64_target_cpu,
        gate: input.context.gate,
        group: input.context.group,
        scenario: input.context.scenario,
        metric: &min_hit_rate_metric,
        observed: Some(min_hit_rate),
        threshold: input.context.threshold,
        comparator: None,
        message: format!(
          "OxiBelt {} {} hit rate {:.4} < {:.4} ({} hits, {} misses)",
          input.context.scenario,
          input.evidence_name,
          min_hit_rate,
          input.context.threshold,
          fast_path.hits,
          fast_path.misses
        ),
      },
      GateDisposition::evidence_blocking(input.failure_reason),
    );
  }
}

fn collect_min_rps_regression_gate(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  primary_target_cpu: &str,
  gate: &str,
  scenario: &str,
  threshold: f64,
  findings: &mut RegressionGateFindings,
) {
  let Some(rps) = aggregate_median_rps(aggregates, Comparator::Oxibelt, scenario) else {
    push_missing_regression_gate_metric(
      findings,
      RegressionGateContext {
        amd64_target_cpu: primary_target_cpu,
        gate,
        group: ScenarioGroup::OxibeltOnly.as_str(),
        scenario,
        threshold,
      },
      "median_rps",
      Some("oxibelt"),
      format!("missing OxiBelt {scenario} median RPS; cannot evaluate {gate}"),
    );
    return;
  };
  if rps <= 0.0 {
    push_invalid_regression_gate_metric(
      findings,
      RegressionGateContext {
        amd64_target_cpu: primary_target_cpu,
        gate,
        group: ScenarioGroup::OxibeltOnly.as_str(),
        scenario,
        threshold,
      },
      "median_rps",
      rps,
      Some("oxibelt"),
      format!("OxiBelt {scenario} median RPS must be positive; got {rps:.3}"),
    );
    return;
  }
  if rps < threshold {
    let decision = classify_absolute_rps_threshold_miss(aggregates, baseline, scenario);
    push_threshold_regression_gate_metric(
      findings,
      RegressionGateFindingInput {
        amd64_target_cpu: primary_target_cpu,
        gate,
        group: ScenarioGroup::OxibeltOnly.as_str(),
        scenario,
        metric: "median_rps",
        observed: Some(rps),
        threshold,
        comparator: None,
        message: format!(
          "OxiBelt {scenario} median RPS {:.3} < {:.3}",
          rps, threshold
        ),
      },
      decision,
    );
  }
}

fn collect_p99_ratio_regression_gate(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  primary_target_cpu: &str,
  gate: P99RatioGate<'_>,
  findings: &mut RegressionGateFindings,
) {
  let context = RegressionGateContext {
    amd64_target_cpu: primary_target_cpu,
    gate: gate.gate,
    group: ScenarioGroup::OxibeltOnly.as_str(),
    scenario: gate.enforcing_scenario,
    threshold: gate.threshold,
  };
  let Some(monitor_p99) =
    aggregate_median_p99(aggregates, Comparator::Oxibelt, gate.monitor_scenario)
  else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "median_p99_ms",
      Some(gate.monitor_scenario),
      format!(
        "missing OxiBelt {} median p99; cannot evaluate {}",
        gate.monitor_scenario, gate.gate
      ),
    );
    return;
  };
  let Some(enforcing_p99) =
    aggregate_median_p99(aggregates, Comparator::Oxibelt, gate.enforcing_scenario)
  else {
    push_missing_regression_gate_metric(
      findings,
      context,
      "median_p99_ms",
      Some(gate.enforcing_scenario),
      format!(
        "missing OxiBelt {} median p99; cannot evaluate {}",
        gate.enforcing_scenario, gate.gate
      ),
    );
    return;
  };
  if monitor_p99 <= 0.0 {
    push_invalid_regression_gate_metric(
      findings,
      context,
      "median_p99_ms",
      monitor_p99,
      Some(gate.monitor_scenario),
      format!(
        "OxiBelt {} median p99 must be positive; got {:.3}ms",
        gate.monitor_scenario, monitor_p99
      ),
    );
    return;
  }
  if enforcing_p99 <= 0.0 {
    push_invalid_regression_gate_metric(
      findings,
      context,
      "median_p99_ms",
      enforcing_p99,
      Some(gate.enforcing_scenario),
      format!(
        "OxiBelt {} median p99 must be positive; got {:.3}ms",
        gate.enforcing_scenario, enforcing_p99
      ),
    );
    return;
  }

  let ratio = enforcing_p99 / monitor_p99;
  if ratio > gate.threshold {
    let decision = classify_p99_ratio_threshold_miss(
      aggregates,
      baseline,
      gate.monitor_scenario,
      gate.enforcing_scenario,
    );
    push_threshold_regression_gate_metric(
      findings,
      RegressionGateFindingInput {
        amd64_target_cpu: primary_target_cpu,
        gate: gate.gate,
        group: ScenarioGroup::OxibeltOnly.as_str(),
        scenario: gate.enforcing_scenario,
        metric: "median_p99_ratio",
        observed: Some(ratio),
        threshold: gate.threshold,
        comparator: Some(gate.monitor_scenario),
        message: format!(
          "OxiBelt {} median p99 ratio {:.4} > {:.4} vs {} ({:.3}ms vs {:.3}ms)",
          gate.enforcing_scenario,
          ratio,
          gate.threshold,
          gate.monitor_scenario,
          enforcing_p99,
          monitor_p99
        ),
      },
      decision,
    );
  }
}

fn push_missing_regression_gate_metric(
  findings: &mut RegressionGateFindings,
  context: RegressionGateContext<'_>,
  metric: &str,
  comparator: Option<&str>,
  message: impl Into<String>,
) {
  findings.violations.push(RegressionGateViolation {
    amd64_target_cpu: context.amd64_target_cpu.to_owned(),
    disposition: "blocking".to_owned(),
    gate: context.gate.to_owned(),
    group: context.group.to_owned(),
    scenario: context.scenario.to_owned(),
    metric: metric.to_owned(),
    observed: None,
    threshold: context.threshold,
    comparator: comparator.map(str::to_owned),
    evaluation_mode: "evidence".to_owned(),
    stat_band: None,
    baseline_source: None,
    message: message.into(),
  });
}

fn push_invalid_regression_gate_metric(
  findings: &mut RegressionGateFindings,
  context: RegressionGateContext<'_>,
  metric: &str,
  observed: f64,
  comparator: Option<&str>,
  message: impl Into<String>,
) {
  findings.violations.push(RegressionGateViolation {
    amd64_target_cpu: context.amd64_target_cpu.to_owned(),
    disposition: "blocking".to_owned(),
    gate: context.gate.to_owned(),
    group: context.group.to_owned(),
    scenario: context.scenario.to_owned(),
    metric: metric.to_owned(),
    observed: Some(observed),
    threshold: context.threshold,
    comparator: comparator.map(str::to_owned),
    evaluation_mode: "evidence".to_owned(),
    stat_band: None,
    baseline_source: None,
    message: message.into(),
  });
}

struct RegressionGateFindingInput<'a> {
  amd64_target_cpu: &'a str,
  gate: &'a str,
  group: &'a str,
  scenario: &'a str,
  metric: &'a str,
  observed: Option<f64>,
  threshold: f64,
  comparator: Option<&'a str>,
  message: String,
}

fn push_threshold_regression_gate_metric(
  findings: &mut RegressionGateFindings,
  input: RegressionGateFindingInput<'_>,
  decision: GateDisposition,
) {
  let (target, disposition, message, evaluation_mode, stat_band, baseline_source) = match decision {
    GateDisposition::Blocking {
      reason,
      evaluation_mode,
      stat_band,
      baseline_source,
    } => (
      &mut findings.violations,
      "blocking",
      format!("{}; {reason}", input.message),
      evaluation_mode,
      stat_band,
      baseline_source,
    ),
    GateDisposition::Advisory {
      reason,
      evaluation_mode,
      stat_band,
      baseline_source,
    } => (
      &mut findings.advisories,
      "advisory",
      format!("{}; advisory: {reason}", input.message),
      evaluation_mode,
      stat_band,
      baseline_source,
    ),
  };
  target.push(RegressionGateViolation {
    amd64_target_cpu: input.amd64_target_cpu.to_owned(),
    disposition: disposition.to_owned(),
    gate: input.gate.to_owned(),
    group: input.group.to_owned(),
    scenario: input.scenario.to_owned(),
    metric: input.metric.to_owned(),
    observed: input.observed,
    threshold: input.threshold,
    comparator: input.comparator.map(str::to_owned),
    evaluation_mode,
    stat_band,
    baseline_source,
    message,
  });
}

fn classify_throughput_ratio_threshold_miss(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  oxibelt_scenario: &str,
  comparator: Comparator,
  comparator_scenario: &str,
  threshold: f64,
  allow_statistical_comparator_shift: bool,
) -> GateDisposition {
  if let Some(decision) = classify_statistical_ratio_threshold_miss(
    aggregates,
    baseline,
    oxibelt_scenario,
    comparator,
    comparator_scenario,
    allow_statistical_comparator_shift,
  ) {
    return decision;
  }

  let oxibelt_rps_delta = match baseline_metric_delta_percent(
    aggregates,
    baseline,
    Comparator::Oxibelt,
    "oxibelt",
    oxibelt_scenario,
    GateMetric::Rps,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };
  let oxibelt_p99_delta = match baseline_metric_delta_percent(
    aggregates,
    baseline,
    Comparator::Oxibelt,
    "oxibelt",
    oxibelt_scenario,
    GateMetric::P99,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };
  let comparator_rps_delta = match baseline_metric_delta_percent(
    aggregates,
    baseline,
    comparator,
    comparator.as_str(),
    comparator_scenario,
    GateMetric::Rps,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };
  let comparator_p99_delta = match baseline_metric_delta_percent(
    aggregates,
    baseline,
    comparator,
    comparator.as_str(),
    comparator_scenario,
    GateMetric::P99,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };
  let throughput_ratio_delta = match baseline_metric_ratio_delta_percent(
    aggregates,
    baseline,
    oxibelt_scenario,
    comparator,
    comparator_scenario,
    GateMetric::Rps,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };
  let p99_ratio_delta = match baseline_metric_ratio_delta_percent(
    aggregates,
    baseline,
    oxibelt_scenario,
    comparator,
    comparator_scenario,
    GateMetric::P99,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };

  let rps_ratio_is_stable =
    throughput_ratio_delta.ratio_delta_percent >= BASELINE_RPS_REGRESSION_TOLERANCE_PERCENT;
  let oxibelt_rps_is_stable = oxibelt_rps_delta >= BASELINE_RPS_REGRESSION_TOLERANCE_PERCENT;
  let oxibelt_p99_is_stable = oxibelt_p99_delta <= BASELINE_P99_REGRESSION_TOLERANCE_PERCENT;
  let p99_ratio_is_stable =
    p99_ratio_delta.ratio_delta_percent <= BASELINE_P99_REGRESSION_TOLERANCE_PERCENT;
  let comparator_outpaced_oxibelt = comparator_rps_delta > oxibelt_rps_delta;

  if throughput_ratio_delta.before_ratio < threshold
    && rps_ratio_is_stable
    && (p99_ratio_is_stable || oxibelt_p99_is_stable)
  {
    GateDisposition::advisory(format!(
      "baseline-stable ratio gap from `{}`: baseline RPS ratio {:.4} < threshold {:.4}, current RPS ratio {:.4} ({:+.1}%), p99 ratio {:.4} -> {:.4} ({:+.1}%), OxiBelt RPS {oxibelt_rps_delta:+.1}%, OxiBelt p99 {oxibelt_p99_delta:+.1}%, comparator RPS {comparator_rps_delta:+.1}%, comparator p99 {comparator_p99_delta:+.1}%",
      baseline_report_label(baseline),
      throughput_ratio_delta.before_ratio,
      threshold,
      throughput_ratio_delta.after_ratio,
      throughput_ratio_delta.ratio_delta_percent,
      p99_ratio_delta.before_ratio,
      p99_ratio_delta.after_ratio,
      p99_ratio_delta.ratio_delta_percent,
    ))
  } else if throughput_ratio_delta.before_ratio < threshold
    && oxibelt_rps_is_stable
    && oxibelt_p99_is_stable
    && comparator_outpaced_oxibelt
  {
    GateDisposition::advisory(format!(
      "baseline-stable comparator-shift ratio gap from `{}`: baseline RPS ratio {:.4} < threshold {:.4}, current RPS ratio {:.4} ({:+.1}%), p99 ratio {:.4} -> {:.4} ({:+.1}%), OxiBelt RPS {oxibelt_rps_delta:+.1}% and p99 {oxibelt_p99_delta:+.1}% remain within tolerances, comparator RPS {comparator_rps_delta:+.1}% and p99 {comparator_p99_delta:+.1}%",
      baseline_report_label(baseline),
      throughput_ratio_delta.before_ratio,
      threshold,
      throughput_ratio_delta.after_ratio,
      throughput_ratio_delta.ratio_delta_percent,
      p99_ratio_delta.before_ratio,
      p99_ratio_delta.after_ratio,
      p99_ratio_delta.ratio_delta_percent,
    ))
  } else {
    GateDisposition::blocking(format!(
      "baseline evidence from `{}` did not qualify for advisory pass: baseline RPS ratio {:.4}, current RPS ratio {:.4} ({:+.1}%), p99 ratio {:.4} -> {:.4} ({:+.1}%), OxiBelt RPS {oxibelt_rps_delta:+.1}%, OxiBelt p99 {oxibelt_p99_delta:+.1}%, comparator RPS {comparator_rps_delta:+.1}%, comparator p99 {comparator_p99_delta:+.1}%",
      baseline_report_label(baseline),
      throughput_ratio_delta.before_ratio,
      throughput_ratio_delta.after_ratio,
      throughput_ratio_delta.ratio_delta_percent,
      p99_ratio_delta.before_ratio,
      p99_ratio_delta.after_ratio,
      p99_ratio_delta.ratio_delta_percent,
    ))
  }
}

fn classify_baseline_stable_ratio_threshold_miss(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  miss: BaselineStableRatioMiss<'_>,
  allow_statistical_comparator_shift: bool,
) -> GateDisposition {
  if let Some(decision) = classify_statistical_ratio_threshold_miss(
    aggregates,
    baseline,
    miss.oxibelt_scenario,
    miss.comparator,
    miss.comparator_scenario,
    allow_statistical_comparator_shift,
  ) {
    return decision;
  }

  let near_target_floor = miss.threshold - miss.policy.near_target_tolerance;
  let comparator_shift_floor = miss.threshold - miss.policy.comparator_shift_tolerance;
  if miss.current_ratio < comparator_shift_floor {
    return GateDisposition::blocking(format!(
      "baseline-stable advisory unavailable: current RPS ratio {:.4} is below comparator-shift advisory floor {:.4}",
      miss.current_ratio, comparator_shift_floor
    ));
  }

  let oxibelt_rps_delta = match baseline_metric_delta_percent(
    aggregates,
    baseline,
    Comparator::Oxibelt,
    "oxibelt",
    miss.oxibelt_scenario,
    GateMetric::Rps,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };
  let oxibelt_p99_delta = match baseline_metric_delta_percent(
    aggregates,
    baseline,
    Comparator::Oxibelt,
    "oxibelt",
    miss.oxibelt_scenario,
    GateMetric::P99,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };
  let comparator_rps_delta = match baseline_metric_delta_percent(
    aggregates,
    baseline,
    miss.comparator,
    miss.comparator.as_str(),
    miss.comparator_scenario,
    GateMetric::Rps,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };
  let comparator_p99_delta = match baseline_metric_delta_percent(
    aggregates,
    baseline,
    miss.comparator,
    miss.comparator.as_str(),
    miss.comparator_scenario,
    GateMetric::P99,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };
  let throughput_ratio_delta = match baseline_metric_ratio_delta_percent(
    aggregates,
    baseline,
    miss.oxibelt_scenario,
    miss.comparator,
    miss.comparator_scenario,
    GateMetric::Rps,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };
  let p99_ratio_delta = match baseline_metric_ratio_delta_percent(
    aggregates,
    baseline,
    miss.oxibelt_scenario,
    miss.comparator,
    miss.comparator_scenario,
    GateMetric::P99,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };

  let baseline_ratio_passed = throughput_ratio_delta.before_ratio >= miss.threshold;
  let near_target_advisory = miss.current_ratio >= near_target_floor
    && baseline_ratio_passed
    && throughput_ratio_delta.ratio_delta_percent >= BASELINE_RPS_REGRESSION_TOLERANCE_PERCENT
    && p99_ratio_delta.ratio_delta_percent <= BASELINE_P99_REGRESSION_TOLERANCE_PERCENT;
  let comparator_shift_advisory = baseline_ratio_passed
    && oxibelt_rps_delta >= BASELINE_RPS_REGRESSION_TOLERANCE_PERCENT
    && (oxibelt_p99_delta <= BASELINE_P99_REGRESSION_TOLERANCE_PERCENT
      || p99_ratio_delta.ratio_delta_percent <= BASELINE_P99_REGRESSION_TOLERANCE_PERCENT);

  if near_target_advisory {
    GateDisposition::advisory(format!(
      "near-target ratio miss from `{}`: current RPS ratio {:.4} is within {:.4} of threshold {:.4}, baseline RPS ratio {:.4} >= threshold, current RPS ratio {:.4} ({:+.1}%), p99 ratio {:.4} -> {:.4} ({:+.1}%), OxiBelt RPS {oxibelt_rps_delta:+.1}%, OxiBelt p99 {oxibelt_p99_delta:+.1}%, comparator RPS {comparator_rps_delta:+.1}%, comparator p99 {comparator_p99_delta:+.1}%",
      baseline_report_label(baseline),
      miss.current_ratio,
      miss.policy.near_target_tolerance,
      miss.threshold,
      throughput_ratio_delta.before_ratio,
      throughput_ratio_delta.after_ratio,
      throughput_ratio_delta.ratio_delta_percent,
      p99_ratio_delta.before_ratio,
      p99_ratio_delta.after_ratio,
      p99_ratio_delta.ratio_delta_percent,
    ))
  } else if comparator_shift_advisory {
    GateDisposition::advisory(format!(
      "comparator-shift ratio miss from `{}`: current RPS ratio {:.4} is within {:.4} of threshold {:.4}, baseline RPS ratio {:.4} >= threshold, OxiBelt RPS {oxibelt_rps_delta:+.1}% remains within tolerance, p99 evidence remains stable (OxiBelt p99 {oxibelt_p99_delta:+.1}%, p99 ratio {:+.1}%), comparator RPS {comparator_rps_delta:+.1}% and p99 {comparator_p99_delta:+.1}%, current RPS ratio {:.4} ({:+.1}%), p99 ratio {:.4} -> {:.4}",
      baseline_report_label(baseline),
      miss.current_ratio,
      miss.policy.comparator_shift_tolerance,
      miss.threshold,
      throughput_ratio_delta.before_ratio,
      p99_ratio_delta.ratio_delta_percent,
      throughput_ratio_delta.after_ratio,
      throughput_ratio_delta.ratio_delta_percent,
      p99_ratio_delta.before_ratio,
      p99_ratio_delta.after_ratio,
    ))
  } else {
    GateDisposition::blocking(format!(
      "baseline evidence from `{}` did not qualify for baseline-stable advisory pass: baseline RPS ratio {:.4}, current RPS ratio {:.4} ({:+.1}%), near-target floor {:.4}, comparator-shift floor {:.4}, p99 ratio {:.4} -> {:.4} ({:+.1}%), OxiBelt RPS {oxibelt_rps_delta:+.1}%, OxiBelt p99 {oxibelt_p99_delta:+.1}%, comparator RPS {comparator_rps_delta:+.1}%, comparator p99 {comparator_p99_delta:+.1}%",
      baseline_report_label(baseline),
      throughput_ratio_delta.before_ratio,
      throughput_ratio_delta.after_ratio,
      throughput_ratio_delta.ratio_delta_percent,
      near_target_floor,
      comparator_shift_floor,
      p99_ratio_delta.before_ratio,
      p99_ratio_delta.after_ratio,
      p99_ratio_delta.ratio_delta_percent,
    ))
  }
}

fn classify_absolute_rps_threshold_miss(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  scenario: &str,
) -> GateDisposition {
  if let Some(decision) = classify_statistical_oxibelt_row(aggregates, baseline, scenario) {
    return decision;
  }

  let rps_delta = match baseline_metric_delta_percent(
    aggregates,
    baseline,
    Comparator::Oxibelt,
    "oxibelt",
    scenario,
    GateMetric::Rps,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };
  let p99_delta = match baseline_metric_delta_percent(
    aggregates,
    baseline,
    Comparator::Oxibelt,
    "oxibelt",
    scenario,
    GateMetric::P99,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };

  if rps_delta >= BASELINE_RPS_REGRESSION_TOLERANCE_PERCENT
    && p99_delta <= BASELINE_P99_REGRESSION_TOLERANCE_PERCENT
  {
    GateDisposition::advisory(format!(
      "baseline-stable OxiBelt row from `{}`: RPS {rps_delta:+.1}%, p99 {p99_delta:+.1}%",
      baseline_report_label(baseline)
    ))
  } else {
    GateDisposition::blocking(format!(
      "baseline evidence from `{}` did not qualify for advisory pass: OxiBelt RPS {rps_delta:+.1}%, p99 {p99_delta:+.1}%",
      baseline_report_label(baseline)
    ))
  }
}

fn classify_p99_ratio_threshold_miss(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  monitor_scenario: &str,
  enforcing_scenario: &str,
) -> GateDisposition {
  if let Some(decision) = classify_statistical_oxibelt_row(aggregates, baseline, enforcing_scenario)
  {
    return decision;
  }

  let enforcing_p99_delta = match baseline_metric_delta_percent(
    aggregates,
    baseline,
    Comparator::Oxibelt,
    "oxibelt",
    enforcing_scenario,
    GateMetric::P99,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };
  let monitor_p99_delta = match baseline_metric_delta_percent(
    aggregates,
    baseline,
    Comparator::Oxibelt,
    "oxibelt",
    monitor_scenario,
    GateMetric::P99,
  ) {
    Ok(value) => value,
    Err(error) => return baseline_unavailable_blocking(error),
  };

  if enforcing_p99_delta <= BASELINE_P99_REGRESSION_TOLERANCE_PERCENT
    && monitor_p99_delta <= BASELINE_MONITOR_P99_IMPROVEMENT_PERCENT
  {
    GateDisposition::advisory(format!(
      "baseline monitor p99 shift from `{}`: enforcing p99 {enforcing_p99_delta:+.1}%, monitor p99 {monitor_p99_delta:+.1}%",
      baseline_report_label(baseline)
    ))
  } else {
    GateDisposition::blocking(format!(
      "baseline evidence from `{}` did not qualify for advisory pass: enforcing p99 {enforcing_p99_delta:+.1}%, monitor p99 {monitor_p99_delta:+.1}%",
      baseline_report_label(baseline)
    ))
  }
}

fn baseline_unavailable_blocking(error: String) -> GateDisposition {
  GateDisposition::blocking(format!("baseline-aware advisory unavailable: {error}"))
}

fn classify_statistical_oxibelt_row(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  scenario: &str,
) -> Option<GateDisposition> {
  classify_statistical_ratio_threshold_miss(
    aggregates,
    baseline,
    scenario,
    Comparator::Oxibelt,
    scenario,
    false,
  )
}

fn classify_statistical_ratio_threshold_miss(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  scenario: &str,
  comparator: Comparator,
  comparator_scenario: &str,
  allow_statistical_comparator_shift: bool,
) -> Option<GateDisposition> {
  let baseline = baseline?;
  let current = aggregates.get(&(Comparator::Oxibelt, scenario.to_owned()))?;
  let previous = baseline
    .aggregates
    .get(&("oxibelt".to_owned(), scenario.to_owned()))?;
  let stat_band = build_stat_band_report(previous, current, baseline)?;
  let stable = stat_band.status == "stable";
  let reason = if stable {
    format!(
      "statistical baseline band from `{}` keeps OxiBelt stable: RPS median {}, RPS p10 {}, p99 median {}, p99 p90 {}; comparator-driven threshold miss is advisory",
      baseline.report,
      format_percent(stat_band.rps_median_delta_percent),
      format_percent(stat_band.rps_p10_delta_percent),
      format_percent(stat_band.p99_median_delta_percent),
      format_percent(stat_band.p99_p90_delta_percent),
    )
  } else if allow_statistical_comparator_shift {
    if let Some(reason) = statistical_shared_comparator_shift_reason(
      aggregates,
      baseline,
      scenario,
      comparator,
      comparator_scenario,
      &stat_band,
    ) {
      return Some(GateDisposition::statistical(
        false,
        reason,
        stat_band,
        Some(baseline.report.clone()),
      ));
    }
    format!(
      "statistical baseline band from `{}` found material OxiBelt regression: RPS median {}, RPS p10 {}, p99 median {}, p99 p90 {}",
      baseline.report,
      format_percent(stat_band.rps_median_delta_percent),
      format_percent(stat_band.rps_p10_delta_percent),
      format_percent(stat_band.p99_median_delta_percent),
      format_percent(stat_band.p99_p90_delta_percent),
    )
  } else {
    format!(
      "statistical baseline band from `{}` found material OxiBelt regression: RPS median {}, RPS p10 {}, p99 median {}, p99 p90 {}",
      baseline.report,
      format_percent(stat_band.rps_median_delta_percent),
      format_percent(stat_band.rps_p10_delta_percent),
      format_percent(stat_band.p99_median_delta_percent),
      format_percent(stat_band.p99_p90_delta_percent),
    )
  };
  Some(GateDisposition::statistical(
    !stable,
    reason,
    stat_band,
    Some(baseline.report.clone()),
  ))
}

fn statistical_shared_comparator_shift_reason(
  aggregates: &PrimaryAggregateMap,
  baseline: &BaselineGateContext,
  oxibelt_scenario: &str,
  comparator: Comparator,
  comparator_scenario: &str,
  stat_band: &StatBandReport,
) -> Option<String> {
  let comparator_rps_delta = baseline_metric_delta_percent(
    aggregates,
    Some(baseline),
    comparator,
    comparator.as_str(),
    comparator_scenario,
    GateMetric::Rps,
  )
  .ok()?;
  let comparator_p99_delta = baseline_metric_delta_percent(
    aggregates,
    Some(baseline),
    comparator,
    comparator.as_str(),
    comparator_scenario,
    GateMetric::P99,
  )
  .ok()?;
  let throughput_ratio_delta = baseline_metric_ratio_delta_percent(
    aggregates,
    Some(baseline),
    oxibelt_scenario,
    comparator,
    comparator_scenario,
    GateMetric::Rps,
  )
  .ok()?;
  let p99_ratio_delta = baseline_metric_ratio_delta_percent(
    aggregates,
    Some(baseline),
    oxibelt_scenario,
    comparator,
    comparator_scenario,
    GateMetric::P99,
  )
  .ok()?;

  let comparator_rps_fell = comparator_rps_delta <= BASELINE_RPS_REGRESSION_TOLERANCE_PERCENT;
  let rps_ratio_is_stable =
    throughput_ratio_delta.ratio_delta_percent >= BASELINE_RPS_REGRESSION_TOLERANCE_PERCENT;
  let p99_ratio_is_stable =
    p99_ratio_delta.ratio_delta_percent <= BASELINE_P99_REGRESSION_TOLERANCE_PERCENT;

  let comparator_name = comparator.as_str();
  if comparator_rps_fell && rps_ratio_is_stable && p99_ratio_is_stable {
    return Some(format!(
      "statistical baseline band from `{}` saw shared {comparator_name} shift: RPS median {}, RPS p10 {}, p99 median {}, p99 p90 {}; {comparator_name} RPS {comparator_rps_delta:+.1}% and p99 {comparator_p99_delta:+.1}%, RPS ratio {:.4} -> {:.4} ({:+.1}%), p99 ratio {:.4} -> {:.4} ({:+.1}%); comparator-driven threshold miss is advisory",
      baseline.report,
      format_percent(stat_band.rps_median_delta_percent),
      format_percent(stat_band.rps_p10_delta_percent),
      format_percent(stat_band.p99_median_delta_percent),
      format_percent(stat_band.p99_p90_delta_percent),
      throughput_ratio_delta.before_ratio,
      throughput_ratio_delta.after_ratio,
      throughput_ratio_delta.ratio_delta_percent,
      p99_ratio_delta.before_ratio,
      p99_ratio_delta.after_ratio,
      p99_ratio_delta.ratio_delta_percent,
    ));
  }

  let comparator_rps_rose_materially =
    comparator_rps_delta >= COMPARATOR_RPS_MATERIAL_IMPROVEMENT_PERCENT;
  let rps_ratio_fell = throughput_ratio_delta.ratio_delta_percent < 0.0;
  let oxibelt_central_evidence_is_stable = stat_band
    .rps_median_delta_percent
    .is_some_and(|delta| delta >= BASELINE_RPS_REGRESSION_TOLERANCE_PERCENT)
    && stat_band
      .rps_p10_delta_percent
      .is_some_and(|delta| delta >= STAT_BAND_RPS_P10_REGRESSION_TOLERANCE_PERCENT)
    && stat_band
      .p99_median_delta_percent
      .is_some_and(|delta| delta <= BASELINE_P99_REGRESSION_TOLERANCE_PERCENT);

  if !comparator_rps_rose_materially || !rps_ratio_fell || !oxibelt_central_evidence_is_stable {
    return None;
  }

  Some(format!(
    "statistical baseline band from `{}` saw {comparator_name} outpace stable OxiBelt: RPS median {}, RPS p10 {}, p99 median {}, p99 p90 {}; {comparator_name} RPS {comparator_rps_delta:+.1}% and p99 {comparator_p99_delta:+.1}%, RPS ratio {:.4} -> {:.4} ({:+.1}%), p99 ratio {:.4} -> {:.4} ({:+.1}%); comparator-driven threshold miss is advisory",
    baseline.report,
    format_percent(stat_band.rps_median_delta_percent),
    format_percent(stat_band.rps_p10_delta_percent),
    format_percent(stat_band.p99_median_delta_percent),
    format_percent(stat_band.p99_p90_delta_percent),
    throughput_ratio_delta.before_ratio,
    throughput_ratio_delta.after_ratio,
    throughput_ratio_delta.ratio_delta_percent,
    p99_ratio_delta.before_ratio,
    p99_ratio_delta.after_ratio,
    p99_ratio_delta.ratio_delta_percent,
  ))
}

fn build_stat_band_report(
  baseline: &AggregateStats,
  current: &AggregateStats,
  baseline_context: &BaselineGateContext,
) -> Option<StatBandReport> {
  build_stat_band_report_with_schema(baseline, current, baseline_context.schema_version)
}

fn build_stat_band_report_with_schema(
  baseline: &AggregateStats,
  current: &AggregateStats,
  baseline_schema_version: Option<u32>,
) -> Option<StatBandReport> {
  if baseline.distribution.shard_count == 0 || current.distribution.shard_count == 0 {
    return None;
  }

  let baseline_rps_median =
    distribution_percentile(&baseline.distribution.per_shard_median_rps, 50.0)?;
  let current_rps_median =
    distribution_percentile(&current.distribution.per_shard_median_rps, 50.0)?;
  let baseline_rps_p10 =
    distribution_percentile(&baseline.distribution.per_shard_median_rps, 10.0)?;
  let current_rps_p10 = distribution_percentile(&current.distribution.per_shard_median_rps, 10.0)?;
  let baseline_p99_median =
    distribution_percentile(&baseline.distribution.per_shard_median_p99_ms, 50.0)?;
  let current_p99_median =
    distribution_percentile(&current.distribution.per_shard_median_p99_ms, 50.0)?;
  let baseline_p99_p90 =
    distribution_percentile(&baseline.distribution.per_shard_median_p99_ms, 90.0)?;
  let current_p99_p90 =
    distribution_percentile(&current.distribution.per_shard_median_p99_ms, 90.0)?;

  let rps_median_delta_percent = percent_delta(Some(baseline_rps_median), Some(current_rps_median));
  let rps_p10_delta_percent = percent_delta(Some(baseline_rps_p10), Some(current_rps_p10));
  let p99_median_delta_percent = percent_delta(Some(baseline_p99_median), Some(current_p99_median));
  let p99_p90_delta_percent = percent_delta(Some(baseline_p99_p90), Some(current_p99_p90));
  let stable = rps_median_delta_percent
    .is_some_and(|delta| delta >= BASELINE_RPS_REGRESSION_TOLERANCE_PERCENT)
    && rps_p10_delta_percent
      .is_some_and(|delta| delta >= STAT_BAND_RPS_P10_REGRESSION_TOLERANCE_PERCENT)
    && p99_median_delta_percent
      .is_some_and(|delta| delta <= BASELINE_P99_REGRESSION_TOLERANCE_PERCENT)
    && p99_p90_delta_percent
      .is_some_and(|delta| delta <= STAT_BAND_P99_P90_REGRESSION_TOLERANCE_PERCENT);

  Some(StatBandReport {
    mode: "per_shard_median_distribution".to_owned(),
    status: if stable { "stable" } else { "regression" }.to_owned(),
    baseline_schema_version,
    baseline_shards: baseline.distribution.shard_count,
    current_shards: current.distribution.shard_count,
    baseline_samples: baseline.distribution.sample_count,
    current_samples: current.distribution.sample_count,
    rps_median_delta_percent,
    rps_p10_delta_percent,
    p99_median_delta_percent,
    p99_p90_delta_percent,
    rps_median_min_delta_percent: BASELINE_RPS_REGRESSION_TOLERANCE_PERCENT,
    rps_p10_min_delta_percent: STAT_BAND_RPS_P10_REGRESSION_TOLERANCE_PERCENT,
    p99_median_max_delta_percent: BASELINE_P99_REGRESSION_TOLERANCE_PERCENT,
    p99_p90_max_delta_percent: STAT_BAND_P99_P90_REGRESSION_TOLERANCE_PERCENT,
  })
}

fn baseline_report_label(baseline: Option<&BaselineGateContext>) -> &str {
  baseline
    .map(|context| context.report.as_str())
    .unwrap_or("-")
}

fn baseline_metric_delta_percent(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  current_comparator: Comparator,
  baseline_comparator: &str,
  scenario: &str,
  metric: GateMetric,
) -> std::result::Result<f64, String> {
  let baseline =
    baseline.ok_or_else(|| "no baseline performance report was provided".to_owned())?;
  let metric_name = metric.name();
  let before = baseline
    .aggregates
    .get(&(baseline_comparator.to_owned(), scenario.to_owned()))
    .and_then(|aggregate| metric.value(aggregate))
    .ok_or_else(|| format!("missing baseline {baseline_comparator} {scenario} {metric_name}"))?;
  let after = aggregates
    .get(&(current_comparator, scenario.to_owned()))
    .and_then(|aggregate| metric.value(aggregate))
    .ok_or_else(|| {
      format!(
        "missing current {} {scenario} {metric_name}",
        current_comparator.as_str()
      )
    })?;
  if before <= 0.0 {
    return Err(format!(
      "baseline {baseline_comparator} {scenario} {metric_name} must be positive; got {before:.3}"
    ));
  }
  Ok(((after - before) / before) * 100.0)
}

fn baseline_metric_ratio_delta_percent(
  aggregates: &PrimaryAggregateMap,
  baseline: Option<&BaselineGateContext>,
  oxibelt_scenario: &str,
  comparator: Comparator,
  comparator_scenario: &str,
  metric: GateMetric,
) -> std::result::Result<MetricRatioDelta, String> {
  let baseline =
    baseline.ok_or_else(|| "no baseline performance report was provided".to_owned())?;
  let before_oxibelt = baseline_gate_metric(baseline, "oxibelt", oxibelt_scenario, metric)?;
  let before_comparator =
    baseline_gate_metric(baseline, comparator.as_str(), comparator_scenario, metric)?;
  let after_oxibelt =
    current_gate_metric(aggregates, Comparator::Oxibelt, oxibelt_scenario, metric)?;
  let after_comparator = current_gate_metric(aggregates, comparator, comparator_scenario, metric)?;

  let before_ratio = before_oxibelt / before_comparator;
  let after_ratio = after_oxibelt / after_comparator;
  Ok(MetricRatioDelta {
    before_ratio,
    after_ratio,
    ratio_delta_percent: ((after_ratio - before_ratio) / before_ratio) * 100.0,
  })
}

fn baseline_gate_metric(
  baseline: &BaselineGateContext,
  comparator: &str,
  scenario: &str,
  metric: GateMetric,
) -> std::result::Result<f64, String> {
  let metric_name = metric.name();
  let value = baseline
    .aggregates
    .get(&(comparator.to_owned(), scenario.to_owned()))
    .and_then(|aggregate| metric.value(aggregate))
    .ok_or_else(|| format!("missing baseline {comparator} {scenario} {metric_name}"))?;
  if value <= 0.0 {
    return Err(format!(
      "baseline {comparator} {scenario} {metric_name} must be positive; got {value:.3}"
    ));
  }
  Ok(value)
}

fn current_gate_metric(
  aggregates: &PrimaryAggregateMap,
  comparator: Comparator,
  scenario: &str,
  metric: GateMetric,
) -> std::result::Result<f64, String> {
  let metric_name = metric.name();
  let value = aggregates
    .get(&(comparator, scenario.to_owned()))
    .and_then(|aggregate| metric.value(aggregate))
    .ok_or_else(|| {
      format!(
        "missing current {} {scenario} {metric_name}",
        comparator.as_str()
      )
    })?;
  if value <= 0.0 {
    return Err(format!(
      "current {} {scenario} {metric_name} must be positive; got {value:.3}",
      comparator.as_str()
    ));
  }
  Ok(value)
}

impl GateMetric {
  fn name(self) -> &'static str {
    match self {
      Self::Rps => "median RPS",
      Self::P99 => "median p99",
    }
  }

  fn value(self, aggregate: &AggregateStats) -> Option<f64> {
    match self {
      Self::Rps => aggregate.median_rps,
      Self::P99 => aggregate.median_p99_ms,
    }
  }
}

fn aggregate_median_rps(
  aggregates: &PrimaryAggregateMap,
  comparator: Comparator,
  scenario: &str,
) -> Option<f64> {
  aggregates
    .get(&(comparator, scenario.to_owned()))
    .and_then(|aggregate| aggregate.median_rps)
}

fn aggregate_median_p99(
  aggregates: &PrimaryAggregateMap,
  comparator: Comparator,
  scenario: &str,
) -> Option<f64> {
  aggregates
    .get(&(comparator, scenario.to_owned()))
    .and_then(|aggregate| aggregate.median_p99_ms)
}

fn summarize_group(comparisons: &[ScenarioComparison]) -> GroupSummary {
  GroupSummary {
    scenarios: comparisons.len(),
    oxibelt_vs_nginx: summarize_ratios(
      comparisons
        .iter()
        .filter_map(|comparison| comparison.oxibelt_vs_nginx.ratio),
      comparisons.len(),
    ),
    oxibelt_vs_caddy: summarize_ratios(
      comparisons
        .iter()
        .filter_map(|comparison| comparison.oxibelt_vs_caddy.ratio),
      comparisons.len(),
    ),
    oxibelt_vs_openresty: summarize_ratios(
      comparisons
        .iter()
        .filter_map(|comparison| comparison.oxibelt_vs_openresty.ratio),
      comparisons.len(),
    ),
  }
}

fn summarize_accept_multiplier_comparisons(
  comparisons: &[AcceptMultiplierComparison],
) -> AcceptMultiplierSummary {
  let mut values = comparisons
    .iter()
    .filter_map(|comparison| comparison.accept_1_0_vs_0_5.ratio)
    .collect::<Vec<_>>();
  let median_ratio = percentile(&mut values, 50.0);
  AcceptMultiplierSummary {
    scenario_count: comparisons.len(),
    valid_comparisons: values.len(),
    median_ratio,
    median_percent_of_accept_0_5: median_ratio.map(|ratio| ratio * 100.0),
  }
}

fn summarize_remote_signer_comparisons(
  comparisons: &[RemoteSignerComparison],
) -> RemoteSignerSummary {
  let mut throughput_values = comparisons
    .iter()
    .filter_map(|comparison| comparison.remote_signer_vs_local_key.throughput_ratio)
    .collect::<Vec<_>>();
  let mut p99_values = comparisons
    .iter()
    .filter_map(|comparison| comparison.remote_signer_vs_local_key.p99_ratio)
    .collect::<Vec<_>>();
  let median_throughput_ratio = percentile(&mut throughput_values, 50.0);
  let median_p99_ratio = percentile(&mut p99_values, 50.0);
  RemoteSignerSummary {
    scenario_count: comparisons.len(),
    valid_comparisons: throughput_values.len(),
    median_throughput_ratio,
    median_throughput_percent_of_local_key: median_throughput_ratio.map(|ratio| ratio * 100.0),
    median_p99_ratio,
    median_p99_percent_of_local_key: median_p99_ratio.map(|ratio| ratio * 100.0),
  }
}

fn summarize_ratios(values: impl Iterator<Item = f64>, scenario_count: usize) -> RatioSummary {
  let mut values = values.collect::<Vec<_>>();
  let median_ratio = percentile(&mut values, 50.0);
  RatioSummary {
    scenario_count,
    valid_comparisons: values.len(),
    median_ratio,
    median_percent_of_comparator: median_ratio.map(|ratio| ratio * 100.0),
  }
}

fn skipped_or_missing_rows(
  reverse_proxy: &[ScenarioComparison],
  static_files: &[ScenarioComparison],
) -> Vec<MissingComparatorRow> {
  let mut rows = Vec::new();
  for comparison in reverse_proxy.iter().chain(static_files.iter()) {
    collect_missing_row(
      comparison,
      Comparator::Nginx,
      &comparison.oxibelt_vs_nginx,
      &mut rows,
    );
    collect_missing_row(
      comparison,
      Comparator::Caddy,
      &comparison.oxibelt_vs_caddy,
      &mut rows,
    );
    collect_missing_row(
      comparison,
      Comparator::OpenResty,
      &comparison.oxibelt_vs_openresty,
      &mut rows,
    );
  }
  rows
}

fn collect_missing_row(
  comparison: &ScenarioComparison,
  comparator: Comparator,
  ratio: &RatioResult,
  rows: &mut Vec<MissingComparatorRow>,
) {
  if ratio.status == "ok" {
    return;
  }
  rows.push(MissingComparatorRow {
    amd64_target_cpu: comparison.amd64_target_cpu.clone(),
    group: comparison.group.clone(),
    scenario: comparison.scenario.clone(),
    comparator: comparator.as_str().to_owned(),
    status: ratio.status.clone(),
    reason: ratio.reason.clone().unwrap_or_else(|| ratio.text.clone()),
  });
}

fn build_delta_report(baseline_report: &Path, current: &Report) -> DeltaReport {
  let baseline_label = baseline_report.display().to_string();
  let baseline = match fs::read_to_string(baseline_report)
    .map_err(|error| error.to_string())
    .and_then(|raw| serde_json::from_str::<BaselineReport>(&raw).map_err(|error| error.to_string()))
  {
    Ok(report) => report,
    Err(error) => {
      return DeltaReport {
        schema_version: DELTA_SCHEMA_VERSION,
        baseline_report: baseline_label,
        summary: DeltaSummary::default(),
        rows: Vec::new(),
        warnings: vec![format!(
          "failed to read baseline performance report: {error}"
        )],
      };
    }
  };

  let baseline_schema_version = baseline.schema_version;
  let baseline_map = aggregate_lookup(&baseline.aggregates, &current.primary_target_cpu);
  let current_map = aggregate_lookup(&current.aggregates, &current.primary_target_cpu);
  let mut rows = Vec::new();
  collect_delta_rows(
    &current.comparisons.reverse_proxy,
    &current.primary_target_cpu,
    Comparator::Nginx,
    &baseline_map,
    &current_map,
    baseline_schema_version,
    &mut rows,
  );
  collect_delta_rows(
    &current.comparisons.reverse_proxy,
    &current.primary_target_cpu,
    Comparator::Caddy,
    &baseline_map,
    &current_map,
    baseline_schema_version,
    &mut rows,
  );
  collect_delta_rows(
    &current.comparisons.reverse_proxy,
    &current.primary_target_cpu,
    Comparator::OpenResty,
    &baseline_map,
    &current_map,
    baseline_schema_version,
    &mut rows,
  );
  collect_delta_rows(
    &current.comparisons.static_files,
    &current.primary_target_cpu,
    Comparator::Nginx,
    &baseline_map,
    &current_map,
    baseline_schema_version,
    &mut rows,
  );
  collect_delta_rows(
    &current.comparisons.static_files,
    &current.primary_target_cpu,
    Comparator::Caddy,
    &baseline_map,
    &current_map,
    baseline_schema_version,
    &mut rows,
  );
  collect_delta_rows(
    &current.comparisons.static_files,
    &current.primary_target_cpu,
    Comparator::OpenResty,
    &baseline_map,
    &current_map,
    baseline_schema_version,
    &mut rows,
  );

  DeltaReport {
    schema_version: DELTA_SCHEMA_VERSION,
    baseline_report: baseline_label,
    summary: summarize_delta_rows(&rows),
    rows,
    warnings: Vec::new(),
  }
}

fn aggregate_lookup<'a>(
  aggregates: &'a [AggregateStats],
  primary_target_cpu: &str,
) -> BTreeMap<(String, String), &'a AggregateStats> {
  aggregates
    .iter()
    .filter(|aggregate| aggregate.amd64_target_cpu == primary_target_cpu)
    .map(|aggregate| {
      (
        (aggregate.comparator.clone(), aggregate.scenario.clone()),
        aggregate,
      )
    })
    .collect()
}

struct DeltaRowInput<'a> {
  amd64_target_cpu: &'a str,
  group: &'a str,
  scenario: &'a str,
  comparator: &'a str,
  before_oxibelt: Option<&'a AggregateStats>,
  after_oxibelt: Option<&'a AggregateStats>,
  before_comparator: Option<&'a AggregateStats>,
  after_comparator: Option<&'a AggregateStats>,
  baseline_schema_version: Option<u32>,
}

fn collect_delta_rows(
  comparisons: &[ScenarioComparison],
  primary_target_cpu: &str,
  comparator: Comparator,
  baseline: &BTreeMap<(String, String), &AggregateStats>,
  current: &BTreeMap<(String, String), &AggregateStats>,
  baseline_schema_version: Option<u32>,
  rows: &mut Vec<PerformanceDeltaRow>,
) {
  let comparator_name = comparator.as_str();
  for comparison in comparisons {
    if comparison.amd64_target_cpu != primary_target_cpu {
      continue;
    }
    let oxibelt_key = ("oxibelt".to_owned(), comparison.scenario.clone());
    let comparator_key = (comparator_name.to_owned(), comparison.scenario.clone());
    rows.push(delta_row(DeltaRowInput {
      amd64_target_cpu: &comparison.amd64_target_cpu,
      group: &comparison.group,
      scenario: &comparison.scenario,
      comparator: comparator_name,
      before_oxibelt: baseline.get(&oxibelt_key).copied(),
      after_oxibelt: current.get(&oxibelt_key).copied(),
      before_comparator: baseline.get(&comparator_key).copied(),
      after_comparator: current.get(&comparator_key).copied(),
      baseline_schema_version,
    }));
  }
}

fn delta_row(input: DeltaRowInput<'_>) -> PerformanceDeltaRow {
  let before_oxibelt_rps = input.before_oxibelt.and_then(|stats| stats.median_rps);
  let after_oxibelt_rps = input.after_oxibelt.and_then(|stats| stats.median_rps);
  let before_comparator_rps = input.before_comparator.and_then(|stats| stats.median_rps);
  let after_comparator_rps = input.after_comparator.and_then(|stats| stats.median_rps);
  let before_ratio = ratio(before_oxibelt_rps, before_comparator_rps);
  let after_ratio = ratio(after_oxibelt_rps, after_comparator_rps);
  let before_oxibelt_p99_ms = input.before_oxibelt.and_then(|stats| stats.median_p99_ms);
  let after_oxibelt_p99_ms = input.after_oxibelt.and_then(|stats| stats.median_p99_ms);
  let stat_band = input
    .before_oxibelt
    .zip(input.after_oxibelt)
    .and_then(|(before, after)| {
      build_stat_band_report_with_schema(before, after, input.baseline_schema_version)
    });
  let classification_source = if stat_band.is_some() {
    "statistical_band"
  } else {
    "median_delta"
  };
  let mut row = PerformanceDeltaRow {
    amd64_target_cpu: input.amd64_target_cpu.to_owned(),
    group: input.group.to_owned(),
    scenario: input.scenario.to_owned(),
    comparator: input.comparator.to_owned(),
    before_oxibelt_rps,
    after_oxibelt_rps,
    oxibelt_rps_delta_percent: percent_delta(before_oxibelt_rps, after_oxibelt_rps),
    before_comparator_rps,
    after_comparator_rps,
    comparator_rps_delta_percent: percent_delta(before_comparator_rps, after_comparator_rps),
    before_ratio,
    after_ratio,
    ratio_delta_percent: percent_delta(before_ratio, after_ratio),
    before_oxibelt_p99_ms,
    after_oxibelt_p99_ms,
    oxibelt_p99_delta_percent: percent_delta(before_oxibelt_p99_ms, after_oxibelt_p99_ms),
    classification_source: classification_source.to_owned(),
    stat_band,
    classification: String::new(),
    reason: String::new(),
  };
  let (classification, reason) = classify_delta_row(&row);
  row.classification = classification.to_owned();
  row.reason = reason;
  row
}

fn ratio(oxibelt: Option<f64>, comparator: Option<f64>) -> Option<f64> {
  match (oxibelt, comparator) {
    (Some(oxibelt), Some(comparator)) if comparator > 0.0 => Some(oxibelt / comparator),
    _ => None,
  }
}

fn percent_delta(before: Option<f64>, after: Option<f64>) -> Option<f64> {
  match (before, after) {
    (Some(before), Some(after)) if before > 0.0 => Some(((after - before) / before) * 100.0),
    _ => None,
  }
}

fn classify_delta_row(row: &PerformanceDeltaRow) -> (&'static str, String) {
  let Some(oxibelt_rps_delta) = row.oxibelt_rps_delta_percent else {
    return (
      "incomplete",
      "missing OxiBelt baseline or current RPS".to_owned(),
    );
  };
  let Some(comparator_rps_delta) = row.comparator_rps_delta_percent else {
    return (
      "incomplete",
      "missing comparator baseline or current RPS".to_owned(),
    );
  };
  let Some(ratio_delta) = row.ratio_delta_percent else {
    return (
      "incomplete",
      "missing baseline or current ratio denominator".to_owned(),
    );
  };
  let oxibelt_p99_delta = row.oxibelt_p99_delta_percent.unwrap_or(0.0);
  let oxibelt_regressed = oxibelt_rps_delta <= -3.0 || oxibelt_p99_delta >= 5.0;
  let ratio_regressed = ratio_delta < -0.5;
  let comparator_improved = comparator_rps_delta >= 3.0;

  if ratio_regressed && oxibelt_regressed && comparator_improved {
    (
      "mixed",
      format!(
        "OxiBelt changed {oxibelt_rps_delta:.1}% RPS / {oxibelt_p99_delta:.1}% p99 while comparator changed {comparator_rps_delta:.1}% RPS"
      ),
    )
  } else if oxibelt_regressed {
    (
      "oxibelt_regression",
      format!("OxiBelt changed {oxibelt_rps_delta:.1}% RPS / {oxibelt_p99_delta:.1}% p99"),
    )
  } else if ratio_regressed && comparator_improved {
    (
      "comparator_shift",
      format!(
        "ratio fell {ratio_delta:.1}% while OxiBelt held {oxibelt_rps_delta:.1}% RPS and comparator rose {comparator_rps_delta:.1}%"
      ),
    )
  } else if ratio_regressed {
    (
      "mixed",
      format!(
        "ratio fell {ratio_delta:.1}% with OxiBelt at {oxibelt_rps_delta:.1}% RPS and comparator at {comparator_rps_delta:.1}%"
      ),
    )
  } else if ratio_delta >= 0.5 || oxibelt_rps_delta >= 3.0 || oxibelt_p99_delta <= -5.0 {
    (
      "improvement",
      format!(
        "ratio changed {ratio_delta:.1}% and OxiBelt changed {oxibelt_rps_delta:.1}% RPS / {oxibelt_p99_delta:.1}% p99"
      ),
    )
  } else {
    (
      "stable",
      format!(
        "ratio changed {ratio_delta:.1}% and OxiBelt changed {oxibelt_rps_delta:.1}% RPS / {oxibelt_p99_delta:.1}% p99"
      ),
    )
  }
}

fn summarize_delta_rows(rows: &[PerformanceDeltaRow]) -> DeltaSummary {
  let mut summary = DeltaSummary {
    rows: rows.len(),
    ..DeltaSummary::default()
  };
  for row in rows {
    match row.classification.as_str() {
      "oxibelt_regression" => summary.oxibelt_regression += 1,
      "comparator_shift" => summary.comparator_shift += 1,
      "mixed" => summary.mixed += 1,
      "improvement" => summary.improvement += 1,
      "stable" => summary.stable += 1,
      "incomplete" => summary.incomplete += 1,
      _ => {}
    }
  }
  summary
}

fn render_markdown(report: &Report) -> String {
  let mut markdown = String::new();
  writeln!(markdown, "# OxiBelt Docker Performance Comparison\n").unwrap();
  writeln!(markdown, "## Summary\n").unwrap();
  writeln!(
    markdown,
    "- Results files parsed: `{}`",
    report.artifact_discovery.results_files
  )
  .unwrap();
  writeln!(
    markdown,
    "- External result files parsed: `{}`",
    report.artifact_discovery.external_results_files
  )
  .unwrap();
  writeln!(
    markdown,
    "- Profile result files parsed: `{}`",
    report.artifact_discovery.profile_results_files
  )
  .unwrap();
  writeln!(
    markdown,
    "- Primary AMD64 target CPU: `{}`",
    report.primary_target_cpu
  )
  .unwrap();
  if !report.expected_target_cpus.is_empty() {
    writeln!(
      markdown,
      "- Expected AMD64 target CPUs: `{}`",
      report.expected_target_cpus.join("`, `")
    )
    .unwrap();
  }
  writeln!(
    markdown,
    "- Unsupported AMD64 target artifacts: `{}`",
    report.artifact_discovery.unsupported_cpu.count
  )
  .unwrap();
  if !report.artifact_discovery.unsupported_cpu.shards.is_empty() {
    writeln!(
      markdown,
      "- Unsupported AMD64 target shards excluded: `{}`",
      report
        .artifact_discovery
        .unsupported_cpu
        .shards
        .join("`, `")
    )
    .unwrap();
  }
  writeln!(
    markdown,
    "- Iteration status files parsed: `{}` ({} failed, {} diagnostic warnings)",
    report.sample_quality.iteration_status_files,
    report.sample_quality.failed_iterations,
    report.sample_quality.diagnostic_warning_iterations
  )
  .unwrap();
  writeln!(
    markdown,
    "- Sample quorum: `{}` (policy `{}`)",
    report.quorum.status, report.quorum.policy
  )
  .unwrap();
  writeln!(
    markdown,
    "- Baseline context: `{}`{}",
    report.baseline_context.status,
    report
      .baseline_context
      .schema_version
      .map(|schema| format!(" (schema `{schema}`)"))
      .unwrap_or_default()
  )
  .unwrap();
  writeln!(
    markdown,
    "- Reverse proxy vs nginx: {}",
    format_ratio_summary(&report.summary.reverse_proxy.oxibelt_vs_nginx, "nginx")
  )
  .unwrap();
  writeln!(
    markdown,
    "- Reverse proxy vs Caddy: {}",
    format_ratio_summary(&report.summary.reverse_proxy.oxibelt_vs_caddy, "caddy")
  )
  .unwrap();
  writeln!(
    markdown,
    "- Reverse proxy vs OpenResty: {}",
    format_ratio_summary(
      &report.summary.reverse_proxy.oxibelt_vs_openresty,
      "openresty"
    )
  )
  .unwrap();
  writeln!(
    markdown,
    "- Static files vs nginx: {}",
    format_ratio_summary(&report.summary.static_files.oxibelt_vs_nginx, "nginx")
  )
  .unwrap();
  writeln!(
    markdown,
    "- Static files vs Caddy: {}",
    format_ratio_summary(&report.summary.static_files.oxibelt_vs_caddy, "caddy")
  )
  .unwrap();
  writeln!(
    markdown,
    "- Static files vs OpenResty: {}",
    format_ratio_summary(
      &report.summary.static_files.oxibelt_vs_openresty,
      "openresty"
    )
  )
  .unwrap();
  writeln!(
    markdown,
    "- Accept = 1.0 vs accept = 0.5: {}",
    format_accept_multiplier_summary(&report.summary.accept_multipliers)
  )
  .unwrap();
  writeln!(
    markdown,
    "- Remote signer vs local key: {}",
    format_remote_signer_summary(&report.summary.remote_signer)
  )
  .unwrap();
  writeln!(
    markdown,
    "- AMD64 ISA comparisons: `{}` scenario(s)",
    report.amd64_isa_comparisons.len()
  )
  .unwrap();
  writeln!(
    markdown,
    "- External benchmark rows: `{}`",
    report.summary.external_benchmark_row_count
  )
  .unwrap();
  writeln!(
    markdown,
    "- Diagnostic profiling rows: `{}`",
    report.summary.diagnostic_profile_row_count
  )
  .unwrap();
  writeln!(
    markdown,
    "- Regression gates: `{}` ({} violation(s), {} advisory/advisories)",
    report.regression_gates.status,
    report.regression_gates.violations.len(),
    report.regression_gates.advisories.len()
  )
  .unwrap();
  writeln!(
    markdown,
    "- OxiBelt-only rows: `{}`\n",
    report.summary.oxibelt_only_row_count
  )
  .unwrap();

  write_comparison_table(
    &mut markdown,
    "Reverse proxy comparison",
    &report.comparisons.reverse_proxy,
  );
  write_comparison_table(
    &mut markdown,
    "Static file comparison",
    &report.comparisons.static_files,
  );
  write_accept_multiplier_table(&mut markdown, &report.accept_multiplier_comparisons);
  write_remote_signer_table(&mut markdown, &report.remote_signer_comparisons);
  write_amd64_isa_table(&mut markdown, &report.amd64_isa_comparisons);
  write_direct_h1_pool_diagnostics_table(&mut markdown, report);
  write_direct_h2_pool_diagnostics_table(&mut markdown, report);
  write_fast_path_stage_timing_table(&mut markdown, report);
  write_external_benchmark_table(&mut markdown, &report.external_benchmarks);
  write_diagnostic_profile_table(&mut markdown, &report.profiling);
  write_oxibelt_only_table(&mut markdown, &report.oxibelt_only_results);
  write_missing_table(&mut markdown, &report.skipped_or_missing_comparator_rows);
  write_quorum_table(&mut markdown, &report.quorum);
  write_regression_gate_table(&mut markdown, &report.regression_gates);
  write_warnings(&mut markdown, report);
  markdown
}

fn write_direct_h1_pool_diagnostics_table(markdown: &mut String, report: &Report) {
  let rows = report
    .aggregates
    .iter()
    .filter(|aggregate| {
      aggregate.amd64_target_cpu == report.primary_target_cpu
        && aggregate.comparator == Comparator::Oxibelt.as_str()
        && matches!(aggregate.scenario.as_str(), "h1-keepalive" | "h2" | "h3")
    })
    .filter_map(|aggregate| {
      aggregate
        .fast_path
        .as_ref()
        .and_then(|fast_path| fast_path.direct_h1_pool.as_ref())
        .map(|pool| (aggregate.scenario.as_str(), pool))
    })
    .collect::<Vec<_>>();
  if rows.is_empty() {
    return;
  }

  writeln!(markdown, "\n## Direct-H1 pool diagnostics\n").unwrap();
  writeln!(
    markdown,
    "| Scenario | Samples | Hit | Miss | Miss % | Miss empty | Miss locked | Reconnect | Stale | Drop | Drop full | Drop locked |"
  )
  .unwrap();
  writeln!(
    markdown,
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
  )
  .unwrap();
  for (scenario, pool) in rows {
    let hit = counter_map_value(pool, "hit");
    let miss = counter_map_value(pool, "miss");
    writeln!(
      markdown,
      "| `{scenario}` | `{}` | `{hit}` | `{miss}` | {} | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |",
      pool.sample_count,
      format_pool_miss_percent(hit, miss),
      counter_map_value(pool, "miss_empty"),
      counter_map_value(pool, "miss_locked"),
      counter_map_value(pool, "reconnect"),
      counter_map_value(pool, "stale"),
      counter_map_value(pool, "drop"),
      counter_map_value(pool, "drop_full"),
      counter_map_value(pool, "drop_locked")
    )
    .unwrap();
  }
}

fn write_direct_h2_pool_diagnostics_table(markdown: &mut String, report: &Report) {
  let rows = report
    .aggregates
    .iter()
    .filter(|aggregate| {
      aggregate.amd64_target_cpu == report.primary_target_cpu
        && aggregate.comparator == Comparator::Oxibelt.as_str()
        && matches!(
          aggregate.scenario.as_str(),
          "h2-upstream-h2c" | "h2-upstream-h2"
        )
    })
    .filter_map(|aggregate| {
      aggregate
        .fast_path
        .as_ref()
        .and_then(|fast_path| fast_path.direct_h2_pool.as_ref())
        .map(|pool| (aggregate.scenario.as_str(), pool))
    })
    .collect::<Vec<_>>();
  if rows.is_empty() {
    return;
  }

  writeln!(markdown, "\n## Direct-H2 pool diagnostics\n").unwrap();
  writeln!(
    markdown,
    "| Scenario | Samples | Hit | Miss | Miss % | Miss empty | Miss saturated | Miss locked | Connect | Connect error | Reconnect | Stale | Drop |"
  )
  .unwrap();
  writeln!(
    markdown,
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
  )
  .unwrap();
  for (scenario, pool) in rows {
    let hit = counter_map_value(pool, "hit");
    let miss = counter_map_value(pool, "miss");
    writeln!(
      markdown,
      "| `{scenario}` | `{}` | `{hit}` | `{miss}` | {} | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |",
      pool.sample_count,
      format_pool_miss_percent(hit, miss),
      counter_map_value(pool, "miss_empty"),
      counter_map_value(pool, "miss_saturated"),
      counter_map_value(pool, "miss_locked"),
      counter_map_value(pool, "connect"),
      counter_map_value(pool, "connect_error"),
      counter_map_value(pool, "reconnect"),
      counter_map_value(pool, "stale"),
      counter_map_value(pool, "drop")
    )
    .unwrap();
  }
}

fn counter_map_value(stats: &CounterMapAggregateStats, name: &str) -> u64 {
  stats.values.get(name).copied().unwrap_or(0)
}

fn format_pool_miss_percent(hit: u64, miss: u64) -> String {
  let attempts = hit.saturating_add(miss);
  if attempts == 0 {
    return "`n/a`".to_owned();
  }
  format!("`{:.3}%`", (miss as f64) * 100.0 / (attempts as f64))
}

fn write_fast_path_stage_timing_table(markdown: &mut String, report: &Report) {
  let rows = report
    .aggregates
    .iter()
    .filter(|aggregate| {
      aggregate.amd64_target_cpu == report.primary_target_cpu
        && aggregate.comparator == Comparator::Oxibelt.as_str()
        && matches!(aggregate.scenario.as_str(), "h2" | "h3")
    })
    .filter_map(|aggregate| {
      aggregate
        .fast_path
        .as_ref()
        .and_then(|fast_path| fast_path.stage_timing.as_ref())
        .map(|stage_timing| (aggregate.scenario.as_str(), stage_timing))
    })
    .collect::<Vec<_>>();
  if rows.is_empty() {
    return;
  }

  writeln!(markdown, "\n## Fast-path stage timing diagnostics\n").unwrap();
  writeln!(
    markdown,
    "| Scenario | Path | Protocol | Stage | Outcome | Count | Median avg ns | Max avg ns |"
  )
  .unwrap();
  writeln!(
    markdown,
    "| --- | --- | --- | --- | --- | ---: | ---: | ---: |"
  )
  .unwrap();
  for (scenario, stage_timing) in rows {
    for (path, protocols) in stage_timing {
      for (protocol, stages) in protocols {
        for (stage, outcomes) in stages {
          for (outcome, sample) in outcomes {
            writeln!(
              markdown,
              "| `{scenario}` | `{path}` | `{protocol}` | `{stage}` | `{outcome}` | `{}` | {} | {} |",
              sample.count,
              format_optional_ns(sample.median_avg_ns),
              format_optional_ns(sample.max_avg_ns)
            )
            .unwrap();
          }
        }
      }
    }
  }
}

fn format_optional_ns(value: Option<f64>) -> String {
  value
    .map(|value| format!("`{value:.1}`"))
    .unwrap_or_else(|| "`n/a`".to_owned())
}

fn format_ratio_summary(summary: &RatioSummary, comparator: &str) -> String {
  match summary.median_ratio {
    Some(ratio) => format!(
      "{:.1}% of {comparator} ({:.2}x {comparator}, {}/{}) scenarios",
      ratio * 100.0,
      ratio,
      summary.valid_comparisons,
      summary.scenario_count
    ),
    None => format!("n/a (0/{}) scenarios", summary.scenario_count),
  }
}

fn format_accept_multiplier_summary(summary: &AcceptMultiplierSummary) -> String {
  match summary.median_ratio {
    Some(ratio) => format!(
      "{:.1}% of accept = 0.5 ({:.2}x, {}/{}) scenarios",
      ratio * 100.0,
      ratio,
      summary.valid_comparisons,
      summary.scenario_count
    ),
    None => format!("n/a (0/{}) scenarios", summary.scenario_count),
  }
}

fn format_remote_signer_summary(summary: &RemoteSignerSummary) -> String {
  match (summary.median_throughput_ratio, summary.median_p99_ratio) {
    (Some(throughput_ratio), Some(p99_ratio)) => format!(
      "{:.1}% throughput of local key ({:+.1}%), p99 {:.1}% of local key ({:+.1}%, {}/{}) scenarios",
      throughput_ratio * 100.0,
      (throughput_ratio - 1.0) * 100.0,
      p99_ratio * 100.0,
      (p99_ratio - 1.0) * 100.0,
      summary.valid_comparisons,
      summary.scenario_count
    ),
    (Some(throughput_ratio), None) => format!(
      "{:.1}% throughput of local key ({:+.1}%), p99 n/a ({}/{}) scenarios",
      throughput_ratio * 100.0,
      (throughput_ratio - 1.0) * 100.0,
      summary.valid_comparisons,
      summary.scenario_count
    ),
    _ => format!("n/a (0/{}) scenarios", summary.scenario_count),
  }
}

fn write_comparison_table(markdown: &mut String, title: &str, comparisons: &[ScenarioComparison]) {
  writeln!(markdown, "## {title}\n").unwrap();
  if comparisons.is_empty() {
    writeln!(markdown, "No comparable OxiBelt rows were found.\n").unwrap();
    return;
  }

  writeln!(
        markdown,
        "| Target CPU | Scenario | OxiBelt median rate/sec | nginx median rate/sec | OxiBelt vs nginx | Caddy median rate/sec | OxiBelt vs Caddy | OpenResty median rate/sec | OxiBelt vs OpenResty | OxiBelt median p95 ms | OxiBelt median p99 ms |"
    )
    .unwrap();
  writeln!(
    markdown,
    "| --- | --- | ---: | ---: | --- | ---: | --- | ---: | --- | ---: | ---: |"
  )
  .unwrap();
  for comparison in comparisons {
    let oxibelt = comparison.oxibelt.as_ref();
    writeln!(
      markdown,
      "| `{}` | `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
      comparison.amd64_target_cpu,
      comparison.scenario,
      format_number(oxibelt.and_then(|stats| stats.median_rps)),
      format_number(comparison.nginx.as_ref().and_then(|stats| stats.median_rps)),
      comparison.oxibelt_vs_nginx.text,
      format_number(comparison.caddy.as_ref().and_then(|stats| stats.median_rps)),
      comparison.oxibelt_vs_caddy.text,
      format_number(
        comparison
          .openresty
          .as_ref()
          .and_then(|stats| stats.median_rps)
      ),
      comparison.oxibelt_vs_openresty.text,
      format_number(oxibelt.and_then(|stats| stats.median_p95_ms)),
      format_number(oxibelt.and_then(|stats| stats.median_p99_ms)),
    )
    .unwrap();
  }
  writeln!(markdown).unwrap();
}

fn write_accept_multiplier_table(
  markdown: &mut String,
  comparisons: &[AcceptMultiplierComparison],
) {
  writeln!(markdown, "## Accept multiplier comparison\n").unwrap();
  if comparisons.is_empty() {
    writeln!(markdown, "No accept multiplier rows were found.\n").unwrap();
    return;
  }

  writeln!(
        markdown,
        "| Target CPU | Scenario | accept = 0.5 median rate/sec | accept = 1.0 median rate/sec | 1.0 / 0.5 | accept = 0.5 median p95 ms | accept = 1.0 median p95 ms | accept = 0.5 median p99 ms | accept = 1.0 median p99 ms |"
    )
    .unwrap();
  writeln!(
    markdown,
    "| --- | --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |"
  )
  .unwrap();
  for comparison in comparisons {
    let accept_0_5 = comparison.accept_0_5.as_ref();
    let accept_1_0 = comparison.accept_1_0.as_ref();
    writeln!(
      markdown,
      "| `{}` | `{}` | {} | {} | {} | {} | {} | {} | {} |",
      comparison.amd64_target_cpu,
      comparison.scenario,
      format_number(accept_0_5.and_then(|stats| stats.median_rps)),
      format_number(accept_1_0.and_then(|stats| stats.median_rps)),
      comparison.accept_1_0_vs_0_5.text,
      format_number(accept_0_5.and_then(|stats| stats.median_p95_ms)),
      format_number(accept_1_0.and_then(|stats| stats.median_p95_ms)),
      format_number(accept_0_5.and_then(|stats| stats.median_p99_ms)),
      format_number(accept_1_0.and_then(|stats| stats.median_p99_ms)),
    )
    .unwrap();
  }
  writeln!(markdown).unwrap();
}

fn write_remote_signer_table(markdown: &mut String, comparisons: &[RemoteSignerComparison]) {
  writeln!(markdown, "## Remote signer overhead\n").unwrap();
  if comparisons.is_empty() {
    writeln!(markdown, "No remote signer rows were found.\n").unwrap();
    return;
  }

  writeln!(
        markdown,
        "| Target CPU | Scenario | Local-key median rate/sec | Remote-signer median rate/sec | Remote signer vs local key | Local-key median p99 ms | Remote-signer median p99 ms |"
    )
    .unwrap();
  writeln!(markdown, "| --- | --- | ---: | ---: | --- | ---: | ---: |").unwrap();
  for comparison in comparisons {
    let local_key = comparison.local_key.as_ref();
    let remote_signer = comparison.remote_signer.as_ref();
    writeln!(
      markdown,
      "| `{}` | `{}` | {} | {} | {} | {} | {} |",
      comparison.amd64_target_cpu,
      comparison.scenario,
      format_number(local_key.and_then(|stats| stats.median_rps)),
      format_number(remote_signer.and_then(|stats| stats.median_rps)),
      comparison.remote_signer_vs_local_key.text,
      format_number(local_key.and_then(|stats| stats.median_p99_ms)),
      format_number(remote_signer.and_then(|stats| stats.median_p99_ms)),
    )
    .unwrap();
  }
  writeln!(markdown).unwrap();
}

fn write_amd64_isa_table(markdown: &mut String, comparisons: &[Amd64IsaComparison]) {
  writeln!(markdown, "## AMD64 ISA comparison\n").unwrap();
  if comparisons.is_empty() {
    writeln!(markdown, "No AMD64 ISA comparison rows were found.\n").unwrap();
    return;
  }

  writeln!(
        markdown,
        "| Group | Scenario | Target CPU | Primary median rate/sec | Target median rate/sec | Target RPS delta | Primary median p99 ms | Target median p99 ms | Target p99 delta | Status |"
    )
    .unwrap();
  writeln!(
    markdown,
    "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |"
  )
  .unwrap();
  for comparison in comparisons {
    for variant in &comparison.variants {
      writeln!(
        markdown,
        "| `{}` | `{}` | `{}` | {} | {} | {} | {} | {} | {} | `{}` |",
        comparison.group,
        comparison.scenario,
        variant.amd64_target_cpu,
        format_number(
          comparison
            .primary
            .as_ref()
            .and_then(|stats| stats.median_rps)
        ),
        format_number(variant.target.as_ref().and_then(|stats| stats.median_rps)),
        format_percent(variant.rps_delta_percent_vs_primary),
        format_number(
          comparison
            .primary
            .as_ref()
            .and_then(|stats| stats.median_p99_ms)
        ),
        format_number(
          variant
            .target
            .as_ref()
            .and_then(|stats| stats.median_p99_ms)
        ),
        format_percent(variant.p99_delta_percent_vs_primary),
        variant.status,
      )
      .unwrap();
    }
  }
  writeln!(markdown).unwrap();
}

fn write_external_benchmark_table(markdown: &mut String, rows: &[ExternalBenchmarkStats]) {
  writeln!(markdown, "## External benchmark validation\n").unwrap();
  if rows.is_empty() {
    writeln!(markdown, "No external benchmark rows were found.\n").unwrap();
    return;
  }

  writeln!(
        markdown,
        "| Target CPU | Tool | Comparator | Scenario | Protocol | Samples | Passed | Failed | Skipped | Median rate/sec | Median p99 ms | Median error rate | Output files | Reasons |"
    )
    .unwrap();
  writeln!(
    markdown,
    "| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |"
  )
  .unwrap();
  for row in rows {
    let notes = external_benchmark_notes(row);
    writeln!(
      markdown,
      "| `{}` | `{}` | `{}` | `{}` | `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
      row.amd64_target_cpu,
      row.tool,
      row.comparator,
      row.scenario,
      row.protocol,
      row.sample_count,
      row.pass_count,
      row.fail_count,
      row.skipped_count,
      format_number(row.median_rps),
      format_number(row.median_p99_ms),
      format_number(row.median_error_rate),
      format_list_cell(&row.output_files),
      format_list_cell(&notes),
    )
    .unwrap();
  }
  writeln!(markdown).unwrap();
}

fn external_benchmark_notes(row: &ExternalBenchmarkStats) -> Vec<String> {
  let mut notes = row.reasons.iter().cloned().collect::<BTreeSet<_>>();
  if let Some(reason) = &row.diagnostic_reason {
    notes.insert(reason.clone());
  }
  notes.into_iter().collect()
}

fn write_diagnostic_profile_table(markdown: &mut String, rows: &[DiagnosticProfileStats]) {
  writeln!(markdown, "## Diagnostic profiling\n").unwrap();
  if rows.is_empty() {
    writeln!(markdown, "No diagnostic profiling rows were found.\n").unwrap();
    return;
  }

  writeln!(
        markdown,
        "| Target CPU | Comparator | Scenario | Protocol | Mode | Samples | Passed | Failed | Skipped | CPU samples | Memory samples | Artifacts | Notes |"
    )
    .unwrap();
  writeln!(
    markdown,
    "| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |"
  )
  .unwrap();
  for row in rows {
    let notes = diagnostic_profile_notes(row);
    writeln!(
      markdown,
      "| `{}` | `{}` | `{}` | `{}` | `{}` | {} | {} | {} | {} | {} | {} | {} | {} |",
      row.amd64_target_cpu,
      row.comparator,
      row.scenario,
      row.protocol,
      row.profile_mode,
      row.sample_count,
      row.pass_count,
      row.fail_count,
      row.skipped_count,
      row.cpu_enabled_count,
      row.memory_enabled_count,
      format_list_cell(&row.artifact_files),
      format_list_cell(&notes),
    )
    .unwrap();
  }
  writeln!(markdown).unwrap();
}

fn diagnostic_profile_notes(row: &DiagnosticProfileStats) -> Vec<String> {
  if row.classification == PROFILE_CLASSIFICATION_ENV_UNAVAILABLE {
    return row
      .diagnostic_reason
      .clone()
      .into_iter()
      .collect::<Vec<_>>();
  }

  let mut notes = row
    .reasons
    .iter()
    .map(|reason| normalize_diagnostic_profile_reason(reason))
    .collect::<BTreeSet<_>>();
  if let Some(reason) = &row.diagnostic_reason {
    notes.insert(reason.clone());
  }
  if notes.is_empty() && row.fail_count > 0 {
    notes.insert("profiling evidence unavailable; see artifacts".to_owned());
  }
  notes.into_iter().collect()
}

fn normalize_diagnostic_profile_reason(reason: &str) -> String {
  let reason = reason.trim();
  let normalized = reason.to_ascii_lowercase();
  match normalized.as_str() {
    "failed" | "failure" | "unknown failure" => {
      "profiling evidence unavailable; see artifacts".to_owned()
    }
    "perf report failed" => "perf report unavailable; see artifacts".to_owned(),
    "perf script failed" => "perf script unavailable; see artifacts".to_owned(),
    _ => reason
      .strip_prefix("perf record failed with status ")
      .map(|status| format!("perf record exited with status {status}; see artifacts"))
      .unwrap_or_else(|| reason.to_owned()),
  }
}

fn write_oxibelt_only_table(markdown: &mut String, rows: &[AggregateStats]) {
  writeln!(markdown, "## OxiBelt-only results\n").unwrap();
  if rows.is_empty() {
    writeln!(markdown, "No OxiBelt-only rows were found.\n").unwrap();
    return;
  }

  writeln!(
        markdown,
        "| Target CPU | Label | Type | Protocol/mode | Samples | Median rate/sec | Median p95 ms | Median p99 ms | Errors | Skipped |"
    )
    .unwrap();
  writeln!(
    markdown,
    "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"
  )
  .unwrap();
  for row in rows {
    writeln!(
      markdown,
      "| `{}` | `{}` | `{}` | `{}` | {} | {} | {} | {} | {} | {} |",
      row.amd64_target_cpu,
      row.label,
      row.result_type.as_deref().unwrap_or("-"),
      row.protocol_or_mode.as_deref().unwrap_or("-"),
      row.sample_count,
      format_number(row.median_rps),
      format_number(row.median_p95_ms),
      format_number(row.median_p99_ms),
      row.total_errors,
      row.skipped_count,
    )
    .unwrap();
  }
  writeln!(markdown).unwrap();
}

fn write_missing_table(markdown: &mut String, rows: &[MissingComparatorRow]) {
  writeln!(markdown, "## Skipped/missing comparator rows\n").unwrap();
  if rows.is_empty() {
    writeln!(markdown, "None.\n").unwrap();
    return;
  }

  writeln!(
    markdown,
    "| Target CPU | Group | Scenario | Comparator | Status | Reason |"
  )
  .unwrap();
  writeln!(markdown, "| --- | --- | --- | --- | --- | --- |").unwrap();
  for row in rows {
    writeln!(
      markdown,
      "| `{}` | `{}` | `{}` | `{}` | `{}` | {} |",
      row.amd64_target_cpu, row.group, row.scenario, row.comparator, row.status, row.reason
    )
    .unwrap();
  }
  writeln!(markdown).unwrap();
}

fn write_quorum_table(markdown: &mut String, quorum: &QuorumReport) {
  writeln!(markdown, "## Sample quorum\n").unwrap();
  writeln!(
    markdown,
    "Status: `{}`; policy: `{}`; required samples: `{}`; required shards: `{}`\n",
    quorum.status,
    quorum.policy,
    quorum
      .required_sample_count
      .map(|value| value.to_string())
      .unwrap_or_else(|| "n/a".to_owned()),
    quorum
      .required_shards
      .map(|value| value.to_string())
      .unwrap_or_else(|| "n/a".to_owned()),
  )
  .unwrap();
  if quorum.rows.is_empty() {
    writeln!(markdown, "No quorum rows were evaluated.\n").unwrap();
    return;
  }
  writeln!(
    markdown,
    "| Group | Scenario | Comparator | Samples | Shards | Status | Reason |"
  )
  .unwrap();
  writeln!(markdown, "| --- | --- | --- | ---: | ---: | --- | --- |").unwrap();
  for row in &quorum.rows {
    writeln!(
      markdown,
      "| `{}` | `{}` | `{}` | {} | {} | `{}` | {} |",
      row.group,
      row.scenario,
      row.comparator,
      row.sample_count,
      row.shard_count,
      row.status,
      row.reason
    )
    .unwrap();
  }
  writeln!(markdown).unwrap();
}

fn write_regression_gate_table(markdown: &mut String, gates: &RegressionGateReport) {
  writeln!(markdown, "## Regression gates\n").unwrap();
  writeln!(markdown, "Status: `{}`\n", gates.status).unwrap();
  if gates.accepted_regression.status != "inactive" {
    writeln!(
      markdown,
      "- Accepted regression: `{}` (accepted `{}`, remaining blocking `{}`)",
      gates.accepted_regression.status,
      gates.accepted_regression.accepted_violations,
      gates.accepted_regression.remaining_blocking_violations
    )
    .unwrap();
    if let Some(reason) = &gates.accepted_regression.reason {
      writeln!(markdown, "- Accepted regression reason: {reason}").unwrap();
    }
    writeln!(markdown).unwrap();
  }
  if gates.violations.is_empty() {
    writeln!(markdown, "Blocking violations: none.\n").unwrap();
  } else {
    writeln!(markdown, "### Blocking violations\n").unwrap();
    write_regression_gate_findings(markdown, &gates.violations);
  }

  if gates.advisories.is_empty() {
    writeln!(markdown, "Advisories: none.\n").unwrap();
  } else {
    writeln!(markdown, "### Advisories\n").unwrap();
    write_regression_gate_findings(markdown, &gates.advisories);
  }
}

fn write_regression_gate_findings(markdown: &mut String, findings: &[RegressionGateViolation]) {
  writeln!(
        markdown,
        "| Target CPU | Disposition | Mode | Gate | Group | Scenario | Metric | Observed | Threshold | Comparator | Message |"
    )
    .unwrap();
  writeln!(
    markdown,
    "| --- | --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |"
  )
  .unwrap();
  for violation in findings {
    writeln!(
      markdown,
      "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} | {} | `{}` | {} |",
      violation.amd64_target_cpu,
      violation.disposition,
      violation.evaluation_mode,
      violation.gate,
      violation.group,
      violation.scenario,
      violation.metric,
      format_number(violation.observed),
      format_number(Some(violation.threshold)),
      violation.comparator.as_deref().unwrap_or("-"),
      violation.message,
    )
    .unwrap();
  }
  writeln!(markdown).unwrap();
}

fn write_warnings(markdown: &mut String, report: &Report) {
  writeln!(markdown, "## Warnings\n").unwrap();
  if report.warnings.is_empty() && report.warnings_omitted == 0 {
    writeln!(markdown, "None.\n").unwrap();
    return;
  }

  for warning in &report.warnings {
    writeln!(markdown, "- {warning}").unwrap();
  }
  if report.warnings_omitted > 0 {
    writeln!(
      markdown,
      "- ... {} additional warning(s) omitted",
      report.warnings_omitted
    )
    .unwrap();
  }
  writeln!(markdown).unwrap();
}

fn render_delta_markdown(report: &DeltaReport) -> String {
  let mut markdown = String::new();
  writeln!(markdown, "# OxiBelt Docker Performance Delta\n").unwrap();
  writeln!(markdown, "## Summary\n").unwrap();
  writeln!(markdown, "- Baseline: `{}`", report.baseline_report).unwrap();
  writeln!(markdown, "- Rows compared: `{}`", report.summary.rows).unwrap();
  writeln!(
        markdown,
        "- Classifications: `{}` OxiBelt regression, `{}` comparator shift, `{}` mixed, `{}` improvement, `{}` stable, `{}` incomplete\n",
        report.summary.oxibelt_regression,
        report.summary.comparator_shift,
        report.summary.mixed,
        report.summary.improvement,
        report.summary.stable,
        report.summary.incomplete,
    )
    .unwrap();

  writeln!(markdown, "## Scenario deltas\n").unwrap();
  if report.rows.is_empty() {
    writeln!(markdown, "No baseline rows could be compared.\n").unwrap();
  } else {
    writeln!(
            markdown,
            "| Target CPU | Group | Scenario | Comparator | OxiBelt RPS delta | Comparator RPS delta | Ratio delta | OxiBelt p99 delta | Source | Classification | Reason |"
        )
        .unwrap();
    writeln!(
      markdown,
      "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |"
    )
    .unwrap();
    for row in &report.rows {
      writeln!(
        markdown,
        "| `{}` | `{}` | `{}` | `{}` | {} | {} | {} | {} | `{}` | `{}` | {} |",
        row.amd64_target_cpu,
        row.group,
        row.scenario,
        row.comparator,
        format_percent(row.oxibelt_rps_delta_percent),
        format_percent(row.comparator_rps_delta_percent),
        format_percent(row.ratio_delta_percent),
        format_percent(row.oxibelt_p99_delta_percent),
        row.classification_source,
        row.classification,
        row.reason,
      )
      .unwrap();
    }
    writeln!(markdown).unwrap();
  }

  if !report.warnings.is_empty() {
    writeln!(markdown, "## Warnings\n").unwrap();
    for warning in &report.warnings {
      writeln!(markdown, "- {warning}").unwrap();
    }
    writeln!(markdown).unwrap();
  }
  markdown
}

fn merge_text_field(target: &mut Option<String>, value: Option<String>) {
  let Some(value) = value else {
    return;
  };
  match target {
    Some(existing) if existing != &value => *existing = "mixed".to_owned(),
    Some(_) => {}
    None => *target = Some(value),
  }
}

fn percentile(values: &mut [f64], percent: f64) -> Option<f64> {
  if values.is_empty() {
    return None;
  }
  values.sort_by(f64::total_cmp);
  if values.len() == 1 {
    return Some(values[0]);
  }
  let rank = (percent / 100.0) * ((values.len() - 1) as f64);
  let low = rank.floor() as usize;
  let high = rank.ceil() as usize;
  if low == high {
    Some(values[low])
  } else {
    let weight = rank - (low as f64);
    Some(values[low] * (1.0 - weight) + values[high] * weight)
  }
}

fn distribution_percentile(values: &[f64], percent: f64) -> Option<f64> {
  let mut values = values.to_vec();
  percentile(&mut values, percent)
}

fn per_shard_medians(values_by_shard: BTreeMap<String, Vec<f64>>) -> Vec<f64> {
  values_by_shard
    .into_values()
    .filter_map(|mut values| percentile(&mut values, 50.0))
    .collect()
}

fn shard_id_from_source_file(source_file: &str) -> String {
  source_file
    .split(['/', '\\'])
    .find(|component| component.contains("-shard-"))
    .unwrap_or(source_file)
    .to_owned()
}

fn min_value(values: &[f64]) -> Option<f64> {
  values.iter().copied().min_by(f64::total_cmp)
}

fn max_value(values: &[f64]) -> Option<f64> {
  values.iter().copied().max_by(f64::total_cmp)
}

fn format_number(value: Option<f64>) -> String {
  value.map_or_else(|| "n/a".to_owned(), |value| format!("{value:.2}"))
}

fn format_percent(value: Option<f64>) -> String {
  value.map_or_else(|| "n/a".to_owned(), |value| format!("{value:.1}%"))
}

fn format_list_cell(values: &[String]) -> String {
  if values.is_empty() {
    "-".to_owned()
  } else {
    values
      .iter()
      .map(|value| format!("`{value}`"))
      .collect::<Vec<_>>()
      .join(", ")
  }
}

fn display_path(input_dir: &Path, path: &Path) -> String {
  path
    .strip_prefix(input_dir)
    .unwrap_or(path)
    .display()
    .to_string()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn temp_dir(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
      .prefix(&format!("oxibelt-performance-aggregate-{name}-"))
      .tempdir()
      .expect("temporary aggregate directory should be creatable")
  }

  fn aggregate_stat(
    comparator: Comparator,
    scenario: &str,
    group: ScenarioGroup,
    median_rps: f64,
    median_p99_ms: f64,
  ) -> AggregateStats {
    let fast_path = if comparator == Comparator::Oxibelt && scenario == "h1-keepalive" {
      Some(AggregateFastPathStats {
        plain_proxy_h1: Some(passing_fast_path_aggregate()),
        plain_proxy_h2: None,
        plain_proxy_h3: None,
        transport_direct_h1_h1: Some(passing_fast_path_aggregate()),
        transport_direct_h1_h2: None,
        transport_direct_h1_h3: None,
        transport_direct_h2_h1: None,
        transport_direct_h2_h2: None,
        transport_direct_h2_h3: None,
        direct_h1_pool: None,
        direct_h2_pool: None,
        static_responses: None,
        stage_timing: None,
      })
    } else if comparator == Comparator::Oxibelt && scenario == "h2" {
      Some(AggregateFastPathStats {
        plain_proxy_h1: None,
        plain_proxy_h2: Some(passing_fast_path_aggregate()),
        plain_proxy_h3: None,
        transport_direct_h1_h1: None,
        transport_direct_h1_h2: Some(passing_fast_path_aggregate()),
        transport_direct_h1_h3: None,
        transport_direct_h2_h1: None,
        transport_direct_h2_h2: None,
        transport_direct_h2_h3: None,
        direct_h1_pool: None,
        direct_h2_pool: None,
        static_responses: None,
        stage_timing: None,
      })
    } else if comparator == Comparator::Oxibelt && scenario == "h3" {
      Some(AggregateFastPathStats {
        plain_proxy_h1: None,
        plain_proxy_h2: None,
        plain_proxy_h3: Some(passing_fast_path_aggregate()),
        transport_direct_h1_h1: None,
        transport_direct_h1_h2: None,
        transport_direct_h1_h3: Some(passing_fast_path_aggregate()),
        transport_direct_h2_h1: None,
        transport_direct_h2_h2: None,
        transport_direct_h2_h3: None,
        direct_h1_pool: None,
        direct_h2_pool: None,
        static_responses: None,
        stage_timing: None,
      })
    } else {
      None
    };
    AggregateStats {
      amd64_target_cpu: DEFAULT_AMD64_TARGET_CPU.to_owned(),
      label: format!("{}-{scenario}", comparator.as_str()),
      comparator: comparator.as_str().to_owned(),
      scenario: scenario.to_owned(),
      group: group.as_str().to_owned(),
      result_type: Some("load".to_owned()),
      protocol_or_mode: Some(scenario.to_owned()),
      sample_count: 1,
      median_rps: Some(median_rps),
      min_rps: Some(median_rps),
      max_rps: Some(median_rps),
      p25_rps: Some(median_rps),
      p75_rps: Some(median_rps),
      median_p50_ms: Some(median_p99_ms / 2.0),
      median_p90_ms: Some(median_p99_ms * 0.9),
      median_p95_ms: Some(median_p99_ms * 0.95),
      median_p99_ms: Some(median_p99_ms),
      total_errors: 0,
      skipped_count: 0,
      skip_reasons: Vec::new(),
      source_files: vec!["synthetic/results.json".to_owned()],
      distribution: AggregateDistribution::default(),
      fast_path,
    }
  }

  fn passing_fast_path_aggregate() -> FastPathAggregateStats {
    FastPathAggregateStats {
      sample_count: 1,
      hits: 100,
      misses: 0,
      attempts: 100,
      median_hit_rate: Some(1.0),
      min_hit_rate: Some(1.0),
    }
  }

  fn insert_primary_aggregate(
    aggregates: &mut PrimaryAggregateMap,
    comparator: Comparator,
    scenario: &str,
    rps: f64,
    p99: f64,
  ) {
    aggregates.insert(
      (comparator, scenario.to_owned()),
      aggregate_stat(comparator, scenario, ScenarioGroup::ReverseProxy, rps, p99),
    );
  }

  fn baseline_context_for(aggregates: &PrimaryAggregateMap) -> BaselineGateContext {
    BaselineGateContext {
      report: "synthetic-baseline.json".to_owned(),
      schema_version: Some(COMPARISON_SCHEMA_VERSION),
      aggregates: aggregates
        .iter()
        .map(|((comparator, scenario), aggregate)| {
          (
            (comparator.as_str().to_owned(), scenario.clone()),
            aggregate.clone(),
          )
        })
        .collect(),
    }
  }

  #[test]
  fn comparison_report_schema_and_target_thresholds_are_current() {
    let input_dir = temp_dir("schema-thresholds");
    let report = aggregate(
      input_dir.path(),
      AggregateOptions {
        profile: Some("smoke".to_owned()),
        expected_runs: None,
        expected_shards: None,
        expected_target_cpus: Vec::new(),
        primary_target_cpu: DEFAULT_AMD64_TARGET_CPU.to_owned(),
        baseline_report: None,
        baseline_context: None,
        accepted_regression_reason: None,
      },
    );

    assert_eq!(report.schema_version, COMPARISON_SCHEMA_VERSION);
    assert_eq!(
      report
        .regression_gates
        .thresholds
        .h1_keepalive_min_nginx_ratio,
      0.80
    );
    assert_eq!(
      report.regression_gates.thresholds.h1_fast_path_min_hit_rate,
      0.99
    );
    assert_eq!(report.regression_gates.thresholds.h2_min_nginx_ratio, 0.80);
    assert_eq!(report.regression_gates.thresholds.h3_min_nginx_ratio, 0.80);
  }

  #[test]
  fn aggregate_parses_h1_fast_path_evidence_from_result_rows() {
    let input_dir = temp_dir("h1-fast-path-parse");
    let run_dir = input_dir.path().join("run-1");
    std::fs::create_dir_all(&run_dir).expect("run dir should be created");
    std::fs::write(
      run_dir.join("results.json"),
      r#"[{
              "type": "load",
              "label": "oxibelt-h1-keepalive",
              "protocol": "h1",
              "requests": 100,
              "rps": 1000.0,
              "p99_ms": 1.0,
              "errors": 0,
              "fast_path": {
                "plain_proxy": {
                  "h1": {
                    "hits": 99,
                    "misses": 1,
                    "attempts": 100,
                    "hit_rate": 0.99,
                    "miss_reasons": {"cache_policy": 1}
                  }
                },
                "transport": {
                  "direct_h1": {
                    "h1": {
                      "hits": 98,
                      "misses": 2,
                      "attempts": 100,
                      "hit_rate": 0.98,
                      "miss_reasons": {"send_error": 2}
                    }
                  }
                },
                "pool": {
                  "direct_h1": {
                    "hit": 90,
                    "miss": 10,
                    "reconnect": 2,
                    "stale": 1,
                    "drop": 3
                  }
                }
              }
            }]"#,
    )
    .expect("results should be written");

    let report = aggregate(
      input_dir.path(),
      AggregateOptions {
        profile: None,
        expected_runs: None,
        expected_shards: None,
        expected_target_cpus: Vec::new(),
        primary_target_cpu: DEFAULT_AMD64_TARGET_CPU.to_owned(),
        baseline_report: None,
        baseline_context: None,
        accepted_regression_reason: None,
      },
    );
    let h1 = report
      .aggregates
      .iter()
      .find(|aggregate| aggregate.comparator == "oxibelt" && aggregate.scenario == "h1-keepalive")
      .and_then(|aggregate| aggregate.fast_path.as_ref())
      .expect("fast-path aggregate should exist");
    let plain_proxy_h1 = h1
      .plain_proxy_h1
      .as_ref()
      .expect("plain-proxy fast-path aggregate should exist");
    let direct_h1 = h1
      .transport_direct_h1_h1
      .as_ref()
      .expect("direct-H1 transport aggregate should exist");

    assert_eq!(plain_proxy_h1.hits, 99);
    assert_eq!(plain_proxy_h1.misses, 1);
    assert_eq!(plain_proxy_h1.attempts, 100);
    assert_eq!(plain_proxy_h1.min_hit_rate, Some(0.99));
    assert_eq!(direct_h1.hits, 98);
    assert_eq!(direct_h1.misses, 2);
    assert_eq!(direct_h1.attempts, 100);
    assert_eq!(direct_h1.min_hit_rate, Some(0.98));
    let pool = h1
      .direct_h1_pool
      .as_ref()
      .expect("direct-H1 pool events should aggregate");
    assert_eq!(pool.sample_count, 1);
    assert_eq!(pool.values["hit"], 90);
    assert_eq!(pool.values["miss"], 10);
    assert_eq!(pool.values["reconnect"], 2);
    assert_eq!(pool.values["stale"], 1);
    assert_eq!(pool.values["drop"], 3);
  }

  #[test]
  fn aggregate_parses_h2_fast_path_evidence_from_result_rows() {
    let input_dir = temp_dir("h2-fast-path-parse");
    let run_dir = input_dir.path().join("run-1");
    std::fs::create_dir_all(&run_dir).expect("run dir should be created");
    std::fs::write(
      run_dir.join("results.json"),
      r#"[{
              "type": "load",
              "label": "oxibelt-h2",
              "protocol": "h2",
              "requests": 100,
              "rps": 1000.0,
              "p99_ms": 1.0,
              "errors": 0,
              "fast_path": {
                "plain_proxy": {
                  "h2": {
                    "hits": 97,
                    "misses": 3,
                    "attempts": 100,
                    "hit_rate": 0.97,
                    "miss_reasons": {"policy": 3}
                  }
                },
                "transport": {
                  "direct_h1": {
                    "h2": {
                      "hits": 96,
                      "misses": 4,
                      "attempts": 100,
                      "hit_rate": 0.96,
                      "miss_reasons": {"request_body": 4}
                    }
                  },
                  "direct_h2": {
                    "h2": {
                      "hits": 95,
                      "misses": 5,
                      "attempts": 100,
                      "hit_rate": 0.95,
                      "miss_reasons": {"send_error": 5}
                    }
                  }
                },
                "pool": {
                  "direct_h2": {
                    "hit": 88,
                    "miss": 12,
                    "miss_saturated": 3,
                    "connect": 4,
                    "reconnect": 1,
                    "drop": 2
                  }
                }
              }
            }]"#,
    )
    .expect("results should be written");

    let report = aggregate(
      input_dir.path(),
      AggregateOptions {
        profile: None,
        expected_runs: None,
        expected_shards: None,
        expected_target_cpus: Vec::new(),
        primary_target_cpu: DEFAULT_AMD64_TARGET_CPU.to_owned(),
        baseline_report: None,
        baseline_context: None,
        accepted_regression_reason: None,
      },
    );
    let h2 = report
      .aggregates
      .iter()
      .find(|aggregate| aggregate.comparator == "oxibelt" && aggregate.scenario == "h2")
      .and_then(|aggregate| aggregate.fast_path.as_ref())
      .expect("fast-path aggregate should exist");
    let plain_proxy_h2 = h2
      .plain_proxy_h2
      .as_ref()
      .expect("plain-proxy H2 fast-path aggregate should exist");
    let direct_h1 = h2
      .transport_direct_h1_h2
      .as_ref()
      .expect("direct-H1 H2 transport aggregate should exist");
    let direct_h2 = h2
      .transport_direct_h2_h2
      .as_ref()
      .expect("direct-H2 H2 transport aggregate should exist");

    assert_eq!(plain_proxy_h2.hits, 97);
    assert_eq!(plain_proxy_h2.misses, 3);
    assert_eq!(plain_proxy_h2.attempts, 100);
    assert_eq!(plain_proxy_h2.min_hit_rate, Some(0.97));
    assert_eq!(direct_h1.hits, 96);
    assert_eq!(direct_h1.misses, 4);
    assert_eq!(direct_h1.attempts, 100);
    assert_eq!(direct_h1.min_hit_rate, Some(0.96));
    assert_eq!(direct_h2.hits, 95);
    assert_eq!(direct_h2.misses, 5);
    assert_eq!(direct_h2.attempts, 100);
    assert_eq!(direct_h2.min_hit_rate, Some(0.95));
    let pool = h2
      .direct_h2_pool
      .as_ref()
      .expect("direct-H2 pool events should aggregate");
    assert_eq!(pool.sample_count, 1);
    assert_eq!(pool.values["hit"], 88);
    assert_eq!(pool.values["miss"], 12);
    assert_eq!(pool.values["miss_saturated"], 3);
    assert_eq!(pool.values["connect"], 4);
    assert_eq!(pool.values["reconnect"], 1);
    assert_eq!(pool.values["drop"], 2);
  }

  #[test]
  fn aggregate_parses_h3_fast_path_evidence_from_result_rows() {
    let input_dir = temp_dir("h3-fast-path-parse");
    let run_dir = input_dir.path().join("run-1");
    std::fs::create_dir_all(&run_dir).expect("run dir should be created");
    std::fs::write(
      run_dir.join("results.json"),
      r#"[{
              "type": "load",
              "label": "oxibelt-h3",
              "protocol": "h3",
              "requests": 100,
              "rps": 1000.0,
              "p99_ms": 1.0,
              "errors": 0,
              "fast_path": {
                "plain_proxy": {
                  "h3": {
                    "hits": 95,
                    "misses": 5,
                    "attempts": 100,
                    "hit_rate": 0.95,
                    "miss_reasons": {"policy": 5}
                  }
                },
                "transport": {
                  "direct_h1": {
                    "h3": {
                      "hits": 94,
                      "misses": 6,
                      "attempts": 100,
                      "hit_rate": 0.94,
                      "miss_reasons": {"request_body": 6}
                    }
                  },
                  "direct_h2": {
                    "h3": {
                      "hits": 93,
                      "misses": 7,
                      "attempts": 100,
                      "hit_rate": 0.93,
                      "miss_reasons": {"send_error": 7}
                    }
                  }
                }
              }
            }]"#,
    )
    .expect("results should be written");

    let report = aggregate(
      input_dir.path(),
      AggregateOptions {
        profile: None,
        expected_runs: None,
        expected_shards: None,
        expected_target_cpus: Vec::new(),
        primary_target_cpu: DEFAULT_AMD64_TARGET_CPU.to_owned(),
        baseline_report: None,
        baseline_context: None,
        accepted_regression_reason: None,
      },
    );
    let h3 = report
      .aggregates
      .iter()
      .find(|aggregate| aggregate.comparator == "oxibelt" && aggregate.scenario == "h3")
      .and_then(|aggregate| aggregate.fast_path.as_ref())
      .expect("fast-path aggregate should exist");
    let plain_proxy_h3 = h3
      .plain_proxy_h3
      .as_ref()
      .expect("plain-proxy H3 fast-path aggregate should exist");
    let direct_h1 = h3
      .transport_direct_h1_h3
      .as_ref()
      .expect("direct-H1 H3 transport aggregate should exist");
    let direct_h2 = h3
      .transport_direct_h2_h3
      .as_ref()
      .expect("direct-H2 H3 transport aggregate should exist");

    assert_eq!(plain_proxy_h3.hits, 95);
    assert_eq!(plain_proxy_h3.misses, 5);
    assert_eq!(plain_proxy_h3.attempts, 100);
    assert_eq!(plain_proxy_h3.min_hit_rate, Some(0.95));
    assert_eq!(direct_h1.hits, 94);
    assert_eq!(direct_h1.misses, 6);
    assert_eq!(direct_h1.attempts, 100);
    assert_eq!(direct_h1.min_hit_rate, Some(0.94));
    assert_eq!(direct_h2.hits, 93);
    assert_eq!(direct_h2.misses, 7);
    assert_eq!(direct_h2.attempts, 100);
    assert_eq!(direct_h2.min_hit_rate, Some(0.93));
  }

  #[test]
  fn aggregate_parses_fast_path_stage_timing_from_result_rows() {
    let input_dir = temp_dir("fast-path-stage-timing-parse");
    let run_dir = input_dir.path().join("run-1");
    std::fs::create_dir_all(&run_dir).expect("run dir should be created");
    std::fs::write(
      run_dir.join("results.json"),
      r#"[{
              "type": "load",
              "label": "oxibelt-h2",
              "protocol": "h2",
              "requests": 100,
              "rps": 1000.0,
              "p99_ms": 1.0,
              "errors": 0,
              "fast_path": {
                "stage_timing": {
                  "plain_proxy": {
                    "h2": {
                      "transport_direct_h1": {
                        "ok": {
                          "count": 4,
                          "total_ns": 100,
                          "avg_ns": 25.0
                        }
                      },
                      "direct_h1_pool_take": {
                        "ok": {
                          "count": 4,
                          "total_ns": 40,
                          "avg_ns": 10.0
                        }
                      },
                      "direct_h1_response_head": {
                        "ok": {
                          "count": 4,
                          "total_ns": 80,
                          "avg_ns": 20.0
                        }
                      },
                      "h2_downstream_response_return": {
                        "ok": {
                          "count": 4,
                          "total_ns": 12,
                          "avg_ns": 3.0
                        }
                      }
                    }
                  }
                }
              }
            }]"#,
    )
    .expect("results should be written");

    let report = aggregate(
      input_dir.path(),
      AggregateOptions {
        profile: None,
        expected_runs: None,
        expected_shards: None,
        expected_target_cpus: Vec::new(),
        primary_target_cpu: DEFAULT_AMD64_TARGET_CPU.to_owned(),
        baseline_report: None,
        baseline_context: None,
        accepted_regression_reason: None,
      },
    );
    let stage_timing = report
      .aggregates
      .iter()
      .find(|aggregate| aggregate.comparator == "oxibelt" && aggregate.scenario == "h2")
      .and_then(|aggregate| aggregate.fast_path.as_ref())
      .and_then(|fast_path| fast_path.stage_timing.as_ref())
      .expect("stage timing aggregate should exist");
    let sample = &stage_timing["plain_proxy"]["h2"]["transport_direct_h1"]["ok"];

    assert_eq!(sample.sample_count, 1);
    assert_eq!(sample.count, 4);
    assert_eq!(sample.total_ns, 100);
    assert_eq!(sample.median_avg_ns, Some(25.0));
    assert_eq!(sample.max_avg_ns, Some(25.0));
    let pool_take_sample = &stage_timing["plain_proxy"]["h2"]["direct_h1_pool_take"]["ok"];
    assert_eq!(pool_take_sample.sample_count, 1);
    assert_eq!(pool_take_sample.count, 4);
    assert_eq!(pool_take_sample.total_ns, 40);
    assert_eq!(pool_take_sample.median_avg_ns, Some(10.0));
    assert_eq!(pool_take_sample.max_avg_ns, Some(10.0));
    let response_head_sample = &stage_timing["plain_proxy"]["h2"]["direct_h1_response_head"]["ok"];
    assert_eq!(response_head_sample.sample_count, 1);
    assert_eq!(response_head_sample.total_ns, 80);
    assert_eq!(response_head_sample.median_avg_ns, Some(20.0));
    let h2_return_sample =
      &stage_timing["plain_proxy"]["h2"]["h2_downstream_response_return"]["ok"];
    assert_eq!(h2_return_sample.sample_count, 1);
    assert_eq!(h2_return_sample.total_ns, 12);
    assert_eq!(h2_return_sample.median_avg_ns, Some(3.0));
  }

  #[test]
  fn aggregate_parses_static_fast_path_evidence_from_result_rows() {
    let input_dir = temp_dir("static-fast-path-parse");
    let run_dir = input_dir.path().join("run-1");
    std::fs::create_dir_all(&run_dir).expect("run dir should be created");
    std::fs::write(
      run_dir.join("results.json"),
      r#"[{
              "type": "load",
              "label": "oxibelt-static-16k-h1c",
              "protocol": "h1c",
              "requests": 100,
              "rps": 1000.0,
              "p99_ms": 1.0,
              "errors": 0,
              "fast_path": {
                "static_responses": {
                  "hot_object": {
                    "served": 97
                  },
                  "sendfile": {
                    "fallback": 3
                  }
                }
              }
            }]"#,
    )
    .expect("results should be written");

    let report = aggregate(
      input_dir.path(),
      AggregateOptions {
        profile: None,
        expected_runs: None,
        expected_shards: None,
        expected_target_cpus: Vec::new(),
        primary_target_cpu: DEFAULT_AMD64_TARGET_CPU.to_owned(),
        baseline_report: None,
        baseline_context: None,
        accepted_regression_reason: None,
      },
    );
    let static_fast_path = report
      .aggregates
      .iter()
      .find(|aggregate| aggregate.comparator == "oxibelt" && aggregate.scenario == "static-16k-h1c")
      .and_then(|aggregate| aggregate.fast_path.as_ref())
      .and_then(|fast_path| fast_path.static_responses.as_ref())
      .expect("static fast-path aggregate should exist");

    assert_eq!(static_fast_path.sample_count, 1);
    assert_eq!(static_fast_path.values["hot_object"]["served"], 97);
    assert_eq!(static_fast_path.values["sendfile"]["fallback"], 3);
  }

  #[test]
  fn h1_fast_path_hit_rate_gate_fails_below_threshold() {
    let mut aggregates = PrimaryAggregateMap::new();
    insert_primary_aggregate(
      &mut aggregates,
      Comparator::Oxibelt,
      "h1-keepalive",
      100.0,
      1.0,
    );
    let aggregate = aggregates
      .get_mut(&(Comparator::Oxibelt, "h1-keepalive".to_owned()))
      .expect("synthetic aggregate should exist");
    aggregate.fast_path = Some(AggregateFastPathStats {
      plain_proxy_h1: Some(FastPathAggregateStats {
        sample_count: 1,
        hits: 98,
        misses: 2,
        attempts: 100,
        median_hit_rate: Some(0.98),
        min_hit_rate: Some(0.98),
      }),
      plain_proxy_h2: None,
      plain_proxy_h3: None,
      transport_direct_h1_h1: Some(FastPathAggregateStats {
        sample_count: 1,
        hits: 100,
        misses: 0,
        attempts: 100,
        median_hit_rate: Some(1.0),
        min_hit_rate: Some(1.0),
      }),
      transport_direct_h1_h2: None,
      transport_direct_h1_h3: None,
      transport_direct_h2_h1: None,
      transport_direct_h2_h2: None,
      transport_direct_h2_h3: None,
      direct_h1_pool: None,
      direct_h2_pool: None,
      static_responses: None,
      stage_timing: None,
    });

    let gates = build_regression_gate_report(
      &aggregates,
      RegressionGateThresholds {
        h1_keepalive_min_nginx_ratio: DEFAULT_H1_KEEPALIVE_MIN_NGINX_RATIO,
        h1_fast_path_min_hit_rate: DEFAULT_H1_FAST_PATH_MIN_HIT_RATE,
        h2_min_nginx_ratio: DEFAULT_H2_MIN_NGINX_RATIO,
        h3_min_nginx_ratio: DEFAULT_H3_MIN_NGINX_RATIO,
        static_16k_h1c_min_caddy_ratio: DEFAULT_STATIC_16K_H1C_MIN_CADDY_RATIO,
        static_16k_h1c_min_nginx_ratio: DEFAULT_STATIC_16K_H1C_MIN_NGINX_RATIO,
        remote_signer_handshake_min_local_ratio: DEFAULT_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO,
        waf_enforcing_min_rps: DEFAULT_WAF_ENFORCING_MIN_RPS,
        crs_enforcing_min_rps: DEFAULT_CRS_ENFORCING_MIN_RPS,
        waf_crs_max_enforce_p99_ratio: DEFAULT_WAF_CRS_MAX_ENFORCE_P99_RATIO,
      },
      None,
      DEFAULT_AMD64_TARGET_CPU,
      None,
    );

    assert!(gates.violations.iter().any(|violation| {
      violation.gate == "h1_fast_path_min_hit_rate"
        && violation.metric == "plain_proxy_h1_min_hit_rate"
        && violation.observed == Some(0.98)
        && violation.evaluation_mode == "evidence"
    }));
  }

  #[test]
  fn h2_direct_h1_fast_path_hit_rate_gate_fails_below_threshold() {
    let mut aggregates = PrimaryAggregateMap::new();
    insert_primary_aggregate(
      &mut aggregates,
      Comparator::Oxibelt,
      "h1-keepalive",
      100.0,
      1.0,
    );
    insert_primary_aggregate(&mut aggregates, Comparator::Oxibelt, "h2", 100.0, 1.0);
    let aggregate = aggregates
      .get_mut(&(Comparator::Oxibelt, "h2".to_owned()))
      .expect("synthetic aggregate should exist");
    aggregate.fast_path = Some(AggregateFastPathStats {
      plain_proxy_h1: None,
      plain_proxy_h2: Some(passing_fast_path_aggregate()),
      plain_proxy_h3: None,
      transport_direct_h1_h1: None,
      transport_direct_h1_h2: Some(FastPathAggregateStats {
        sample_count: 1,
        hits: 98,
        misses: 2,
        attempts: 100,
        median_hit_rate: Some(0.98),
        min_hit_rate: Some(0.98),
      }),
      transport_direct_h1_h3: None,
      transport_direct_h2_h1: None,
      transport_direct_h2_h2: None,
      transport_direct_h2_h3: None,
      direct_h1_pool: None,
      direct_h2_pool: None,
      static_responses: None,
      stage_timing: None,
    });

    let gates = build_regression_gate_report(
      &aggregates,
      RegressionGateThresholds {
        h1_keepalive_min_nginx_ratio: DEFAULT_H1_KEEPALIVE_MIN_NGINX_RATIO,
        h1_fast_path_min_hit_rate: DEFAULT_H1_FAST_PATH_MIN_HIT_RATE,
        h2_min_nginx_ratio: DEFAULT_H2_MIN_NGINX_RATIO,
        h3_min_nginx_ratio: DEFAULT_H3_MIN_NGINX_RATIO,
        static_16k_h1c_min_caddy_ratio: DEFAULT_STATIC_16K_H1C_MIN_CADDY_RATIO,
        static_16k_h1c_min_nginx_ratio: DEFAULT_STATIC_16K_H1C_MIN_NGINX_RATIO,
        remote_signer_handshake_min_local_ratio: DEFAULT_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO,
        waf_enforcing_min_rps: DEFAULT_WAF_ENFORCING_MIN_RPS,
        crs_enforcing_min_rps: DEFAULT_CRS_ENFORCING_MIN_RPS,
        waf_crs_max_enforce_p99_ratio: DEFAULT_WAF_CRS_MAX_ENFORCE_P99_RATIO,
      },
      None,
      DEFAULT_AMD64_TARGET_CPU,
      None,
    );

    assert!(gates.violations.iter().any(|violation| {
      violation.gate == "h2_fast_path_min_hit_rate"
        && violation.metric == "transport_direct_h1_h2_min_hit_rate"
        && violation.observed == Some(0.98)
        && violation.evaluation_mode == "evidence"
    }));
  }

  #[test]
  fn h2_upstream_direct_h2_fast_path_hit_rate_gate_fails_below_threshold() {
    let mut aggregates = PrimaryAggregateMap::new();
    insert_primary_aggregate(
      &mut aggregates,
      Comparator::Oxibelt,
      "h2-upstream-h2",
      100.0,
      1.0,
    );
    let aggregate = aggregates
      .get_mut(&(Comparator::Oxibelt, "h2-upstream-h2".to_owned()))
      .expect("synthetic aggregate should exist");
    aggregate.fast_path = Some(AggregateFastPathStats {
      plain_proxy_h1: None,
      plain_proxy_h2: Some(passing_fast_path_aggregate()),
      plain_proxy_h3: None,
      transport_direct_h1_h1: None,
      transport_direct_h1_h2: None,
      transport_direct_h1_h3: None,
      transport_direct_h2_h1: None,
      transport_direct_h2_h2: Some(FastPathAggregateStats {
        sample_count: 1,
        hits: 98,
        misses: 2,
        attempts: 100,
        median_hit_rate: Some(0.98),
        min_hit_rate: Some(0.98),
      }),
      transport_direct_h2_h3: None,
      direct_h1_pool: None,
      direct_h2_pool: None,
      static_responses: None,
      stage_timing: None,
    });

    let gates = build_regression_gate_report(
      &aggregates,
      RegressionGateThresholds {
        h1_keepalive_min_nginx_ratio: DEFAULT_H1_KEEPALIVE_MIN_NGINX_RATIO,
        h1_fast_path_min_hit_rate: DEFAULT_H1_FAST_PATH_MIN_HIT_RATE,
        h2_min_nginx_ratio: DEFAULT_H2_MIN_NGINX_RATIO,
        h3_min_nginx_ratio: DEFAULT_H3_MIN_NGINX_RATIO,
        static_16k_h1c_min_caddy_ratio: DEFAULT_STATIC_16K_H1C_MIN_CADDY_RATIO,
        static_16k_h1c_min_nginx_ratio: DEFAULT_STATIC_16K_H1C_MIN_NGINX_RATIO,
        remote_signer_handshake_min_local_ratio: DEFAULT_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO,
        waf_enforcing_min_rps: DEFAULT_WAF_ENFORCING_MIN_RPS,
        crs_enforcing_min_rps: DEFAULT_CRS_ENFORCING_MIN_RPS,
        waf_crs_max_enforce_p99_ratio: DEFAULT_WAF_CRS_MAX_ENFORCE_P99_RATIO,
      },
      None,
      DEFAULT_AMD64_TARGET_CPU,
      None,
    );

    assert!(gates.violations.iter().any(|violation| {
      violation.gate == "h2_upstream_direct_h2_min_hit_rate"
        && violation.metric == "transport_direct_h2_h2_min_hit_rate"
        && violation.observed == Some(0.98)
        && violation.evaluation_mode == "evidence"
    }));
  }

  #[test]
  fn h3_direct_h1_fast_path_hit_rate_gate_fails_below_threshold() {
    let mut aggregates = PrimaryAggregateMap::new();
    insert_primary_aggregate(
      &mut aggregates,
      Comparator::Oxibelt,
      "h1-keepalive",
      100.0,
      1.0,
    );
    insert_primary_aggregate(&mut aggregates, Comparator::Oxibelt, "h2", 100.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Oxibelt, "h3", 100.0, 1.0);
    let aggregate = aggregates
      .get_mut(&(Comparator::Oxibelt, "h3".to_owned()))
      .expect("synthetic aggregate should exist");
    aggregate.fast_path = Some(AggregateFastPathStats {
      plain_proxy_h1: None,
      plain_proxy_h2: None,
      plain_proxy_h3: Some(passing_fast_path_aggregate()),
      transport_direct_h1_h1: None,
      transport_direct_h1_h2: None,
      transport_direct_h1_h3: Some(FastPathAggregateStats {
        sample_count: 1,
        hits: 98,
        misses: 2,
        attempts: 100,
        median_hit_rate: Some(0.98),
        min_hit_rate: Some(0.98),
      }),
      transport_direct_h2_h1: None,
      transport_direct_h2_h2: None,
      transport_direct_h2_h3: None,
      direct_h1_pool: None,
      direct_h2_pool: None,
      static_responses: None,
      stage_timing: None,
    });

    let gates = build_regression_gate_report(
      &aggregates,
      RegressionGateThresholds {
        h1_keepalive_min_nginx_ratio: DEFAULT_H1_KEEPALIVE_MIN_NGINX_RATIO,
        h1_fast_path_min_hit_rate: DEFAULT_H1_FAST_PATH_MIN_HIT_RATE,
        h2_min_nginx_ratio: DEFAULT_H2_MIN_NGINX_RATIO,
        h3_min_nginx_ratio: DEFAULT_H3_MIN_NGINX_RATIO,
        static_16k_h1c_min_caddy_ratio: DEFAULT_STATIC_16K_H1C_MIN_CADDY_RATIO,
        static_16k_h1c_min_nginx_ratio: DEFAULT_STATIC_16K_H1C_MIN_NGINX_RATIO,
        remote_signer_handshake_min_local_ratio: DEFAULT_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO,
        waf_enforcing_min_rps: DEFAULT_WAF_ENFORCING_MIN_RPS,
        crs_enforcing_min_rps: DEFAULT_CRS_ENFORCING_MIN_RPS,
        waf_crs_max_enforce_p99_ratio: DEFAULT_WAF_CRS_MAX_ENFORCE_P99_RATIO,
      },
      None,
      DEFAULT_AMD64_TARGET_CPU,
      None,
    );

    assert!(gates.violations.iter().any(|violation| {
      violation.gate == "h3_fast_path_min_hit_rate"
        && violation.metric == "transport_direct_h1_h3_min_hit_rate"
        && violation.observed == Some(0.98)
        && violation.evaluation_mode == "evidence"
    }));
  }

  #[test]
  fn h1_near_target_ratio_miss_is_advisory_with_passing_stable_baseline() {
    let mut aggregates = PrimaryAggregateMap::new();
    insert_primary_aggregate(
      &mut aggregates,
      Comparator::Oxibelt,
      "h1-keepalive",
      79.91894755703424,
      10.2,
    );
    insert_primary_aggregate(
      &mut aggregates,
      Comparator::Nginx,
      "h1-keepalive",
      100.0,
      10.0,
    );
    insert_primary_aggregate(&mut aggregates, Comparator::Oxibelt, "h2", 100.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Nginx, "h2", 100.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Oxibelt, "h3", 100.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Nginx, "h3", 100.0, 1.0);

    let mut baseline_aggregates = PrimaryAggregateMap::new();
    insert_primary_aggregate(
      &mut baseline_aggregates,
      Comparator::Oxibelt,
      "h1-keepalive",
      81.0,
      10.0,
    );
    insert_primary_aggregate(
      &mut baseline_aggregates,
      Comparator::Nginx,
      "h1-keepalive",
      100.0,
      10.0,
    );
    let baseline = baseline_context_for(&baseline_aggregates);

    let gates = build_regression_gate_report(
      &aggregates,
      RegressionGateThresholds {
        h1_keepalive_min_nginx_ratio: 0.80,
        h1_fast_path_min_hit_rate: DEFAULT_H1_FAST_PATH_MIN_HIT_RATE,
        h2_min_nginx_ratio: 0.80,
        h3_min_nginx_ratio: 0.80,
        static_16k_h1c_min_caddy_ratio: DEFAULT_STATIC_16K_H1C_MIN_CADDY_RATIO,
        static_16k_h1c_min_nginx_ratio: DEFAULT_STATIC_16K_H1C_MIN_NGINX_RATIO,
        remote_signer_handshake_min_local_ratio: DEFAULT_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO,
        waf_enforcing_min_rps: DEFAULT_WAF_ENFORCING_MIN_RPS,
        crs_enforcing_min_rps: DEFAULT_CRS_ENFORCING_MIN_RPS,
        waf_crs_max_enforce_p99_ratio: DEFAULT_WAF_CRS_MAX_ENFORCE_P99_RATIO,
      },
      Some(&baseline),
      DEFAULT_AMD64_TARGET_CPU,
      None,
    );

    assert!(
      gates.advisories.iter().any(|advisory| {
        advisory.gate == "h1_keepalive_min_nginx_ratio" && advisory.disposition == "advisory"
      }),
      "H1 keep-alive should become an advisory for a baseline-stable near miss"
    );
    assert!(
      !gates
        .violations
        .iter()
        .any(|violation| violation.gate == "h1_keepalive_min_nginx_ratio"),
      "H1 keep-alive near miss should not block when baseline evidence is stable"
    );
  }

  #[test]
  fn h1_comparator_shift_ratio_miss_is_advisory_when_oxibelt_stays_stable() {
    let mut aggregates = PrimaryAggregateMap::new();
    insert_primary_aggregate(
      &mut aggregates,
      Comparator::Oxibelt,
      "h1-keepalive",
      78.8,
      10.4,
    );
    insert_primary_aggregate(
      &mut aggregates,
      Comparator::Nginx,
      "h1-keepalive",
      100.0,
      10.0,
    );
    insert_primary_aggregate(&mut aggregates, Comparator::Oxibelt, "h2", 100.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Nginx, "h2", 100.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Oxibelt, "h3", 100.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Nginx, "h3", 100.0, 1.0);

    let mut baseline_aggregates = PrimaryAggregateMap::new();
    insert_primary_aggregate(
      &mut baseline_aggregates,
      Comparator::Oxibelt,
      "h1-keepalive",
      81.0,
      10.0,
    );
    insert_primary_aggregate(
      &mut baseline_aggregates,
      Comparator::Nginx,
      "h1-keepalive",
      98.0,
      10.0,
    );
    let baseline = baseline_context_for(&baseline_aggregates);

    let gates = build_regression_gate_report(
      &aggregates,
      RegressionGateThresholds {
        h1_keepalive_min_nginx_ratio: 0.80,
        h1_fast_path_min_hit_rate: DEFAULT_H1_FAST_PATH_MIN_HIT_RATE,
        h2_min_nginx_ratio: 0.80,
        h3_min_nginx_ratio: 0.80,
        static_16k_h1c_min_caddy_ratio: DEFAULT_STATIC_16K_H1C_MIN_CADDY_RATIO,
        static_16k_h1c_min_nginx_ratio: DEFAULT_STATIC_16K_H1C_MIN_NGINX_RATIO,
        remote_signer_handshake_min_local_ratio: DEFAULT_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO,
        waf_enforcing_min_rps: DEFAULT_WAF_ENFORCING_MIN_RPS,
        crs_enforcing_min_rps: DEFAULT_CRS_ENFORCING_MIN_RPS,
        waf_crs_max_enforce_p99_ratio: DEFAULT_WAF_CRS_MAX_ENFORCE_P99_RATIO,
      },
      Some(&baseline),
      DEFAULT_AMD64_TARGET_CPU,
      None,
    );

    assert!(
      gates.advisories.iter().any(|advisory| {
        advisory.gate == "h1_keepalive_min_nginx_ratio"
          && advisory.disposition == "advisory"
          && advisory.message.contains("comparator-shift ratio miss")
      }),
      "H1 keep-alive should become an advisory when OxiBelt is baseline-stable"
    );
    assert!(
      !gates
        .violations
        .iter()
        .any(|violation| violation.gate == "h1_keepalive_min_nginx_ratio"),
      "H1 keep-alive comparator-shift miss should not block when OxiBelt is stable"
    );
  }

  #[test]
  fn h1_comparator_shift_ratio_miss_blocks_below_floor() {
    let mut aggregates = PrimaryAggregateMap::new();
    insert_primary_aggregate(
      &mut aggregates,
      Comparator::Oxibelt,
      "h1-keepalive",
      74.9,
      10.0,
    );
    insert_primary_aggregate(
      &mut aggregates,
      Comparator::Nginx,
      "h1-keepalive",
      100.0,
      10.0,
    );
    insert_primary_aggregate(&mut aggregates, Comparator::Oxibelt, "h2", 100.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Nginx, "h2", 100.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Oxibelt, "h3", 100.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Nginx, "h3", 100.0, 1.0);

    let mut baseline_aggregates = PrimaryAggregateMap::new();
    insert_primary_aggregate(
      &mut baseline_aggregates,
      Comparator::Oxibelt,
      "h1-keepalive",
      81.0,
      10.0,
    );
    insert_primary_aggregate(
      &mut baseline_aggregates,
      Comparator::Nginx,
      "h1-keepalive",
      100.0,
      10.0,
    );
    let baseline = baseline_context_for(&baseline_aggregates);

    let gates = build_regression_gate_report(
      &aggregates,
      RegressionGateThresholds {
        h1_keepalive_min_nginx_ratio: 0.80,
        h1_fast_path_min_hit_rate: DEFAULT_H1_FAST_PATH_MIN_HIT_RATE,
        h2_min_nginx_ratio: 0.80,
        h3_min_nginx_ratio: 0.80,
        static_16k_h1c_min_caddy_ratio: DEFAULT_STATIC_16K_H1C_MIN_CADDY_RATIO,
        static_16k_h1c_min_nginx_ratio: DEFAULT_STATIC_16K_H1C_MIN_NGINX_RATIO,
        remote_signer_handshake_min_local_ratio: DEFAULT_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO,
        waf_enforcing_min_rps: DEFAULT_WAF_ENFORCING_MIN_RPS,
        crs_enforcing_min_rps: DEFAULT_CRS_ENFORCING_MIN_RPS,
        waf_crs_max_enforce_p99_ratio: DEFAULT_WAF_CRS_MAX_ENFORCE_P99_RATIO,
      },
      Some(&baseline),
      DEFAULT_AMD64_TARGET_CPU,
      None,
    );

    assert!(
      gates.violations.iter().any(|violation| {
        violation.gate == "h1_keepalive_min_nginx_ratio"
          && violation.disposition == "blocking"
          && violation
            .message
            .contains("below comparator-shift advisory floor")
      }),
      "H1 keep-alive should block below the comparator-shift advisory floor"
    );
    assert!(
      !gates
        .advisories
        .iter()
        .any(|advisory| advisory.gate == "h1_keepalive_min_nginx_ratio"),
      "H1 keep-alive should not be advisory below the comparator-shift floor"
    );
  }

  #[test]
  fn h1_material_ratio_miss_blocks_while_h2_and_h3_stable_gaps_are_advisory() {
    let mut aggregates = PrimaryAggregateMap::new();
    insert_primary_aggregate(
      &mut aggregates,
      Comparator::Oxibelt,
      "h1-keepalive",
      79.0,
      1.0,
    );
    insert_primary_aggregate(
      &mut aggregates,
      Comparator::Nginx,
      "h1-keepalive",
      100.0,
      1.0,
    );
    insert_primary_aggregate(&mut aggregates, Comparator::Oxibelt, "h2", 79.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Nginx, "h2", 100.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Oxibelt, "h3", 79.0, 1.0);
    insert_primary_aggregate(&mut aggregates, Comparator::Nginx, "h3", 100.0, 1.0);
    let baseline = baseline_context_for(&aggregates);

    let gates = build_regression_gate_report(
      &aggregates,
      RegressionGateThresholds {
        h1_keepalive_min_nginx_ratio: 0.80,
        h1_fast_path_min_hit_rate: DEFAULT_H1_FAST_PATH_MIN_HIT_RATE,
        h2_min_nginx_ratio: 0.80,
        h3_min_nginx_ratio: 0.80,
        static_16k_h1c_min_caddy_ratio: DEFAULT_STATIC_16K_H1C_MIN_CADDY_RATIO,
        static_16k_h1c_min_nginx_ratio: DEFAULT_STATIC_16K_H1C_MIN_NGINX_RATIO,
        remote_signer_handshake_min_local_ratio: DEFAULT_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO,
        waf_enforcing_min_rps: DEFAULT_WAF_ENFORCING_MIN_RPS,
        crs_enforcing_min_rps: DEFAULT_CRS_ENFORCING_MIN_RPS,
        waf_crs_max_enforce_p99_ratio: DEFAULT_WAF_CRS_MAX_ENFORCE_P99_RATIO,
      },
      Some(&baseline),
      DEFAULT_AMD64_TARGET_CPU,
      None,
    );

    assert!(
      gates.violations.iter().any(|violation| {
        violation.gate == "h1_keepalive_min_nginx_ratio" && violation.disposition == "blocking"
      }),
      "H1 keep-alive should remain a blocking target gate"
    );
    assert!(
      !gates
        .advisories
        .iter()
        .any(|advisory| advisory.gate == "h1_keepalive_min_nginx_ratio"),
      "H1 keep-alive should not be downgraded to an advisory"
    );

    for gate in ["h2_min_nginx_ratio", "h3_min_nginx_ratio"] {
      assert!(
        gates
          .advisories
          .iter()
          .any(|advisory| advisory.gate == gate && advisory.disposition == "advisory"),
        "{gate} should become an advisory when baseline evidence is stable"
      );
      assert!(
        !gates
          .violations
          .iter()
          .any(|violation| violation.gate == gate),
        "{gate} should not block when baseline evidence is stable"
      );
    }
  }

  #[test]
  fn unsupported_cpu_markers_are_excluded_from_expected_results() {
    let input_dir = temp_dir("unsupported");
    let artifact_dir = input_dir
      .path()
      .join("oxibelt-docker-performance-smoke-reverse-proxy-shard-1");
    fs::create_dir_all(&artifact_dir).expect("unsupported artifact dir should be creatable");
    fs::write(
      artifact_dir.join("unsupported-cpu.json"),
      r#"{"schema_version":1,"required_target_cpu":"x86-64-v3"}"#,
    )
    .expect("unsupported marker should be writable");
    fs::create_dir_all(artifact_dir.join("run-1")).expect("run dir should be creatable");
    fs::write(
      artifact_dir.join("run-1/results.json"),
      r#"{"type":"load","label":"oxibelt-h1-keepalive","requests":1,"rps":1}"#,
    )
    .expect("ignored unsupported result should be writable");

    let report = aggregate(
      input_dir.path(),
      AggregateOptions {
        profile: Some("smoke".to_owned()),
        expected_runs: Some(5),
        expected_shards: Some(2),
        expected_target_cpus: Vec::new(),
        primary_target_cpu: DEFAULT_AMD64_TARGET_CPU.to_owned(),
        baseline_report: None,
        baseline_context: None,
        accepted_regression_reason: None,
      },
    );

    assert_eq!(report.artifact_discovery.results_files, 0);
    assert!(report.aggregates.is_empty());
    assert_eq!(report.artifact_discovery.unsupported_cpu.count, 1);
    assert_eq!(
      report.artifact_discovery.unsupported_cpu.shards,
      vec!["reverse-proxy/shard-1".to_owned()]
    );
    assert_eq!(
      report.artifact_discovery.expected_results_files,
      Some((SERVING_TYPES.len() * 2 - 1) * 5)
    );
    assert!(
      !report
        .artifact_discovery
        .missing_expected_paths
        .iter()
        .any(|path| path == "oxibelt-docker-performance-smoke-reverse-proxy-shard-1"),
      "unsupported shard should not be reported as missing expected results"
    );
    assert!(
      report
        .warnings
        .iter()
        .any(|warning| warning.contains("only unsupported CPU marker artifacts")),
      "all-unsupported aggregate should explain why no results were found"
    );
  }

  #[test]
  fn target_cpu_unsupported_markers_are_excluded_from_expected_results() {
    let input_dir = temp_dir("target-unsupported");
    let artifact_dir = input_dir
      .path()
      .join("oxibelt-docker-performance-smoke-reverse-proxy-shard-1/x86-64-v4");
    fs::create_dir_all(&artifact_dir).expect("unsupported target dir should be creatable");
    fs::write(
      artifact_dir.join("unsupported-cpu.json"),
      r#"{"schema_version":1,"required_target_cpu":"x86-64-v4"}"#,
    )
    .expect("unsupported marker should be writable");

    let report = aggregate(
      input_dir.path(),
      AggregateOptions {
        profile: Some("smoke".to_owned()),
        expected_runs: Some(1),
        expected_shards: Some(1),
        expected_target_cpus: vec![
          "x86-64-v2".to_owned(),
          "x86-64-v3".to_owned(),
          "x86-64-v4".to_owned(),
        ],
        primary_target_cpu: DEFAULT_AMD64_TARGET_CPU.to_owned(),
        baseline_report: None,
        baseline_context: None,
        accepted_regression_reason: None,
      },
    );

    assert_eq!(report.artifact_discovery.unsupported_cpu.count, 1);
    assert_eq!(
      report.artifact_discovery.unsupported_cpu.shards,
      vec!["reverse-proxy/shard-1/x86-64-v4".to_owned()]
    );
    assert_eq!(
      report.artifact_discovery.expected_results_files,
      Some(SERVING_TYPES.len() * 3 - 1)
    );
    assert!(
      !report
        .artifact_discovery
        .missing_expected_paths
        .iter()
        .any(|path| path
          == "oxibelt-docker-performance-smoke-reverse-proxy-shard-1/x86-64-v4/run-1/results.json"),
      "unsupported target should not be reported as a missing expected result"
    );
  }

  #[test]
  fn unsupported_cpu_markers_are_rendered_in_markdown() {
    let input_dir = temp_dir("markdown");
    let artifact_dir = input_dir
      .path()
      .join("oxibelt-docker-performance-benchmark-static-files-shard-20");
    fs::create_dir_all(&artifact_dir).expect("unsupported artifact dir should be creatable");
    fs::write(
      artifact_dir.join("unsupported-cpu.json"),
      r#"{"schema_version":1,"required_target_cpu":"x86-64-v3"}"#,
    )
    .expect("unsupported marker should be writable");

    let report = aggregate(
      input_dir.path(),
      AggregateOptions {
        profile: Some("benchmark".to_owned()),
        expected_runs: Some(5),
        expected_shards: Some(20),
        expected_target_cpus: Vec::new(),
        primary_target_cpu: DEFAULT_AMD64_TARGET_CPU.to_owned(),
        baseline_report: None,
        baseline_context: None,
        accepted_regression_reason: None,
      },
    );
    let markdown = render_markdown(&report);

    assert!(markdown.contains("Unsupported AMD64 target artifacts: `1`"));
    assert!(markdown.contains("Unsupported AMD64 target shards excluded: `static-files/shard-20`"));
  }
}
