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
const DEFAULT_H2_MIN_NGINX_RATIO: f64 = 0.90;
const DEFAULT_STATIC_16K_H1C_MIN_CADDY_RATIO: f64 = 0.85;
const DEFAULT_STATIC_16K_H1C_MIN_NGINX_RATIO: f64 = 0.95;
const DEFAULT_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO: f64 = 0.95;
const DEFAULT_WAF_ENFORCING_MIN_RPS: f64 = 11000.0;
const DEFAULT_CRS_ENFORCING_MIN_RPS: f64 = 9000.0;
const DEFAULT_WAF_CRS_MAX_ENFORCE_P99_RATIO: f64 = 1.20;
const SERVING_TYPES: [&str; 6] = [
    "reverse-proxy",
    "static-files",
    "oxibelt-features",
    "oxibelt-soak-stress",
    "accept-multipliers",
    "remote-signer",
];

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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
    baseline_report: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Comparator {
    Oxibelt,
    Nginx,
    Caddy,
}

impl Comparator {
    fn as_str(self) -> &'static str {
        match self {
            Self::Oxibelt => "oxibelt",
            Self::Nginx => "nginx",
            Self::Caddy => "caddy",
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
    summary_count: usize,
    docker_stats_count: usize,
}

#[derive(Serialize)]
struct ArtifactDiscovery {
    results_files: usize,
    summary_files: usize,
    docker_stats_files: usize,
    expected_results_files: Option<usize>,
    missing_expected_paths: Vec<String>,
}

#[derive(Clone)]
struct BenchmarkRow {
    source_file: String,
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
}

#[derive(Default)]
struct AggregateBuilder {
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
    total_errors: u64,
    skipped_count: u64,
    skip_reasons: BTreeSet<String>,
    source_files: BTreeSet<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct AggregateStats {
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
}

#[derive(Serialize)]
struct RatioResult {
    status: String,
    ratio: Option<f64>,
    percent_of_comparator: Option<f64>,
    text: String,
    reason: Option<String>,
}

#[derive(Serialize)]
struct ScenarioComparison {
    scenario: String,
    group: String,
    oxibelt: Option<AggregateStats>,
    nginx: Option<AggregateStats>,
    caddy: Option<AggregateStats>,
    oxibelt_vs_nginx: RatioResult,
    oxibelt_vs_caddy: RatioResult,
}

#[derive(Serialize)]
struct ComparisonGroups {
    reverse_proxy: Vec<ScenarioComparison>,
    static_files: Vec<ScenarioComparison>,
}

#[derive(Serialize)]
struct AcceptMultiplierRatio {
    status: String,
    ratio: Option<f64>,
    percent_of_accept_0_5: Option<f64>,
    text: String,
    reason: Option<String>,
}

#[derive(Serialize)]
struct AcceptMultiplierComparison {
    scenario: String,
    accept_0_5: Option<AggregateStats>,
    accept_1_0: Option<AggregateStats>,
    accept_1_0_vs_0_5: AcceptMultiplierRatio,
}

#[derive(Serialize)]
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

#[derive(Serialize)]
struct RemoteSignerComparison {
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
}

#[derive(Serialize)]
struct ReportSummary {
    reverse_proxy: GroupSummary,
    static_files: GroupSummary,
    accept_multipliers: AcceptMultiplierSummary,
    remote_signer: RemoteSignerSummary,
    oxibelt_only_row_count: usize,
}

#[derive(Clone, Copy, Serialize)]
struct RegressionGateThresholds {
    h2_min_nginx_ratio: f64,
    static_16k_h1c_min_caddy_ratio: f64,
    static_16k_h1c_min_nginx_ratio: f64,
    remote_signer_handshake_min_local_ratio: f64,
    waf_enforcing_min_rps: f64,
    crs_enforcing_min_rps: f64,
    waf_crs_max_enforce_p99_ratio: f64,
}

#[derive(Serialize)]
struct RegressionGateViolation {
    gate: String,
    group: String,
    scenario: String,
    metric: String,
    observed: Option<f64>,
    threshold: f64,
    comparator: Option<String>,
    message: String,
}

#[derive(Serialize)]
struct RegressionGateReport {
    status: String,
    thresholds: RegressionGateThresholds,
    violations: Vec<RegressionGateViolation>,
}

#[derive(Clone, Copy)]
struct RegressionGateContext<'a> {
    gate: &'a str,
    group: &'a str,
    scenario: &'a str,
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
    group: String,
    scenario: String,
    comparator: String,
    status: String,
    reason: String,
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    profile: Option<String>,
    expected_runs: Option<usize>,
    artifact_discovery: ArtifactDiscovery,
    summary: ReportSummary,
    comparisons: ComparisonGroups,
    accept_multiplier_comparisons: Vec<AcceptMultiplierComparison>,
    remote_signer_comparisons: Vec<RemoteSignerComparison>,
    oxibelt_only_results: Vec<AggregateStats>,
    skipped_or_missing_comparator_rows: Vec<MissingComparatorRow>,
    regression_gates: RegressionGateReport,
    aggregates: Vec<AggregateStats>,
    warnings: Vec<String>,
    warnings_omitted: usize,
}

#[derive(Deserialize)]
struct BaselineReport {
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
    classification: String,
    reason: String,
}

impl AggregateBuilder {
    fn push(&mut self, row: BenchmarkRow) {
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
        }
        self.total_errors = self.total_errors.saturating_add(row.errors);
        if row.skipped {
            self.skipped_count = self.skipped_count.saturating_add(1);
            if let Some(reason) = row.reason {
                self.skip_reasons.insert(reason);
            }
        }
        self.source_files.insert(row.source_file);
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

        AggregateStats {
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
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let report = aggregate(&args.input_dir, args.profile, args.expected_runs);
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

fn aggregate(input_dir: &Path, profile: Option<String>, expected_runs: Option<usize>) -> Report {
    let mut warnings = WarningBag::default();
    let regression_gate_thresholds = regression_gate_thresholds(&mut warnings);
    let discovered = discover_files(input_dir, &mut warnings);
    let mut artifact_discovery = ArtifactDiscovery {
        results_files: discovered.results.len(),
        summary_files: discovered.summary_count,
        docker_stats_files: discovered.docker_stats_count,
        expected_results_files: None,
        missing_expected_paths: Vec::new(),
    };

    add_expected_artifact_warnings(
        input_dir,
        profile.as_deref(),
        expected_runs,
        &mut artifact_discovery,
        &mut warnings,
    );
    if discovered.results.is_empty() {
        warnings.push("no results.json files were discovered");
    }

    let mut builders: BTreeMap<(Comparator, String), AggregateBuilder> = BTreeMap::new();
    for results_path in &discovered.results {
        for row in parse_results_file(input_dir, results_path, &mut warnings) {
            builders
                .entry((row.comparator, row.scenario.clone()))
                .or_default()
                .push(row);
        }
    }

    let mut aggregate_map = BTreeMap::new();
    for (key, builder) in builders {
        aggregate_map.insert(key, builder.finish());
    }

    let reverse_proxy = build_group_comparisons(ScenarioGroup::ReverseProxy, &aggregate_map);
    let static_files = build_group_comparisons(ScenarioGroup::StaticFiles, &aggregate_map);
    let accept_multiplier_comparisons = build_accept_multiplier_comparisons(&aggregate_map);
    let remote_signer_comparisons = build_remote_signer_comparisons(&aggregate_map);
    let regression_gates = build_regression_gate_report(&aggregate_map, regression_gate_thresholds);
    let oxibelt_only_results = aggregate_map
        .iter()
        .filter(|((comparator, _), aggregate)| {
            *comparator == Comparator::Oxibelt
                && aggregate.group == ScenarioGroup::OxibeltOnly.as_str()
        })
        .map(|(_, aggregate)| aggregate.clone())
        .collect::<Vec<_>>();
    let skipped_or_missing_comparator_rows = skipped_or_missing_rows(&reverse_proxy, &static_files);
    let aggregates = aggregate_map.into_values().collect::<Vec<_>>();
    let summary = ReportSummary {
        reverse_proxy: summarize_group(&reverse_proxy),
        static_files: summarize_group(&static_files),
        accept_multipliers: summarize_accept_multiplier_comparisons(&accept_multiplier_comparisons),
        remote_signer: summarize_remote_signer_comparisons(&remote_signer_comparisons),
        oxibelt_only_row_count: oxibelt_only_results.len(),
    };
    let (warnings, warnings_omitted) = warnings.finish();

    Report {
        schema_version: 4,
        profile,
        expected_runs,
        artifact_discovery,
        summary,
        comparisons: ComparisonGroups {
            reverse_proxy,
            static_files,
        },
        accept_multiplier_comparisons,
        remote_signer_comparisons,
        oxibelt_only_results,
        skipped_or_missing_comparator_rows,
        regression_gates,
        aggregates,
        warnings,
        warnings_omitted,
    }
}

fn discover_files(input_dir: &Path, warnings: &mut WarningBag) -> DiscoveredFiles {
    let mut discovered = DiscoveredFiles {
        results: Vec::new(),
        summary_count: 0,
        docker_stats_count: 0,
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
                "summary.md" => discovered.summary_count += 1,
                "docker-stats.jsonl" => discovered.docker_stats_count += 1,
                _ => {}
            }
        }
    }

    discovered.results.sort();
    discovered
}

fn add_expected_artifact_warnings(
    input_dir: &Path,
    profile: Option<&str>,
    expected_runs: Option<usize>,
    artifact_discovery: &mut ArtifactDiscovery,
    warnings: &mut WarningBag,
) {
    let Some(profile) = profile else {
        if expected_runs.is_some() {
            warnings.push(
                "--expected-runs was provided without --profile; skipping expected artifact checks",
            );
        }
        return;
    };
    let Some(expected_runs) = expected_runs else {
        return;
    };

    artifact_discovery.expected_results_files = Some(SERVING_TYPES.len() * 5 * expected_runs);
    for serving_type in SERVING_TYPES {
        for shard in 1..=5 {
            let artifact_name =
                format!("oxibelt-docker-performance-{profile}-{serving_type}-shard-{shard}");
            let artifact_dir = input_dir.join(&artifact_name);
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
        }
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
            "{source_file} row {row_index}: label {label:?} does not start with oxibelt-, nginx-, or caddy-"
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
    })
}

fn normalize_label(label: &str) -> Option<(Comparator, &str)> {
    if let Some(scenario) = label.strip_prefix("oxibelt-") {
        Some((Comparator::Oxibelt, scenario))
    } else if let Some(scenario) = label.strip_prefix("nginx-") {
        Some((Comparator::Nginx, scenario))
    } else if let Some(scenario) = label.strip_prefix("caddy-") {
        Some((Comparator::Caddy, scenario))
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
    aggregates: &BTreeMap<(Comparator, String), AggregateStats>,
) -> Vec<ScenarioComparison> {
    let mut scenarios = BTreeSet::new();
    for ((comparator, scenario), aggregate) in aggregates {
        if *comparator == Comparator::Oxibelt && aggregate.group == group.as_str() {
            scenarios.insert(scenario.clone());
        }
    }

    scenarios
        .into_iter()
        .map(|scenario| {
            let oxibelt = aggregates
                .get(&(Comparator::Oxibelt, scenario.clone()))
                .cloned();
            let nginx = aggregates
                .get(&(Comparator::Nginx, scenario.clone()))
                .cloned();
            let caddy = aggregates
                .get(&(Comparator::Caddy, scenario.clone()))
                .cloned();
            let oxibelt_vs_nginx =
                ratio_result(oxibelt.as_ref(), nginx.as_ref(), Comparator::Nginx);
            let oxibelt_vs_caddy =
                ratio_result(oxibelt.as_ref(), caddy.as_ref(), Comparator::Caddy);

            ScenarioComparison {
                scenario,
                group: group.as_str().to_owned(),
                oxibelt,
                nginx,
                caddy,
                oxibelt_vs_nginx,
                oxibelt_vs_caddy,
            }
        })
        .collect()
}

fn build_accept_multiplier_comparisons(
    aggregates: &BTreeMap<(Comparator, String), AggregateStats>,
) -> Vec<AcceptMultiplierComparison> {
    let mut scenarios = BTreeSet::new();
    for ((comparator, scenario), aggregate) in aggregates {
        if *comparator == Comparator::Oxibelt
            && aggregate.group == ScenarioGroup::AcceptMultipliers.as_str()
            && let Some(base) = accept_multiplier_base_scenario(scenario)
        {
            scenarios.insert(base.to_owned());
        }
    }

    scenarios
        .into_iter()
        .map(|scenario| {
            let accept_0_5 = aggregates
                .get(&(Comparator::Oxibelt, format!("accept-0_5-{scenario}")))
                .cloned();
            let accept_1_0 = aggregates
                .get(&(Comparator::Oxibelt, format!("accept-1_0-{scenario}")))
                .cloned();
            let accept_1_0_vs_0_5 =
                accept_multiplier_ratio(accept_1_0.as_ref(), accept_0_5.as_ref());

            AcceptMultiplierComparison {
                scenario,
                accept_0_5,
                accept_1_0,
                accept_1_0_vs_0_5,
            }
        })
        .collect()
}

fn build_remote_signer_comparisons(
    aggregates: &BTreeMap<(Comparator, String), AggregateStats>,
) -> Vec<RemoteSignerComparison> {
    let mut scenarios = BTreeSet::new();
    for ((comparator, scenario), aggregate) in aggregates {
        if *comparator == Comparator::Oxibelt
            && aggregate.group == ScenarioGroup::RemoteSigner.as_str()
            && let Some(base) = remote_signer_base_scenario(scenario)
        {
            scenarios.insert(base.to_owned());
        }
    }

    scenarios
        .into_iter()
        .map(|scenario| {
            let local_key = aggregates
                .get(&(Comparator::Oxibelt, format!("local-key-{scenario}")))
                .cloned();
            let remote_signer = aggregates
                .get(&(Comparator::Oxibelt, format!("remote-signer-{scenario}")))
                .cloned();
            let remote_signer_vs_local_key =
                remote_signer_ratio(remote_signer.as_ref(), local_key.as_ref());

            RemoteSignerComparison {
                scenario,
                local_key,
                remote_signer,
                remote_signer_vs_local_key,
            }
        })
        .collect()
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
        return remote_signer_ratio_status(
            "no_remote_signer",
            None,
            None,
            "missing remote-signer row",
        );
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
        h2_min_nginx_ratio: env_threshold(
            "OXIBELT_PERF_H2_MIN_NGINX_RATIO",
            DEFAULT_H2_MIN_NGINX_RATIO,
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

fn build_regression_gate_report(
    aggregates: &BTreeMap<(Comparator, String), AggregateStats>,
    thresholds: RegressionGateThresholds,
) -> RegressionGateReport {
    let mut violations = Vec::new();

    collect_comparator_ratio_regression_gate(
        aggregates,
        "h2_min_nginx_ratio",
        ScenarioGroup::ReverseProxy,
        "h2",
        Comparator::Nginx,
        thresholds.h2_min_nginx_ratio,
        &mut violations,
    );
    collect_static_regression_gate(aggregates, thresholds, &mut violations);
    collect_comparator_ratio_regression_gate(
        aggregates,
        "static_16k_h1c_min_nginx_ratio",
        ScenarioGroup::StaticFiles,
        "static-16k-h1c",
        Comparator::Nginx,
        thresholds.static_16k_h1c_min_nginx_ratio,
        &mut violations,
    );
    collect_remote_signer_handshake_regression_gate(aggregates, thresholds, &mut violations);
    collect_min_rps_regression_gate(
        aggregates,
        "waf_enforcing_min_rps",
        "waf-enforcing",
        thresholds.waf_enforcing_min_rps,
        &mut violations,
    );
    collect_min_rps_regression_gate(
        aggregates,
        "crs_enforcing_min_rps",
        "crs-enforcing",
        thresholds.crs_enforcing_min_rps,
        &mut violations,
    );
    collect_p99_ratio_regression_gate(
        aggregates,
        "waf_enforce_p99_ratio",
        "waf-monitor",
        "waf-enforcing",
        thresholds.waf_crs_max_enforce_p99_ratio,
        &mut violations,
    );
    collect_p99_ratio_regression_gate(
        aggregates,
        "crs_enforce_p99_ratio",
        "crs-monitor",
        "crs-enforcing",
        thresholds.waf_crs_max_enforce_p99_ratio,
        &mut violations,
    );

    let status = if violations.is_empty() {
        "pass"
    } else {
        "fail"
    };
    RegressionGateReport {
        status: status.to_owned(),
        thresholds,
        violations,
    }
}

fn collect_static_regression_gate(
    aggregates: &BTreeMap<(Comparator, String), AggregateStats>,
    thresholds: RegressionGateThresholds,
    violations: &mut Vec<RegressionGateViolation>,
) {
    let gate = "static_16k_h1c_min_caddy_ratio";
    let scenario = "static-16k-h1c";
    let group = ScenarioGroup::StaticFiles.as_str();
    let threshold = thresholds.static_16k_h1c_min_caddy_ratio;
    let context = RegressionGateContext {
        gate,
        group,
        scenario,
        threshold,
    };
    let Some(oxibelt_rps) = aggregate_median_rps(aggregates, Comparator::Oxibelt, scenario) else {
        push_missing_regression_gate_metric(
            violations,
            context,
            "median_rps",
            Some("oxibelt"),
            "missing OxiBelt static-16k-h1c median RPS; cannot evaluate static regression gate",
        );
        return;
    };
    if oxibelt_rps <= 0.0 {
        push_invalid_regression_gate_metric(
            violations,
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
            violations,
            context,
            "median_rps",
            Some("caddy"),
            "missing Caddy static-16k-h1c median RPS; cannot evaluate static regression gate",
        );
        return;
    };
    if caddy_rps <= 0.0 {
        push_invalid_regression_gate_metric(
            violations,
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
        violations.push(RegressionGateViolation {
            gate: gate.to_owned(),
            group: group.to_owned(),
            scenario: scenario.to_owned(),
            metric: "median_rps_ratio".to_owned(),
            observed: Some(ratio),
            threshold,
            comparator: Some("caddy".to_owned()),
            message: format!(
                "OxiBelt static-16k-h1c median RPS ratio {:.4} < {:.4} vs Caddy ({:.3} RPS vs {:.3} RPS)",
                ratio, threshold, oxibelt_rps, caddy_rps
            ),
        });
    }
}

fn collect_comparator_ratio_regression_gate(
    aggregates: &BTreeMap<(Comparator, String), AggregateStats>,
    gate: &str,
    group: ScenarioGroup,
    scenario: &str,
    comparator: Comparator,
    threshold: f64,
    violations: &mut Vec<RegressionGateViolation>,
) {
    let comparator_name = comparator.as_str();
    let context = RegressionGateContext {
        gate,
        group: group.as_str(),
        scenario,
        threshold,
    };
    let Some(oxibelt_rps) = aggregate_median_rps(aggregates, Comparator::Oxibelt, scenario) else {
        push_missing_regression_gate_metric(
            violations,
            context,
            "median_rps",
            Some("oxibelt"),
            format!("missing OxiBelt {scenario} median RPS; cannot evaluate {gate}"),
        );
        return;
    };
    if oxibelt_rps <= 0.0 {
        push_invalid_regression_gate_metric(
            violations,
            context,
            "median_rps",
            oxibelt_rps,
            Some("oxibelt"),
            format!(
                "OxiBelt {scenario} median RPS must be positive; got {:.3}",
                oxibelt_rps
            ),
        );
        return;
    }
    let Some(comparator_rps) = aggregate_median_rps(aggregates, comparator, scenario) else {
        push_missing_regression_gate_metric(
            violations,
            context,
            "median_rps",
            Some(comparator_name),
            format!("missing {comparator_name} {scenario} median RPS; cannot evaluate {gate}"),
        );
        return;
    };
    if comparator_rps <= 0.0 {
        push_invalid_regression_gate_metric(
            violations,
            context,
            "median_rps",
            comparator_rps,
            Some(comparator_name),
            format!(
                "{comparator_name} {scenario} median RPS must be positive; got {:.3}",
                comparator_rps
            ),
        );
        return;
    }

    let ratio = oxibelt_rps / comparator_rps;
    if ratio < threshold {
        violations.push(RegressionGateViolation {
            gate: gate.to_owned(),
            group: group.as_str().to_owned(),
            scenario: scenario.to_owned(),
            metric: "median_rps_ratio".to_owned(),
            observed: Some(ratio),
            threshold,
            comparator: Some(comparator_name.to_owned()),
            message: format!(
                "OxiBelt {scenario} median RPS ratio {:.4} < {:.4} vs {comparator_name} ({:.3} RPS vs {:.3} RPS)",
                ratio, threshold, oxibelt_rps, comparator_rps
            ),
        });
    }
}

fn collect_remote_signer_handshake_regression_gate(
    aggregates: &BTreeMap<(Comparator, String), AggregateStats>,
    thresholds: RegressionGateThresholds,
    violations: &mut Vec<RegressionGateViolation>,
) {
    let gate = "remote_signer_handshake_min_local_ratio";
    let scenario = "tls-handshake-h2";
    let local_scenario = "local-key-tls-handshake-h2";
    let remote_scenario = "remote-signer-tls-handshake-h2";
    let threshold = thresholds.remote_signer_handshake_min_local_ratio;
    let context = RegressionGateContext {
        gate,
        group: ScenarioGroup::RemoteSigner.as_str(),
        scenario,
        threshold,
    };
    let Some(remote_rate) = aggregate_median_rps(aggregates, Comparator::Oxibelt, remote_scenario)
    else {
        push_missing_regression_gate_metric(
            violations,
            context,
            "median_rps",
            Some("remote-signer"),
            format!("missing OxiBelt {remote_scenario} median rate; cannot evaluate {gate}"),
        );
        return;
    };
    if remote_rate <= 0.0 {
        push_invalid_regression_gate_metric(
            violations,
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
            violations,
            context,
            "median_rps",
            Some("local-key"),
            format!("missing OxiBelt {local_scenario} median rate; cannot evaluate {gate}"),
        );
        return;
    };
    if local_rate <= 0.0 {
        push_invalid_regression_gate_metric(
            violations,
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
        violations.push(RegressionGateViolation {
            gate: gate.to_owned(),
            group: ScenarioGroup::RemoteSigner.as_str().to_owned(),
            scenario: scenario.to_owned(),
            metric: "median_rps_ratio".to_owned(),
            observed: Some(ratio),
            threshold,
            comparator: Some("local-key".to_owned()),
            message: format!(
                "OxiBelt remote-signer cold H2 handshake median rate ratio {:.4} < {:.4} vs local key ({:.3} handshakes/s vs {:.3} handshakes/s)",
                ratio, threshold, remote_rate, local_rate
            ),
        });
    }
}

fn collect_min_rps_regression_gate(
    aggregates: &BTreeMap<(Comparator, String), AggregateStats>,
    gate: &str,
    scenario: &str,
    threshold: f64,
    violations: &mut Vec<RegressionGateViolation>,
) {
    let Some(rps) = aggregate_median_rps(aggregates, Comparator::Oxibelt, scenario) else {
        push_missing_regression_gate_metric(
            violations,
            RegressionGateContext {
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
    if rps < threshold {
        violations.push(RegressionGateViolation {
            gate: gate.to_owned(),
            group: ScenarioGroup::OxibeltOnly.as_str().to_owned(),
            scenario: scenario.to_owned(),
            metric: "median_rps".to_owned(),
            observed: Some(rps),
            threshold,
            comparator: None,
            message: format!(
                "OxiBelt {scenario} median RPS {:.3} < {:.3}",
                rps, threshold
            ),
        });
    }
}

fn collect_p99_ratio_regression_gate(
    aggregates: &BTreeMap<(Comparator, String), AggregateStats>,
    gate: &str,
    monitor_scenario: &str,
    enforcing_scenario: &str,
    threshold: f64,
    violations: &mut Vec<RegressionGateViolation>,
) {
    let context = RegressionGateContext {
        gate,
        group: ScenarioGroup::OxibeltOnly.as_str(),
        scenario: enforcing_scenario,
        threshold,
    };
    let Some(monitor_p99) = aggregate_median_p99(aggregates, Comparator::Oxibelt, monitor_scenario)
    else {
        push_missing_regression_gate_metric(
            violations,
            context,
            "median_p99_ms",
            Some(monitor_scenario),
            format!("missing OxiBelt {monitor_scenario} median p99; cannot evaluate {gate}"),
        );
        return;
    };
    let Some(enforcing_p99) =
        aggregate_median_p99(aggregates, Comparator::Oxibelt, enforcing_scenario)
    else {
        push_missing_regression_gate_metric(
            violations,
            context,
            "median_p99_ms",
            Some(enforcing_scenario),
            format!("missing OxiBelt {enforcing_scenario} median p99; cannot evaluate {gate}"),
        );
        return;
    };
    if monitor_p99 <= 0.0 {
        push_invalid_regression_gate_metric(
            violations,
            context,
            "median_p99_ms",
            monitor_p99,
            Some(monitor_scenario),
            format!(
                "OxiBelt {monitor_scenario} median p99 must be positive; got {:.3}ms",
                monitor_p99
            ),
        );
        return;
    }
    if enforcing_p99 <= 0.0 {
        push_invalid_regression_gate_metric(
            violations,
            context,
            "median_p99_ms",
            enforcing_p99,
            Some(enforcing_scenario),
            format!(
                "OxiBelt {enforcing_scenario} median p99 must be positive; got {:.3}ms",
                enforcing_p99
            ),
        );
        return;
    }

    let ratio = enforcing_p99 / monitor_p99;
    if ratio > threshold {
        violations.push(RegressionGateViolation {
            gate: gate.to_owned(),
            group: ScenarioGroup::OxibeltOnly.as_str().to_owned(),
            scenario: enforcing_scenario.to_owned(),
            metric: "median_p99_ratio".to_owned(),
            observed: Some(ratio),
            threshold,
            comparator: Some(monitor_scenario.to_owned()),
            message: format!(
                "OxiBelt {enforcing_scenario} median p99 ratio {:.4} > {:.4} vs {monitor_scenario} ({:.3}ms vs {:.3}ms)",
                ratio, threshold, enforcing_p99, monitor_p99
            ),
        });
    }
}

fn push_missing_regression_gate_metric(
    violations: &mut Vec<RegressionGateViolation>,
    context: RegressionGateContext<'_>,
    metric: &str,
    comparator: Option<&str>,
    message: impl Into<String>,
) {
    violations.push(RegressionGateViolation {
        gate: context.gate.to_owned(),
        group: context.group.to_owned(),
        scenario: context.scenario.to_owned(),
        metric: metric.to_owned(),
        observed: None,
        threshold: context.threshold,
        comparator: comparator.map(str::to_owned),
        message: message.into(),
    });
}

fn push_invalid_regression_gate_metric(
    violations: &mut Vec<RegressionGateViolation>,
    context: RegressionGateContext<'_>,
    metric: &str,
    observed: f64,
    comparator: Option<&str>,
    message: impl Into<String>,
) {
    violations.push(RegressionGateViolation {
        gate: context.gate.to_owned(),
        group: context.group.to_owned(),
        scenario: context.scenario.to_owned(),
        metric: metric.to_owned(),
        observed: Some(observed),
        threshold: context.threshold,
        comparator: comparator.map(str::to_owned),
        message: message.into(),
    });
}

fn aggregate_median_rps(
    aggregates: &BTreeMap<(Comparator, String), AggregateStats>,
    comparator: Comparator,
    scenario: &str,
) -> Option<f64> {
    aggregates
        .get(&(comparator, scenario.to_owned()))
        .and_then(|aggregate| aggregate.median_rps)
}

fn aggregate_median_p99(
    aggregates: &BTreeMap<(Comparator, String), AggregateStats>,
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
        .and_then(|raw| {
            serde_json::from_str::<BaselineReport>(&raw).map_err(|error| error.to_string())
        }) {
        Ok(report) => report,
        Err(error) => {
            return DeltaReport {
                schema_version: 1,
                baseline_report: baseline_label,
                summary: DeltaSummary::default(),
                rows: Vec::new(),
                warnings: vec![format!(
                    "failed to read baseline performance report: {error}"
                )],
            };
        }
    };

    let baseline_map = aggregate_lookup(&baseline.aggregates);
    let current_map = aggregate_lookup(&current.aggregates);
    let mut rows = Vec::new();
    collect_delta_rows(
        &current.comparisons.reverse_proxy,
        Comparator::Nginx,
        &baseline_map,
        &current_map,
        &mut rows,
    );
    collect_delta_rows(
        &current.comparisons.reverse_proxy,
        Comparator::Caddy,
        &baseline_map,
        &current_map,
        &mut rows,
    );
    collect_delta_rows(
        &current.comparisons.static_files,
        Comparator::Nginx,
        &baseline_map,
        &current_map,
        &mut rows,
    );
    collect_delta_rows(
        &current.comparisons.static_files,
        Comparator::Caddy,
        &baseline_map,
        &current_map,
        &mut rows,
    );

    DeltaReport {
        schema_version: 1,
        baseline_report: baseline_label,
        summary: summarize_delta_rows(&rows),
        rows,
        warnings: Vec::new(),
    }
}

fn aggregate_lookup(aggregates: &[AggregateStats]) -> BTreeMap<(String, String), &AggregateStats> {
    aggregates
        .iter()
        .map(|aggregate| {
            (
                (aggregate.comparator.clone(), aggregate.scenario.clone()),
                aggregate,
            )
        })
        .collect()
}

fn collect_delta_rows(
    comparisons: &[ScenarioComparison],
    comparator: Comparator,
    baseline: &BTreeMap<(String, String), &AggregateStats>,
    current: &BTreeMap<(String, String), &AggregateStats>,
    rows: &mut Vec<PerformanceDeltaRow>,
) {
    let comparator_name = comparator.as_str();
    for comparison in comparisons {
        let oxibelt_key = ("oxibelt".to_owned(), comparison.scenario.clone());
        let comparator_key = (comparator_name.to_owned(), comparison.scenario.clone());
        rows.push(delta_row(
            &comparison.group,
            &comparison.scenario,
            comparator_name,
            baseline.get(&oxibelt_key).copied(),
            current.get(&oxibelt_key).copied(),
            baseline.get(&comparator_key).copied(),
            current.get(&comparator_key).copied(),
        ));
    }
}

fn delta_row(
    group: &str,
    scenario: &str,
    comparator: &str,
    before_oxibelt: Option<&AggregateStats>,
    after_oxibelt: Option<&AggregateStats>,
    before_comparator: Option<&AggregateStats>,
    after_comparator: Option<&AggregateStats>,
) -> PerformanceDeltaRow {
    let before_oxibelt_rps = before_oxibelt.and_then(|stats| stats.median_rps);
    let after_oxibelt_rps = after_oxibelt.and_then(|stats| stats.median_rps);
    let before_comparator_rps = before_comparator.and_then(|stats| stats.median_rps);
    let after_comparator_rps = after_comparator.and_then(|stats| stats.median_rps);
    let before_ratio = ratio(before_oxibelt_rps, before_comparator_rps);
    let after_ratio = ratio(after_oxibelt_rps, after_comparator_rps);
    let before_oxibelt_p99_ms = before_oxibelt.and_then(|stats| stats.median_p99_ms);
    let after_oxibelt_p99_ms = after_oxibelt.and_then(|stats| stats.median_p99_ms);
    let mut row = PerformanceDeltaRow {
        group: group.to_owned(),
        scenario: scenario.to_owned(),
        comparator: comparator.to_owned(),
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
        "- Regression gates: `{}` ({} violation(s))",
        report.regression_gates.status,
        report.regression_gates.violations.len()
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
    write_oxibelt_only_table(&mut markdown, &report.oxibelt_only_results);
    write_missing_table(&mut markdown, &report.skipped_or_missing_comparator_rows);
    write_regression_gate_table(&mut markdown, &report.regression_gates);
    write_warnings(&mut markdown, report);
    markdown
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
        "| Scenario | OxiBelt median rate/sec | nginx median rate/sec | OxiBelt vs nginx | Caddy median rate/sec | OxiBelt vs Caddy | OxiBelt median p95 ms | OxiBelt median p99 ms |"
    )
    .unwrap();
    writeln!(
        markdown,
        "| --- | ---: | ---: | --- | ---: | --- | ---: | ---: |"
    )
    .unwrap();
    for comparison in comparisons {
        let oxibelt = comparison.oxibelt.as_ref();
        writeln!(
            markdown,
            "| `{}` | {} | {} | {} | {} | {} | {} | {} |",
            comparison.scenario,
            format_number(oxibelt.and_then(|stats| stats.median_rps)),
            format_number(comparison.nginx.as_ref().and_then(|stats| stats.median_rps)),
            comparison.oxibelt_vs_nginx.text,
            format_number(comparison.caddy.as_ref().and_then(|stats| stats.median_rps)),
            comparison.oxibelt_vs_caddy.text,
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
        "| Scenario | accept = 0.5 median rate/sec | accept = 1.0 median rate/sec | 1.0 / 0.5 | accept = 0.5 median p95 ms | accept = 1.0 median p95 ms | accept = 0.5 median p99 ms | accept = 1.0 median p99 ms |"
    )
    .unwrap();
    writeln!(
        markdown,
        "| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |"
    )
    .unwrap();
    for comparison in comparisons {
        let accept_0_5 = comparison.accept_0_5.as_ref();
        let accept_1_0 = comparison.accept_1_0.as_ref();
        writeln!(
            markdown,
            "| `{}` | {} | {} | {} | {} | {} | {} | {} |",
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
        "| Scenario | Local-key median rate/sec | Remote-signer median rate/sec | Remote signer vs local key | Local-key median p99 ms | Remote-signer median p99 ms |"
    )
    .unwrap();
    writeln!(markdown, "| --- | ---: | ---: | --- | ---: | ---: |").unwrap();
    for comparison in comparisons {
        let local_key = comparison.local_key.as_ref();
        let remote_signer = comparison.remote_signer.as_ref();
        writeln!(
            markdown,
            "| `{}` | {} | {} | {} | {} | {} |",
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

fn write_oxibelt_only_table(markdown: &mut String, rows: &[AggregateStats]) {
    writeln!(markdown, "## OxiBelt-only results\n").unwrap();
    if rows.is_empty() {
        writeln!(markdown, "No OxiBelt-only rows were found.\n").unwrap();
        return;
    }

    writeln!(
        markdown,
        "| Label | Type | Protocol/mode | Samples | Median rate/sec | Median p95 ms | Median p99 ms | Errors | Skipped |"
    )
    .unwrap();
    writeln!(
        markdown,
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"
    )
    .unwrap();
    for row in rows {
        writeln!(
            markdown,
            "| `{}` | `{}` | `{}` | {} | {} | {} | {} | {} | {} |",
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
        "| Group | Scenario | Comparator | Status | Reason |"
    )
    .unwrap();
    writeln!(markdown, "| --- | --- | --- | --- | --- |").unwrap();
    for row in rows {
        writeln!(
            markdown,
            "| `{}` | `{}` | `{}` | `{}` | {} |",
            row.group, row.scenario, row.comparator, row.status, row.reason
        )
        .unwrap();
    }
    writeln!(markdown).unwrap();
}

fn write_regression_gate_table(markdown: &mut String, gates: &RegressionGateReport) {
    writeln!(markdown, "## Regression gates\n").unwrap();
    writeln!(markdown, "Status: `{}`\n", gates.status).unwrap();
    if gates.violations.is_empty() {
        writeln!(markdown, "None.\n").unwrap();
        return;
    }

    writeln!(
        markdown,
        "| Gate | Group | Scenario | Metric | Observed | Threshold | Comparator | Message |"
    )
    .unwrap();
    writeln!(
        markdown,
        "| --- | --- | --- | --- | ---: | ---: | --- | --- |"
    )
    .unwrap();
    for violation in &gates.violations {
        writeln!(
            markdown,
            "| `{}` | `{}` | `{}` | `{}` | {} | {} | `{}` | {} |",
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
            "| Group | Scenario | Comparator | OxiBelt RPS delta | Comparator RPS delta | Ratio delta | OxiBelt p99 delta | Classification | Reason |"
        )
        .unwrap();
        writeln!(
            markdown,
            "| --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |"
        )
        .unwrap();
        for row in &report.rows {
            writeln!(
                markdown,
                "| `{}` | `{}` | `{}` | {} | {} | {} | {} | `{}` | {} |",
                row.group,
                row.scenario,
                row.comparator,
                format_percent(row.oxibelt_rps_delta_percent),
                format_percent(row.comparator_rps_delta_percent),
                format_percent(row.ratio_delta_percent),
                format_percent(row.oxibelt_p99_delta_percent),
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

fn display_path(input_dir: &Path, path: &Path) -> String {
    path.strip_prefix(input_dir)
        .unwrap_or(path)
        .display()
        .to_string()
}
