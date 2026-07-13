use anyhow::{Context, bail};
use bytes::Bytes;

use super::cli::{Command, DoctorArgs};

pub(crate) async fn run_local_if_requested(command: &Command) -> anyhow::Result<bool> {
  let Command::Doctor(args) = command else {
    return Ok(false);
  };
  validate_local_inputs(args)?;
  if !args.has_local_source() {
    return Ok(false);
  }

  let mut reports = Vec::new();
  if let Some(config_path) = &args.config {
    let options = oxibelt::diagnostics::DoctorOptions {
      external_probes: args.external_probes.clone(),
      allow_secret_env_probes: true,
    };
    reports.push(oxibelt::diagnostics::diagnose_config_path(config_path, &options).await);
  }
  if let Some(path) = &args.helm_rendered {
    reports.push(oxibelt::diagnostics::diagnose_rendered_directory(path)?);
  }
  if let Some(chart) = &args.helm_chart {
    reports.push(
      oxibelt::diagnostics::diagnose_helm_chart(
        chart,
        &args.helm_values,
        &args.helm_release,
        &args.helm_namespace,
      )
      .await?,
    );
  }
  if args.kubernetes {
    reports.push(
      oxibelt::diagnostics::diagnose_kubernetes(&oxibelt::diagnostics::KubernetesDoctorOptions {
        context: args.kube_context.clone(),
        namespace: args.kube_namespace.clone(),
        all_namespaces: args.all_namespaces,
        selector: args.kube_selector.clone(),
      })
      .await?,
    );
  }
  let report = oxibelt::diagnostics::combine_reports(reports);
  print_report(&report, args)?;
  Ok(true)
}

fn validate_local_inputs(args: &DoctorArgs) -> anyhow::Result<()> {
  if args.deployment_source_count() > 1 {
    bail!(
      "doctor accepts at most one deployment source: --helm-rendered, --helm-chart, or --kubernetes"
    );
  }
  if args.candidate.is_some() && args.has_local_source() {
    bail!("--candidate cannot be combined with local doctor sources");
  }
  if !args.external_probes.is_empty() && args.config.is_none() && args.deployment_source_count() > 0
  {
    bail!("--external-probe requires --config when using a local deployment source");
  }
  if !args.helm_values.is_empty() && args.helm_chart.is_none() {
    bail!("--helm-values requires --helm-chart");
  }
  Ok(())
}

pub(crate) fn print_report_body(body: &Bytes, args: &DoctorArgs) -> anyhow::Result<()> {
  let mut report: oxibelt::diagnostics::DiagnosticReport =
    serde_json::from_slice(body).context("doctor response was not a diagnostics report")?;
  report.normalize();
  print_report(&report, args)
}

fn print_report(
  report: &oxibelt::diagnostics::DiagnosticReport,
  args: &DoctorArgs,
) -> anyhow::Result<()> {
  match args.format {
    oxibelt::diagnostics::DoctorOutputFormat::NaturalLanguage => {
      print!("{}", oxibelt::diagnostics::format_natural_language(report));
    }
    oxibelt::diagnostics::DoctorOutputFormat::Json => {
      println!("{}", serde_json::to_string_pretty(report)?);
    }
    oxibelt::diagnostics::DoctorOutputFormat::Sarif => {
      println!(
        "{}",
        serde_json::to_string_pretty(&oxibelt::diagnostics::format_sarif(report))?
      );
    }
  }
  if report.fails_on(args.fail_on) {
    std::process::exit(1);
  }
  Ok(())
}
