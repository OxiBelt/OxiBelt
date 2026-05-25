use anyhow::Context;
use bytes::Bytes;

use super::cli::{Command, DoctorArgs};

pub(crate) async fn run_local_if_requested(command: &Command) -> anyhow::Result<bool> {
  let Command::Doctor(args) = command else {
    return Ok(false);
  };
  let Some(config_path) = &args.config else {
    return Ok(false);
  };
  let options = oxibelt::diagnostics::DoctorOptions {
    external_probes: args.external_probes.clone(),
    allow_secret_env_probes: true,
  };
  let report = oxibelt::diagnostics::diagnose_config_path(config_path, &options).await;
  print_report(&report, args)?;
  Ok(true)
}

pub(crate) fn print_report_body(body: &Bytes, args: &DoctorArgs) -> anyhow::Result<()> {
  let report: oxibelt::diagnostics::DiagnosticReport =
    serde_json::from_slice(body).context("doctor response was not a diagnostics report")?;
  print_report(&report, args)
}

fn print_report(
  report: &oxibelt::diagnostics::DiagnosticReport,
  args: &DoctorArgs,
) -> anyhow::Result<()> {
  match args.format {
    oxibelt::diagnostics::DoctorOutputFormat::Text => {
      print!("{}", oxibelt::diagnostics::format_text(report));
    }
    oxibelt::diagnostics::DoctorOutputFormat::Json => {
      println!("{}", serde_json::to_string_pretty(report)?);
    }
  }
  if report.fails_on(args.fail_on) {
    std::process::exit(1);
  }
  Ok(())
}
