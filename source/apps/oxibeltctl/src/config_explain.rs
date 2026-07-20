use oxibelt::config::explain_native_config;

use crate::cli::{Command, ConfigSubcommand, OutputFormat};
use crate::config_output::{error_report, print_serializable, report_ok};

pub(crate) fn run_local_if_requested(
  command: &Command,
  format: OutputFormat,
) -> anyhow::Result<Option<i32>> {
  let Command::Config(config) = command else {
    return Ok(None);
  };
  let ConfigSubcommand::Explain(args) = &config.command else {
    return Ok(None);
  };
  let Some(file) = &args.file else {
    return Ok(None);
  };

  if args.field_path.trim().is_empty() {
    let report = error_report("explain", "field_path", "field path must not be empty");
    print_serializable(&report, format)?;
    return Ok(Some(1));
  }

  let report = match explain_native_config(file, &args.field_path) {
    Ok(report) => serde_json::to_value(report)?,
    Err(_error) => error_report(
      "explain",
      "load",
      "configuration could not be loaded or explained safely",
    ),
  };
  let code = if report_ok(&report) { 0 } else { 1 };
  print_serializable(&report, format)?;
  Ok(Some(code))
}

#[cfg(test)]
mod tests {
  use clap::Parser;

  use super::*;
  use crate::cli::{Cli, ConfigCommand};

  #[test]
  fn explain_is_remote_by_default() {
    let cli = Cli::try_parse_from(["oxibeltctl", "config", "explain", "tls.min_version"])
      .expect("explain command should parse");
    let Command::Config(ConfigCommand {
      command: ConfigSubcommand::Explain(args),
    }) = cli.command
    else {
      panic!("expected explain command");
    };
    assert_eq!(args.field_path, "tls.min_version");
    assert!(args.file.is_none());
  }

  #[test]
  fn explain_accepts_a_local_file() {
    let cli = Cli::try_parse_from([
      "oxibeltctl",
      "config",
      "explain",
      "listeners.https_binds",
      "--file",
      "config.toml",
    ])
    .expect("local explain should parse");
    let Command::Config(config) = cli.command else {
      panic!("expected config command");
    };
    let ConfigSubcommand::Explain(args) = config.command else {
      panic!("expected explain command");
    };
    assert_eq!(
      args.file.as_deref(),
      Some(std::path::Path::new("config.toml"))
    );
  }
}
