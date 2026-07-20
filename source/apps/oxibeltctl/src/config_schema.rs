use oxibelt::config::native_config_schema;
use serde_json::Value;

use crate::cli::{Command, ConfigSubcommand, OutputFormat};
use crate::config_output::{error_report, print_serializable};

pub(crate) fn run_if_requested(
  command: &Command,
  format: OutputFormat,
) -> anyhow::Result<Option<i32>> {
  let Command::Config(config) = command else {
    return Ok(None);
  };
  let ConfigSubcommand::Schema(args) = &config.command else {
    return Ok(None);
  };

  let raw = match native_config_schema(args.epoch) {
    Ok(raw) => raw,
    Err(error) => {
      print_serializable(
        &error_report("schema", "epoch", &format!("{error:#}")),
        format,
      )?;
      return Ok(Some(1));
    }
  };
  let schema: Value = serde_json::from_str(raw)?;
  print_serializable(&schema, format)?;
  Ok(Some(0))
}

#[cfg(test)]
mod tests {
  use clap::Parser;

  use super::*;
  use crate::cli::{Cli, ConfigCommand};

  #[test]
  fn parses_explicit_schema_epoch() {
    let cli = Cli::try_parse_from(["oxibeltctl", "config", "schema", "--epoch", "1"])
      .expect("schema command should parse");
    let Command::Config(ConfigCommand {
      command: ConfigSubcommand::Schema(args),
    }) = cli.command
    else {
      panic!("expected schema command");
    };
    assert_eq!(args.epoch, 1);
  }
}
