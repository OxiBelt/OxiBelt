use anyhow::Context;
use oxibelt::config::{
  Config, LbPolicyCompatDiagnosticKind, LbPolicyCompatProfile, LbPolicyCompatReport,
};

use crate::cli::{
  Command, ConfigLbPolicyCompatArgs, ConfigLbPolicyCompatOutputFormat, ConfigLbPolicyCompatProfile,
  ConfigSubcommand,
};

pub(crate) fn run_local_if_requested(command: &Command) -> anyhow::Result<bool> {
  let Command::Config(config) = command else {
    return Ok(false);
  };
  let ConfigSubcommand::LbPolicyCompat(args) = &config.command else {
    return Ok(false);
  };
  let report = build_report(args)?;
  println!("{}", render_report(&report, args.format)?);
  Ok(true)
}

pub(crate) fn build_report(
  args: &ConfigLbPolicyCompatArgs,
) -> anyhow::Result<LbPolicyCompatReport> {
  Config::load_lb_policy_compat_report(&args.file, args.profile.into())
    .with_context(|| format!("failed to inspect {}", args.file.display()))
}

pub(crate) fn render_report(
  report: &LbPolicyCompatReport,
  format: ConfigLbPolicyCompatOutputFormat,
) -> anyhow::Result<String> {
  match format {
    ConfigLbPolicyCompatOutputFormat::Json => {
      serde_json::to_string_pretty(report).map_err(Into::into)
    }
    ConfigLbPolicyCompatOutputFormat::Text => Ok(render_text_report(report)),
  }
}

fn render_text_report(report: &LbPolicyCompatReport) -> String {
  let mut rendered = String::new();
  rendered.push_str("# Converted TOML\n");
  rendered.push_str(report.converted_toml.trim_end());
  rendered.push_str("\n\n# LB policy compatibility diagnostics\n");
  if report.diagnostics.is_empty() {
    rendered.push_str("none\n");
    return rendered;
  }
  for diagnostic in &report.diagnostics {
    match diagnostic.kind {
      LbPolicyCompatDiagnosticKind::Converted => {
        let replacement = diagnostic.replacement.unwrap_or("<missing>");
        rendered.push_str(&format!(
          "converted {}: {} -> {} ({})\n",
          diagnostic.path, diagnostic.original, replacement, diagnostic.message
        ));
      }
      LbPolicyCompatDiagnosticKind::Unsupported => {
        rendered.push_str(&format!(
          "unsupported {}: {} ({})\n",
          diagnostic.path, diagnostic.original, diagnostic.message
        ));
      }
    }
  }
  rendered
}

impl From<ConfigLbPolicyCompatProfile> for LbPolicyCompatProfile {
  fn from(value: ConfigLbPolicyCompatProfile) -> Self {
    match value {
      ConfigLbPolicyCompatProfile::Nginx => Self::Nginx,
      ConfigLbPolicyCompatProfile::Caddy => Self::Caddy,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use clap::Parser;

  use crate::cli::{Cli, ConfigCommand};

  #[test]
  fn cli_parses_local_report_options() {
    let parsed = Cli::try_parse_from([
      "oxibeltctl",
      "config",
      "lb-policy-compat",
      "source/config/oxibelt.toml",
      "--profile",
      "nginx",
      "--format",
      "json",
    ])
    .expect("compat command should parse");

    let Command::Config(ConfigCommand {
      command: ConfigSubcommand::LbPolicyCompat(args),
    }) = parsed.command
    else {
      panic!("expected lb-policy-compat command");
    };
    assert_eq!(
      args.file,
      std::path::PathBuf::from("source/config/oxibelt.toml")
    );
    assert_eq!(args.profile, ConfigLbPolicyCompatProfile::Nginx);
    assert_eq!(args.format, ConfigLbPolicyCompatOutputFormat::Json);
  }

  #[test]
  fn text_report_renders_conversions_and_unsupported_diagnostics() {
    let mut value: toml::Value = toml::from_str(
      r#"
[[upstream_pools]]
name = "app"
algorithm = "least_conn"

[[upstream_pools]]
name = "legacy"
algorithm = "round_robin"
"#,
    )
    .expect("fixture should parse");
    let diagnostics =
      oxibelt::config::normalize_toml_with_profile(&mut value, LbPolicyCompatProfile::Nginx);
    let report = LbPolicyCompatReport {
      profile: "nginx",
      converted_toml: toml::to_string_pretty(&value).expect("TOML should render"),
      diagnostics,
    };

    let rendered =
      render_report(&report, ConfigLbPolicyCompatOutputFormat::Text).expect("report should render");

    assert!(rendered.contains("algorithm = \"weighted_least_conn\""));
    assert!(rendered.contains("converted upstream_pools[0].algorithm"));
    assert!(rendered.contains("unsupported upstream_pools[1].algorithm"));
  }

  #[test]
  fn json_report_contains_converted_toml_and_diagnostics() {
    let report = LbPolicyCompatReport {
      profile: "caddy",
      converted_toml: "converted = true\n".to_string(),
      diagnostics: Vec::new(),
    };

    let rendered =
      render_report(&report, ConfigLbPolicyCompatOutputFormat::Json).expect("report should render");
    let value: serde_json::Value =
      serde_json::from_str(&rendered).expect("JSON report should parse");

    assert_eq!(value["profile"], "caddy");
    assert_eq!(value["converted_toml"], "converted = true\n");
    assert!(value["diagnostics"].as_array().unwrap().is_empty());
  }
}
