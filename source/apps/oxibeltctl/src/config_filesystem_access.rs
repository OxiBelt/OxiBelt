use anyhow::Context;
use oxibelt::config::Config;
use oxibelt::filesystem_access::{
  FilesystemAccessCheckReport, FilesystemAccessEntryView, FilesystemAccessManifest,
  FilesystemAccessManifestView,
};
use serde::Serialize;

use crate::cli::{
  Command, ConfigFilesystemAccessArgs, ConfigFilesystemAccessOutputFormat, ConfigSubcommand,
};

#[derive(Debug, Serialize)]
struct FilesystemAccessOutput {
  manifest: FilesystemAccessManifestView,
  #[serde(skip_serializing_if = "Option::is_none")]
  check: Option<FilesystemAccessCheckReport>,
}

pub(crate) fn run_if_requested(command: &Command) -> anyhow::Result<Option<i32>> {
  let Command::Config(config) = command else {
    return Ok(None);
  };
  let ConfigSubcommand::FilesystemAccess(args) = &config.command else {
    return Ok(None);
  };

  let config = Config::load(&args.file).with_context(|| {
    format!(
      "failed to load resolved configuration {}",
      args.file.display()
    )
  })?;
  config
    .validate()
    .with_context(|| format!("configuration {} is invalid", args.file.display()))?;
  let manifest = FilesystemAccessManifest::from_config(&config)?;
  let check = args.check.then(|| manifest.check_current(args.show_paths));
  let exit_code = if check.as_ref().is_some_and(|check| check.has_errors()) {
    1
  } else {
    0
  };
  let output = FilesystemAccessOutput {
    manifest: manifest.view(args.show_paths),
    check,
  };
  print_output(&output, args)?;
  Ok(Some(exit_code))
}

fn print_output(
  output: &FilesystemAccessOutput,
  args: &ConfigFilesystemAccessArgs,
) -> anyhow::Result<()> {
  match args.format {
    ConfigFilesystemAccessOutputFormat::Json => {
      println!("{}", serde_json::to_string_pretty(output)?);
    }
    ConfigFilesystemAccessOutputFormat::Text => print!("{}", render_text(output)),
  }
  Ok(())
}

fn render_text(output: &FilesystemAccessOutput) -> String {
  let manifest = &output.manifest;
  let mut rendered = String::new();
  rendered.push_str("Filesystem access manifest\n");
  rendered.push_str(&format!("schema version: {}\n", manifest.schema_version));
  if let Some(digest) = &manifest.manifest_digest {
    rendered.push_str(&format!("manifest digest: {digest}\n"));
  } else {
    rendered.push_str("manifest digest: withheld (pass --show-paths to reveal)\n");
  }
  rendered.push_str(&format!(
    "paths: {}\n",
    if manifest.paths_redacted {
      "redacted (pass --show-paths to reveal)"
    } else {
      "shown"
    }
  ));
  rendered.push_str(&format!("entries: {}\n", manifest.entries.len()));
  for entry in &manifest.entries {
    render_entry(&mut rendered, entry);
  }
  if let Some(check) = &output.check {
    rendered.push_str(&format!(
      "check: {}\n",
      if check.ok { "ok" } else { "failed" }
    ));
    rendered.push_str(&format!(
      "mountinfo detected: {}\n",
      check.mountinfo_detected
    ));
    if let Some(compatible) = check.read_only_rootfs_compatible {
      rendered.push_str(&format!("read-only rootfs compatible: {compatible}\n"));
    }
    rendered.push_str(&format!("findings: {}\n", check.total_findings));
    rendered.push_str(&format!("findings shown: {}\n", check.findings.len()));
    rendered.push_str(&format!(
      "findings truncated: {}\n",
      check.findings_truncated
    ));
    for finding in &check.findings {
      let path = finding
        .path
        .as_deref()
        .or(finding.path_id.as_deref())
        .unwrap_or("manifest");
      rendered.push_str(&format!(
        "- {:?} {:?} {path}: {}\n",
        finding.severity, finding.code, finding.detail
      ));
    }
  }
  rendered
}

fn render_entry(rendered: &mut String, entry: &FilesystemAccessEntryView) {
  let path = entry.path.as_deref().unwrap_or(&entry.path_id);
  rendered.push_str(&format!(
    "- {path}: {:?}; purpose={:?}; type={:?}; scope={:?}; parent_write={}; optional={}",
    entry.access,
    entry.purpose,
    entry.expected_type,
    entry.scope,
    entry.requires_parent_write,
    entry.optional
  ));
  if let Some(source) = &entry.source_config_path {
    rendered.push_str("; source=");
    rendered.push_str(source);
  }
  rendered.push('\n');
}

#[cfg(test)]
mod tests {
  use clap::Parser;

  use super::*;
  use crate::cli::{Cli, ConfigCommand};

  fn manifest_view(show_paths: bool) -> FilesystemAccessManifestView {
    FilesystemAccessManifestView {
      schema_version: 3,
      manifest_digest: show_paths.then(|| format!("sha256:{}", "a".repeat(64))),
      manifest_digest_withheld: !show_paths,
      paths_redacted: !show_paths,
      normalization: "canonical_enforcement_with_verified_kubernetes_atomic_writer_digest_identity_v3",
      entries: Vec::new(),
    }
  }

  #[test]
  fn filesystem_access_command_defaults_to_redacted_text_without_checks() {
    let cli = Cli::try_parse_from(["oxibeltctl", "config", "filesystem-access", "config.toml"])
      .expect("filesystem-access command should parse");
    let Command::Config(ConfigCommand {
      command: ConfigSubcommand::FilesystemAccess(args),
    }) = cli.command
    else {
      panic!("expected filesystem-access command");
    };
    assert_eq!(args.file, std::path::PathBuf::from("config.toml"));
    assert_eq!(args.format, ConfigFilesystemAccessOutputFormat::Text);
    assert!(!args.check);
    assert!(!args.show_paths);
  }

  #[test]
  fn filesystem_access_command_accepts_stable_json_check_and_full_paths() {
    let cli = Cli::try_parse_from([
      "oxibeltctl",
      "config",
      "filesystem-access",
      "config.toml",
      "--format",
      "json",
      "--check",
      "--show-paths",
    ])
    .expect("filesystem-access command should parse");
    let Command::Config(ConfigCommand {
      command: ConfigSubcommand::FilesystemAccess(args),
    }) = cli.command
    else {
      panic!("expected filesystem-access command");
    };
    assert_eq!(args.format, ConfigFilesystemAccessOutputFormat::Json);
    assert!(args.check);
    assert!(args.show_paths);
  }

  #[test]
  fn redacted_output_withholds_the_path_derived_manifest_digest() {
    let output = FilesystemAccessOutput {
      manifest: manifest_view(false),
      check: None,
    };

    let text = render_text(&output);
    assert!(text.contains("manifest digest: withheld"));
    assert!(!text.contains("sha256:"));
    let json = serde_json::to_value(&output).expect("output should serialize");
    assert_eq!(json["manifest"]["manifest_digest_withheld"], true);
    assert!(json["manifest"].get("manifest_digest").is_none());
  }

  #[test]
  fn explicit_path_disclosure_also_reveals_the_comparison_digest() {
    let output = FilesystemAccessOutput {
      manifest: manifest_view(true),
      check: None,
    };

    let text = render_text(&output);
    assert!(text.contains("manifest digest: sha256:"));
    let json = serde_json::to_value(&output).expect("output should serialize");
    assert_eq!(json["manifest"]["manifest_digest_withheld"], false);
    assert!(
      json["manifest"]["manifest_digest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:"))
    );
  }
}
