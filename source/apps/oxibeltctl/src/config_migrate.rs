use std::collections::{BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oxibelt::config::{load_native_config_document, validate_native_config_with_overrides};
use serde::Serialize;
use serde_json::Value;

use crate::cli::{Command, ConfigMigrateArgs, ConfigSubcommand, OutputFormat};
use crate::config_migrate_transform::{MigrationChange, transform_document};
use crate::config_output::{
  NATIVE_SCHEMA_EPOCH, REPORT_SCHEMA_VERSION, error_report, print_serializable, report_ok,
};

#[derive(Debug, Serialize)]
struct MigrationReport {
  report_schema_version: u32,
  operation: &'static str,
  native_schema_epoch: u32,
  ok: bool,
  from_epoch: u32,
  to_epoch: u32,
  dry_run: bool,
  source_file: String,
  planned_output_dir: String,
  output_dir: Option<String>,
  changed_files: Vec<String>,
  changes: Vec<MigrationChange>,
  validation: Value,
  diagnostics: Vec<Value>,
}

struct MigratedDocument {
  source: PathBuf,
  relative: PathBuf,
  rendered: String,
}

pub(crate) fn run_if_requested(
  command: &Command,
  format: OutputFormat,
) -> anyhow::Result<Option<i32>> {
  let Command::Config(config) = command else {
    return Ok(None);
  };
  let ConfigSubcommand::Migrate(args) = &config.command else {
    return Ok(None);
  };

  match migrate(args) {
    Ok(report) => {
      let code = if report.ok { 0 } else { 1 };
      print_serializable(&report, format)?;
      Ok(Some(code))
    }
    Err(error) => {
      // Keep parser/source chains out of machine-readable output because they may
      // contain configuration snippets with secret material.
      let mut report = error_report("migrate", "operation", &error.to_string());
      let object = report
        .as_object_mut()
        .expect("error report must be a JSON object");
      object.insert("from_epoch".to_string(), args.from_epoch.into());
      object.insert("to_epoch".to_string(), args.to_epoch.into());
      object.insert("dry_run".to_string(), args.dry_run.into());
      object.insert(
        "source_file".to_string(),
        args.file.display().to_string().into(),
      );
      print_serializable(&report, format)?;
      Ok(Some(1))
    }
  }
}

fn migrate(args: &ConfigMigrateArgs) -> anyhow::Result<MigrationReport> {
  if args.from_epoch != 0 || args.to_epoch != NATIVE_SCHEMA_EPOCH {
    bail!(
      "only the explicit native configuration migration 0 -> {} is supported",
      NATIVE_SCHEMA_EPOCH
    );
  }

  let source_file = args
    .file
    .canonicalize()
    .with_context(|| format!("failed to resolve {}", args.file.display()))?;
  let source_root = source_file
    .parent()
    .context("configuration file must have a parent directory")?
    .to_path_buf();
  let output_dir = resolve_output_dir(&source_root, args.output_dir.as_deref(), args.to_epoch)?;
  if output_dir.exists() {
    bail!("migration output {} already exists", output_dir.display());
  }

  let document = load_native_config_document(&source_file)?;
  let mut source_files = document.files;
  source_files.sort();
  source_files.dedup();
  if !source_files.iter().any(|file| file == &source_file) {
    bail!("production loader did not report the root configuration file");
  }

  let mut documents = Vec::with_capacity(source_files.len());
  let mut changes = Vec::new();
  for source in source_files {
    let relative = source.strip_prefix(&source_root).with_context(|| {
      format!(
        "included configuration {} escapes migration root {}",
        source.display(),
        source_root.display()
      )
    })?;
    if relative.as_os_str().is_empty() {
      bail!("configuration source path must identify a file");
    }
    let relative = relative.to_path_buf();
    let raw = fs::read_to_string(&source)
      .with_context(|| format!("failed to read {}", source.display()))?;
    let display = relative.to_string_lossy().replace('\\', "/");
    let (rendered, mut file_changes) = transform_document(&raw, &display)?;
    changes.append(&mut file_changes);
    documents.push(MigratedDocument {
      source,
      relative,
      rendered,
    });
  }
  changes.sort_by(|left, right| {
    (&left.file, &left.field_path, left.action, &left.replacement).cmp(&(
      &right.file,
      &right.field_path,
      right.action,
      &right.replacement,
    ))
  });
  let changed_files = changes
    .iter()
    .map(|change| change.file.clone())
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect::<Vec<_>>();

  let overrides = documents
    .iter()
    .map(|document| (document.source.clone(), Some(document.rendered.clone())))
    .collect::<HashMap<_, _>>();
  let validation = serde_json::to_value(validate_native_config_with_overrides(
    &source_file,
    &overrides,
  ))?;
  let valid = report_ok(&validation);
  if !valid || args.dry_run {
    return Ok(MigrationReport {
      report_schema_version: REPORT_SCHEMA_VERSION,
      operation: "migrate",
      native_schema_epoch: NATIVE_SCHEMA_EPOCH,
      ok: valid,
      from_epoch: args.from_epoch,
      to_epoch: args.to_epoch,
      dry_run: args.dry_run,
      source_file: source_file.display().to_string(),
      planned_output_dir: output_dir.display().to_string(),
      output_dir: None,
      changed_files,
      changes,
      validation,
      diagnostics: Vec::new(),
    });
  }

  let output_parent = output_dir
    .parent()
    .context("migration output must have a parent directory")?;
  let staging = tempfile::Builder::new()
    .prefix(".oxibelt-config-migrate-")
    .tempdir_in(output_parent)
    .with_context(|| {
      format!(
        "failed to create migration staging directory in {}",
        output_parent.display()
      )
    })?;
  write_staging_tree(staging.path(), &documents)?;

  if output_dir.exists() {
    bail!(
      "migration output {} appeared while validation was running",
      output_dir.display()
    );
  }
  sync_directory(staging.path())?;
  fs::rename(staging.path(), &output_dir).with_context(|| {
    format!(
      "failed to publish migration output {}",
      output_dir.display()
    )
  })?;
  let _published_staging_path = staging.keep();
  sync_directory(output_parent)?;

  Ok(MigrationReport {
    report_schema_version: REPORT_SCHEMA_VERSION,
    operation: "migrate",
    native_schema_epoch: NATIVE_SCHEMA_EPOCH,
    ok: true,
    from_epoch: args.from_epoch,
    to_epoch: args.to_epoch,
    dry_run: false,
    source_file: source_file.display().to_string(),
    planned_output_dir: output_dir.display().to_string(),
    output_dir: Some(output_dir.display().to_string()),
    changed_files,
    changes,
    validation,
    diagnostics: Vec::new(),
  })
}

fn resolve_output_dir(
  source_root: &Path,
  requested: Option<&Path>,
  to_epoch: u32,
) -> anyhow::Result<PathBuf> {
  let source_parent = source_root
    .parent()
    .context("cannot create a sibling migration tree for the filesystem root")?
    .canonicalize()
    .context("failed to resolve source configuration parent")?;
  let source_name = source_root
    .file_name()
    .and_then(|name| name.to_str())
    .context("configuration directory name must be valid UTF-8")?;
  let requested = requested
    .map(Path::to_path_buf)
    .unwrap_or_else(|| source_parent.join(format!("{source_name}.migrated-v{to_epoch}")));
  let absolute = if requested.is_absolute() {
    requested
  } else {
    std::env::current_dir()?.join(requested)
  };
  let parent = absolute
    .parent()
    .context("migration output must have a parent directory")?
    .canonicalize()
    .with_context(|| format!("failed to resolve parent of {}", absolute.display()))?;
  if parent != source_parent {
    bail!(
      "migration output must be a sibling of {}",
      source_root.display()
    );
  }
  let name = absolute
    .file_name()
    .context("migration output must have a directory name")?;
  let resolved = parent.join(name);
  if resolved == source_root {
    bail!("migration output must not replace the source directory");
  }
  Ok(resolved)
}

fn write_staging_tree(root: &Path, documents: &[MigratedDocument]) -> anyhow::Result<()> {
  for document in documents {
    let target = root.join(&document.relative);
    let parent = target
      .parent()
      .context("staged configuration file must have a parent")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let mut output = OpenOptions::new()
      .create_new(true)
      .write(true)
      .open(&target)
      .with_context(|| format!("failed to create {}", target.display()))?;
    output
      .write_all(document.rendered.as_bytes())
      .with_context(|| format!("failed to write {}", target.display()))?;
    let permissions = fs::metadata(&document.source)
      .with_context(|| format!("failed to inspect {}", document.source.display()))?
      .permissions();
    fs::set_permissions(&target, permissions)
      .with_context(|| format!("failed to preserve permissions on {}", target.display()))?;
    output
      .sync_all()
      .with_context(|| format!("failed to sync {}", target.display()))?;
  }
  Ok(())
}

fn sync_directory(path: &Path) -> anyhow::Result<()> {
  fs::File::open(path)
    .with_context(|| format!("failed to open directory {}", path.display()))?
    .sync_all()
    .with_context(|| format!("failed to sync directory {}", path.display()))
}

#[cfg(test)]
mod tests {
  use clap::Parser;

  use super::*;
  use crate::cli::{Cli, ConfigCommand};

  #[test]
  fn migrate_requires_explicit_source_and_target_epochs() {
    let cli = Cli::try_parse_from([
      "oxibeltctl",
      "config",
      "migrate",
      "config.toml",
      "--from",
      "0",
      "--to",
      "1",
      "--dry-run",
    ])
    .expect("migration command should parse");
    let Command::Config(ConfigCommand {
      command: ConfigSubcommand::Migrate(args),
    }) = cli.command
    else {
      panic!("expected migration command");
    };
    assert_eq!(args.from_epoch, 0);
    assert_eq!(args.to_epoch, 1);
    assert!(args.dry_run);
  }

  #[test]
  fn default_output_is_a_sibling_tree() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let source = temp.path().join("config");
    fs::create_dir(&source).expect("source directory");
    let output = resolve_output_dir(&source, None, 1).expect("output path");
    assert_eq!(output, temp.path().join("config.migrated-v1"));
  }
}
