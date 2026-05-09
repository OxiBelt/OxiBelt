use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;

use crate::config::{
  canonicalize_existing_file, resolve_existing_local_config_file_path_with_logical,
  resolve_local_config_file_path,
};

use super::super::WafMode;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct WafCrsConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_crs_mode")]
  pub mode: WafMode,
  #[serde(default = "default_setup_file")]
  pub setup_file: PathBuf,
  #[serde(default = "default_rule_files")]
  pub rule_files: Vec<PathBuf>,
  #[serde(default = "default_paranoia_level")]
  pub paranoia_level: u8,
  #[serde(default = "default_inbound_threshold")]
  pub inbound_anomaly_score_threshold: i64,
  #[serde(default = "default_outbound_threshold")]
  pub outbound_anomaly_score_threshold: i64,
  #[serde(default)]
  pub unsupported_directive_policy: WafCrsUnsupportedDirectivePolicy,
  #[serde(skip)]
  pub(super) setup_file_resolved: Option<PathBuf>,
  #[serde(skip)]
  setup_file_logical: Option<PathBuf>,
  #[serde(skip)]
  pub(super) rule_files_resolved: Vec<PathBuf>,
  #[serde(skip)]
  rule_files_logical: Vec<PathBuf>,
}

impl Default for WafCrsConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      mode: WafMode::Monitor,
      setup_file: default_setup_file(),
      rule_files: default_rule_files(),
      paranoia_level: default_paranoia_level(),
      inbound_anomaly_score_threshold: default_inbound_threshold(),
      outbound_anomaly_score_threshold: default_outbound_threshold(),
      unsupported_directive_policy: WafCrsUnsupportedDirectivePolicy::FailClosed,
      setup_file_resolved: None,
      setup_file_logical: None,
      rule_files_resolved: Vec::new(),
      rule_files_logical: Vec::new(),
    }
  }
}

impl WafCrsConfig {
  pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) -> anyhow::Result<()> {
    self.setup_file_resolved = None;
    self.setup_file_logical = None;
    self.rule_files_resolved.clear();
    self.rule_files_logical.clear();
    if !self.enabled {
      return Ok(());
    }

    let (setup, setup_logical) = resolve_existing_local_config_file_path_with_logical(
      "waf.crs.setup_file",
      base_dir,
      &self.setup_file,
    )?;
    self.setup_file_resolved = Some(setup);
    self.setup_file_logical = Some(setup_logical);

    let canonical_base = base_dir.canonicalize().with_context(|| {
      format!(
        "failed to resolve CRS base directory {}",
        base_dir.display()
      )
    })?;
    for pattern in &self.rule_files {
      let logical_pattern =
        resolve_local_config_file_path("waf.crs.rule_files", base_dir, pattern)?;
      let pattern_text = logical_pattern.to_str().ok_or_else(|| {
        anyhow!(
          "waf.crs.rule_files entry is not valid UTF-8: {}",
          logical_pattern.display()
        )
      })?;
      let mut matched = Vec::new();
      for path in glob::glob(pattern_text)
        .with_context(|| format!("invalid waf.crs.rule_files glob {}", pattern.display()))?
      {
        let path = path.with_context(|| {
          format!(
            "failed to expand waf.crs.rule_files glob {}",
            pattern.display()
          )
        })?;
        if path.is_file() {
          let canonical = canonicalize_existing_file("waf.crs.rule_files", &path)?;
          if !canonical.starts_with(&canonical_base) {
            bail!("waf.crs.rule_files entries must stay within the OxiRule directory");
          }
          matched.push((canonical, path));
        }
      }
      matched.sort_by(|left, right| left.0.cmp(&right.0));
      if matched.is_empty() {
        bail!(
          "waf.crs.rule_files entry matched no files: {}",
          pattern.display()
        );
      }
      for (canonical, logical) in matched {
        self.rule_files_resolved.push(canonical);
        self.rule_files_logical.push(logical);
      }
    }
    Ok(())
  }

  pub(crate) fn loaded_paths(&self) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = &self.setup_file_logical {
      paths.push(path.clone());
    }
    paths.extend(self.rule_files_logical.iter().cloned());
    paths
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafCrsUnsupportedDirectivePolicy {
  #[default]
  FailClosed,
}

pub(super) fn validate_config(config: &WafCrsConfig) -> anyhow::Result<()> {
  if !(1..=4).contains(&config.paranoia_level) {
    bail!("waf.crs.paranoia_level must be between 1 and 4");
  }
  if config.inbound_anomaly_score_threshold <= 0 {
    bail!("waf.crs.inbound_anomaly_score_threshold must be greater than 0");
  }
  if config.outbound_anomaly_score_threshold <= 0 {
    bail!("waf.crs.outbound_anomaly_score_threshold must be greater than 0");
  }
  if config.rule_files.is_empty() {
    bail!("waf.crs.rule_files must include at least one entry when CRS is enabled");
  }
  Ok(())
}

fn default_setup_file() -> PathBuf {
  PathBuf::from("crs/crs-setup.conf")
}

fn default_crs_mode() -> WafMode {
  WafMode::Monitor
}

fn default_rule_files() -> Vec<PathBuf> {
  vec![PathBuf::from("crs/rules/*.conf")]
}

fn default_paranoia_level() -> u8 {
  1
}

fn default_inbound_threshold() -> i64 {
  5
}

fn default_outbound_threshold() -> i64 {
  4
}
