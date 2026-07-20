//! External WAF file resolution helpers.
//! Paths are resolved against configured roots before rule loading.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};

use super::{
  ExternalRuleFile, ExternalRuleGroupFile, RULEPACK_FILE_SUFFIX, RouteWafConfig, WafConditionMerge,
  WafConfig, WafRuleConfig, WafRuleGroupConfig, WafRulepackSummary,
  resolve_existing_local_config_file_path_with_logical, rulepacks, validate_rule_group_scope,
};

fn resolve_rule_group_file_paths(
  field_name: &str,
  base_dir: &Path,
  paths: &[PathBuf],
) -> anyhow::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
  if paths.is_empty() {
    return Ok((Vec::new(), Vec::new()));
  }
  let canonical_base = base_dir
    .canonicalize()
    .with_context(|| format!("failed to resolve OxiRule directory {}", base_dir.display()))?;
  let mut resolved = Vec::new();
  let mut logical = Vec::new();
  for path in paths {
    if path_has_glob_pattern(path)? {
      let pattern_path = crate::config::resolve_local_config_file_path(field_name, base_dir, path)?;
      let pattern = pattern_path.to_str().ok_or_else(|| {
        anyhow!(
          "{field_name} entry is not valid UTF-8: {}",
          pattern_path.display()
        )
      })?;
      let mut matched = Vec::new();
      for candidate in glob::glob(pattern)
        .with_context(|| format!("invalid {field_name} glob {}", path.display()))?
      {
        let candidate = candidate
          .with_context(|| format!("failed to expand {field_name} glob {}", path.display()))?;
        if candidate.is_file() {
          let canonical = crate::config::canonicalize_existing_file(field_name, &candidate)?;
          if !canonical.starts_with(&canonical_base) {
            bail!("{field_name} entries must stay within the OxiRule directory");
          }
          matched.push((canonical, candidate));
        }
      }
      matched.sort_by(|left, right| left.0.cmp(&right.0));
      for (canonical, candidate) in matched {
        resolved.push(canonical);
        logical.push(candidate);
      }
    } else {
      let (canonical, candidate) =
        resolve_existing_local_config_file_path_with_logical(field_name, base_dir, path)?;
      resolved.push(canonical);
      logical.push(candidate);
    }
  }
  Ok((resolved, logical))
}

fn path_has_glob_pattern(path: &Path) -> anyhow::Result<bool> {
  let value = path.to_str().ok_or_else(|| {
    anyhow!(
      "OxiRule group file path is not valid UTF-8: {}",
      path.display()
    )
  })?;
  Ok(value.chars().any(|ch| matches!(ch, '*' | '?' | '[')))
}

fn load_external_rule_groups(
  scope: &str,
  paths: &[PathBuf],
) -> anyhow::Result<Vec<WafRuleGroupConfig>> {
  let mut groups = Vec::new();
  for path in paths {
    let raw = std::fs::read_to_string(path)
      .with_context(|| format!("failed to read OxiRule group file {}", path.display()))?;
    let external: ExternalRuleGroupFile = toml::from_str(&raw)
      .with_context(|| format!("failed to parse OxiRule group file {}", path.display()))?;
    if external.rule_groups.is_empty() {
      bail!(
        "{scope} OxiRule group file {} must contain at least one [[rule_groups]] entry",
        path.display()
      );
    }
    groups.extend(external.rule_groups);
  }
  Ok(groups)
}

pub fn validate_external_rule_group_file(raw: &str) -> anyhow::Result<()> {
  let external: ExternalRuleGroupFile =
    toml::from_str(raw).context("failed to parse OxiRule group file")?;
  if external.rule_groups.is_empty() {
    bail!("OxiRule group file must contain at least one [[rule_groups]] entry");
  }
  validate_rule_group_scope("OxiRule group file", &external.rule_groups)
}

fn resolve_rule_path(rule: &mut WafRuleConfig, base_dir: &Path) -> anyhow::Result<()> {
  rule.path = rule
    .path
    .take()
    .map(|path| {
      let (resolved, logical) =
        resolve_existing_local_config_file_path_with_logical("WAF rule path", base_dir, &path)?;
      rule.loaded_from_logical_path = Some(logical);
      Ok::<PathBuf, anyhow::Error>(resolved)
    })
    .transpose()?;
  Ok(())
}

fn load_external_rule(rule: &mut WafRuleConfig) -> anyhow::Result<()> {
  let Some(path) = rule.path.take() else {
    return Ok(());
  };

  if rule.when.is_some()
    || rule.merge_condition_as != WafConditionMerge::And
    || !rule.groups.is_empty()
    || !rule.actions.is_empty()
  {
    bail!(
      "WAF rule {} external path cannot be combined with inline when, merge_condition_as, groups, or actions",
      rule.name
    );
  }

  let raw = std::fs::read_to_string(&path)
    .with_context(|| format!("failed to read WAF rule file {}", path.display()))?;
  let external: ExternalRuleFile = toml::from_str(&raw)
    .with_context(|| format!("failed to parse WAF rule file {}", path.display()))?;

  rule.when = external.when;
  rule.merge_condition_as = external.merge_condition_as;
  rule.groups = external.groups;
  rule.local_rule_groups = external.rule_groups;
  rule.actions = external.actions;
  rule.loaded_from_path = Some(path);
  Ok(())
}

impl WafConfig {
  pub fn resolve_relative_paths(&mut self, base_dir: &Path) -> anyhow::Result<()> {
    self.crs.resolve_relative_paths(base_dir)?;
    self.rulepack_base_dir = Some(base_dir.to_path_buf());
    let (rulepack_resolved, rulepack_logical) =
      resolve_rulepack_file_paths("waf.rulepack_files", base_dir, &self.rulepack_files)?;
    self.rulepack_files_resolved = rulepack_resolved;
    self.rulepack_files_logical = rulepack_logical;
    let (resolved, logical) =
      resolve_rule_group_file_paths("waf.rule_group_files", base_dir, &self.rule_group_files)?;
    self.rule_group_files_resolved = resolved;
    self.rule_group_files_logical = logical;
    for rule in &mut self.rules {
      resolve_rule_path(rule, base_dir)?;
    }
    Ok(())
  }

  pub fn load_external_rules(&mut self) -> anyhow::Result<()> {
    let rulepack_base_dir = self.rulepack_base_dir.clone();
    let rulepack_files_resolved = self.rulepack_files_resolved.clone();
    let rulepack_files_logical = self.rulepack_files_logical.clone();
    append_rulepacks(
      self,
      "global WAF",
      rulepack_base_dir.as_deref(),
      rulepack_files_resolved,
      rulepack_files_logical,
    )?;
    let mut external_groups =
      load_external_rule_groups("global WAF", &self.rule_group_files_resolved)?;
    self.rule_groups.append(&mut external_groups);
    for rule in &mut self.rules {
      load_external_rule(rule)?;
    }
    Ok(())
  }

  pub fn loaded_rule_paths(&self) -> Vec<PathBuf> {
    let mut paths = loaded_rule_file_paths(&self.rules);
    paths.extend(self.rule_group_files_logical.iter().cloned());
    paths.extend(self.rulepack_files_logical.iter().cloned());
    for rulepack in &self.loaded_rulepacks {
      paths.extend(rulepack.loaded_files.iter().cloned());
    }
    paths.extend(self.crs.loaded_paths());
    paths
  }

  pub fn rulepack_summaries(&self) -> &[WafRulepackSummary] {
    &self.loaded_rulepacks
  }
}

impl RouteWafConfig {
  pub fn resolve_relative_paths(&mut self, base_dir: &Path) -> anyhow::Result<()> {
    self.rulepack_base_dir = Some(base_dir.to_path_buf());
    let (rulepack_resolved, rulepack_logical) =
      resolve_rulepack_file_paths("routes.waf.rulepack_files", base_dir, &self.rulepack_files)?;
    self.rulepack_files_resolved = rulepack_resolved;
    self.rulepack_files_logical = rulepack_logical;
    let (resolved, logical) = resolve_rule_group_file_paths(
      "routes.waf.rule_group_files",
      base_dir,
      &self.rule_group_files,
    )?;
    self.rule_group_files_resolved = resolved;
    self.rule_group_files_logical = logical;
    for rule in &mut self.rules {
      resolve_rule_path(rule, base_dir)?;
    }
    Ok(())
  }

  pub fn load_external_rules(&mut self) -> anyhow::Result<()> {
    let rulepack_base_dir = self.rulepack_base_dir.clone();
    let rulepack_files_resolved = self.rulepack_files_resolved.clone();
    let rulepack_files_logical = self.rulepack_files_logical.clone();
    append_route_rulepacks(
      self,
      "route WAF",
      rulepack_base_dir.as_deref(),
      rulepack_files_resolved,
      rulepack_files_logical,
    )?;
    let mut external_groups =
      load_external_rule_groups("route WAF", &self.rule_group_files_resolved)?;
    self.rule_groups.append(&mut external_groups);
    for rule in &mut self.rules {
      load_external_rule(rule)?;
    }
    Ok(())
  }

  pub fn loaded_rule_paths(&self) -> Vec<PathBuf> {
    loaded_rule_file_paths(&self.rules)
      .into_iter()
      .chain(self.rule_group_files_logical.iter().cloned())
      .chain(self.rulepack_files_logical.iter().cloned())
      .chain(
        self
          .loaded_rulepacks
          .iter()
          .flat_map(|rulepack| rulepack.loaded_files.iter().cloned()),
      )
      .collect()
  }

  pub fn rulepack_summaries(&self) -> &[WafRulepackSummary] {
    &self.loaded_rulepacks
  }
}

fn append_rulepacks(
  config: &mut WafConfig,
  scope: &str,
  base_dir: Option<&Path>,
  resolved: Vec<PathBuf>,
  logical: Vec<PathBuf>,
) -> anyhow::Result<()> {
  for mut rulepack in rulepacks::load_rulepacks(scope, base_dir, &resolved, &logical)? {
    config.rule_groups.append(&mut rulepack.rule_groups);
    config.rules.append(&mut rulepack.rules);
    config.loaded_rulepacks.push(rulepack.summary);
  }
  Ok(())
}

fn append_route_rulepacks(
  config: &mut RouteWafConfig,
  scope: &str,
  base_dir: Option<&Path>,
  resolved: Vec<PathBuf>,
  logical: Vec<PathBuf>,
) -> anyhow::Result<()> {
  for mut rulepack in rulepacks::load_rulepacks(scope, base_dir, &resolved, &logical)? {
    config.rule_groups.append(&mut rulepack.rule_groups);
    config.rules.append(&mut rulepack.rules);
    config.loaded_rulepacks.push(rulepack.summary);
  }
  Ok(())
}

fn loaded_rule_file_paths(rules: &[super::WafRuleConfig]) -> Vec<PathBuf> {
  rules
    .iter()
    .filter_map(|rule| {
      rule
        .loaded_from_logical_path
        .clone()
        .or_else(|| rule.loaded_from_path.clone())
    })
    .collect()
}

fn resolve_rulepack_file_paths(
  field_name: &str,
  base_dir: &Path,
  paths: &[PathBuf],
) -> anyhow::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
  let (resolved, logical) = resolve_rule_group_file_paths(field_name, base_dir, paths)?;
  for path in &logical {
    let Some(value) = path.to_str() else {
      bail!("{field_name} entry is not valid UTF-8: {}", path.display());
    };
    if !value.ends_with(RULEPACK_FILE_SUFFIX) {
      bail!("{field_name} entries must end with {RULEPACK_FILE_SUFFIX}");
    }
  }
  Ok((resolved, logical))
}
