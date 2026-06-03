//! External WAF file resolution helpers.
//! Paths are resolved against configured roots before rule loading.

use std::path::{Path, PathBuf};

use anyhow::bail;

use super::{
  RULEPACK_FILE_SUFFIX, RouteWafConfig, WafConfig, WafRulepackSummary, load_external_rule,
  load_external_rule_groups, resolve_rule_group_file_paths, resolve_rule_path, rulepacks,
};

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
