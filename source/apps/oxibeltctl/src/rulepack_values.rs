use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oxibelt::waf::{
  RulepackException, RulepackInputMetadata, RulepackOverride, WafMode, inspect_rulepack_inputs,
};
use serde::Deserialize;

use crate::cli::RulepackModeArg;

#[derive(Debug, Clone)]
pub(crate) struct RulepackResolvedInputs {
  pub(crate) vars: BTreeMap<String, String>,
  pub(crate) binds: BTreeMap<String, String>,
  pub(crate) selected_profile: Option<String>,
  pub(crate) mode: Option<RulepackModeArg>,
  pub(crate) force_mode: bool,
  pub(crate) values_file: Option<PathBuf>,
  pub(crate) rule_overrides: Vec<RulepackOverride>,
  pub(crate) exceptions: Vec<RulepackException>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulepackValuesFile {
  #[serde(default)]
  bindings: BTreeMap<String, String>,
  #[serde(default)]
  values: BTreeMap<String, String>,
  #[serde(default)]
  overrides: RulepackValuesOverrides,
  #[serde(default)]
  rule_overrides: Vec<RulepackOverride>,
  #[serde(default)]
  exceptions: Vec<RulepackException>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulepackValuesOverrides {
  #[serde(default)]
  profile: Option<String>,
  #[serde(default)]
  mode: Option<WafMode>,
  #[serde(default)]
  force_mode: Option<bool>,
}

pub(crate) struct RulepackResolveRequest<'a> {
  pub(crate) raw: &'a str,
  pub(crate) source: &'a str,
  pub(crate) values_file: Option<&'a Path>,
  pub(crate) cli_vars: &'a BTreeMap<String, String>,
  pub(crate) cli_binds: &'a BTreeMap<String, String>,
  pub(crate) cli_profile: Option<&'a str>,
  pub(crate) cli_mode: Option<RulepackModeArg>,
  pub(crate) cli_force_mode: bool,
  pub(crate) default_mode: Option<RulepackModeArg>,
}

pub(crate) fn resolve_rulepack_inputs(
  request: RulepackResolveRequest<'_>,
) -> anyhow::Result<RulepackResolvedInputs> {
  let inputs = inspect_rulepack_inputs(request.raw, request.source)?;
  resolve_rulepack_inputs_from_metadata(request, &inputs)
}

fn resolve_rulepack_inputs_from_metadata(
  request: RulepackResolveRequest<'_>,
  inputs: &RulepackInputMetadata,
) -> anyhow::Result<RulepackResolvedInputs> {
  let values_file = match request.values_file {
    Some(path) => load_values_file(path)?,
    None => RulepackValuesFile::default(),
  };
  oxibelt::waf::validate_rulepack_overrides(
    request.source,
    &inputs.summary.name,
    &values_file.rule_overrides,
  )?;
  oxibelt::waf::validate_rulepack_exception_list(request.source, &values_file.exceptions)?;
  let selected_profile = request
    .cli_profile
    .map(str::to_string)
    .or_else(|| values_file.overrides.profile.clone());
  let profile = selected_profile
    .as_deref()
    .map(|name| {
      inputs
        .profiles
        .iter()
        .find(|profile| profile.name == name)
        .with_context(|| {
          format!(
            "rulepack {} does not declare profile {name}",
            inputs.summary.name
          )
        })
    })
    .transpose()?;

  let mut vars = profile
    .map(|profile| profile.values.clone())
    .unwrap_or_default();
  vars.extend(values_file.values);
  vars.extend(request.cli_vars.clone());

  let mut binds = values_file.bindings;
  binds.extend(request.cli_binds.clone());

  let profile_mode = profile.and_then(|profile| profile.mode.map(mode_arg_from_waf));
  let mode = request
    .cli_mode
    .or_else(|| values_file.overrides.mode.map(mode_arg_from_waf))
    .or(profile_mode)
    .or(request.default_mode);
  let force_mode = request.cli_force_mode || values_file.overrides.force_mode.unwrap_or(false);

  Ok(RulepackResolvedInputs {
    vars,
    binds,
    selected_profile,
    mode,
    force_mode,
    values_file: request.values_file.map(Path::to_path_buf),
    rule_overrides: values_file.rule_overrides,
    exceptions: values_file.exceptions,
  })
}

fn load_values_file(path: &Path) -> anyhow::Result<RulepackValuesFile> {
  let raw =
    std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
  let value: toml::Value =
    toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
  let table = value
    .as_table()
    .with_context(|| format!("{} must contain a TOML table", path.display()))?;
  for key in table.keys() {
    if !matches!(
      key.as_str(),
      "bindings" | "values" | "overrides" | "rule_overrides" | "exceptions"
    ) {
      bail!("{} contains unsupported table [{key}]", path.display());
    }
  }
  value
    .try_into()
    .with_context(|| format!("failed to decode {}", path.display()))
}

fn mode_arg_from_waf(mode: WafMode) -> RulepackModeArg {
  match mode {
    WafMode::Monitor => RulepackModeArg::Monitor,
    WafMode::Enforcing => RulepackModeArg::Enforcing,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn metadata() -> RulepackInputMetadata {
    inspect_rulepack_inputs(
      r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[variables]]
name = "admin_cidr"
type = "cidr"
default = "10.0.0.0/8"

[[variables]]
name = "login_rate"
type = "rate"
default = "5r/m"

[[bindings]]
name = "app_route"
kind = "route"
bind_as = "route_name"
required = true

[[profiles]]
name = "public-production"
mode = "enforcing"
values = { login_rate = "10r/m" }

[[rules]]
name = "admin"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#,
      "test rulepack",
    )
    .expect("metadata")
  }

  #[test]
  fn values_file_and_cli_precedence_are_merged() {
    let file = write_temp_values(
      r#"[bindings]
app_route = "from-file"

[values]
admin_cidr = "10.10.0.0/16"

[overrides]
profile = "public-production"
mode = "monitor"
"#,
    );
    let cli_vars = BTreeMap::from([("login_rate".to_string(), "20r/m".to_string())]);
    let cli_binds = BTreeMap::from([("app_route".to_string(), "from-cli".to_string())]);

    let resolved = resolve_rulepack_inputs_from_metadata(
      RulepackResolveRequest {
        raw: "",
        source: "test rulepack",
        values_file: Some(file.path()),
        cli_vars: &cli_vars,
        cli_binds: &cli_binds,
        cli_profile: None,
        cli_mode: None,
        cli_force_mode: false,
        default_mode: None,
      },
      &metadata(),
    )
    .expect("resolved values");

    assert_eq!(
      resolved.selected_profile.as_deref(),
      Some("public-production")
    );
    assert_eq!(resolved.mode, Some(RulepackModeArg::Monitor));
    assert_eq!(resolved.binds["app_route"], "from-cli");
    assert_eq!(resolved.vars["admin_cidr"], "10.10.0.0/16");
    assert_eq!(resolved.vars["login_rate"], "20r/m");
  }

  #[test]
  fn values_file_rejects_unknown_tables() {
    let file = write_temp_values("[later]\nname = \"later\"\n");
    let error = load_values_file(file.path()).expect_err("unknown table should fail");

    assert!(error.to_string().contains("unsupported table [later]"));
  }

  #[test]
  fn values_file_accepts_local_rule_overrides() {
    let file = write_temp_values(
      r#"[bindings]
app_route = "mmsecretvault"

[[rule_overrides]]
selector = { rule_name = "admin" }
mode = "enforcing"
priority = 90
"#,
    );
    let cli_vars = BTreeMap::new();
    let cli_binds = BTreeMap::new();

    let resolved = resolve_rulepack_inputs_from_metadata(
      RulepackResolveRequest {
        raw: "",
        source: "test rulepack",
        values_file: Some(file.path()),
        cli_vars: &cli_vars,
        cli_binds: &cli_binds,
        cli_profile: None,
        cli_mode: None,
        cli_force_mode: false,
        default_mode: None,
      },
      &metadata(),
    )
    .expect("resolved values");

    assert_eq!(resolved.rule_overrides.len(), 1);
    assert_eq!(
      resolved.rule_overrides[0].selector.rule_name.as_deref(),
      Some("admin")
    );
    assert_eq!(resolved.rule_overrides[0].mode, Some(WafMode::Enforcing));
    assert_eq!(resolved.rule_overrides[0].priority, Some(90));
  }

  #[test]
  fn values_file_accepts_local_exceptions() {
    let file = write_temp_values(
      r#"[bindings]
app_route = "mmsecretvault"

[[exceptions]]
name = "allow-healthcheck-login-preflight"
rule_names = ["admin"]
routes = ["mmsecretvault"]
methods = ["GET"]
path_prefixes = ["/identity/accounts/prelogin"]
source_cidrs = ["10.20.0.0/16"]
reason = "internal synthetic healthcheck"
expires_at = "2999-07-01T00:00:00Z"
"#,
    );
    let cli_vars = BTreeMap::new();
    let cli_binds = BTreeMap::new();

    let resolved = resolve_rulepack_inputs_from_metadata(
      RulepackResolveRequest {
        raw: "",
        source: "test rulepack",
        values_file: Some(file.path()),
        cli_vars: &cli_vars,
        cli_binds: &cli_binds,
        cli_profile: None,
        cli_mode: None,
        cli_force_mode: false,
        default_mode: None,
      },
      &metadata(),
    )
    .expect("resolved values");

    assert_eq!(resolved.exceptions.len(), 1);
    assert_eq!(
      resolved.exceptions[0].name,
      "allow-healthcheck-login-preflight"
    );
  }

  #[test]
  fn values_file_rejects_malformed_rule_overrides() {
    let file = write_temp_values(
      r#"[[rule_overrides]]
selector = {}
mode = "enforcing"
"#,
    );
    let cli_vars = BTreeMap::new();
    let cli_binds = BTreeMap::new();

    let error = resolve_rulepack_inputs_from_metadata(
      RulepackResolveRequest {
        raw: "",
        source: "test rulepack",
        values_file: Some(file.path()),
        cli_vars: &cli_vars,
        cli_binds: &cli_binds,
        cli_profile: None,
        cli_mode: None,
        cli_force_mode: false,
        default_mode: None,
      },
      &metadata(),
    )
    .expect_err("empty selector should fail");

    assert!(error.to_string().contains("exactly one selector kind"));
  }

  #[test]
  fn values_file_rejects_non_string_values() {
    let file = write_temp_values("[values]\nlogin_rate = 10\n");
    let error = load_values_file(file.path()).expect_err("integer values should fail");

    assert!(error.to_string().contains("failed to decode"));
  }

  fn write_temp_values(content: &str) -> tempfile::NamedTempFile {
    let file = tempfile::Builder::new()
      .prefix("rulepack-values-")
      .suffix(".toml")
      .tempfile()
      .expect("temp values file");
    std::fs::write(file.path(), content).expect("write values file");
    file
  }
}
