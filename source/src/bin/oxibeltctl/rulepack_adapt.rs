use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, bail};
use http::Method;
use serde::{Deserialize, Serialize};

use crate::cli::{RulepackAdaptArgs, RulepackAdapterArg};

pub(crate) fn run_adapt(args: &RulepackAdaptArgs) -> anyhow::Result<()> {
  let raw = fs::read_to_string(&args.input)
    .with_context(|| format!("failed to read {}", args.input.display()))?;
  let rendered = adapt_to_toml(args, &raw)?;
  if let Some(path) = args.output.as_deref() {
    write_output(path, args.force, &rendered)?;
  } else {
    print!("{rendered}");
  }
  Ok(())
}

pub(crate) fn adapt_to_toml(args: &RulepackAdaptArgs, raw: &str) -> anyhow::Result<String> {
  match args.adapter {
    RulepackAdapterArg::ModsecurityCrsExclusion => adapt_modsecurity_crs_exclusion(args, raw),
  }
}

fn adapt_modsecurity_crs_exclusion(args: &RulepackAdaptArgs, raw: &str) -> anyhow::Result<String> {
  let cli_scope = TrafficScope::from_args(args)?;
  let exclusions = parse_modsecurity_crs_exclusions(raw)?;
  if exclusions.is_empty() {
    bail!("adapter input did not contain any supported ModSecurity CRS exclusion directives");
  }

  let mut names = BTreeMap::new();
  let mut allowlists = Vec::new();
  let mut rule_overrides = Vec::new();
  for exclusion in exclusions {
    let scope = cli_scope
      .with_location(exclusion.location_path.as_deref())
      .with_context(|| format!("line {} has incompatible traffic scope", exclusion.line))?;
    let selector = exclusion.selector.into_patch_selector();
    if scope.has_traffic_selector() {
      allowlists.push(GeneratedCrsAllowlist {
        name: unique_name(&args.name_prefix, "allow", &selector, &mut names),
        selector,
        methods: scope.methods,
        routes: scope.routes,
        path_prefixes: scope.path_prefixes,
        reason: args.reason.clone(),
      });
    } else if args.allow_global_disable {
      rule_overrides.push(GeneratedCrsRuleOverride {
        name: unique_name(&args.name_prefix, "disable", &selector, &mut names),
        selector,
        mode: "disabled".to_string(),
        reason: Some(args.reason.clone()),
      });
    } else {
      bail!(
        "line {} would disable CRS rules globally; add --route, --method, --path-prefix, a literal <Location>, or --allow-global-disable",
        exclusion.line
      );
    }
  }

  let rendered = toml::to_string_pretty(&GeneratedCrsPatchRoot {
    waf: GeneratedWafPatch {
      crs: GeneratedCrsPatch {
        allowlists,
        rule_overrides,
      },
    },
  })
  .context("failed to render adapted CRS tuning TOML")?;
  validate_generated_patch(&rendered)?;
  Ok(rendered)
}

fn write_output(path: &Path, force: bool, rendered: &str) -> anyhow::Result<()> {
  if path.extension().and_then(|value| value.to_str()) != Some("toml") {
    bail!("adapt output path must end with .toml");
  }
  let mut options = OpenOptions::new();
  options.write(true);
  if force {
    options.create(true).truncate(true);
  } else {
    options.create_new(true);
  }
  let mut file = options
    .open(path)
    .with_context(|| format!("failed to create {}", path.display()))?;
  file
    .write_all(rendered.as_bytes())
    .with_context(|| format!("failed to write {}", path.display()))?;
  Ok(())
}

fn parse_modsecurity_crs_exclusions(raw: &str) -> anyhow::Result<Vec<ParsedExclusion>> {
  let mut exclusions = Vec::new();
  let mut location_path: Option<String> = None;
  for (index, raw_line) in raw.lines().enumerate() {
    let line_number = index + 1;
    if raw_line.trim_end().ends_with('\\') {
      bail!(
        "line {line_number} uses a continuation; adapter input must use one directive per line"
      );
    }
    let line = strip_comment(raw_line);
    let line = line.trim();
    if line.is_empty() {
      continue;
    }
    let lower = line.to_ascii_lowercase();
    if lower.contains("ctl:ruleremove") {
      bail!("line {line_number} uses ctl:ruleRemove*, which is not supported by this adapter");
    }
    if line.starts_with("<LocationMatch") {
      bail!("line {line_number} uses LocationMatch; regex location scopes are not supported");
    }
    if line.starts_with("<Location") {
      if location_path.is_some() {
        bail!("line {line_number} starts a nested Location block");
      }
      location_path = Some(parse_location(line, line_number)?);
      continue;
    }
    if line == "</Location>" {
      if location_path.take().is_none() {
        bail!("line {line_number} closes a Location block that was not opened");
      }
      continue;
    }
    if line.starts_with('<') {
      bail!("line {line_number} uses an unsupported Apache block");
    }

    if let Some(rest) = line.strip_prefix("SecRuleRemoveById") {
      let rule_ids = parse_rule_ids(rest, line_number)?;
      exclusions.push(ParsedExclusion {
        selector: ParsedSelector::RuleIds(rule_ids),
        location_path: location_path.clone(),
        line: line_number,
      });
    } else if let Some(rest) = line.strip_prefix("SecRuleRemoveByTag") {
      let tag = parse_single_argument(rest, "SecRuleRemoveByTag", line_number)?;
      validate_non_empty_text("tag", &tag, line_number)?;
      exclusions.push(ParsedExclusion {
        selector: ParsedSelector::Tags(vec![tag]),
        location_path: location_path.clone(),
        line: line_number,
      });
    } else if let Some(rest) = line.strip_prefix("SecRuleRemoveByMsg") {
      let message = parse_single_argument(rest, "SecRuleRemoveByMsg", line_number)?;
      validate_non_empty_text("message", &message, line_number)?;
      exclusions.push(ParsedExclusion {
        selector: ParsedSelector::MsgContains(vec![message]),
        location_path: location_path.clone(),
        line: line_number,
      });
    } else if line.starts_with("SecRuleUpdateTargetById")
      || line.starts_with("SecRuleUpdateActionById")
    {
      bail!("line {line_number} uses a ModSecurity update directive, which is not supported");
    } else {
      bail!("line {line_number} uses unsupported ModSecurity directive {line}");
    }
  }
  if location_path.is_some() {
    bail!("adapter input ended before closing a Location block");
  }
  Ok(exclusions)
}

fn strip_comment(raw: &str) -> String {
  let mut quote = None;
  for (index, ch) in raw.char_indices() {
    match quote {
      Some(active) if ch == active => quote = None,
      Some(_) => {}
      None if ch == '"' || ch == '\'' => quote = Some(ch),
      None if ch == '#' => return raw[..index].to_string(),
      None => {}
    }
  }
  raw.to_string()
}

fn parse_location(line: &str, line_number: usize) -> anyhow::Result<String> {
  let Some(rest) = line.strip_prefix("<Location") else {
    bail!("line {line_number} is not a Location block");
  };
  let rest = rest.trim();
  if !rest.ends_with('>') {
    bail!("line {line_number} has an unterminated Location block");
  }
  let path = parse_single_argument(rest.trim_end_matches('>').trim(), "Location", line_number)?;
  validate_path_prefix(&path).with_context(|| format!("line {line_number} Location"))?;
  Ok(path)
}

fn parse_rule_ids(rest: &str, line_number: usize) -> anyhow::Result<Vec<String>> {
  let values = sorted_unique(
    rest
      .split_whitespace()
      .map(str::to_string)
      .collect::<Vec<_>>(),
  );
  if values.is_empty() {
    bail!("line {line_number} SecRuleRemoveById requires at least one rule id");
  }
  for value in &values {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
      bail!(
        "line {line_number} has unsupported CRS rule id {value}; ranges and expressions are not supported"
      );
    }
  }
  Ok(values)
}

fn parse_single_argument(raw: &str, label: &str, line_number: usize) -> anyhow::Result<String> {
  let raw = raw.trim();
  if raw.is_empty() {
    bail!("line {line_number} {label} requires an argument");
  }
  if let Some(quote) = raw.chars().next().filter(|ch| *ch == '"' || *ch == '\'') {
    let mut chars = raw.char_indices().skip(1);
    for (index, ch) in &mut chars {
      if ch == quote {
        let value = raw[1..index].to_string();
        if !raw[index + quote.len_utf8()..].trim().is_empty() {
          bail!("line {line_number} {label} accepts exactly one argument");
        }
        return Ok(value);
      }
    }
    bail!("line {line_number} {label} has an unterminated quoted argument");
  }
  let mut parts = raw.split_whitespace();
  let Some(value) = parts.next() else {
    bail!("line {line_number} {label} requires an argument");
  };
  if parts.next().is_some() {
    bail!("line {line_number} {label} accepts exactly one argument");
  }
  Ok(value.to_string())
}

fn validate_non_empty_text(label: &str, value: &str, line_number: usize) -> anyhow::Result<()> {
  if value.trim().is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("line {line_number} {label} must be non-empty printable text");
  }
  Ok(())
}

fn validate_path_prefix(prefix: &str) -> anyhow::Result<()> {
  if prefix.is_empty() || !prefix.starts_with('/') {
    bail!("path prefixes must start with /");
  }
  if prefix
    .bytes()
    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
  {
    bail!("path prefixes must not contain whitespace or control characters");
  }
  if prefix.contains('\\') || prefix.contains('?') || prefix.contains('#') {
    bail!("path prefixes must not contain backslashes, query strings, or fragments");
  }
  if prefix
    .split('/')
    .any(|component| component == "." || component == "..")
  {
    bail!("path prefixes must not contain . or .. path components");
  }
  if prefix.chars().any(|ch| {
    matches!(
      ch,
      '*' | '[' | ']' | '(' | ')' | '{' | '}' | '|' | '^' | '$' | '+'
    )
  }) {
    bail!("path prefixes must be literal prefixes, not patterns");
  }
  Ok(())
}

fn validate_route(route: &str) -> anyhow::Result<()> {
  if route.trim().is_empty() || route.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("routes must be non-empty printable text");
  }
  Ok(())
}

fn sorted_unique(values: Vec<String>) -> Vec<String> {
  values
    .into_iter()
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect()
}

#[derive(Clone, Debug)]
struct TrafficScope {
  routes: Vec<String>,
  methods: Vec<String>,
  path_prefixes: Vec<String>,
}

impl TrafficScope {
  fn from_args(args: &RulepackAdaptArgs) -> anyhow::Result<Self> {
    let mut methods = Vec::new();
    for method in &args.methods {
      let parsed = method
        .parse::<Method>()
        .with_context(|| format!("invalid HTTP method {method}"))?;
      methods.push(parsed.as_str().to_string());
    }
    for route in &args.routes {
      validate_route(route)?;
    }
    for prefix in &args.path_prefixes {
      validate_path_prefix(prefix)?;
    }
    Ok(Self {
      routes: sorted_unique(args.routes.clone()),
      methods: sorted_unique(methods),
      path_prefixes: sorted_unique(args.path_prefixes.clone()),
    })
  }

  fn with_location(&self, location_path: Option<&str>) -> anyhow::Result<Self> {
    let mut scope = self.clone();
    if let Some(path) = location_path {
      if !scope.path_prefixes.is_empty() {
        bail!(
          "cannot combine --path-prefix with <Location> because OxiBelt CRS allowlist prefixes are ORed"
        );
      }
      scope.path_prefixes = vec![path.to_string()];
    }
    Ok(scope)
  }

  fn has_traffic_selector(&self) -> bool {
    !self.routes.is_empty() || !self.methods.is_empty() || !self.path_prefixes.is_empty()
  }
}

#[derive(Clone, Debug)]
struct ParsedExclusion {
  selector: ParsedSelector,
  location_path: Option<String>,
  line: usize,
}

#[derive(Clone, Debug)]
enum ParsedSelector {
  RuleIds(Vec<String>),
  Tags(Vec<String>),
  MsgContains(Vec<String>),
}

impl ParsedSelector {
  fn into_patch_selector(self) -> GeneratedCrsSelector {
    match self {
      Self::RuleIds(rule_ids) => GeneratedCrsSelector {
        rule_ids,
        ..GeneratedCrsSelector::default()
      },
      Self::Tags(tags) => GeneratedCrsSelector {
        tags,
        ..GeneratedCrsSelector::default()
      },
      Self::MsgContains(msg_contains) => GeneratedCrsSelector {
        msg_contains,
        ..GeneratedCrsSelector::default()
      },
    }
  }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct GeneratedCrsPatch {
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  allowlists: Vec<GeneratedCrsAllowlist>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  rule_overrides: Vec<GeneratedCrsRuleOverride>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GeneratedCrsAllowlist {
  name: String,
  #[serde(flatten)]
  selector: GeneratedCrsSelector,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  methods: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  routes: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  path_prefixes: Vec<String>,
  reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GeneratedCrsRuleOverride {
  name: String,
  #[serde(flatten)]
  selector: GeneratedCrsSelector,
  mode: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  reason: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct GeneratedCrsSelector {
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  rule_ids: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  tags: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  msg_contains: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GeneratedCrsPatchRoot {
  waf: GeneratedWafPatch,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GeneratedWafPatch {
  crs: GeneratedCrsPatch,
}

fn validate_generated_patch(rendered: &str) -> anyhow::Result<()> {
  let parsed: GeneratedCrsPatchRoot =
    toml::from_str(rendered).context("generated CRS tuning TOML did not parse")?;
  let crs = parsed.waf.crs;
  if crs.allowlists.is_empty() && crs.rule_overrides.is_empty() {
    bail!("generated CRS tuning TOML must contain at least one entry");
  }
  for allowlist in &crs.allowlists {
    validate_patch_name("allowlist", &allowlist.name)?;
    validate_selector(&allowlist.selector)?;
    for method in &allowlist.methods {
      method
        .parse::<Method>()
        .with_context(|| format!("generated allowlist {} has invalid method", allowlist.name))?;
    }
    for route in &allowlist.routes {
      validate_route(route)?;
    }
    for prefix in &allowlist.path_prefixes {
      validate_path_prefix(prefix)?;
    }
    if allowlist.methods.is_empty()
      && allowlist.routes.is_empty()
      && allowlist.path_prefixes.is_empty()
    {
      bail!(
        "generated allowlist {} must include at least one traffic selector",
        allowlist.name
      );
    }
    validate_patch_reason("allowlist", &allowlist.name, &allowlist.reason)?;
  }
  for override_config in &crs.rule_overrides {
    validate_patch_name("rule override", &override_config.name)?;
    validate_selector(&override_config.selector)?;
    if override_config.mode != "disabled" {
      bail!(
        "generated rule override {} must use mode = \"disabled\"",
        override_config.name
      );
    }
    if let Some(reason) = &override_config.reason {
      validate_patch_reason("rule override", &override_config.name, reason)?;
    }
  }
  Ok(())
}

fn validate_patch_name(kind: &str, name: &str) -> anyhow::Result<()> {
  if name.trim().is_empty() {
    bail!("generated {kind} name must not be empty");
  }
  Ok(())
}

fn validate_patch_reason(kind: &str, name: &str, reason: &str) -> anyhow::Result<()> {
  if reason.trim().is_empty() || reason.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("generated {kind} {name} reason must be non-empty printable text");
  }
  Ok(())
}

fn validate_selector(selector: &GeneratedCrsSelector) -> anyhow::Result<()> {
  if selector.rule_ids.is_empty() && selector.tags.is_empty() && selector.msg_contains.is_empty() {
    bail!("generated CRS selector must not be empty");
  }
  for id in &selector.rule_ids {
    if !id.bytes().all(|byte| byte.is_ascii_digit()) {
      bail!("generated CRS rule id {id} is invalid");
    }
  }
  for tag in &selector.tags {
    if tag.trim().is_empty() || tag.bytes().any(|byte| byte.is_ascii_control()) {
      bail!("generated CRS tag selectors must be non-empty printable text");
    }
  }
  for message in &selector.msg_contains {
    if message.trim().is_empty() || message.bytes().any(|byte| byte.is_ascii_control()) {
      bail!("generated CRS message selectors must be non-empty printable text");
    }
  }
  Ok(())
}

fn unique_name(
  prefix: &str,
  action: &str,
  selector: &GeneratedCrsSelector,
  names: &mut BTreeMap<String, usize>,
) -> String {
  let prefix = slug_piece(prefix, "adapted-crs");
  let mut base = format!("{prefix}-{action}-{}", selector_slug(selector));
  if base.len() > 96 {
    base.truncate(96);
    base = base.trim_end_matches('-').to_string();
  }
  let count = names.entry(base.clone()).or_insert(0);
  *count += 1;
  if *count == 1 {
    base
  } else {
    format!("{base}-{count}")
  }
}

fn selector_slug(selector: &GeneratedCrsSelector) -> String {
  if !selector.rule_ids.is_empty() {
    return format!("id-{}", selector.rule_ids.join("-"));
  }
  if !selector.tags.is_empty() {
    return format!("tag-{}", slug_piece(&selector.tags.join("-"), "tag"));
  }
  format!(
    "msg-{}",
    slug_piece(&selector.msg_contains.join("-"), "message")
  )
}

fn slug_piece(value: &str, fallback: &str) -> String {
  let mut slug = String::new();
  let mut previous_dash = false;
  for ch in value.chars() {
    let next = if ch.is_ascii_alphanumeric() {
      Some(ch.to_ascii_lowercase())
    } else if ch == '_' || ch == '-' || ch == '.' {
      Some('-')
    } else {
      Some('-')
    };
    if let Some(ch) = next {
      if ch == '-' {
        if !previous_dash && !slug.is_empty() {
          slug.push(ch);
        }
        previous_dash = true;
      } else {
        slug.push(ch);
        previous_dash = false;
      }
    }
  }
  let slug = slug.trim_matches('-');
  if slug.is_empty() {
    fallback.to_string()
  } else {
    slug.to_string()
  }
}

#[cfg(test)]
#[path = "rulepack_adapt_tests.rs"]
mod tests;
