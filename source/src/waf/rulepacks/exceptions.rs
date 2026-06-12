use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{RulepackRule, WafPhase};

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RulepackException {
  pub name: String,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub rule_ids: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub rule_names: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub tags: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub routes: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub methods: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub path_prefixes: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub source_cidrs: Vec<String>,
  pub reason: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub expires_at: Option<String>,
}

pub fn validate_rulepack_exception_list(
  source: &str,
  exceptions: &[RulepackException],
) -> anyhow::Result<()> {
  validate_exception_shapes(source, exceptions)
}

pub(super) fn validate_rulepack_exceptions(
  source: &str,
  exceptions: &[RulepackException],
  rules: &[RulepackRule],
) -> anyhow::Result<()> {
  validate_exception_shapes(source, exceptions)?;
  for exception in active_exception_entries(source, exceptions)? {
    let matches = rules
      .iter()
      .filter(|rule| exception_matches_rule(exception, rule))
      .collect::<Vec<_>>();
    if matches.is_empty() {
      bail!(
        "{source} exception {} did not match any rule",
        exception.name
      );
    }
    if matches.iter().any(|rule| rule.phase == WafPhase::Stream) {
      bail!(
        "{source} exception {} matched a stream-phase rule; rulepack exceptions only support HTTP request-context selectors",
        exception.name
      );
    }
  }
  Ok(())
}

pub(super) fn append_local_exceptions(
  value: &mut toml::Value,
  source: &str,
  exceptions: &[RulepackException],
) -> anyhow::Result<()> {
  if exceptions.is_empty() {
    return Ok(());
  }
  let table = value
    .as_table_mut()
    .with_context(|| format!("{source} must contain a TOML table"))?;
  let entry = table
    .entry("exceptions".to_string())
    .or_insert_with(|| toml::Value::Array(Vec::new()));
  let Some(items) = entry.as_array_mut() else {
    bail!("{source} exceptions must be an array of tables");
  };
  for exception in exceptions {
    let encoded = toml::Value::try_from(exception.clone()).with_context(|| {
      format!(
        "failed to encode local rulepack exception {}",
        exception.name
      )
    })?;
    items.push(encoded);
  }
  Ok(())
}

pub(super) struct ActiveRulepackExceptions<'a> {
  entries: Vec<&'a RulepackException>,
  matches: Vec<usize>,
}

impl<'a> ActiveRulepackExceptions<'a> {
  pub(super) fn new(source: &str, exceptions: &'a [RulepackException]) -> anyhow::Result<Self> {
    let entries = active_exception_entries(source, exceptions)?;
    let matches = vec![0; entries.len()];
    Ok(Self { entries, matches })
  }

  pub(super) fn apply_to_rule_content(
    &mut self,
    source: &str,
    rule: &RulepackRule,
    content: &str,
  ) -> anyhow::Result<String> {
    let mut predicates = Vec::new();
    for (index, exception) in self.entries.iter().enumerate() {
      if !exception_matches_rule(exception, rule) {
        continue;
      }
      if rule.phase == WafPhase::Stream {
        bail!(
          "{source} exception {} matched a stream-phase rule; rulepack exceptions only support HTTP request-context selectors",
          exception.name
        );
      }
      self.matches[index] += 1;
      predicates.push(exception_traffic_predicate(exception));
    }
    if predicates.is_empty() {
      return Ok(content.to_string());
    }

    let mut value: toml::Value =
      toml::from_str(content).with_context(|| format!("failed to parse {source} rule content"))?;
    let table = value
      .as_table_mut()
      .with_context(|| format!("{source} rule content must be a TOML table"))?;
    let exception_predicate = predicates.join(" || ");
    let when = table
      .get("when")
      .and_then(toml::Value::as_str)
      .map(|existing| format!("({existing}) && !({exception_predicate})"))
      .unwrap_or_else(|| format!("!({exception_predicate})"));
    table.insert("when".to_string(), toml::Value::String(when));
    toml::to_string_pretty(&value).context("failed to render exception-scoped rule content")
  }

  pub(super) fn finish(self, source: &str) -> anyhow::Result<()> {
    for (index, count) in self.matches.into_iter().enumerate() {
      if count == 0 {
        bail!(
          "{source} exception {} did not match any rule",
          self.entries[index].name
        );
      }
    }
    Ok(())
  }
}

fn validate_exception_shapes(source: &str, exceptions: &[RulepackException]) -> anyhow::Result<()> {
  let mut names = HashSet::new();
  for exception in exceptions {
    super::validate_label(source, "exceptions.name", &exception.name)?;
    if !names.insert(exception.name.clone()) {
      bail!("{source} contains duplicate exception {}", exception.name);
    }
    validate_selector(source, exception)?;
    validate_traffic_selector(source, exception)?;
    validate_reason(source, exception)?;
    if let Some(expires_at) = &exception.expires_at {
      parse_strict_utc_rfc3339(expires_at).with_context(|| {
        format!(
          "{source} exception {} expires_at is invalid",
          exception.name
        )
      })?;
    }
  }
  Ok(())
}

fn validate_selector(source: &str, exception: &RulepackException) -> anyhow::Result<()> {
  if exception.rule_ids.is_empty() && exception.rule_names.is_empty() && exception.tags.is_empty() {
    bail!(
      "{source} exception {} must include at least one rule selector",
      exception.name
    );
  }
  for value in &exception.rule_ids {
    super::validate_label(source, "exceptions.rule_ids", value)?;
  }
  for value in &exception.rule_names {
    super::validate_label(source, "exceptions.rule_names", value)?;
  }
  for value in &exception.tags {
    super::validate_label(source, "exceptions.tags", value)?;
  }
  Ok(())
}

fn validate_traffic_selector(source: &str, exception: &RulepackException) -> anyhow::Result<()> {
  if exception.routes.is_empty()
    && exception.methods.is_empty()
    && exception.path_prefixes.is_empty()
    && exception.source_cidrs.is_empty()
  {
    bail!(
      "{source} exception {} must include at least one traffic selector",
      exception.name
    );
  }
  for value in &exception.routes {
    super::validate_label(source, "exceptions.routes", value)?;
  }
  for value in &exception.methods {
    value.parse::<http::Method>().with_context(|| {
      format!(
        "{source} exception {} has invalid HTTP method {value}",
        exception.name
      )
    })?;
  }
  for value in &exception.path_prefixes {
    if value.trim().is_empty()
      || value.len() > 512
      || value.bytes().any(|byte| byte.is_ascii_control())
    {
      bail!(
        "{source} exception {} path_prefixes entries must be 1 to 512 printable bytes",
        exception.name
      );
    }
    if !value.starts_with('/') {
      bail!(
        "{source} exception {} path_prefixes entries must start with /",
        exception.name
      );
    }
  }
  for value in &exception.source_cidrs {
    crate::identity::Cidr::parse(value).with_context(|| {
      format!(
        "{source} exception {} source_cidrs entry {value} is invalid",
        exception.name
      )
    })?;
  }
  Ok(())
}

fn validate_reason(source: &str, exception: &RulepackException) -> anyhow::Result<()> {
  if exception.reason.trim().is_empty()
    || exception.reason.len() > 512
    || exception.reason.bytes().any(|byte| byte.is_ascii_control())
  {
    bail!(
      "{source} exception {} reason must be 1 to 512 printable bytes",
      exception.name
    );
  }
  Ok(())
}

fn active_exception_entries<'a>(
  source: &str,
  exceptions: &'a [RulepackException],
) -> anyhow::Result<Vec<&'a RulepackException>> {
  let now = now_unix_seconds();
  let mut active = Vec::new();
  for exception in exceptions {
    if let Some(expires_at) = &exception.expires_at {
      let expires_at = parse_strict_utc_rfc3339(expires_at).with_context(|| {
        format!(
          "{source} exception {} expires_at is invalid",
          exception.name
        )
      })?;
      if expires_at <= now {
        warn!(
          exception = exception.name.as_str(),
          source, "expired rulepack exception ignored"
        );
        continue;
      }
    }
    active.push(exception);
  }
  Ok(active)
}

fn exception_matches_rule(exception: &RulepackException, rule: &RulepackRule) -> bool {
  exception
    .rule_ids
    .iter()
    .any(|id| rule.id.as_deref() == Some(id.as_str()))
    || exception.rule_names.iter().any(|name| name == &rule.name)
    || exception
      .tags
      .iter()
      .any(|wanted| rule.tags.iter().any(|tag| tag == wanted))
}

fn exception_traffic_predicate(exception: &RulepackException) -> String {
  let mut categories = Vec::new();
  if !exception.methods.is_empty() {
    categories.push(any_equals("Request.Http.Method", &exception.methods));
  }
  if !exception.routes.is_empty() {
    categories.push(any_equals("Context.RouteName", &exception.routes));
  }
  if !exception.path_prefixes.is_empty() {
    categories.push(any_call(
      "Request.Http.Path.startsWith",
      &exception.path_prefixes,
    ));
  }
  if !exception.source_cidrs.is_empty() {
    categories.push(any_call(
      "Request.Client.Ip.inCidr",
      &exception.source_cidrs,
    ));
  }
  categories.join(" && ")
}

fn any_equals(field: &str, values: &[String]) -> String {
  values
    .iter()
    .map(|value| format!("{field} == {}", oxirule_string(value)))
    .collect::<Vec<_>>()
    .join(" || ")
    .pipe_parenthesized()
}

fn any_call(function: &str, values: &[String]) -> String {
  values
    .iter()
    .map(|value| format!("{function}({})", oxirule_string(value)))
    .collect::<Vec<_>>()
    .join(" || ")
    .pipe_parenthesized()
}

trait Parenthesize {
  fn pipe_parenthesized(self) -> String;
}

impl Parenthesize for String {
  fn pipe_parenthesized(self) -> String {
    format!("({self})")
  }
}

fn oxirule_string(value: &str) -> String {
  format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn parse_strict_utc_rfc3339(value: &str) -> anyhow::Result<i64> {
  let bytes = value.as_bytes();
  if bytes.len() != 20
    || bytes[4] != b'-'
    || bytes[7] != b'-'
    || bytes[10] != b'T'
    || bytes[13] != b':'
    || bytes[16] != b':'
    || bytes[19] != b'Z'
    || !bytes
      .iter()
      .enumerate()
      .filter(|(index, _)| !matches!(index, 4 | 7 | 10 | 13 | 16 | 19))
      .all(|(_, byte)| byte.is_ascii_digit())
  {
    bail!("timestamp must use YYYY-MM-DDTHH:MM:SSZ");
  }
  let year = parse_i64(&value[0..4])?;
  let month = parse_u32(&value[5..7])?;
  let day = parse_u32(&value[8..10])?;
  let hour = parse_u32(&value[11..13])?;
  let minute = parse_u32(&value[14..16])?;
  let second = parse_u32(&value[17..19])?;
  if !(1..=12).contains(&month) {
    bail!("month is out of range");
  }
  let max_day = days_in_month(year, month);
  if day == 0 || day > max_day {
    bail!("day is out of range");
  }
  if hour > 23 || minute > 59 || second > 59 {
    bail!("time is out of range");
  }
  let days = days_from_civil(year, month, day);
  Ok(days * 86_400 + i64::from(hour * 3_600 + minute * 60 + second))
}

fn parse_i64(value: &str) -> anyhow::Result<i64> {
  value.parse::<i64>().context("invalid integer")
}

fn parse_u32(value: &str) -> anyhow::Result<u32> {
  value.parse::<u32>().context("invalid integer")
}

fn days_in_month(year: i64, month: u32) -> u32 {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
    4 | 6 | 9 | 11 => 30,
    2 if is_leap_year(year) => 29,
    2 => 28,
    _ => 0,
  }
}

fn is_leap_year(year: i64) -> bool {
  (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
  let year = year - i64::from(month <= 2);
  let era = if year >= 0 { year } else { year - 399 } / 400;
  let year_of_era = year - era * 400;
  let month = i64::from(month);
  let day = i64::from(day);
  let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
  let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
  era * 146_097 + day_of_era - 719_468
}

fn now_unix_seconds() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or(Duration::ZERO)
    .as_secs()
    .min(i64::MAX as u64) as i64
}
