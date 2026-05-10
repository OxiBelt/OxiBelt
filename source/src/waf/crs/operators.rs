use anyhow::bail;
use regex::Regex;

use super::actions::expand_macros;
use super::compatibility::SUPPORTED_OPERATORS;
use super::model::CrsTransaction;
use super::syntax::split_phrases;
use super::utils::{invalid_url_encoding, invalid_utf8_encoding};

#[derive(Clone)]
pub(super) enum CrsOperator {
  Regex(Regex),
  Contains(String),
  ContainsWord(String),
  BeginsWith(String),
  EndsWith(String),
  Streq(String),
  Pm(Vec<String>),
  Eq(i64),
  Ge(i64),
  Gt(i64),
  Le(i64),
  Lt(i64),
  DetectSqli,
  DetectXss,
  UnconditionalMatch,
  ValidateUrlEncoding,
  ValidateUtf8Encoding,
  Negated(Box<CrsOperator>),
}

impl CrsOperator {
  pub(super) fn parse(raw: &str) -> anyhow::Result<Self> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('!') {
      return Ok(Self::Negated(Box::new(Self::parse(rest)?)));
    }
    if let Some(rest) = raw.strip_prefix('@') {
      let (name, arg) = rest
        .split_once(char::is_whitespace)
        .map(|(name, arg)| (name, arg.trim()))
        .unwrap_or((rest, ""));
      if !SUPPORTED_OPERATORS.contains(&name) {
        bail!("unsupported CRS operator @{name}");
      }
      return match name {
        "rx" => Ok(Self::Regex(Regex::new(arg)?)),
        "contains" => Ok(Self::Contains(arg.to_string())),
        "containsWord" => Ok(Self::ContainsWord(arg.to_string())),
        "beginsWith" => Ok(Self::BeginsWith(arg.to_string())),
        "endsWith" => Ok(Self::EndsWith(arg.to_string())),
        "streq" => Ok(Self::Streq(arg.to_string())),
        "pm" => Ok(Self::Pm(split_phrases(arg))),
        "eq" => Ok(Self::Eq(arg.parse()?)),
        "ge" => Ok(Self::Ge(arg.parse()?)),
        "gt" => Ok(Self::Gt(arg.parse()?)),
        "le" => Ok(Self::Le(arg.parse()?)),
        "lt" => Ok(Self::Lt(arg.parse()?)),
        "detectSQLi" => Ok(Self::DetectSqli),
        "detectXSS" => Ok(Self::DetectXss),
        "unconditionalMatch" => Ok(Self::UnconditionalMatch),
        "validateUrlEncoding" => Ok(Self::ValidateUrlEncoding),
        "validateUtf8Encoding" => Ok(Self::ValidateUtf8Encoding),
        _ => bail!("CRS compatibility matrix lists unimplemented operator @{name}"),
      };
    }
    Ok(Self::Regex(Regex::new(raw)?))
  }

  pub(super) fn matches(&self, value: &str, tx: &CrsTransaction<'_>) -> anyhow::Result<bool> {
    let result = match self {
      Self::Regex(regex) => regex.is_match(value),
      Self::Contains(needle) => value.contains(&expand_macros(needle, tx)),
      Self::ContainsWord(needle) => {
        let needle = expand_macros(needle, tx);
        Regex::new(&format!(r"(?i)\b{}\b", regex::escape(&needle)))?.is_match(value)
      }
      Self::BeginsWith(needle) => value.starts_with(&expand_macros(needle, tx)),
      Self::EndsWith(needle) => value.ends_with(&expand_macros(needle, tx)),
      Self::Streq(expected) => value == expand_macros(expected, tx),
      Self::Pm(phrases) => phrases
        .iter()
        .map(|phrase| expand_macros(phrase, tx))
        .any(|phrase| value.contains(&phrase)),
      Self::Eq(expected) => value.parse::<i64>().unwrap_or(0) == *expected,
      Self::Ge(expected) => value.parse::<i64>().unwrap_or(0) >= *expected,
      Self::Gt(expected) => value.parse::<i64>().unwrap_or(0) > *expected,
      Self::Le(expected) => value.parse::<i64>().unwrap_or(0) <= *expected,
      Self::Lt(expected) => value.parse::<i64>().unwrap_or(0) < *expected,
      Self::DetectSqli => Regex::new(
        "(?i)(union\\s+select|sleep\\s*\\(|information_schema|or\\s+1\\s*=\\s*1|drop\\s+table)",
      )?
      .is_match(value),
      Self::DetectXss => {
        Regex::new("(?i)(<\\s*script|javascript:|onerror\\s*=|onload\\s*=)")?.is_match(value)
      }
      Self::UnconditionalMatch => true,
      Self::ValidateUrlEncoding => invalid_url_encoding(value),
      Self::ValidateUtf8Encoding => invalid_utf8_encoding(value),
      Self::Negated(inner) => !inner.matches(value, tx)?,
    };
    Ok(result)
  }
}
