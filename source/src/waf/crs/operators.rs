//! CRS operator implementations.
//! Operators consume normalized variables and return match state without mutating requests.

use aho_corasick::AhoCorasick;
use anyhow::bail;
use regex::Regex;
use std::sync::LazyLock;

use super::actions::expand_macros;
use super::compatibility::SUPPORTED_OPERATORS;
use super::model::CrsTransaction;
use super::syntax::split_phrases;
use super::utils::{invalid_url_encoding, invalid_utf8_encoding};

#[derive(Clone)]
pub(super) enum CrsOperator {
  Regex(Regex),
  Contains(String),
  ContainsWord {
    needle: String,
    literal_regex: Option<Regex>,
  },
  BeginsWith(String),
  EndsWith(String),
  Streq(String),
  Pm(CrsPhraseMatcher),
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
        "containsWord" => Ok(Self::ContainsWord {
          needle: arg.to_string(),
          literal_regex: (!contains_tx_macro(arg))
            .then(|| contains_word_regex(arg))
            .transpose()?,
        }),
        "beginsWith" => Ok(Self::BeginsWith(arg.to_string())),
        "endsWith" => Ok(Self::EndsWith(arg.to_string())),
        "streq" => Ok(Self::Streq(arg.to_string())),
        "pm" => Ok(Self::Pm(CrsPhraseMatcher::new(split_phrases(arg))?)),
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
      Self::Contains(needle) => {
        let needle = expand_macros(needle, tx);
        value.contains(needle.as_ref())
      }
      Self::ContainsWord {
        needle,
        literal_regex,
      } => {
        if let Some(regex) = literal_regex {
          regex.is_match(value)
        } else {
          let needle = expand_macros(needle, tx);
          contains_word_regex(needle.as_ref())?.is_match(value)
        }
      }
      Self::BeginsWith(needle) => {
        let needle = expand_macros(needle, tx);
        value.starts_with(needle.as_ref())
      }
      Self::EndsWith(needle) => {
        let needle = expand_macros(needle, tx);
        value.ends_with(needle.as_ref())
      }
      Self::Streq(expected) => {
        let expected = expand_macros(expected, tx);
        value == expected.as_ref()
      }
      Self::Pm(phrases) => phrases.is_match(value, tx),
      Self::Eq(expected) => value.parse::<i64>().unwrap_or(0) == *expected,
      Self::Ge(expected) => value.parse::<i64>().unwrap_or(0) >= *expected,
      Self::Gt(expected) => value.parse::<i64>().unwrap_or(0) > *expected,
      Self::Le(expected) => value.parse::<i64>().unwrap_or(0) <= *expected,
      Self::Lt(expected) => value.parse::<i64>().unwrap_or(0) < *expected,
      Self::DetectSqli => DETECT_SQLI_REGEX.is_match(value),
      Self::DetectXss => DETECT_XSS_REGEX.is_match(value),
      Self::UnconditionalMatch => true,
      Self::ValidateUrlEncoding => invalid_url_encoding(value),
      Self::ValidateUtf8Encoding => invalid_utf8_encoding(value),
      Self::Negated(inner) => !inner.matches(value, tx)?,
    };
    Ok(result)
  }
}

#[derive(Clone)]
pub(super) struct CrsPhraseMatcher {
  literal_automaton: Option<AhoCorasick>,
  literal_has_empty: bool,
  dynamic_phrases: Vec<String>,
}

impl CrsPhraseMatcher {
  fn new(phrases: Vec<String>) -> anyhow::Result<Self> {
    let mut literal_phrases = Vec::new();
    let mut literal_has_empty = false;
    let mut dynamic_phrases = Vec::new();
    for phrase in phrases {
      if contains_tx_macro(&phrase) {
        dynamic_phrases.push(phrase);
      } else if phrase.is_empty() {
        literal_has_empty = true;
      } else {
        literal_phrases.push(phrase);
      }
    }
    let literal_automaton = if literal_phrases.is_empty() {
      None
    } else {
      Some(AhoCorasick::new(literal_phrases)?)
    };
    Ok(Self {
      literal_automaton,
      literal_has_empty,
      dynamic_phrases,
    })
  }

  fn is_match(&self, value: &str, tx: &CrsTransaction<'_>) -> bool {
    self.literal_has_empty
      || self
        .literal_automaton
        .as_ref()
        .is_some_and(|automaton| automaton.is_match(value))
      || self.dynamic_phrases.iter().any(|phrase| {
        let phrase = expand_macros(phrase, tx);
        value.contains(phrase.as_ref())
      })
  }
}

#[allow(
  clippy::expect_used,
  reason = "the built-in SQLi compatibility expression is a fixed, compile-reviewed regex"
)]
static DETECT_SQLI_REGEX: LazyLock<Regex> = LazyLock::new(|| {
  Regex::new(
    "(?i)(union\\s+select|sleep\\s*\\(|information_schema|or\\s+1\\s*=\\s*1|drop\\s+table)",
  )
  .expect("valid CRS SQLi compatibility regex")
});

#[allow(
  clippy::expect_used,
  reason = "the built-in XSS compatibility expression is a fixed, compile-reviewed regex"
)]
static DETECT_XSS_REGEX: LazyLock<Regex> = LazyLock::new(|| {
  Regex::new("(?i)(<\\s*script|javascript:|onerror\\s*=|onload\\s*=)")
    .expect("valid CRS XSS compatibility regex")
});

fn contains_tx_macro(value: &str) -> bool {
  value.contains("%{tx.")
}

fn contains_word_regex(needle: &str) -> anyhow::Result<Regex> {
  Ok(Regex::new(&format!(r"(?i)\b{}\b", regex::escape(needle)))?)
}
