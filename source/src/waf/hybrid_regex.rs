//! Bounded policy-authored regular expressions with conservative literal prefilters.

use std::sync::Arc;

use anyhow::{Context, bail};
use fancy_regex::Regex as FancyRegex;
use regex::{Regex, RegexBuilder};

use super::WafLimits;
use super::literal_index::CompiledLiteralIndex;

#[derive(Clone)]
pub(super) struct HybridRegex {
  pattern: Arc<str>,
  engine: HybridRegexEngine,
  prefilter: Option<CompiledLiteralIndex>,
  required_literals: Arc<[Arc<[u8]>]>,
  max_advanced_subject_bytes: usize,
}

#[derive(Clone)]
enum HybridRegexEngine {
  Linear(Regex),
  Advanced(FancyRegex),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HybridMatch<'a> {
  text: &'a str,
  start: usize,
  end: usize,
}

impl HybridMatch<'_> {
  pub(super) fn start(self) -> usize {
    self.start
  }
}

impl<'a> HybridMatch<'a> {
  pub(super) fn matched_text(self) -> &'a str {
    &self.text[self.start..self.end]
  }
}

impl HybridRegex {
  pub(super) fn compile(
    pattern: &str,
    case_insensitive: bool,
    limits: &WafLimits,
  ) -> anyhow::Result<Self> {
    let mut linear = RegexBuilder::new(pattern);
    linear.case_insensitive(case_insensitive);
    let required_literals = compile_required_literals(pattern, case_insensitive);
    let prefilter = compile_prefilter(&required_literals)?;
    match linear.build() {
      Ok(regex) => Ok(Self {
        pattern: Arc::from(pattern),
        engine: HybridRegexEngine::Linear(regex),
        prefilter,
        required_literals,
        max_advanced_subject_bytes: limits.max_advanced_regex_subject_bytes,
      }),
      Err(linear_error) => {
        let mut advanced = fancy_regex::RegexBuilder::new(pattern);
        advanced
          .case_insensitive(case_insensitive)
          .backtrack_limit(limits.max_advanced_regex_backtracks)
          .delegate_size_limit(limits.max_memory_bytes)
          .delegate_dfa_size_limit(limits.max_memory_bytes);
        let regex = advanced.build().with_context(|| {
          format!(
            "regex pattern is unsupported by both the linear engine ({linear_error}) and the advanced engine"
          )
        })?;
        Ok(Self {
          pattern: Arc::from(pattern),
          engine: HybridRegexEngine::Advanced(regex),
          prefilter,
          required_literals,
          max_advanced_subject_bytes: limits.max_advanced_regex_subject_bytes,
        })
      }
    }
  }

  pub(super) fn as_str(&self) -> &str {
    &self.pattern
  }

  pub(super) fn is_advanced(&self) -> bool {
    matches!(self.engine, HybridRegexEngine::Advanced(_))
  }

  pub(super) fn required_literals(&self) -> &[Arc<[u8]>] {
    &self.required_literals
  }

  pub(super) fn is_match(&self, text: &str) -> anyhow::Result<bool> {
    self.check_advanced_subject(text)?;
    if !self.prefilter_matches(text) {
      return Ok(false);
    }
    self.is_match_engine(text)
  }

  pub(super) fn is_match_engine(&self, text: &str) -> anyhow::Result<bool> {
    match &self.engine {
      HybridRegexEngine::Linear(regex) => Ok(regex.is_match(text)),
      HybridRegexEngine::Advanced(regex) => regex
        .is_match(text)
        .context("advanced WAF regex evaluation failed"),
    }
  }

  pub(super) fn find<'a>(&self, text: &'a str) -> anyhow::Result<Option<HybridMatch<'a>>> {
    self.check_advanced_subject(text)?;
    if !self.prefilter_matches(text) {
      return Ok(None);
    }
    self.find_engine(text)
  }

  pub(super) fn find_engine<'a>(&self, text: &'a str) -> anyhow::Result<Option<HybridMatch<'a>>> {
    let bounds = match &self.engine {
      HybridRegexEngine::Linear(regex) => {
        regex.find(text).map(|found| (found.start(), found.end()))
      }
      HybridRegexEngine::Advanced(regex) => regex
        .find(text)
        .context("advanced WAF regex evaluation failed")?
        .map(|found| (found.start(), found.end())),
    };
    Ok(bounds.map(|(start, end)| HybridMatch { text, start, end }))
  }

  pub(super) fn check_advanced_subject(&self, text: &str) -> anyhow::Result<()> {
    if self.is_advanced() && text.len() > self.max_advanced_subject_bytes {
      bail!(
        "advanced WAF regex subject exceeds max_advanced_regex_subject_bytes ({})",
        self.max_advanced_subject_bytes
      );
    }
    Ok(())
  }

  fn prefilter_matches(&self, text: &str) -> bool {
    self
      .prefilter
      .as_ref()
      .is_none_or(|prefilter| prefilter.is_match(text))
  }
}

fn compile_required_literals(pattern: &str, case_insensitive: bool) -> Arc<[Arc<[u8]>]> {
  if case_insensitive {
    return Arc::from([]);
  }
  Arc::from(
    required_literal_alternatives(pattern)
      .into_iter()
      .map(|literal| Arc::<[u8]>::from(literal.into_bytes()))
      .collect::<Vec<_>>(),
  )
}

fn compile_prefilter(literals: &[Arc<[u8]>]) -> anyhow::Result<Option<CompiledLiteralIndex>> {
  if literals.is_empty() {
    return Ok(None);
  }
  CompiledLiteralIndex::new(literals.iter().map(|literal| (0usize, literal.as_ref())))
    .map(Some)
    .context("failed to compile WAF regex literal prefilter")
}

fn required_literal_alternatives(pattern: &str) -> Vec<String> {
  let branches = split_top_level_alternatives(pattern);
  if branches.len() > 1 {
    let mut literals = Vec::with_capacity(branches.len());
    for branch in branches {
      let Some(literal) = exact_literal_pattern(branch) else {
        return Vec::new();
      };
      if literal.is_empty() {
        return Vec::new();
      }
      if !literals.contains(&literal) {
        literals.push(literal);
      }
    }
    return literals;
  }
  required_literal_prefix(pattern).into_iter().collect()
}

fn split_top_level_alternatives(pattern: &str) -> Vec<&str> {
  let mut branches = Vec::new();
  let mut start = 0;
  let mut depth = 0usize;
  let mut escaped = false;
  let mut in_class = false;
  for (index, ch) in pattern.char_indices() {
    if escaped {
      escaped = false;
      continue;
    }
    match ch {
      '\\' => escaped = true,
      '[' if !in_class => in_class = true,
      ']' if in_class => in_class = false,
      '(' if !in_class => depth = depth.saturating_add(1),
      ')' if !in_class => depth = depth.saturating_sub(1),
      '|' if !in_class && depth == 0 => {
        branches.push(&pattern[start..index]);
        start = index + ch.len_utf8();
      }
      _ => {}
    }
  }
  branches.push(&pattern[start..]);
  branches
}

fn exact_literal_pattern(pattern: &str) -> Option<String> {
  let mut pattern = pattern;
  if let Some(rest) = pattern.strip_prefix('^') {
    pattern = rest;
  }
  if let Some(rest) = pattern.strip_suffix('$') {
    pattern = rest;
  }
  parse_literal_run(pattern, true)
    .filter(|(_, consumed)| *consumed == pattern.len())
    .map(|(literal, _)| literal)
}

fn required_literal_prefix(pattern: &str) -> Option<String> {
  if split_top_level_alternatives(pattern).len() > 1 {
    return None;
  }
  let mut pattern = pattern;
  if let Some(rest) = pattern.strip_prefix('^') {
    pattern = rest;
  } else if let Some(rest) = pattern.strip_prefix("\\A") {
    pattern = rest;
  }
  let (mut literal, consumed) = parse_literal_run(pattern, false)?;
  match pattern.as_bytes().get(consumed).copied() {
    Some(b'*' | b'?') => {
      literal.pop();
    }
    Some(b'{') if pattern[consumed..].starts_with("{0") => {
      literal.pop();
    }
    _ => {}
  }
  (!literal.is_empty()).then_some(literal)
}

fn parse_literal_run(pattern: &str, require_complete: bool) -> Option<(String, usize)> {
  let mut literal = String::new();
  let mut chars = pattern.char_indices().peekable();
  while let Some((index, ch)) = chars.next() {
    match ch {
      '\\' => {
        let (_, escaped) = chars.next()?;
        if escaped.is_ascii_alphanumeric() {
          if require_complete {
            return None;
          }
          return Some((literal, index));
        }
        literal.push(escaped);
      }
      '.' | '*' | '+' | '?' | '{' | '[' | '(' | '|' | '$' | '^' => {
        if require_complete {
          return None;
        }
        return Some((literal, index));
      }
      _ => literal.push(ch),
    }
  }
  Some((literal, pattern.len()))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn derives_only_sound_literal_prefilters() {
    assert_eq!(required_literal_alternatives("needle(?=tail)"), ["needle"]);
    assert_eq!(required_literal_alternatives("foo|bar"), ["foo", "bar"]);
    assert_eq!(required_literal_alternatives("fo?"), ["f"]);
    assert!(required_literal_alternatives("foo.*|bar").is_empty());
    assert!(required_literal_alternatives("(?<=prefix)value").is_empty());
  }

  #[test]
  fn hybrid_match_reports_original_bounds() {
    let regex = HybridRegex::compile("(?<=prefix)value", false, &WafLimits::default()).unwrap();
    let found = regex.find("prefixvalue").unwrap().unwrap();
    assert_eq!(found.start(), 6);
    assert_eq!(found.matched_text(), "value");
  }

  #[test]
  fn compiler_prefers_linear_and_falls_back_for_lookaround() {
    let limits = WafLimits::default();
    assert!(
      !HybridRegex::compile("^linear+$", false, &limits)
        .unwrap()
        .is_advanced()
    );
    assert!(
      HybridRegex::compile("value(?=tail)", false, &limits)
        .unwrap()
        .is_advanced()
    );
    assert!(
      HybridRegex::compile("(?<=prefix+)value", false, &limits)
        .unwrap()
        .is_advanced()
    );
  }

  #[test]
  fn advanced_subject_limit_is_an_evaluation_error() {
    let limits = WafLimits {
      max_advanced_regex_subject_bytes: 4,
      ..WafLimits::default()
    };
    let regex = HybridRegex::compile("(?=a)a", false, &limits).unwrap();
    let error = regex
      .is_match("aaaaa")
      .expect_err("oversized advanced subjects must fail");
    assert!(
      error
        .to_string()
        .contains("max_advanced_regex_subject_bytes")
    );
  }

  #[test]
  fn advanced_backtrack_limit_is_an_evaluation_error() {
    let limits = WafLimits {
      max_advanced_regex_backtracks: 1,
      ..WafLimits::default()
    };
    let regex = HybridRegex::compile("(x+x+)+(?>y)", false, &limits).unwrap();
    let error = regex
      .is_match("xxxxxxxxxxy")
      .expect_err("advanced backtracking must be bounded");
    assert!(error.to_string().contains("advanced WAF regex evaluation"));
  }

  #[test]
  fn prefilter_never_rejects_an_engine_match() {
    let patterns = [
      "a",
      "ab",
      "ab?",
      "foo|bar",
      "needle(?=tail)",
      "(?<=prefix)value",
      "λ(?=x)",
    ];
    let mut haystacks = vec![
      "".to_string(),
      "foo".to_string(),
      "bar".to_string(),
      "needletail".to_string(),
      "prefixvalue".to_string(),
      "λx".to_string(),
    ];
    for length in 0usize..=4 {
      let combinations = 3usize.pow(length as u32);
      for mut encoded in 0..combinations {
        let mut text = String::with_capacity(length);
        for _ in 0..length {
          text.push(['a', 'b', 'x'][encoded % 3]);
          encoded /= 3;
        }
        haystacks.push(text);
      }
    }

    for pattern in patterns {
      let regex = HybridRegex::compile(pattern, false, &WafLimits::default()).unwrap();
      for haystack in &haystacks {
        let oracle = match &regex.engine {
          HybridRegexEngine::Linear(engine) => engine.is_match(haystack),
          HybridRegexEngine::Advanced(engine) => engine.is_match(haystack).unwrap(),
        };
        assert!(
          !oracle || regex.prefilter_matches(haystack),
          "prefilter rejected engine match for {pattern:?} on {haystack:?}"
        );
      }
    }
  }

  #[test]
  fn case_insensitive_advanced_regexes_do_not_receive_case_sensitive_prefilters() {
    let regex = HybridRegex::compile("NEEDLE(?=tail)", true, &WafLimits::default()).unwrap();
    assert!(regex.is_advanced());
    assert!(regex.required_literals().is_empty());
    assert!(regex.is_match("needletail").unwrap());
  }
}
