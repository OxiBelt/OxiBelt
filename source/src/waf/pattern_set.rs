//! Pattern-set compilation and lookup for WAF rules.
//! Sets are compiled once so per-request evaluation does not parse policy files.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, bail};
use regex::RegexSet;

use super::literal_index::CompiledLiteralIndex;
use super::{HybridRegex, WafLimits, WafPatternSetConfig, WafPatternSetKind, body_scan};

const MAX_ADVANCED_PREFILTER_MATCH_WORK: usize = 4_096;

pub(super) fn validate_pattern_sets(
  pattern_sets: &[WafPatternSetConfig],
  limits: &WafLimits,
) -> anyhow::Result<()> {
  let mut names = HashSet::new();
  for set in pattern_sets {
    if set.name.trim().is_empty() {
      bail!("WAF pattern set name must not be empty");
    }
    if !names.insert(set.name.as_str()) {
      bail!("duplicate WAF pattern set name {}", set.name);
    }
    if set.patterns.len() > limits.max_helper_pattern_count {
      bail!(
        "WAF pattern set {} exceeds max_helper_pattern_count",
        set.name
      );
    }
    for pattern in &set.patterns {
      if pattern.len() > limits.max_string_bytes {
        bail!("WAF pattern set {} contains an oversized pattern", set.name);
      }
      if set.kind == WafPatternSetKind::Regex {
        HybridRegex::compile(pattern, false, limits).with_context(|| {
          format!(
            "WAF pattern set {} contains an invalid regex pattern",
            set.name
          )
        })?;
      }
    }
  }
  Ok(())
}

pub(super) fn compile_pattern_sets(
  configs: &[WafPatternSetConfig],
  limits: &WafLimits,
) -> anyhow::Result<HashMap<String, CompiledPatternSet>> {
  validate_pattern_sets(configs, limits)?;
  let mut sets = HashMap::new();
  for config in configs {
    let compiled = match config.kind {
      WafPatternSetKind::Contains => {
        CompiledPatternSet::Contains(CompiledContainsPatternSet::new(config.patterns.clone())?)
      }
      WafPatternSetKind::Regex => {
        let patterns = config
          .patterns
          .iter()
          .map(|pattern| HybridRegex::compile(pattern, false, limits))
          .collect::<anyhow::Result<Vec<_>>>()
          .with_context(|| format!("failed to compile WAF pattern set {}", config.name))?;
        CompiledPatternSet::Regex(
          CompiledRegexPatternSet::new(patterns, limits)
            .with_context(|| format!("failed to compile WAF pattern set {}", config.name))?,
        )
      }
    };
    sets.insert(config.name.clone(), compiled);
  }
  Ok(sets)
}

#[derive(Clone)]
pub(crate) enum CompiledPatternSet {
  Contains(CompiledContainsPatternSet),
  Regex(CompiledRegexPatternSet),
}

#[derive(Clone)]
pub(crate) struct CompiledContainsPatternSet {
  patterns: Arc<[String]>,
  index: CompiledLiteralIndex,
}

impl CompiledContainsPatternSet {
  fn new(patterns: Vec<String>) -> anyhow::Result<Self> {
    let index = CompiledLiteralIndex::new(
      patterns
        .iter()
        .enumerate()
        .map(|(index, pattern)| (index, pattern.as_bytes())),
    )?;
    Ok(Self {
      patterns: Arc::from(patterns),
      index,
    })
  }

  pub(crate) fn is_match(&self, text: &str) -> bool {
    self.index.is_match(text)
  }

  pub(crate) fn scan(&self, text: &str, is_truncated: bool) -> body_scan::BodyScanResult {
    if let Some(found) = self.index.scan_lowest_target(text) {
      let pattern_index = found.target_index;
      let pattern = self.patterns[pattern_index].clone();
      return body_scan::BodyScanResult {
        matched: true,
        pattern: Some(pattern.clone()),
        offset: Some(found.start),
        matched_text: Some(pattern),
        is_truncated,
      };
    }

    body_scan::BodyScanResult::no_match(is_truncated)
  }
}

#[derive(Clone)]
pub(crate) struct CompiledRegexPatternSet {
  patterns: Arc<[HybridRegex]>,
  linear_set: RegexSet,
  linear_set_indices: Arc<[Option<usize>]>,
  advanced_prefilter: Option<CompiledAdvancedRegexPrefilter>,
}

impl CompiledRegexPatternSet {
  fn new(patterns: Vec<HybridRegex>, limits: &WafLimits) -> anyhow::Result<Self> {
    let mut linear_patterns = Vec::new();
    let linear_set_indices = patterns
      .iter()
      .map(|pattern| {
        if pattern.is_advanced() {
          None
        } else {
          let index = linear_patterns.len();
          linear_patterns.push(pattern.as_str());
          Some(index)
        }
      })
      .collect::<Vec<_>>();
    let linear_set = RegexSet::new(linear_patterns)?;
    let advanced_prefilter = CompiledAdvancedRegexPrefilter::new(&patterns, limits);
    Ok(Self {
      patterns: Arc::from(patterns),
      linear_set,
      linear_set_indices: Arc::from(linear_set_indices),
      advanced_prefilter,
    })
  }

  pub(crate) fn is_match(&self, text: &str) -> anyhow::Result<bool> {
    let linear_matches = self.linear_set.matches(text);
    let mut advanced_candidates = None::<Option<Vec<bool>>>;
    for (pattern_index, pattern) in self.patterns.iter().enumerate() {
      match self.linear_set_indices[pattern_index] {
        Some(linear_index) if linear_matches.matched(linear_index) => return Ok(true),
        Some(_) => {}
        None => {
          let matched = if let Some(prefilter) = &self.advanced_prefilter {
            pattern.check_advanced_subject(text)?;
            if pattern.required_literals().is_empty() {
              pattern.is_match_engine(text)?
            } else {
              let candidates = advanced_candidates
                .get_or_insert_with(|| prefilter.candidates(text, self.patterns.len()));
              match candidates {
                Some(candidates) => candidates[pattern_index] && pattern.is_match_engine(text)?,
                None => pattern.is_match(text)?,
              }
            }
          } else {
            pattern.is_match(text)?
          };
          if matched {
            return Ok(true);
          }
        }
      }
    }
    Ok(false)
  }

  pub(crate) fn scan(
    &self,
    text: &str,
    is_truncated: bool,
  ) -> anyhow::Result<body_scan::BodyScanResult> {
    let linear_matches = self.linear_set.matches(text);
    let mut advanced_candidates = None::<Option<Vec<bool>>>;
    for (pattern_index, pattern) in self.patterns.iter().enumerate() {
      let found = match self.linear_set_indices[pattern_index] {
        Some(linear_index) if linear_matches.matched(linear_index) => pattern.find(text)?,
        Some(_) => None,
        None => {
          if let Some(prefilter) = &self.advanced_prefilter {
            pattern.check_advanced_subject(text)?;
            if pattern.required_literals().is_empty() {
              pattern.find_engine(text)?
            } else {
              let candidates = advanced_candidates
                .get_or_insert_with(|| prefilter.candidates(text, self.patterns.len()));
              match candidates {
                Some(candidates) if candidates[pattern_index] => pattern.find_engine(text)?,
                Some(_) => None,
                None => pattern.find(text)?,
              }
            }
          } else {
            pattern.find(text)?
          }
        }
      };
      if let Some(found) = found {
        return Ok(body_scan::BodyScanResult {
          matched: true,
          pattern: Some(pattern.as_str().to_string()),
          offset: Some(found.start()),
          matched_text: Some(found.matched_text().to_string()),
          is_truncated,
        });
      }
    }
    Ok(body_scan::BodyScanResult::no_match(is_truncated))
  }
}

#[derive(Clone)]
struct CompiledAdvancedRegexPrefilter {
  index: CompiledLiteralIndex,
}

impl CompiledAdvancedRegexPrefilter {
  fn new(patterns: &[HybridRegex], limits: &WafLimits) -> Option<Self> {
    let mut unique_literals = HashSet::<Vec<u8>>::new();
    let mut indexed_pattern_count = 0usize;
    for pattern in patterns.iter().filter(|pattern| pattern.is_advanced()) {
      if !pattern.required_literals().is_empty() {
        indexed_pattern_count = indexed_pattern_count.saturating_add(1);
      }
      for literal in pattern.required_literals() {
        unique_literals.insert(literal.to_vec());
      }
    }
    if indexed_pattern_count < 2
      || unique_literals.is_empty()
      || unique_literals.len() > limits.max_helper_pattern_count
      || unique_literals
        .iter()
        .try_fold(0usize, |size, literal| size.checked_add(literal.len()))
        .is_none_or(|size| size > limits.max_memory_bytes)
    {
      return None;
    }

    let index = CompiledLiteralIndex::new(patterns.iter().enumerate().flat_map(
      |(pattern_index, pattern)| {
        pattern
          .is_advanced()
          .then_some(pattern.required_literals())
          .into_iter()
          .flatten()
          .map(move |literal| (pattern_index, literal.as_ref()))
      },
    ))
    .ok()?;
    if index.non_empty_pattern_count() > limits.max_helper_pattern_count
      || index.memory_usage() > limits.max_memory_bytes
    {
      return None;
    }
    Some(Self { index })
  }

  fn candidates(&self, text: &str, pattern_count: usize) -> Option<Vec<bool>> {
    self
      .index
      .matching_targets_bounded(text, pattern_count, MAX_ADVANCED_PREFILTER_MATCH_WORK)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn advanced_regex_scan_preserves_configured_pattern_order() {
    let limits = WafLimits::default();
    let patterns = ["(?<=token=)[a-z]+", "fallback"]
      .into_iter()
      .map(|pattern| HybridRegex::compile(pattern, false, &limits).unwrap())
      .collect();
    let set = CompiledRegexPatternSet::new(patterns, &limits).unwrap();
    let result = set.scan("fallback token=secret", false).unwrap();

    assert!(result.matched);
    assert_eq!(result.pattern.as_deref(), Some("(?<=token=)[a-z]+"));
    assert_eq!(result.offset, Some(15));
    assert_eq!(result.matched_text.as_deref(), Some("secret"));
  }

  #[test]
  fn shared_advanced_prefilter_preserves_order_and_no_literal_fallback() {
    let limits = WafLimits::default();
    let patterns = ["needle(?=tail)", "fallback(?=done)", "(?<=prefix)value"]
      .into_iter()
      .map(|pattern| HybridRegex::compile(pattern, false, &limits).unwrap())
      .collect();
    let set = CompiledRegexPatternSet::new(patterns, &limits).unwrap();
    assert!(set.advanced_prefilter.is_some());

    let ordered = set
      .scan("fallbackdone needletail prefixvalue", false)
      .unwrap();
    assert_eq!(ordered.pattern.as_deref(), Some("needle(?=tail)"));
    assert_eq!(ordered.offset, Some(13));

    let no_literal = set.scan("prefixvalue", false).unwrap();
    assert_eq!(no_literal.pattern.as_deref(), Some("(?<=prefix)value"));
    assert_eq!(no_literal.offset, Some(6));
  }

  #[test]
  fn shared_advanced_prefilter_checks_subject_limit_before_eligibility() {
    let limits = WafLimits {
      max_advanced_regex_subject_bytes: 4,
      ..WafLimits::default()
    };
    let patterns = ["needle(?=tail)", "fallback(?=tail)"]
      .into_iter()
      .map(|pattern| HybridRegex::compile(pattern, false, &limits).unwrap())
      .collect();
    let set = CompiledRegexPatternSet::new(patterns, &limits).unwrap();
    assert!(set.advanced_prefilter.is_some());

    let error = set
      .is_match("absent-literals")
      .expect_err("subject limits must be checked before candidate filtering");
    assert!(
      error
        .to_string()
        .contains("max_advanced_regex_subject_bytes")
    );
  }

  #[test]
  fn shared_advanced_prefilter_preserves_backtrack_errors() {
    let limits = WafLimits {
      max_advanced_regex_backtracks: 1,
      ..WafLimits::default()
    };
    let patterns = ["(x+x+)+(?>y)", "needle(?=tail)", "fallback(?=done)"]
      .into_iter()
      .map(|pattern| HybridRegex::compile(pattern, false, &limits).unwrap())
      .collect();
    let set = CompiledRegexPatternSet::new(patterns, &limits).unwrap();
    assert!(set.advanced_prefilter.is_some());

    let error = set
      .is_match("xxxxxxxxxxy")
      .expect_err("unfiltered advanced patterns must preserve backtrack errors");
    assert!(error.to_string().contains("advanced WAF regex evaluation"));
  }

  #[test]
  fn aggregate_prefilter_falls_back_when_current_count_limit_is_exceeded() {
    let limits = WafLimits {
      max_helper_pattern_count: 1,
      ..WafLimits::default()
    };
    let patterns = ["needle(?=tail)", "fallback(?=done)"]
      .into_iter()
      .map(|pattern| HybridRegex::compile(pattern, false, &limits).unwrap())
      .collect();
    let set = CompiledRegexPatternSet::new(patterns, &limits).unwrap();

    assert!(set.advanced_prefilter.is_none());
    assert!(set.is_match("needletail").unwrap());
  }

  #[test]
  fn aggregate_prefilter_requires_multiple_indexable_advanced_patterns() {
    let limits = WafLimits::default();
    let patterns = ["needle(?=tail)", "(?<=prefix)value"]
      .into_iter()
      .map(|pattern| HybridRegex::compile(pattern, false, &limits).unwrap())
      .collect();
    let set = CompiledRegexPatternSet::new(patterns, &limits).unwrap();

    assert!(set.advanced_prefilter.is_none());
    assert!(set.is_match("needletail").unwrap());
  }

  #[test]
  fn aggregate_prefilter_falls_back_before_overlap_fanout() {
    let limits = WafLimits::default();
    let patterns = ["a(?=a)", "aa(?=a)"]
      .into_iter()
      .map(|pattern| HybridRegex::compile(pattern, false, &limits).unwrap())
      .collect();
    let set = CompiledRegexPatternSet::new(patterns, &limits).unwrap();
    let text = "a".repeat(MAX_ADVANCED_PREFILTER_MATCH_WORK / 2 + 2);
    let prefilter = set.advanced_prefilter.as_ref().unwrap();

    assert!(prefilter.candidates(&text, set.patterns.len()).is_none());
    assert!(set.is_match(&text).unwrap());
    let result = set.scan(&text, false).unwrap();
    assert_eq!(result.pattern.as_deref(), Some("a(?=a)"));
    assert_eq!(result.offset, Some(0));
  }
}
