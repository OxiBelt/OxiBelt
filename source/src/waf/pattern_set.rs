use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use anyhow::{Context, bail};
use regex::{Regex, RegexSet};

use super::{WafLimits, WafPatternSetConfig, WafPatternSetKind, body_scan};

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
        Regex::new(pattern).with_context(|| {
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
          .map(|pattern| Regex::new(pattern))
          .collect::<Result<Vec<_>, _>>()
          .with_context(|| format!("failed to compile WAF pattern set {}", config.name))?;
        CompiledPatternSet::Regex(
          CompiledRegexPatternSet::new(patterns)
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
  automaton: Option<AhoCorasick>,
  automaton_pattern_indices: Arc<[usize]>,
  first_empty_pattern_index: Option<usize>,
}

impl CompiledContainsPatternSet {
  fn new(patterns: Vec<String>) -> anyhow::Result<Self> {
    let mut automaton_patterns = Vec::new();
    let mut automaton_pattern_indices = Vec::new();
    let mut first_empty_pattern_index = None;
    for (index, pattern) in patterns.iter().enumerate() {
      if pattern.is_empty() {
        first_empty_pattern_index.get_or_insert(index);
      } else {
        automaton_patterns.push(pattern.as_str());
        automaton_pattern_indices.push(index);
      }
    }
    let automaton = if automaton_patterns.is_empty() {
      None
    } else {
      Some(AhoCorasick::new(automaton_patterns)?)
    };

    Ok(Self {
      patterns: Arc::from(patterns),
      automaton,
      automaton_pattern_indices: Arc::from(automaton_pattern_indices),
      first_empty_pattern_index,
    })
  }

  pub(crate) fn is_match(&self, text: &str) -> bool {
    self.first_empty_pattern_index.is_some()
      || self
        .automaton
        .as_ref()
        .is_some_and(|automaton| automaton.is_match(text))
  }

  pub(crate) fn scan(&self, text: &str, is_truncated: bool) -> body_scan::BodyScanResult {
    let mut best = self
      .first_empty_pattern_index
      .map(|pattern_index| (pattern_index, 0usize));
    if let Some(automaton) = &self.automaton {
      for found in automaton.find_overlapping_iter(text) {
        let pattern_index = self.automaton_pattern_indices[found.pattern().as_usize()];
        if best.is_none_or(|(best_index, _)| pattern_index < best_index) {
          best = Some((pattern_index, found.start()));
          if pattern_index == 0 {
            break;
          }
        }
      }
    }

    if let Some((pattern_index, offset)) = best {
      let pattern = self.patterns[pattern_index].clone();
      return body_scan::BodyScanResult {
        matched: true,
        pattern: Some(pattern.clone()),
        offset: Some(offset),
        matched_text: Some(pattern),
        is_truncated,
      };
    }

    body_scan::BodyScanResult::no_match(is_truncated)
  }
}

#[derive(Clone)]
pub(crate) struct CompiledRegexPatternSet {
  patterns: Arc<[Regex]>,
  set: RegexSet,
}

impl CompiledRegexPatternSet {
  fn new(patterns: Vec<Regex>) -> anyhow::Result<Self> {
    let pattern_texts = patterns.iter().map(Regex::as_str).collect::<Vec<_>>();
    let set = RegexSet::new(pattern_texts)?;
    Ok(Self {
      patterns: Arc::from(patterns),
      set,
    })
  }

  pub(crate) fn is_match(&self, text: &str) -> bool {
    self.set.is_match(text)
  }

  pub(crate) fn scan(&self, text: &str, is_truncated: bool) -> body_scan::BodyScanResult {
    let matches = self.set.matches(text);
    for (index, pattern) in self.patterns.iter().enumerate() {
      if !matches.matched(index) {
        continue;
      }
      if let Some(found) = pattern.find(text) {
        return body_scan::BodyScanResult {
          matched: true,
          pattern: Some(pattern.as_str().to_string()),
          offset: Some(found.start()),
          matched_text: Some(found.as_str().to_string()),
          is_truncated,
        };
      }
    }
    body_scan::BodyScanResult::no_match(is_truncated)
  }
}
