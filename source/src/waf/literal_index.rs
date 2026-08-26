//! Reusable compiled indexes for policy-authored literal searches.

use std::collections::HashMap;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use memchr::{memchr, memmem};

#[derive(Clone)]
pub(super) struct CompiledLiteralIndex {
  first_empty_target: Option<usize>,
  searcher: LiteralSearcher,
  memory_usage: usize,
  non_empty_pattern_count: usize,
}

#[derive(Clone)]
enum LiteralSearcher {
  Empty,
  Byte {
    needle: u8,
    targets: Arc<[usize]>,
  },
  Substring {
    finder: Box<memmem::Finder<'static>>,
    targets: Arc<[usize]>,
  },
  Multi {
    automaton: AhoCorasick,
    targets: Arc<[Arc<[usize]>]>,
  },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LiteralMatch {
  pub(super) target_index: usize,
  pub(super) start: usize,
}

impl CompiledLiteralIndex {
  pub(super) fn new<'a, I>(patterns: I) -> anyhow::Result<Self>
  where
    I: IntoIterator<Item = (usize, &'a [u8])>,
  {
    let mut first_empty_target = None;
    let mut unique_patterns = Vec::<Vec<u8>>::new();
    let mut target_lists = Vec::<Vec<usize>>::new();
    let mut unique_pattern_indices = HashMap::<Vec<u8>, usize>::new();

    for (target_index, pattern) in patterns {
      if pattern.is_empty() {
        first_empty_target =
          Some(first_empty_target.map_or(target_index, |current: usize| current.min(target_index)));
        continue;
      }
      if let Some(&unique_index) = unique_pattern_indices.get(pattern) {
        target_lists[unique_index].push(target_index);
        continue;
      }
      let unique_index = unique_patterns.len();
      let owned = pattern.to_vec();
      unique_pattern_indices.insert(owned.clone(), unique_index);
      unique_patterns.push(owned);
      target_lists.push(vec![target_index]);
    }

    for targets in &mut target_lists {
      targets.sort_unstable();
      targets.dedup();
    }

    let non_empty_pattern_count = unique_patterns.len();
    let target_memory = target_lists
      .iter()
      .map(|targets| targets.len().saturating_mul(size_of::<usize>()))
      .sum::<usize>();
    let literal_memory = unique_patterns.iter().map(Vec::len).sum::<usize>();

    let (searcher, searcher_memory) = match unique_patterns.len() {
      0 => (LiteralSearcher::Empty, 0),
      1 => {
        let pattern = unique_patterns.pop().unwrap_or_default();
        let targets = Arc::from(target_lists.pop().unwrap_or_default());
        if pattern.len() == 1 {
          (
            LiteralSearcher::Byte {
              needle: pattern[0],
              targets,
            },
            0,
          )
        } else {
          (
            LiteralSearcher::Substring {
              finder: Box::new(memmem::Finder::new(&pattern).into_owned()),
              targets,
            },
            0,
          )
        }
      }
      _ => {
        let automaton = AhoCorasick::new(&unique_patterns)?;
        let automaton_memory = automaton.memory_usage();
        (
          LiteralSearcher::Multi {
            automaton,
            targets: Arc::from(
              target_lists
                .into_iter()
                .map(Arc::<[usize]>::from)
                .collect::<Vec<_>>(),
            ),
          },
          automaton_memory,
        )
      }
    };

    Ok(Self {
      first_empty_target,
      searcher,
      memory_usage: literal_memory
        .saturating_add(target_memory)
        .saturating_add(searcher_memory),
      non_empty_pattern_count,
    })
  }

  pub(super) fn is_match(&self, haystack: &str) -> bool {
    self.first_empty_target.is_some()
      || match &self.searcher {
        LiteralSearcher::Empty => false,
        LiteralSearcher::Byte { needle, .. } => memchr(*needle, haystack.as_bytes()).is_some(),
        LiteralSearcher::Substring { finder, .. } => finder.find(haystack.as_bytes()).is_some(),
        LiteralSearcher::Multi { automaton, .. } => automaton.is_match(haystack),
      }
  }

  pub(super) fn scan_lowest_target(&self, haystack: &str) -> Option<LiteralMatch> {
    let mut best = self.first_empty_target.map(|target_index| LiteralMatch {
      target_index,
      start: 0,
    });
    if best.is_some_and(|found| found.target_index == 0) {
      return best;
    }

    match &self.searcher {
      LiteralSearcher::Empty => {}
      LiteralSearcher::Byte { needle, targets } => {
        if let Some(start) = memchr(*needle, haystack.as_bytes()) {
          update_best(&mut best, targets, start);
        }
      }
      LiteralSearcher::Substring { finder, targets } => {
        if let Some(start) = finder.find(haystack.as_bytes()) {
          update_best(&mut best, targets, start);
        }
      }
      LiteralSearcher::Multi { automaton, targets } => {
        for found in automaton.find_overlapping_iter(haystack) {
          update_best(
            &mut best,
            &targets[found.pattern().as_usize()],
            found.start(),
          );
          if best.is_some_and(|found| found.target_index == 0) {
            break;
          }
        }
      }
    }
    best
  }

  pub(super) fn matching_targets_bounded(
    &self,
    haystack: &str,
    target_count: usize,
    max_match_work: usize,
  ) -> Option<Vec<bool>> {
    let mut matched = vec![false; target_count];
    if let Some(target) = self.first_empty_target
      && target < matched.len()
    {
      matched[target] = true;
    }
    match &self.searcher {
      LiteralSearcher::Empty => {}
      LiteralSearcher::Byte { needle, targets } => {
        if memchr(*needle, haystack.as_bytes()).is_some() {
          mark_targets(&mut matched, targets);
        }
      }
      LiteralSearcher::Substring { finder, targets } => {
        if finder.find(haystack.as_bytes()).is_some() {
          mark_targets(&mut matched, targets);
        }
      }
      LiteralSearcher::Multi { automaton, targets } => {
        let mut match_work = 0usize;
        for found in automaton.find_overlapping_iter(haystack) {
          let found_targets = &targets[found.pattern().as_usize()];
          let next_match_work = match_work.checked_add(found_targets.len())?;
          if next_match_work > max_match_work {
            return None;
          }
          match_work = next_match_work;
          mark_targets(&mut matched, found_targets);
        }
      }
    }
    Some(matched)
  }

  pub(super) fn memory_usage(&self) -> usize {
    self.memory_usage
  }

  pub(super) fn non_empty_pattern_count(&self) -> usize {
    self.non_empty_pattern_count
  }
}

fn update_best(best: &mut Option<LiteralMatch>, targets: &[usize], start: usize) {
  let Some(&target_index) = targets.first() else {
    return;
  };
  if best.is_none_or(|current| target_index < current.target_index) {
    *best = Some(LiteralMatch {
      target_index,
      start,
    });
  }
}

fn mark_targets(matched: &mut [bool], targets: &[usize]) {
  for &target in targets {
    if let Some(slot) = matched.get_mut(target) {
      *slot = true;
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn index(patterns: &[&str]) -> CompiledLiteralIndex {
    CompiledLiteralIndex::new(
      patterns
        .iter()
        .enumerate()
        .map(|(index, pattern)| (index, pattern.as_bytes())),
    )
    .unwrap()
  }

  #[test]
  fn dispatches_empty_byte_substring_and_multi_pattern_searches() {
    assert!(!index(&[]).is_match("anything"));
    assert_eq!(
      index(&["", "x"]).scan_lowest_target("anything"),
      Some(LiteralMatch {
        target_index: 0,
        start: 0,
      })
    );
    assert_eq!(
      index(&["x"]).scan_lowest_target("prefix"),
      Some(LiteralMatch {
        target_index: 0,
        start: 5,
      })
    );
    assert_eq!(
      index(&["needle"]).scan_lowest_target("a needle"),
      Some(LiteralMatch {
        target_index: 0,
        start: 2,
      })
    );
    assert_eq!(
      index(&["needle", "boundary needle"]).scan_lowest_target("boundary needle"),
      Some(LiteralMatch {
        target_index: 0,
        start: 9,
      })
    );
  }

  #[test]
  fn preserves_duplicate_overlap_order_and_utf8_byte_offsets() {
    let index = index(&["secret", "secret", "ésecret", "ret"]);
    assert_eq!(
      index.scan_lowest_target("ésecret"),
      Some(LiteralMatch {
        target_index: 0,
        start: 2,
      })
    );
    assert_eq!(
      index.matching_targets_bounded("ésecret", 4, 16),
      Some(vec![true, true, true, true])
    );
  }

  #[test]
  fn bounded_target_scan_falls_back_before_overlap_fanout() {
    let index = index(&["a", "aa", "aaa"]);

    assert_eq!(
      index.matching_targets_bounded("aaaa", 3, 9),
      Some(vec![true, true, true])
    );
    assert_eq!(index.matching_targets_bounded("aaaa", 3, 8), None);
  }
}
