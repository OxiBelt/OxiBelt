//! In-memory cache index and tag tracking.
//! Index updates remain separate from object storage so purge semantics are deterministic.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(crate) struct LookupKey {
  policy: String,
  partition: String,
  scheme: String,
  host: String,
  uri: String,
  base_key: String,
}

impl LookupKey {
  pub(crate) fn new(
    policy: &str,
    partition: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    base_key: &str,
  ) -> Self {
    Self {
      policy: policy.to_string(),
      partition: partition.to_string(),
      scheme: scheme.to_string(),
      host: host.to_string(),
      uri: uri.to_string(),
      base_key: base_key.to_string(),
    }
  }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(crate) struct VariantGroupKey {
  policy: String,
  partition: String,
  base_key: String,
}

impl VariantGroupKey {
  pub(crate) fn new(policy: &str, partition: &str, base_key: &str) -> Self {
    Self {
      policy: policy.to_string(),
      partition: partition.to_string(),
      base_key: base_key.to_string(),
    }
  }
}

#[derive(Debug, Default)]
pub(crate) struct CacheIndex {
  variants_by_lookup: HashMap<LookupKey, HashSet<String>>,
  variant_counts_by_group: HashMap<VariantGroupKey, usize>,
}

impl CacheIndex {
  pub(crate) fn insert(&mut self, lookup: LookupKey, variant_key: &str) {
    let group = lookup.group_key();
    let inserted = self
      .variants_by_lookup
      .entry(lookup)
      .or_default()
      .insert(variant_key.to_string());
    if inserted {
      *self.variant_counts_by_group.entry(group).or_default() += 1;
    }
  }

  pub(crate) fn remove(&mut self, lookup: &LookupKey, variant_key: &str) {
    let group = lookup.group_key();
    let Some(variants) = self.variants_by_lookup.get_mut(lookup) else {
      return;
    };
    if variants.remove(variant_key)
      && let Some(count) = self.variant_counts_by_group.get_mut(&group)
    {
      *count = count.saturating_sub(1);
      if *count == 0 {
        self.variant_counts_by_group.remove(&group);
      }
    }
    if variants.is_empty() {
      self.variants_by_lookup.remove(lookup);
    }
  }

  pub(crate) fn candidates(&self, lookup: &LookupKey) -> Option<Vec<String>> {
    self
      .variants_by_lookup
      .get(lookup)
      .map(|variants| variants.iter().cloned().collect())
  }

  pub(crate) fn variant_count(&self, group: &VariantGroupKey) -> usize {
    self
      .variant_counts_by_group
      .get(group)
      .copied()
      .unwrap_or(0)
  }

  pub(crate) fn clear(&mut self) {
    self.variants_by_lookup.clear();
    self.variant_counts_by_group.clear();
  }
}

impl LookupKey {
  fn group_key(&self) -> VariantGroupKey {
    VariantGroupKey::new(&self.policy, &self.partition, &self.base_key)
  }
}
