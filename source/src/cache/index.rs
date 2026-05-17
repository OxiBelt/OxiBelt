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

#[derive(Debug, Default)]
pub(crate) struct CacheIndex {
  variants_by_lookup: HashMap<LookupKey, HashSet<String>>,
}

impl CacheIndex {
  pub(crate) fn insert(&mut self, lookup: LookupKey, variant_key: &str) {
    self
      .variants_by_lookup
      .entry(lookup)
      .or_default()
      .insert(variant_key.to_string());
  }

  pub(crate) fn remove(&mut self, lookup: &LookupKey, variant_key: &str) {
    let Some(variants) = self.variants_by_lookup.get_mut(lookup) else {
      return;
    };
    variants.remove(variant_key);
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

  pub(crate) fn clear(&mut self) {
    self.variants_by_lookup.clear();
  }
}
