//! Pure, bounded cache-group coherence state. No storage or proxy policy lives here.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

use super::origin::CacheGroupOrigin;

pub(in crate::cache) const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SCOPES: usize = 1024;
const MAX_NAMES: usize = 4096;
const MAX_ENTRIES: usize = 4096;
const MAX_STRING_BYTES: usize = 65_536;
const MAX_GROUP_MEMBERS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CacheGroupStamp {
  pub(crate) policy: String,
  pub(crate) origin: CacheGroupOrigin,
  pub(crate) partition: String,
  pub(crate) incarnation: String,
  pub(crate) sequence: u64,
  pub(crate) target: String,
  pub(crate) groups: Vec<String>,
  pub(crate) tags: Vec<String>,
  /// The URI path of a validated No-Vary-Search owner. It deliberately stays
  /// absent for ordinary responses so path invalidations cannot widen them.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub(crate) equivalent_path: Option<String>,
}

impl CacheGroupStamp {
  pub(crate) fn valid(&self) -> bool {
    self.incarnation.len() == 64
      && self.incarnation.bytes().all(|b| b.is_ascii_hexdigit())
      && self.groups.len() <= MAX_GROUP_MEMBERS
      && valid_group_names(&self.groups)
      && self.tags.len() <= MAX_NAMES
      && valid_names(&self.tags)
      && self.target.len() <= MAX_STRING_BYTES
      && self.partition.len() <= MAX_STRING_BYTES
      && self.equivalent_path.as_deref().is_none_or(valid_path)
      && CacheGroupOrigin::new(&self.origin.scheme, &self.origin.authority())
        .ok()
        .as_ref()
        == Some(&self.origin)
  }

  pub(in crate::cache) fn scope_key(&self) -> String {
    scope_key(&self.origin, &self.partition)
  }
}

pub(in crate::cache) fn scope_key(origin: &CacheGroupOrigin, partition: &str) -> String {
  let origin = origin.as_origin();
  digest(
    format!(
      "{}:{}{}:{}",
      origin.len(),
      origin,
      partition.len(),
      partition
    )
    .as_bytes(),
  )
}

pub(in crate::cache) fn digest(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let hash = crate::crypto::sha256(bytes);
  let mut output = String::with_capacity(hash.len() * 2);
  for byte in hash {
    output.push(HEX[(byte >> 4) as usize] as char);
    output.push(HEX[(byte & 0x0f) as usize] as char);
  }
  output
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::cache) struct Authority {
  pub version: u8,
  pub incarnation: String,
  #[serde(default = "default_enabled")]
  pub enabled: bool,
  pub scopes: BTreeMap<String, Scope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::cache) struct Scope {
  pub origin: CacheGroupOrigin,
  pub partition: String,
  pub sequence: u64,
  pub floor: u64,
  pub groups: BTreeMap<String, u64>,
  pub targets: BTreeMap<String, u64>,
  #[serde(default)]
  pub paths: BTreeMap<String, u64>,
  pub prefixes: BTreeMap<String, u64>,
  pub tags: BTreeMap<String, u64>,
  pub entries: BTreeMap<String, Seed>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::cache) struct Seed {
  pub target: String,
  pub groups: Vec<String>,
  pub tags: Vec<String>,
  pub sequence: u64,
  pub expires_ms: u64,
  pub publication: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub equivalent_path: Option<String>,
}

#[derive(Clone, Debug)]
pub(in crate::cache) enum Selector {
  Exact(String),
  Prefix(String),
  Tag(String),
  Groups(Vec<String>),
}

impl Selector {
  fn selects(&self, entry: &Seed) -> bool {
    match self {
      Self::Exact(target) => {
        entry.target == *target
          || entry
            .equivalent_path
            .as_deref()
            .zip(target_path(target))
            .is_some_and(|(entry_path, target_path)| entry_path == target_path)
      }
      Self::Prefix(prefix) => entry
        .target
        .parse::<http::Uri>()
        .ok()
        .is_some_and(|uri| uri.path().starts_with(prefix)),
      Self::Tag(tag) => entry.tags.contains(tag),
      Self::Groups(groups) => entry.groups.iter().any(|g| groups.contains(g)),
    }
  }
}

impl Authority {
  pub fn new(incarnation: String) -> Self {
    Self {
      version: 1,
      incarnation,
      enabled: true,
      scopes: BTreeMap::new(),
    }
  }

  pub fn decode(bytes: &[u8]) -> Result<Self> {
    ensure!(
      bytes.len() <= MAX_STATE_BYTES,
      "cache group state exceeds byte bound"
    );
    let state: Self = serde_json::from_slice(bytes)?;
    state.validate()?;
    ensure!(
      state.scopes.len() <= MAX_SCOPES,
      "cache group scope bound exceeded"
    );
    for (key, scope) in &state.scopes {
      ensure!(
        *key == scope_key(&scope.origin, &scope.partition),
        "cache group scope identity mismatch"
      );
      scope.validate()?;
    }
    Ok(state)
  }

  pub fn encode(&self) -> Result<Vec<u8>> {
    self.validate()?;
    let bytes = serde_json::to_vec(self)?;
    ensure!(
      bytes.len() <= MAX_STATE_BYTES,
      "cache group state exceeds byte bound"
    );
    Ok(bytes)
  }

  pub fn snapshot(
    &mut self,
    policy: &str,
    origin: &CacheGroupOrigin,
    partition: &str,
  ) -> Result<CacheGroupStamp> {
    ensure!(self.enabled, "cache group authority disabled");
    let key = scope_key(origin, partition);
    if !self.scopes.contains_key(&key) {
      ensure!(
        self.scopes.len() < MAX_SCOPES,
        "cache group scope bound exceeded"
      );
      self.scopes.insert(
        key.clone(),
        Scope {
          origin: origin.clone(),
          partition: partition.to_string(),
          sequence: 0,
          floor: 0,
          groups: BTreeMap::new(),
          targets: BTreeMap::new(),
          paths: BTreeMap::new(),
          prefixes: BTreeMap::new(),
          tags: BTreeMap::new(),
          entries: BTreeMap::new(),
        },
      );
    }
    let scope = &self.scopes[&key];
    Ok(CacheGroupStamp {
      policy: policy.into(),
      origin: origin.clone(),
      partition: partition.into(),
      incarnation: self.incarnation.clone(),
      sequence: scope.sequence,
      target: String::new(),
      groups: Vec::new(),
      tags: Vec::new(),
      equivalent_path: None,
    })
  }

  pub fn current(&self, stamp: &CacheGroupStamp) -> bool {
    self.enabled
      && stamp.valid()
      && stamp.incarnation == self.incarnation
      && self.scopes.get(&stamp.scope_key()).is_some_and(|scope| {
        scope.current(
          stamp.sequence,
          &stamp.target,
          &stamp.groups,
          &stamp.tags,
          stamp.equivalent_path.as_deref(),
        )
      })
  }

  pub fn publish(
    &mut self,
    stamp: &CacheGroupStamp,
    variant: &str,
    expires_ms: u64,
    now_ms: u64,
    publication: &str,
  ) -> Result<Option<Seed>> {
    ensure!(self.current(stamp), "cache group fill was invalidated");
    let scope = self
      .scopes
      .get_mut(&stamp.scope_key())
      .ok_or_else(|| anyhow::anyhow!("cache group scope missing"))?;
    scope.entries.retain(|_, entry| entry.expires_ms > now_ms);
    ensure!(
      scope.entries.contains_key(variant) || scope.entries.len() < MAX_ENTRIES,
      "cache group entry index bound exceeded"
    );
    ensure!(
      variant.len() <= MAX_STRING_BYTES,
      "cache group entry key exceeds byte bound"
    );
    Ok(scope.entries.insert(
      variant.to_string(),
      Seed {
        target: stamp.target.clone(),
        groups: stamp.groups.clone(),
        tags: stamp.tags.clone(),
        sequence: stamp.sequence,
        expires_ms,
        publication: publication.to_string(),
        equivalent_path: stamp.equivalent_path.clone(),
      },
    ))
  }

  pub fn rollback_publish(
    &mut self,
    stamp: &CacheGroupStamp,
    variant: &str,
    publication: &str,
    previous: Option<Seed>,
  ) -> Result<()> {
    let scope = self
      .scopes
      .get_mut(&stamp.scope_key())
      .ok_or_else(|| anyhow::anyhow!("cache group scope missing"))?;
    if scope
      .entries
      .get(variant)
      .is_none_or(|seed| seed.publication != publication)
    {
      return Ok(());
    }
    match previous.filter(|seed| {
      scope.current(
        seed.sequence,
        &seed.target,
        &seed.groups,
        &seed.tags,
        seed.equivalent_path.as_deref(),
      )
    }) {
      Some(seed) => {
        scope.entries.insert(variant.to_string(), seed);
      }
      None => {
        scope.entries.remove(variant);
      }
    }
    Ok(())
  }

  #[allow(clippy::too_many_arguments)]
  pub fn invalidate(
    &mut self,
    origin: Option<&CacheGroupOrigin>,
    partition: Option<&str>,
    host: Option<&str>,
    scheme: Option<&str>,
    selector: &Selector,
    explicit: &[String],
    now_ms: u64,
  ) -> Result<usize> {
    ensure!(self.enabled, "cache group authority disabled");
    let enumeration = self
      .scopes
      .values()
      .filter(|scope| {
        origin.is_none_or(|origin| scope.origin == *origin)
          && partition.is_none_or(|partition| scope.partition == partition)
          && host.is_none_or(|host| scope.origin.host == crate::routes::normalize_host(host))
          && scheme.is_none_or(|scheme| scope.origin.scheme == scheme)
      })
      .try_fold(0usize, |count, scope| {
        count
          .checked_add(scope.entries.len())
          .ok_or_else(|| anyhow::anyhow!("cache group entry index bound exceeded"))
      })?;
    ensure!(
      enumeration <= MAX_ENTRIES,
      "cache group aggregate entry index bound exceeded"
    );
    let mut count = 0usize;
    for scope in self.scopes.values_mut().filter(|scope| {
      origin.is_none_or(|origin| scope.origin == *origin)
        && partition.is_none_or(|partition| scope.partition == partition)
        && host.is_none_or(|host| scope.origin.host == crate::routes::normalize_host(host))
        && scheme.is_none_or(|scheme| scope.origin.scheme == scheme)
    }) {
      count = count.saturating_add(scope.invalidate(selector, explicit, now_ms)?);
    }
    Ok(count)
  }

  fn validate(&self) -> Result<()> {
    ensure!(
      self.version == 1 && valid_digest(&self.incarnation),
      "invalid cache group state version"
    );
    ensure!(
      self.scopes.len() <= MAX_SCOPES,
      "cache group scope bound exceeded"
    );
    for (key, scope) in &self.scopes {
      ensure!(
        *key == scope_key(&scope.origin, &scope.partition),
        "cache group scope identity mismatch"
      );
      scope.validate()?;
    }
    Ok(())
  }
}

impl Scope {
  fn validate(&self) -> Result<()> {
    ensure!(
      self.floor <= self.sequence,
      "invalid cache group sequence floor"
    );
    ensure!(
      self.partition.len() <= MAX_STRING_BYTES
        && CacheGroupOrigin::new(&self.origin.scheme, &self.origin.authority())
          .ok()
          .as_ref()
          == Some(&self.origin),
      "invalid cache group scope origin"
    );
    ensure!(
      self.groups.len() <= MAX_NAMES
        && self.targets.len() <= MAX_NAMES
        && self.paths.len() <= MAX_NAMES
        && self.prefixes.len() <= MAX_NAMES
        && self.tags.len() <= MAX_NAMES
        && self.entries.len() <= MAX_ENTRIES,
      "cache group state cardinality exceeded"
    );
    ensure!(
      self
        .groups
        .keys()
        .chain(self.targets.keys())
        .chain(self.paths.keys())
        .chain(self.tags.keys())
        .all(|key| valid_digest(key)),
      "invalid cache group state hash"
    );
    ensure!(
      self.prefixes.keys().all(|prefix| valid_path(prefix)),
      "invalid cache group prefix"
    );
    ensure!(
      self
        .groups
        .values()
        .chain(self.targets.values())
        .chain(self.paths.values())
        .chain(self.prefixes.values())
        .chain(self.tags.values())
        .all(|seq| *seq <= self.sequence),
      "cache group state has a future generation"
    );
    ensure!(
      self
        .entries
        .iter()
        .all(|(variant, seed)| variant.len() <= MAX_STRING_BYTES && seed.valid(self.sequence)),
      "invalid cache group state seed"
    );
    Ok(())
  }

  fn current(
    &self,
    sequence: u64,
    target: &str,
    groups: &[String],
    tags: &[String],
    equivalent_path: Option<&str>,
  ) -> bool {
    sequence >= self.floor
      && sequence <= self.sequence
      && self
        .targets
        .get(&digest(target.as_bytes()))
        .is_none_or(|last| *last <= sequence)
      && equivalent_path.is_none_or(|path| {
        self
          .paths
          .get(&digest(path.as_bytes()))
          .is_none_or(|last| *last <= sequence)
      })
      && groups.iter().all(|g| {
        self
          .groups
          .get(&digest(g.as_bytes()))
          .is_none_or(|last| *last <= sequence)
      })
      && tags.iter().all(|tag| {
        self
          .tags
          .get(&digest(tag.as_bytes()))
          .is_none_or(|last| *last <= sequence)
      })
      && self.prefixes.iter().all(|(prefix, last)| {
        *last <= sequence
          || !target
            .parse::<http::Uri>()
            .ok()
            .is_some_and(|uri| uri.path().starts_with(prefix))
      })
  }

  fn invalidate(&mut self, selector: &Selector, explicit: &[String], now_ms: u64) -> Result<usize> {
    let sequence = self
      .sequence
      .checked_add(1)
      .ok_or_else(|| anyhow::anyhow!("cache group sequence exhausted"))?;
    let mut groups = explicit.iter().cloned().collect::<BTreeSet<_>>();
    if let Selector::Groups(selected) = selector {
      groups.extend(selected.iter().cloned());
    } else {
      // Only the directly selected seed set contributes memberships. Never cascade.
      for seed in self.entries.values().filter(|seed| {
        seed.expires_ms > now_ms
          && self.current(
            seed.sequence,
            &seed.target,
            &seed.groups,
            &seed.tags,
            seed.equivalent_path.as_deref(),
          )
          && selector.selects(seed)
      }) {
        groups.extend(seed.groups.iter().cloned());
      }
    }
    let count = self
      .entries
      .values()
      .filter(|seed| {
        seed.expires_ms > now_ms
          && self.current(
            seed.sequence,
            &seed.target,
            &seed.groups,
            &seed.tags,
            seed.equivalent_path.as_deref(),
          )
          && (selector.selects(seed) || seed.groups.iter().any(|g| groups.contains(g)))
      })
      .count();
    match selector {
      Selector::Exact(target) => {
        self.targets.insert(digest(target.as_bytes()), sequence);
        if let Some(path) = target_path(target) {
          self.paths.insert(digest(path.as_bytes()), sequence);
        }
      }
      Selector::Prefix(prefix) => {
        self.prefixes.insert(prefix.clone(), sequence);
      }
      Selector::Tag(tag) => {
        self.tags.insert(digest(tag.as_bytes()), sequence);
      }
      Selector::Groups(_) => {}
    }
    for group in groups {
      self.groups.insert(digest(group.as_bytes()), sequence);
    }
    self.sequence = sequence;
    if self.validate().is_err() {
      bail!("cache group invalidation state exhausted");
    }
    self.entries.retain(|_, seed| seed.expires_ms > now_ms);
    Ok(count)
  }
}

impl Seed {
  fn valid(&self, scope_sequence: u64) -> bool {
    self.target.len() <= MAX_STRING_BYTES
      && self.groups.len() <= MAX_GROUP_MEMBERS
      && valid_group_names(&self.groups)
      && self.tags.len() <= MAX_NAMES
      && valid_names(&self.tags)
      && self.sequence <= scope_sequence
      && valid_digest(&self.publication)
      && self.equivalent_path.as_deref().is_none_or(valid_path)
  }
}

fn default_enabled() -> bool {
  true
}

fn valid_digest(value: &str) -> bool {
  value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_group_names(values: &[String]) -> bool {
  values
    .iter()
    .all(|value| value.len() <= 256 && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)))
}

fn valid_names(values: &[String]) -> bool {
  values.iter().all(|value| value.len() <= MAX_STRING_BYTES)
}

fn valid_path(path: &str) -> bool {
  path.len() <= MAX_STRING_BYTES
    && path.starts_with('/')
    && !path.contains('?')
    && !path.contains('#')
}

fn target_path(target: &str) -> Option<String> {
  target
    .parse::<http::Uri>()
    .ok()
    .map(|uri| uri.path().to_string())
    .filter(|path| path.starts_with('/'))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn origin() -> CacheGroupOrigin {
    CacheGroupOrigin::new("https", "cache.example.test").unwrap()
  }

  fn stamp(
    authority: &mut Authority,
    target: &str,
    groups: &[&str],
    equivalent_path: Option<&str>,
  ) -> CacheGroupStamp {
    let origin = origin();
    let mut stamp = authority.snapshot("default", &origin, "").unwrap();
    stamp.target = target.to_string();
    stamp.groups = groups.iter().map(|group| (*group).to_string()).collect();
    stamp.equivalent_path = equivalent_path.map(str::to_string);
    stamp
  }

  fn publish(authority: &mut Authority, stamp: &CacheGroupStamp, variant: &str) {
    authority
      .publish(stamp, variant, 100, 0, &"b".repeat(64))
      .unwrap();
  }

  #[test]
  fn exact_invalidation_stops_after_one_membership_hop() {
    let mut authority = Authority::new("a".repeat(64));
    let first = stamp(&mut authority, "/one", &["first"], None);
    let second = stamp(&mut authority, "/two", &["first", "second"], None);
    let third = stamp(&mut authority, "/three", &["second"], None);
    publish(&mut authority, &first, "first");
    publish(&mut authority, &second, "second");
    publish(&mut authority, &third, "third");

    assert_eq!(
      authority
        .invalidate(
          None,
          None,
          None,
          None,
          &Selector::Exact("/one".to_string()),
          &[],
          0
        )
        .unwrap(),
      2
    );
    assert!(!authority.current(&first));
    assert!(!authority.current(&second));
    assert!(authority.current(&third));
  }

  #[test]
  fn failed_publication_rollback_cannot_seed_later_expansion() {
    let mut authority = Authority::new("a".repeat(64));
    let owner = stamp(&mut authority, "/owner", &["linked"], None);
    let publication = "b".repeat(64);
    let previous = authority
      .publish(&owner, "owner-variant", 100, 0, &publication)
      .unwrap();
    authority
      .rollback_publish(&owner, "owner-variant", &publication, previous)
      .unwrap();

    let member = stamp(&mut authority, "/member", &["linked"], None);
    publish(&mut authority, &member, "member-variant");
    authority
      .invalidate(
        Some(&origin()),
        Some(""),
        None,
        None,
        &Selector::Exact("/owner".to_string()),
        &[],
        1,
      )
      .unwrap();
    assert!(authority.current(&member));
  }

  #[test]
  fn exact_invalidation_matches_only_nvs_seeds_by_equivalent_path() {
    let mut authority = Authority::new("a".repeat(64));
    let first = stamp(&mut authority, "/item?old", &[], Some("/item"));
    let second = stamp(&mut authority, "/item?new", &[], Some("/item"));
    let plain = stamp(&mut authority, "/item?plain", &[], None);
    publish(&mut authority, &first, "first");
    publish(&mut authority, &second, "second");
    publish(&mut authority, &plain, "plain");

    assert_eq!(
      authority
        .invalidate(
          None,
          None,
          None,
          None,
          &Selector::Exact("/item?mutate".to_string()),
          &[],
          0
        )
        .unwrap(),
      2
    );
    assert!(!authority.current(&first));
    assert!(!authority.current(&second));
    assert!(authority.current(&plain));
  }

  #[test]
  fn equivalent_path_selection_unions_old_and_new_nvs_memberships() {
    let mut authority = Authority::new("a".repeat(64));
    let old = stamp(&mut authority, "/item?old", &["old"], Some("/item"));
    let new = stamp(&mut authority, "/item?new", &["new"], Some("/item"));
    let old_member = stamp(&mut authority, "/old-member", &["old"], None);
    let new_member = stamp(&mut authority, "/new-member", &["new"], None);
    publish(&mut authority, &old, "old");
    publish(&mut authority, &new, "new");
    publish(&mut authority, &old_member, "old-member");
    publish(&mut authority, &new_member, "new-member");

    assert_eq!(
      authority
        .invalidate(
          None,
          None,
          None,
          None,
          &Selector::Exact("/item?mutate".to_string()),
          &[],
          0
        )
        .unwrap(),
      4
    );
    assert!(!authority.current(&old));
    assert!(!authority.current(&new));
    assert!(!authority.current(&old_member));
    assert!(!authority.current(&new_member));
  }

  #[test]
  fn older_state_without_enabled_decodes_as_enabled() {
    let state = Authority::new("a".repeat(64));
    let mut encoded = serde_json::to_value(&state).unwrap();
    encoded.as_object_mut().unwrap().remove("enabled");
    let decoded = Authority::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(decoded.enabled);
  }
}
