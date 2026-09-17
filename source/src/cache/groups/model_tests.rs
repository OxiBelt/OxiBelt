use super::CacheGroupOrigin;
use super::model::{
  Authority, CacheGroupStamp, LEGACY_AUTHORITY_VERSION, Selector, canonical_target,
};

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
fn canonical_target_preserves_path_query_bytes_and_removes_the_origin() {
  for uri in [
    "/resource?a=1&a=2&encoded=%2F",
    "https://cache.example.test/resource?a=1&a=2&encoded=%2F",
  ] {
    assert_eq!(
      canonical_target(&uri.parse().unwrap()).unwrap(),
      "/resource?a=1&a=2&encoded=%2F"
    );
  }
  assert_eq!(
    canonical_target(&"https://cache.example.test".parse().unwrap()).unwrap(),
    "/"
  );
  assert_eq!(
    canonical_target(&"cache.example.test:443".parse().unwrap()).unwrap(),
    "/"
  );
  // `http::Uri` classifies a pathless token as authority-form as well.
  assert_eq!(canonical_target(&"relative".parse().unwrap()).unwrap(), "/");
  assert!(canonical_target(&"*".parse().unwrap()).is_err());
}

#[test]
fn noncanonical_stamp_seed_and_exact_selector_are_rejected() {
  let mut authority = Authority::new("a".repeat(64));
  let absolute = stamp(
    &mut authority,
    "https://cache.example.test/resource",
    &[],
    None,
  );
  assert!(!absolute.valid());
  assert!(
    authority
      .publish(&absolute, "absolute", 100, 0, &"b".repeat(64))
      .is_err()
  );
  assert!(
    authority
      .invalidate(
        None,
        None,
        None,
        None,
        &Selector::Exact("https://cache.example.test/resource".to_string()),
        &[],
        0,
      )
      .is_err()
  );
}

#[test]
fn legacy_v1_state_is_accepted_only_by_the_activation_decoder() {
  let mut authority = Authority::new("a".repeat(64));
  let current = stamp(&mut authority, "/resource", &[], None);
  publish(&mut authority, &current, "variant");
  authority.version = LEGACY_AUTHORITY_VERSION;
  authority
    .scopes
    .values_mut()
    .flat_map(|scope| scope.entries.values_mut())
    .for_each(|seed| seed.target = "https://cache.example.test/resource".to_string());
  let bytes = serde_json::to_vec(&authority).unwrap();

  assert!(Authority::decode(&bytes).is_err());
  assert_eq!(
    Authority::decode_legacy_v1(&bytes).unwrap().version,
    LEGACY_AUTHORITY_VERSION
  );
  assert!(Authority::decode_legacy_v1(&Authority::new("b".repeat(64)).encode().unwrap()).is_err());
}

#[test]
fn older_state_without_enabled_decodes_as_enabled() {
  let state = Authority::new("a".repeat(64));
  let mut encoded = serde_json::to_value(&state).unwrap();
  encoded.as_object_mut().unwrap().remove("enabled");
  let decoded = Authority::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
  assert!(decoded.enabled);
}
