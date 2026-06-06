use super::*;

#[test]
fn prefix_asn_csv_parses_comments_headers_and_as_prefixes() {
  let database = parse_prefix_asn_csv(
    r#"
# comment
prefix,asn
203.0.113.0/24,AS64500
203.0.113.128/25,64501
2001:db8::/32,AS64502
"#,
    16,
    None,
  )
  .unwrap();

  assert_eq!(
    "203.0.113.20"
      .parse::<IpAddr>()
      .ok()
      .and_then(|ip| database.lookup(ip)),
    Some(64500)
  );
  assert_eq!(
    "203.0.113.200"
      .parse::<IpAddr>()
      .ok()
      .and_then(|ip| database.lookup(ip)),
    Some(64501)
  );
  assert_eq!(
    "2001:db8::1"
      .parse::<IpAddr>()
      .ok()
      .and_then(|ip| database.lookup(ip)),
    Some(64502)
  );
}

#[test]
fn prefix_asn_csv_canonicalizes_networks() {
  let database =
    parse_prefix_asn_csv("203.0.113.77/24,64500\n2001:db8:1::99/48,64501\n", 16, None).unwrap();

  assert_eq!(database.lookup("203.0.113.1".parse().unwrap()), Some(64500));
  assert_eq!(
    database.lookup("2001:db8:1::1".parse().unwrap()),
    Some(64501)
  );
}

#[test]
fn prefix_asn_csv_rejects_invalid_asn_and_prefix() {
  assert!(parse_prefix_asn_csv("203.0.113.0/33,64500\n", 16, None).is_err());
  assert!(parse_prefix_asn_csv("203.0.113.0/24,not-asn\n", 16, None).is_err());
}

#[test]
fn prefix_asn_csv_enforces_max_entries() {
  assert!(parse_prefix_asn_csv("203.0.113.0/24,64500\n203.0.114.0/24,64501\n", 1, None).is_err());
}

#[test]
fn stale_cache_uses_configured_max_age() {
  assert!(!cache_is_stale(unix_now(), 60));
  assert!(cache_is_stale(unix_now().saturating_sub(120), 60));
}
