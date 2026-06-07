use super::*;
use std::path::{Path, PathBuf};

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

#[test]
fn managed_cache_rejects_when_config_sha256_mismatches() {
  let temp_dir = tempfile::tempdir().expect("tempdir");
  let database = b"203.0.113.0/24,64599\n";
  write_managed_cache(temp_dir.path(), database, unix_now());
  let config = managed_disk_config(
    temp_dir.path().to_path_buf(),
    Some(sha256_hex(b"203.0.113.0/24,64500\n")),
    60,
  );

  let error = load_cached_database(&config).expect_err("mismatched configured pin should reject");

  assert!(
    format!("{error:#}").contains("asn_database_sha256_mismatch"),
    "unexpected error: {error:#}"
  );
}

#[tokio::test]
async fn managed_cache_fresh_entry_does_not_parse_when_config_sha256_mismatches() {
  let temp_dir = tempfile::tempdir().expect("tempdir");
  let database = b"203.0.113.0/24,64599\n";
  write_managed_cache(temp_dir.path(), database, unix_now());
  let config = managed_disk_config(
    temp_dir.path().to_path_buf(),
    Some(sha256_hex(b"203.0.113.0/24,64500\n")),
    60,
  );
  let control_http = ControlHttpClient::new(&[]).expect("control HTTP client should build");

  let result = load_or_fetch_managed_database(&config, &control_http, None).await;

  assert!(
    result.is_err(),
    "fresh cache with mismatched configured pin should not load"
  );
}

#[tokio::test]
async fn managed_cache_stale_fallback_does_not_parse_when_config_sha256_mismatches() {
  let temp_dir = tempfile::tempdir().expect("tempdir");
  let database = b"203.0.113.0/24,64599\n";
  write_managed_cache(temp_dir.path(), database, unix_now().saturating_sub(120));
  let config = managed_disk_config(
    temp_dir.path().to_path_buf(),
    Some(sha256_hex(b"203.0.113.0/24,64500\n")),
    60,
  );
  let control_http = ControlHttpClient::new(&[]).expect("control HTTP client should build");

  let result = load_or_fetch_managed_database(&config, &control_http, None).await;

  assert!(
    result.is_err(),
    "stale cache with mismatched configured pin should not load as fallback"
  );
}

#[tokio::test]
async fn managed_cache_accepts_matching_config_sha256() {
  let temp_dir = tempfile::tempdir().expect("tempdir");
  let database = b"203.0.113.0/24,64500\n";
  write_managed_cache(temp_dir.path(), database, unix_now());
  let config = managed_disk_config(
    temp_dir.path().to_path_buf(),
    Some(sha256_hex(database)),
    60,
  );
  let control_http = ControlHttpClient::new(&[]).expect("control HTTP client should build");

  let loaded = load_or_fetch_managed_database(&config, &control_http, None)
    .await
    .expect("matching configured pin should accept fresh cache");

  assert_eq!(
    loaded.database.lookup("203.0.113.42".parse().unwrap()),
    Some(64500)
  );
  assert!(loaded.cache_present);
  assert!(loaded.cache_fresh);
  assert!(!loaded.database_stale);
}

fn managed_disk_config(
  cache_dir: PathBuf,
  database_sha256: Option<String>,
  max_database_age_seconds: u64,
) -> ClientIdentityAsnConfig {
  ClientIdentityAsnConfig {
    mode: ClientIdentityAsnMode::Managed,
    database_sha256,
    max_database_bytes: 4096,
    max_database_age_seconds,
    managed: crate::config::ClientIdentityAsnManagedConfig {
      cache_dir,
      storage: ClientIdentityAsnManagedStorage::Disk,
      max_cache_bytes: 8192,
      request_timeout_ms: 1,
      source_url: Some("http://127.0.0.1/asn-prefixes.csv".to_string()),
      ..Default::default()
    },
    ..Default::default()
  }
}

fn write_managed_cache(cache_dir: &Path, database: &[u8], fetched_at: u64) {
  fs::create_dir_all(cache_dir).expect("cache dir should be created");
  fs::write(cache_dir.join(DATABASE_CACHE_FILE), database).expect("database cache should write");
  let metadata = CacheMetadata {
    sha256: sha256_hex(database),
    size: database.len(),
    fetched_at,
  };
  fs::write(
    cache_dir.join(METADATA_CACHE_FILE),
    serde_json::to_vec(&metadata).expect("metadata should encode"),
  )
  .expect("metadata cache should write");
}
