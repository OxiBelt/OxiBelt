use std::path::PathBuf;

use tempfile::tempdir;

use super::*;

fn dictionary(name: &str) -> DictionaryConfig {
  DictionaryConfig {
    name: name.to_owned(),
    path: PathBuf::from("dictionary.bin"),
    sha256: "00".repeat(32),
    public: true,
    url: Url::parse("https://example.test/assets/dictionary.bin").unwrap(),
  }
}

fn profile() -> CompressionDictionaryProfileConfig {
  CompressionDictionaryProfileConfig {
    name: "default".to_owned(),
    downstream: true,
    upstream: false,
    learn: false,
    request_decode: false,
    prefetch: None,
    advertise: None,
    dictionaries: vec!["site".to_owned()],
    store: "local".to_owned(),
    max_dictionary_bytes: 1_024,
    max_dictionaries: 1,
    max_total_dictionary_bytes: 1_024,
    max_pending_dictionary_bytes: 1_024,
    max_codec_concurrency: 1,
    max_codec_memory_bytes: crate::compression_dictionary::codec::maximum_working_set_bytes(),
    max_decoded_size_bytes: 1_024,
    max_expansion_ratio: 1,
    codec_timeout_ms: 1,
  }
}

fn memory_store() -> CompressionDictionaryStoreConfig {
  CompressionDictionaryStoreConfig {
    name: "local".to_owned(),
    kind: CompressionDictionaryStoreKind::Memory,
    quota_bytes: 1_024,
    disk: None,
    shared: None,
    external: None,
  }
}

fn config() -> CompressionDictionaryConfig {
  CompressionDictionaryConfig {
    enabled: true,
    dictionaries: vec![dictionary("site")],
    stores: vec![memory_store()],
    profiles: vec![profile()],
  }
}

fn loadable_config_toml(dictionary_path: &str, digest: &str) -> String {
  format!(
    r#"
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = "auto"

[runtime.accept]
workers = "auto"
reuse_port = true
backlog = 8192
accept_error_backoff_ms = 10

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "cert.pem"
private_key = "key.pem"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

[proxy.forwarded_headers]
mode = "overwrite"
client_ip_source = "resolved"

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"

[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = false
websocket = true
webrtc = true
webtransport = true

[[routes]]
name = "app-root"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"

[compression_dictionary]
enabled = true

[[compression_dictionary.dictionaries]]
name = "site"
path = "{dictionary_path}"
sha256 = "{digest}"
public = true
url = "https://example.test/assets/dictionary.bin"

[[compression_dictionary.stores]]
name = "local"
kind = "memory"
quota_bytes = 1024

[[compression_dictionary.profiles]]
name = "default"
downstream = true
upstream = false
learn = false
request_decode = false
dictionaries = ["site"]
store = "local"
max_dictionary_bytes = 1024
max_dictionaries = 1
max_total_dictionary_bytes = 1024
max_pending_dictionary_bytes = 1024
max_codec_concurrency = 1
max_codec_memory_bytes = {}
max_decoded_size_bytes = 1024
max_expansion_ratio = 1
codec_timeout_ms = 1
"#,
    crate::compression_dictionary::codec::maximum_working_set_bytes(),
  )
}

#[test]
fn defaults_disable_dictionary_transport() {
  assert_eq!(
    CompressionDictionaryConfig::default(),
    CompressionDictionaryConfig {
      enabled: false,
      dictionaries: Vec::new(),
      stores: Vec::new(),
      profiles: Vec::new(),
    }
  );
}

#[test]
fn enabled_configuration_requires_finite_limits() {
  let mut config = config();
  config.profiles[0].max_codec_memory_bytes = 0;
  assert!(
    validate_compression_dictionary(
      &config,
      &SharedStateConfig::default(),
      &CacheConfig::default(),
    )
    .is_err()
  );
}

#[test]
fn profile_rejects_unknown_dictionary_and_store() {
  let mut dictionary_config = config();
  dictionary_config.profiles[0].dictionaries = vec!["missing".to_owned()];
  assert!(
    validate_compression_dictionary(
      &dictionary_config,
      &SharedStateConfig::default(),
      &CacheConfig::default(),
    )
    .is_err()
  );

  let mut config = config();
  config.profiles[0].store = "missing".to_owned();
  assert!(
    validate_compression_dictionary(
      &config,
      &SharedStateConfig::default(),
      &CacheConfig::default(),
    )
    .is_err()
  );
}

#[test]
fn advertisement_rejects_regular_expression_groups() {
  let mut config = config();
  config.profiles[0].advertise = Some(DictionaryAdvertisementConfig {
    r#match: "/assets/:name(.*)".to_owned(),
    id: String::new(),
    match_dest: Vec::new(),
  });
  assert!(
    validate_compression_dictionary(
      &config,
      &SharedStateConfig::default(),
      &CacheConfig::default(),
    )
    .is_err()
  );
}

#[test]
fn path_resolution_verifies_dictionary_digest() {
  let directory = tempdir().unwrap();
  let path = directory.path().join("dictionary.bin");
  std::fs::write(&path, b"dictionary content").unwrap();
  let mut config = config();
  config.dictionaries[0].sha256 = hex_digest(&Sha256::digest(b"dictionary content"));
  let mut sources = ConfigSourcePaths::default();
  resolve_compression_dictionary_paths(&mut config, directory.path(), &mut sources).unwrap();
  assert_eq!(config.dictionaries[0].path, path.canonicalize().unwrap());
  assert_eq!(sources.runtime_files, vec![path]);
  validate_compression_dictionary(
    &config,
    &SharedStateConfig::default(),
    &CacheConfig::default(),
  )
  .unwrap();
}

#[test]
fn path_resolution_rejects_changed_dictionary_content() {
  let directory = tempdir().unwrap();
  std::fs::write(directory.path().join("dictionary.bin"), b"changed").unwrap();
  let mut config = config();
  let mut sources = ConfigSourcePaths::default();
  assert!(
    resolve_compression_dictionary_paths(&mut config, directory.path(), &mut sources).is_err()
  );
}

#[test]
fn config_load_resolves_relative_dictionary_path_and_revalidates_snapshot() {
  let root = tempdir().unwrap();
  let config_dir = root.path().join("config");
  let cert_dir = root.path().join("cert");
  std::fs::create_dir_all(&config_dir).unwrap();
  std::fs::create_dir_all(&cert_dir).unwrap();
  std::fs::write(cert_dir.join("cert.pem"), b"certificate").unwrap();
  std::fs::write(cert_dir.join("key.pem"), b"private key").unwrap();
  let dictionary_path = config_dir.join("dictionary.bin");
  let dictionary = b"dictionary content";
  std::fs::write(&dictionary_path, dictionary).unwrap();
  let digest = hex_digest(&Sha256::digest(dictionary));
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    loadable_config_toml("dictionary.bin", &digest),
  )
  .unwrap();

  let config = crate::config::Config::load(&config_path).unwrap();
  assert_eq!(
    config.compression_dictionary.dictionaries[0].path,
    dictionary_path.canonicalize().unwrap()
  );
  assert!(config.source_paths.runtime_files.contains(&dictionary_path));
  config.validate().unwrap();
}

#[test]
fn config_load_rejects_absolute_dictionary_path_before_resolution() {
  let root = tempdir().unwrap();
  let config_dir = root.path().join("config");
  let cert_dir = root.path().join("cert");
  std::fs::create_dir_all(&config_dir).unwrap();
  std::fs::create_dir_all(&cert_dir).unwrap();
  std::fs::write(cert_dir.join("cert.pem"), b"certificate").unwrap();
  std::fs::write(cert_dir.join("key.pem"), b"private key").unwrap();
  let dictionary_path = config_dir.join("dictionary.bin");
  let dictionary = b"dictionary content";
  std::fs::write(&dictionary_path, dictionary).unwrap();
  let digest = hex_digest(&Sha256::digest(dictionary));
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    loadable_config_toml(dictionary_path.to_str().unwrap(), &digest),
  )
  .unwrap();

  let error = crate::config::Config::load(&config_path).unwrap_err();
  assert!(
    error.to_string().contains("must be a relative path"),
    "unexpected error: {error:#}"
  );
}
