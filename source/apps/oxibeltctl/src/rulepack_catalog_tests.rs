use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use clap::Parser;
use sha2::{Digest, Sha256};
use url::Url;

use super::*;
use crate::cli::{Cli, RulepackRepoSubcommand};
use crate::rulepack_catalog_index::{compare_versions, load_repo_catalog, parse_catalog_bytes};
use crate::rulepack_catalog_registry::{
  RulepackRepoRegistry, load_registry_from_path, save_registry_to_path,
};
use crate::test_support;

#[test]
fn catalog_parses_toml_and_compares_versions() {
  let entries = parse_catalog_bytes(
    br#"[index]
schema_version = 1
generated_at = "2026-06-14T00:00:00Z"

[[rulepacks]]
name = "vaultwarden-hardening"
version = "0.3.0"
targets = ["vaultwarden"]
source = "https://packs.example.test/vaultwarden/0.3.0/rulepack.oxirule-rulepack.toml"
sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
signature_type = "openpgp"
signature = "https://packs.example.test/vaultwarden/0.3.0/rulepack.sig"
min_oxibelt_version = "0.0.0"
license = "Apache-2.0"
maintainers = ["example-security"]
description = "Vaultwarden hardening"
"#,
    "test catalog",
    false,
  )
  .expect("catalog should parse");

  assert_eq!(entries.len(), 1);
  assert_eq!(entries[0].name, "vaultwarden-hardening");
  assert_eq!(
    is_compatible(&entries[0]),
    oxibelt_build_identity::current()
      .compatibility_version()
      .is_some()
  );
  assert_eq!(
    compare_versions("0.10.0", "0.9.9"),
    std::cmp::Ordering::Greater
  );
}

#[test]
fn catalog_rejects_missing_sha_unsupported_signature_and_duplicates() {
  let missing_sha = parse_catalog_bytes(
    br#"[index]
schema_version = 1

[[rulepacks]]
name = "demo"
version = "0.1.0"
source = "https://packs.example.test/demo.oxirule-rulepack.toml"
"#,
    "missing sha catalog",
    false,
  )
  .expect_err("sha256 should be required");
  assert!(format!("{missing_sha:#}").contains("sha256"));

  let unsupported_signature = parse_catalog_bytes(
    br#"[index]
schema_version = 1

[[rulepacks]]
name = "demo"
version = "0.1.0"
source = "https://packs.example.test/demo.oxirule-rulepack.toml"
sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
signature_type = "sigstore"
"#,
    "sigstore catalog",
    false,
  )
  .expect_err("Sigstore is future work");
  assert!(
    unsupported_signature
      .to_string()
      .contains("unsupported signature_type")
  );

  let duplicate = parse_catalog_bytes(
    br#"[index]
schema_version = 1

[[rulepacks]]
name = "demo"
version = "0.1.0"
source = "https://packs.example.test/demo.oxirule-rulepack.toml"
sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[rulepacks]]
name = "demo"
version = "0.1.0"
source = "https://packs.example.test/demo-again.oxirule-rulepack.toml"
sha256 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#,
    "duplicate catalog",
    false,
  )
  .expect_err("duplicate entries should fail");
  assert!(duplicate.to_string().contains("duplicate rulepack entry"));

  let invalid_minimum = parse_catalog_bytes(
    br#"[index]
schema_version = 1

[[rulepacks]]
name = "demo"
version = "0.1.0"
source = "https://packs.example.test/demo.oxirule-rulepack.toml"
sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
min_oxibelt_version = "1.02.3"
"#,
    "invalid minimum catalog",
    false,
  )
  .expect_err("catalog minimums must use strict SemVer");
  assert!(invalid_minimum.to_string().contains("strict SemVer"));
}

#[test]
fn catalog_rejects_schema_v1_rulepack_and_legacy_discovery_after_resolution() {
  let legacy = r#"[rulepack]
schema_version = 1
name = "legacy"
version = "0.1.0"

[[rules]]
name = "legacy-rule"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;
  let discovery = r#"[rulepack]
schema_version = 2
name = "legacy-discovery"
version = "0.1.0"

[[variables]]
name = "route_name"
type = "string"
required = true

[variables.discovery]
name_any = ["vault"]

[[rules]]
name = "legacy-rule"
phase = "request"
priority = 100
content = "when = \"Context.RouteName == '{{route_name}}'\"\n"
"#;

  for raw in [legacy, discovery] {
    let error = oxibelt::waf::inspect_rulepack_inputs(raw, "catalog-loaded rulepack")
      .expect_err("legacy rulepack shape should fail");
    let rendered = format!("{error:#}");
    assert!(
      rendered.contains("only schema_version 2") || rendered.contains("[variables.discovery]"),
      "unexpected error: {rendered}"
    );
  }
}

#[test]
fn rulepack_catalog_cli_parses_repo_search_info_install_and_update() {
  let repo_add = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "repo",
    "add",
    "official",
    "https://packs.example.test/index.toml",
    "--rulepack-token-env",
    "OXIBELT_RULEPACK_TOKEN",
    "--rulepack-openpgp-keyring",
    "trusted-publishers",
  ])
  .expect("repo add should parse");
  let Command::Rulepack(command) = repo_add.command else {
    panic!("expected rulepack command");
  };
  let RulepackSubcommand::Repo(repo) = command.command else {
    panic!("expected repo command");
  };
  let RulepackRepoSubcommand::Add(add) = repo.command else {
    panic!("expected repo add");
  };
  assert_eq!(add.name, "official");
  assert_eq!(add.token_env.as_deref(), Some("OXIBELT_RULEPACK_TOKEN"));
  assert_eq!(
    add.openpgp_keyring_dirs,
    vec![PathBuf::from("trusted-publishers")]
  );

  for args in [
    ["oxibeltctl", "rulepack", "search", "vaultwarden"].as_slice(),
    [
      "oxibeltctl",
      "rulepack",
      "info",
      "vaultwarden-hardening",
      "--version",
      "0.3.0",
    ]
    .as_slice(),
    [
      "oxibeltctl",
      "rulepack",
      "install",
      "vaultwarden-hardening",
      "--version",
      "0.3.0",
      "--interactive",
      "--dry-run",
      "--bind",
      "app_route=mmsecretvault",
    ]
    .as_slice(),
    ["oxibeltctl", "rulepack", "update", "--plan"].as_slice(),
  ] {
    Cli::try_parse_from(args).expect("catalog command should parse");
  }
}

#[test]
fn registry_writes_user_private_toml_and_never_stores_token_values() {
  let dir = tempfile::tempdir().expect("temp dir");
  let path = dir.path().join("repos.toml");
  let registry = RulepackRepoRegistry {
    repos: BTreeMap::from([(
      "official".to_string(),
      RulepackRepoConfig {
        url: Url::parse("https://packs.example.test/index.toml").expect("url"),
        ca_certs: vec![PathBuf::from("ca.pem")],
        token_env: Some("OXIBELT_RULEPACK_TOKEN".to_string()),
        allow_insecure_rulepack_url: false,
        require_openpgp_signature: true,
        openpgp_key_files: vec![PathBuf::from("publisher.asc")],
        openpgp_keyring_dirs: vec![PathBuf::from("trusted")],
        openpgp_fingerprints: vec!["0123456789abcdef0123456789abcdef01234567".to_string()],
      },
    )]),
  };

  save_registry_to_path(&path, &registry).expect("registry write");
  let raw = std::fs::read_to_string(&path).expect("registry content");

  assert!(raw.contains("token_env = \"OXIBELT_RULEPACK_TOKEN\""));
  assert!(!raw.contains("secret-token-value"));
  assert_eq!(
    load_registry_from_path(&path)
      .expect("registry read")
      .repos
      .len(),
    1
  );

  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(&path)
      .expect("metadata")
      .permissions()
      .mode()
      & 0o777;
    assert_eq!(mode, 0o600);
  }
}

#[test]
fn catalog_selection_resolves_entry_into_existing_url_source_options() {
  let selection = catalog_selection(
    "https://packs.example.test/index.toml",
    "https://packs.example.test/vaultwarden/0.3.0/rulepack.oxirule-rulepack.toml",
    "https://packs.example.test/vaultwarden/0.3.0/rulepack.sig",
  );
  let source = source_args_for_selection(&selection);

  assert_eq!(
    source.sha256.as_deref(),
    Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
  );
  assert_eq!(
    source.openpgp_signature_url.as_ref().map(Url::as_str),
    Some("https://packs.example.test/vaultwarden/0.3.0/rulepack.sig")
  );
  assert!(source.require_openpgp_signature);
  assert_eq!(source.token_env.as_deref(), Some("OXIBELT_RULEPACK_TOKEN"));
  assert_eq!(
    source.openpgp_key_files,
    vec![PathBuf::from("publisher.asc")]
  );
}

#[test]
fn catalog_selection_drops_repo_token_for_cross_origin_source() {
  let selection = catalog_selection(
    "https://packs.example.test/index.toml",
    "https://cdn.example.test/vaultwarden/0.3.0/rulepack.oxirule-rulepack.toml",
    "https://cdn.example.test/vaultwarden/0.3.0/rulepack.sig",
  );
  let source = source_args_for_selection(&selection);

  assert_eq!(source.token_env, None);
  assert_eq!(
    source.url.as_ref().map(Url::as_str),
    Some("https://cdn.example.test/vaultwarden/0.3.0/rulepack.oxirule-rulepack.toml")
  );
}

#[test]
fn catalog_http_install_source_uses_sha256_and_openpgp_verifier() {
  let signed = crate::rulepack_openpgp::test_signed_rulepack_fixture(
    br#"[rulepack]
schema_version = 2
name = "signed-catalog-demo"
version = "0.1.0"

[[rules]]
name = "log"
phase = "request"
priority = 100
content = '''
when = "true"

[[actions]]
type = "log"
'''
"#,
    "Rulepack Catalog <catalog@test>",
  );
  let Some((catalog_url, handle)) = catalog_http_server(&signed.rulepack, &signed.signature) else {
    return;
  };
  let repo = RulepackRepoConfig {
    url: catalog_url,
    ca_certs: Vec::new(),
    token_env: None,
    allow_insecure_rulepack_url: true,
    require_openpgp_signature: false,
    openpgp_key_files: vec![signed.key_file.clone()],
    openpgp_keyring_dirs: Vec::new(),
    openpgp_fingerprints: vec![signed.fingerprint.clone()],
  };
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let mut source = runtime.block_on(async {
    let catalog = load_repo_catalog("local", &repo, Duration::from_secs(2))
      .await
      .expect("catalog should load over HTTP");
    let selection = CatalogEntrySelection {
      repo: catalog.repo,
      repo_config: repo,
      entry: catalog.entries.into_iter().next().expect("catalog entry"),
    };
    let source = source_args_for_selection(&selection);
    let loaded = crate::rulepack::load_rulepack_source(&source, Duration::from_secs(2), true)
      .await
      .expect("catalog source should verify");
    let provenance = loaded.source_provenance.expect("URL provenance");
    assert_eq!(
      provenance.source_openpgp_signer_fingerprint,
      Some(signed.fingerprint)
    );
    source
  });

  source.sha256 = Some("f".repeat(64));
  let error = runtime
    .block_on(crate::rulepack::load_rulepack_source(
      &source,
      Duration::from_secs(2),
      true,
    ))
    .expect_err("catalog SHA-256 pin must feed URL verifier");
  assert!(error.to_string().contains("SHA-256 mismatch"));

  let requests = handle.join().expect("catalog server thread");
  assert!(
    requests
      .iter()
      .any(|request| request.starts_with("GET /index.toml ")),
    "catalog index was not requested: {requests:?}"
  );
  assert!(
    requests
      .iter()
      .any(|request| request.starts_with("GET /rulepack.sig ")),
    "OpenPGP signature was not requested: {requests:?}"
  );
}

#[test]
fn catalog_cross_origin_source_does_not_receive_repo_token() {
  const TOKEN_ENV: &str = "OXIBELT_TEST_RULEPACK_REPO_TOKEN";
  if test_support::run_test_in_subprocess_with_env(
    "rulepack_catalog::tests::catalog_cross_origin_source_does_not_receive_repo_token",
    &[(TOKEN_ENV, "repo-secret-token")],
  ) {
    return;
  }
  let signed = crate::rulepack_openpgp::test_signed_rulepack_fixture(
    br#"[rulepack]
schema_version = 2
name = "cross-origin-catalog-demo"
version = "0.1.0"

[[rules]]
name = "log"
phase = "request"
priority = 100
content = '''
when = "true"

[[actions]]
type = "log"
'''
"#,
    "Rulepack Catalog <catalog@test>",
  );
  let Some((source_url, signature_url, source_handle)) =
    rulepack_source_http_server(&signed.rulepack, &signed.signature)
  else {
    return;
  };
  let Some((catalog_url, catalog_handle)) =
    catalog_index_http_server(&source_url, &signature_url, &sha256_hex(&signed.rulepack))
  else {
    return;
  };
  let repo = RulepackRepoConfig {
    url: catalog_url,
    ca_certs: Vec::new(),
    token_env: Some(TOKEN_ENV.to_string()),
    allow_insecure_rulepack_url: true,
    require_openpgp_signature: false,
    openpgp_key_files: vec![signed.key_file.clone()],
    openpgp_keyring_dirs: Vec::new(),
    openpgp_fingerprints: vec![signed.fingerprint],
  };
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let load_result = runtime.block_on(async {
    let catalog = load_repo_catalog("local", &repo, Duration::from_secs(2)).await?;
    let selection = CatalogEntrySelection {
      repo: catalog.repo,
      repo_config: repo,
      entry: catalog.entries.into_iter().next().expect("catalog entry"),
    };
    let source = source_args_for_selection(&selection);
    crate::rulepack::load_rulepack_source(&source, Duration::from_secs(2), true).await?;
    Ok::<(), anyhow::Error>(())
  });
  load_result.expect("catalog source should verify");

  let catalog_requests = catalog_handle.join().expect("catalog server thread");
  let source_requests = source_handle.join().expect("source server thread");
  let catalog_request = catalog_requests
    .iter()
    .find(|request| request.starts_with("GET /index.toml "))
    .expect("catalog index request");
  assert!(
    catalog_request
      .lines()
      .any(|line| line.eq_ignore_ascii_case("authorization: Bearer repo-secret-token")),
    "expected catalog auth header, got:\n{catalog_request}"
  );

  let rulepack_request = source_requests
    .iter()
    .find(|request| request.starts_with("GET /rulepack.oxirule-rulepack.toml "))
    .expect("rulepack source request");
  assert_no_request_header(rulepack_request, "authorization");
  let signature_request = source_requests
    .iter()
    .find(|request| request.starts_with("GET /rulepack.sig "))
    .expect("signature source request");
  assert_no_request_header(signature_request, "authorization");
}

fn catalog_selection(
  catalog_url: &str,
  source_url: &str,
  signature_url: &str,
) -> CatalogEntrySelection {
  CatalogEntrySelection {
    repo: "official".to_string(),
    repo_config: RulepackRepoConfig {
      url: Url::parse(catalog_url).expect("catalog url"),
      ca_certs: Vec::new(),
      token_env: Some("OXIBELT_RULEPACK_TOKEN".to_string()),
      allow_insecure_rulepack_url: false,
      require_openpgp_signature: false,
      openpgp_key_files: vec![PathBuf::from("publisher.asc")],
      openpgp_keyring_dirs: vec![PathBuf::from("trusted")],
      openpgp_fingerprints: vec!["0123456789abcdef0123456789abcdef01234567".to_string()],
    },
    entry: CatalogRulepack {
      name: "vaultwarden-hardening".to_string(),
      version: "0.3.0".to_string(),
      targets: vec!["vaultwarden".to_string()],
      source: Url::parse(source_url).expect("rulepack url"),
      sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
      signature_type: Some("openpgp".to_string()),
      signature: Some(Url::parse(signature_url).expect("signature url")),
      min_oxibelt_version: Some("0.0.0".to_string()),
      license: Some("Apache-2.0".to_string()),
      maintainers: vec!["example-security".to_string()],
      description: Some("Vaultwarden hardening".to_string()),
    },
  }
}

fn catalog_http_server(
  rulepack: &[u8],
  signature: &[u8],
) -> Option<(Url, thread::JoinHandle<Vec<String>>)> {
  let listener = match TcpListener::bind("127.0.0.1:0") {
    Ok(listener) => listener,
    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
    Err(error) => panic!("catalog listener: {error}"),
  };
  let addr = listener.local_addr().expect("catalog listener address");
  let index = format!(
    r#"[index]
schema_version = 1

[[rulepacks]]
name = "signed-catalog-demo"
version = "0.1.0"
targets = ["demo"]
source = "http://{addr}/rulepack.oxirule-rulepack.toml"
sha256 = "{}"
signature_type = "openpgp"
signature = "http://{addr}/rulepack.sig"
min_oxibelt_version = "0.0.0"
"#,
    sha256_hex(rulepack)
  )
  .into_bytes();
  let rulepack = rulepack.to_vec();
  let signature = signature.to_vec();
  let handle = thread::spawn(move || {
    let mut requests = Vec::new();
    for _ in 0..4 {
      let (mut stream, _) = listener.accept().expect("catalog request");
      stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("catalog read timeout");
      let request = read_http_request(&mut stream);
      let (status, body): (&str, &[u8]) = if request.starts_with("GET /index.toml ") {
        ("200 OK", &index)
      } else if request.starts_with("GET /rulepack.oxirule-rulepack.toml ") {
        ("200 OK", &rulepack)
      } else if request.starts_with("GET /rulepack.sig ") {
        ("200 OK", &signature)
      } else {
        ("404 Not Found", b"not found")
      };
      let header = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
      );
      stream
        .write_all(header.as_bytes())
        .expect("catalog response header");
      stream.write_all(body).expect("catalog response body");
      requests.push(request);
    }
    requests
  });
  Some((
    Url::parse(&format!("http://{addr}/index.toml")).expect("catalog URL"),
    handle,
  ))
}

fn catalog_index_http_server(
  source_url: &Url,
  signature_url: &Url,
  sha256: &str,
) -> Option<(Url, thread::JoinHandle<Vec<String>>)> {
  let listener = match TcpListener::bind("127.0.0.1:0") {
    Ok(listener) => listener,
    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
    Err(error) => panic!("catalog listener: {error}"),
  };
  let addr = listener.local_addr().expect("catalog listener address");
  let index = format!(
    r#"[index]
schema_version = 1

[[rulepacks]]
name = "cross-origin-catalog-demo"
version = "0.1.0"
targets = ["demo"]
source = "{source_url}"
sha256 = "{sha256}"
signature_type = "openpgp"
signature = "{signature_url}"
min_oxibelt_version = "0.0.0"
"#
  )
  .into_bytes();
  let handle = thread::spawn(move || {
    let (mut stream, _) = listener.accept().expect("catalog request");
    stream
      .set_read_timeout(Some(Duration::from_secs(2)))
      .expect("catalog read timeout");
    let request = read_http_request(&mut stream);
    let header = format!(
      "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
      index.len()
    );
    stream
      .write_all(header.as_bytes())
      .expect("catalog response header");
    stream.write_all(&index).expect("catalog response body");
    vec![request]
  });
  Some((
    Url::parse(&format!("http://{addr}/index.toml")).expect("catalog URL"),
    handle,
  ))
}

fn rulepack_source_http_server(
  rulepack: &[u8],
  signature: &[u8],
) -> Option<(Url, Url, thread::JoinHandle<Vec<String>>)> {
  let listener = match TcpListener::bind("127.0.0.1:0") {
    Ok(listener) => listener,
    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
    Err(error) => panic!("source listener: {error}"),
  };
  let addr = listener.local_addr().expect("source listener address");
  let rulepack = rulepack.to_vec();
  let signature = signature.to_vec();
  let source_url =
    Url::parse(&format!("http://{addr}/rulepack.oxirule-rulepack.toml")).expect("source URL");
  let signature_url = Url::parse(&format!("http://{addr}/rulepack.sig")).expect("signature URL");
  let handle = thread::spawn(move || {
    let mut requests = Vec::new();
    for _ in 0..2 {
      let (mut stream, _) = listener.accept().expect("source request");
      stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("source read timeout");
      let request = read_http_request(&mut stream);
      let (status, body): (&str, &[u8]) =
        if request.starts_with("GET /rulepack.oxirule-rulepack.toml ") {
          ("200 OK", &rulepack)
        } else if request.starts_with("GET /rulepack.sig ") {
          ("200 OK", &signature)
        } else {
          ("404 Not Found", b"not found")
        };
      let header = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
      );
      stream
        .write_all(header.as_bytes())
        .expect("source response header");
      stream.write_all(body).expect("source response body");
      requests.push(request);
    }
    requests
  });
  Some((source_url, signature_url, handle))
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
  let mut request = Vec::new();
  let mut buffer = [0_u8; 1024];
  loop {
    match stream.read(&mut buffer) {
      Ok(0) => break,
      Ok(n) => {
        request.extend_from_slice(&buffer[..n]);
        if complete_http_request(&request) {
          break;
        }
      }
      Err(error)
        if error.kind() == std::io::ErrorKind::WouldBlock
          || error.kind() == std::io::ErrorKind::TimedOut =>
      {
        break;
      }
      Err(error) => panic!("failed to read catalog request: {error}"),
    }
  }
  String::from_utf8_lossy(&request).into_owned()
}

fn complete_http_request(request: &[u8]) -> bool {
  let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
    return false;
  };
  let headers = String::from_utf8_lossy(&request[..header_end]);
  let content_length = headers
    .lines()
    .find_map(|line| line.split_once(':'))
    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
    .unwrap_or(0);
  request.len() >= header_end + 4 + content_length
}

fn assert_no_request_header(request: &str, name: &str) {
  let found = request
    .lines()
    .filter_map(|line| line.split_once(':'))
    .any(|(header, _)| header.eq_ignore_ascii_case(name));
  assert!(!found, "unexpected request header {name}, got:\n{request}");
}

fn sha256_hex(bytes: &[u8]) -> String {
  let digest = Sha256::digest(bytes);
  let mut out = String::with_capacity(digest.len() * 2);
  for byte in digest {
    use std::fmt::Write as _;
    write!(&mut out, "{byte:02x}").expect("hex write");
  }
  out
}
