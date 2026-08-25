use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use base64::Engine as _;
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use oxibelt::ct::merkle::{Hash, verify_consistency};
use oxibelt::ct::rfc6962::{
  GetSthConsistencyResponseV1, GetSthResponseV1, HASH_ALGORITHM_SHA256, SIGNATURE_ALGORITHM_ECDSA,
  encode_sth_signed_input,
};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::{Host, Url};

use crate::cli::CtMonitorArgs;
use crate::ct_io::{
  canonical_json_bytes, encode_hex, parse_hex_32, read_integrity_bounded, sync_parent_directory,
  write_new,
};

const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;
const MAX_PUBLIC_KEY_BYTES: u64 = 1024;
const MAX_CA_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WITNESS_BYTES: u64 = 64 * 1024;
const MAX_CONSISTENCY_NODES: usize = 64;

type MonitorClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Witness {
  schema_version: u32,
  log_id: String,
  tree_size: u64,
  timestamp: u64,
  root_hash: String,
}

pub(crate) async fn run(args: &CtMonitorArgs) -> anyhow::Result<i32> {
  validate_url(&args.url, args.allow_loopback_http)?;
  let log_id = parse_hex_32(&args.log_id, "RFC 6962 LogID")?;
  let public_key =
    read_integrity_bounded(&args.public_key, MAX_PUBLIC_KEY_BYTES, "CT log public key")?;
  if public_key.len() != 65 || public_key.first() != Some(&0x04) {
    bail!("CT P-256 public key must be a 65-byte uncompressed SEC1 point");
  }
  let derived_log_id = p256_log_id(&public_key);
  if derived_log_id != log_id {
    bail!("RFC 6962 LogID does not equal SHA-256 of the supplied P-256 SubjectPublicKeyInfo");
  }
  let timeout = Duration::from_millis(args.timeout_ms);
  let client = build_client(&args.ca_certs)?;
  let sth_url = endpoint(&args.url, "ct/v1/get-sth")?;
  let body = get(&client, sth_url, timeout).await?;
  let sth: GetSthResponseV1 =
    serde_json::from_slice(&body).context("failed to parse RFC 6962 get-sth response")?;
  let (new_root, signature) = sth.decode_root_and_signature()?;
  if signature.hash_algorithm != HASH_ALGORITHM_SHA256
    || signature.signature_algorithm != SIGNATURE_ALGORITHM_ECDSA
  {
    bail!("CT monitor supports only RFC 6962 ECDSA P-256 SHA-256 log signatures");
  }
  let transcript = encode_sth_signed_input(sth.timestamp, sth.tree_size, &new_root);
  UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public_key)
    .verify(&transcript, &signature.signature)
    .map_err(|_| anyhow!("RFC 6962 STH signature verification failed"))?;
  validate_sth_time(sth.timestamp, args.max_sth_age_seconds)?;

  let existing = read_witness(&args.witness)?;
  match existing {
    None if !args.initialize_witness => {
      bail!(
        "CT witness is missing; pass --initialize-witness after independently confirming the log identity"
      )
    }
    None => {
      let witness = make_witness(&log_id, &sth, &new_root);
      write_new(
        &args.witness,
        &canonical_json_bytes(&serde_json::to_value(&witness)?)?,
        "CT monitor witness",
      )?;
    }
    Some(old) => {
      validate_witness(&old, &log_id)?;
      if sth.tree_size < old.tree_size || sth.timestamp < old.timestamp {
        bail!("RFC 6962 log STH regressed relative to the durable witness");
      }
      let old_root = parse_hex_32(&old.root_hash, "CT witness root hash")?;
      if sth.tree_size == old.tree_size {
        if new_root != old_root {
          bail!("RFC 6962 log returned conflicting roots for one tree size");
        }
      } else {
        let proof =
          fetch_consistency(&client, &args.url, old.tree_size, sth.tree_size, timeout).await?;
        let old_size =
          usize::try_from(old.tree_size).context("old CT tree size exceeds platform limits")?;
        let new_size =
          usize::try_from(sth.tree_size).context("new CT tree size exceeds platform limits")?;
        if !verify_consistency(old_size, new_size, &old_root, &new_root, &proof) {
          bail!("RFC 6962 consistency proof verification failed");
        }
      }
      replace_witness(&args.witness, &make_witness(&log_id, &sth, &new_root))?;
    }
  }
  println!(
    "{}",
    serde_json::to_string_pretty(&serde_json::json!({
      "verified": true,
      "log_id": encode_hex(&log_id),
      "tree_size": sth.tree_size,
      "timestamp": sth.timestamp,
      "root_hash": encode_hex(&new_root),
      "witness": args.witness,
    }))?
  );
  Ok(0)
}

async fn fetch_consistency(
  client: &MonitorClient,
  base: &Url,
  old_size: u64,
  new_size: u64,
  timeout: Duration,
) -> anyhow::Result<Vec<Hash>> {
  let mut url = endpoint(base, "ct/v1/get-sth-consistency")?;
  url
    .query_pairs_mut()
    .append_pair("first", &old_size.to_string())
    .append_pair("second", &new_size.to_string());
  let body = get(client, url, timeout).await?;
  let response: GetSthConsistencyResponseV1 =
    serde_json::from_slice(&body).context("failed to parse RFC 6962 consistency response")?;
  if response.consistency.len() > MAX_CONSISTENCY_NODES {
    bail!("RFC 6962 consistency proof exceeds {MAX_CONSISTENCY_NODES} nodes");
  }
  response
    .consistency
    .iter()
    .map(|encoded| {
      let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("RFC 6962 consistency node is not base64")?;
      if base64::engine::general_purpose::STANDARD.encode(&bytes) != *encoded {
        bail!("RFC 6962 consistency node is not canonical base64");
      }
      bytes
        .try_into()
        .map_err(|_| anyhow!("RFC 6962 consistency node must be 32 bytes"))
    })
    .collect()
}

fn build_client(extra_roots: &[std::path::PathBuf]) -> anyhow::Result<MonitorClient> {
  let mut roots = RootCertStore::empty();
  roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
  for path in extra_roots {
    let bytes = read_integrity_bounded(path, MAX_CA_FILE_BYTES, "CT monitor CA certificate file")?;
    let certificates = CertificateDer::pem_slice_iter(&bytes)
      .collect::<Result<Vec<_>, _>>()
      .with_context(|| format!("failed to parse CT monitor CA file {}", path.display()))?;
    if certificates.is_empty() {
      bail!(
        "CT monitor CA file {} contains no certificates",
        path.display()
      );
    }
    let (added, ignored) = roots.add_parsable_certificates(certificates);
    if added == 0 || ignored != 0 {
      bail!(
        "CT monitor CA file {} contains an invalid certificate",
        path.display()
      );
    }
  }
  let tls =
    ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
      .with_safe_default_protocol_versions()
      .context("failed to configure CT monitor TLS versions")?
      .with_root_certificates(roots)
      .with_no_client_auth();
  let mut http = HttpConnector::new();
  http.enforce_http(false);
  http.set_connect_timeout(Some(Duration::from_secs(5)));
  let connector = HttpsConnectorBuilder::new()
    .with_tls_config(tls)
    .https_or_http()
    .enable_http1()
    .enable_http2()
    .wrap_connector(http);
  let mut builder = Client::builder(TokioExecutor::new());
  builder.pool_timer(TokioTimer::new());
  builder.pool_idle_timeout(Duration::from_secs(30));
  Ok(builder.build(connector))
}

async fn get(client: &MonitorClient, url: Url, timeout: Duration) -> anyhow::Result<Bytes> {
  let request = Request::builder()
    .method(Method::GET)
    .uri(url.as_str())
    .header(http::header::ACCEPT, "application/json")
    .body(Empty::<Bytes>::new())
    .context("failed to build CT monitor request")?;
  let response = tokio::time::timeout(timeout, client.request(request))
    .await
    .context("CT monitor HTTP request timed out")?
    .context("CT monitor HTTP request failed")?;
  if response.status() != StatusCode::OK {
    bail!("CT monitor endpoint returned HTTP {}", response.status());
  }
  Limited::new(response.into_body(), MAX_HTTP_BODY_BYTES)
    .collect()
    .await
    .map(|body| body.to_bytes())
    .map_err(|error| anyhow!("CT monitor response body failed: {error}"))
}

fn endpoint(base: &Url, relative: &str) -> anyhow::Result<Url> {
  let mut base = base.clone();
  if !base.path().ends_with('/') {
    base.set_path(&format!("{}/", base.path()));
  }
  base
    .join(relative)
    .context("failed to construct CT monitor endpoint")
}

fn validate_url(url: &Url, allow_loopback_http: bool) -> anyhow::Result<()> {
  if url.username() != ""
    || url.password().is_some()
    || url.fragment().is_some()
    || url.query().is_some()
  {
    bail!("CT monitor URL must not contain credentials, a query, or a fragment");
  }
  match url.scheme() {
    "https" => Ok(()),
    "http" if allow_loopback_http && is_loopback(url) => Ok(()),
    _ => {
      bail!("CT monitor requires HTTPS; plaintext HTTP is limited to explicit loopback development")
    }
  }
}

fn is_loopback(url: &Url) -> bool {
  match url.host() {
    Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
    Some(Host::Ipv4(address)) => address.is_loopback(),
    Some(Host::Ipv6(address)) => address.is_loopback(),
    None => false,
  }
}

fn validate_sth_time(timestamp_millis: u64, max_age_seconds: u64) -> anyhow::Result<()> {
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .context("system clock precedes the Unix epoch")?
    .as_millis();
  if u128::from(timestamp_millis) > now.saturating_add(5 * 60 * 1000) {
    bail!("RFC 6962 STH timestamp is more than five minutes in the future");
  }
  let maximum_age_millis = u128::from(max_age_seconds) * 1000;
  if now.saturating_sub(u128::from(timestamp_millis)) > maximum_age_millis {
    bail!("RFC 6962 STH is older than the configured availability window");
  }
  Ok(())
}

fn read_witness(path: &Path) -> anyhow::Result<Option<Witness>> {
  let bytes = match read_integrity_bounded(path, MAX_WITNESS_BYTES, "CT monitor witness") {
    Ok(bytes) => bytes,
    Err(error)
      if error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|value| value.kind() == std::io::ErrorKind::NotFound) =>
    {
      return Ok(None);
    }
    Err(error) => return Err(error),
  };
  let witness: Witness =
    serde_json::from_slice(&bytes).context("failed to parse CT monitor witness")?;
  if canonical_json_bytes(&serde_json::to_value(&witness)?)? != bytes {
    bail!("CT monitor witness must use canonical JSON without trailing bytes");
  }
  Ok(Some(witness))
}

fn validate_witness(witness: &Witness, expected_log_id: &Hash) -> anyhow::Result<()> {
  if witness.schema_version != 1 {
    bail!("unsupported CT monitor witness schema version");
  }
  if witness.log_id.len() != 64
    || parse_hex_32(&witness.log_id, "CT witness LogID")? != *expected_log_id
  {
    bail!("CT monitor witness is bound to a different log");
  }
  if witness.root_hash.len() != 64 {
    bail!("CT monitor witness root hash is not canonical");
  }
  parse_hex_32(&witness.root_hash, "CT witness root hash")?;
  Ok(())
}

fn p256_log_id(public_key: &[u8]) -> Hash {
  // DER SubjectPublicKeyInfo prefix for id-ecPublicKey with namedCurve P-256.
  const SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
  ];
  let mut digest = Sha256::new();
  digest.update(SPKI_PREFIX);
  digest.update(public_key);
  digest.finalize().into()
}

fn make_witness(log_id: &Hash, sth: &GetSthResponseV1, root: &Hash) -> Witness {
  Witness {
    schema_version: 1,
    log_id: encode_hex(log_id),
    tree_size: sth.tree_size,
    timestamp: sth.timestamp,
    root_hash: encode_hex(root),
  }
}

fn replace_witness(path: &Path, witness: &Witness) -> anyhow::Result<()> {
  let parent = path
    .parent()
    .filter(|parent| !parent.as_os_str().is_empty())
    .unwrap_or_else(|| Path::new("."));
  let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
    format!(
      "failed to create temporary CT witness beside {}",
      path.display()
    )
  })?;
  let bytes = canonical_json_bytes(&serde_json::to_value(witness)?)?;
  temporary
    .write_all(&bytes)
    .context("failed to write temporary CT witness")?;
  temporary
    .as_file()
    .sync_all()
    .context("failed to sync temporary CT witness")?;
  temporary
    .persist(path)
    .map_err(|error| error.error)
    .with_context(|| format!("failed to atomically replace CT witness {}", path.display()))?;
  sync_parent_directory(path, "CT monitor witness")?;
  Ok(())
}
