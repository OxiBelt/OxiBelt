use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use http::{HeaderValue, Method, Request};
use oxibelt::control_http::{ControlHttpClient, empty_body};
use oxibelt::waf::{RULEPACK_FILE_SUFFIX, RulepackSourceProvenance};
use sha2::{Digest, Sha256};
use url::Url;

use crate::cli::RulepackSourceArgs;
use crate::rulepack::LoadedRulepackSource;
use crate::rulepack_openpgp::{
  MAX_OPENPGP_SIGNATURE_BYTES, RulepackOpenPgpTrust, read_signature_file, verify_rulepack_signature,
};

const MAX_RULEPACK_BYTES: usize = 1024 * 1024;

pub(crate) async fn load_url_source(
  args: &RulepackSourceArgs,
  url: &Url,
  timeout: Duration,
  require_pin: bool,
) -> anyhow::Result<LoadedRulepackSource> {
  validate_rulepack_url(url, args.allow_insecure_rulepack_url)?;
  ensure_manifest_url_suffix(url)?;
  let require_openpgp_signature = requires_rulepack_openpgp_signature(args, url);
  if url.scheme() == "http"
    && args.openpgp_signature_url.is_none()
    && args.openpgp_signature_file.is_none()
  {
    bail!(
      "HTTP rulepack URL requires --rulepack-openpgp-signature-url or --rulepack-openpgp-signature-file"
    );
  }
  if require_openpgp_signature
    && args.openpgp_signature_url.is_none()
    && args.openpgp_signature_file.is_none()
  {
    bail!(
      "rulepack OpenPGP verification requires --rulepack-openpgp-signature-url or --rulepack-openpgp-signature-file"
    );
  }
  if let Some(signature_url) = &args.openpgp_signature_url {
    validate_rulepack_signature_url(signature_url, args.allow_insecure_rulepack_url)?;
  }
  if require_pin
    && args.sha256.is_none()
    && !args.allow_unpinned_rulepack
    && !require_openpgp_signature
  {
    bail!(
      "rulepack apply from URL requires --sha256, a trusted OpenPGP signature, or --allow-unpinned-rulepack"
    );
  }
  let bytes = download_url_bytes(
    url,
    &args.ca_certs,
    args.token_env.as_deref(),
    timeout,
    MAX_RULEPACK_BYTES,
    "application/toml, text/plain",
    "rulepack",
  )
  .await?;
  let source_sha256 = sha256_hex(&bytes);
  if let Some(expected) = args.sha256.as_deref() {
    verify_sha256_digest(expected, &source_sha256)?;
  }
  let signature_verification = if require_openpgp_signature {
    let signature_bytes = load_rulepack_signature(args, url, timeout).await?;
    Some(verify_rulepack_signature(
      &signature_bytes,
      &bytes,
      RulepackOpenPgpTrust {
        key_files: &args.openpgp_key_files,
        keyring_dirs: &args.openpgp_keyring_dirs,
        fingerprints: &args.openpgp_fingerprints,
      },
    )?)
  } else {
    None
  };
  let source_provenance = RulepackSourceProvenance {
    source_url: diagnostic_url(url),
    source_sha256,
    source_openpgp_signature_url: args.openpgp_signature_url.as_ref().map(diagnostic_url),
    source_openpgp_signer_fingerprint: signature_verification
      .map(|verification| verification.signer_fingerprint),
  };
  LoadedRulepackSource::from_url(
    String::from_utf8(bytes).context("rulepack URL body was not UTF-8")?,
    format!("URL {}", diagnostic_url(url)),
    source_provenance,
  )
}

async fn load_rulepack_signature(
  args: &RulepackSourceArgs,
  rulepack_url: &Url,
  timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
  if let Some(path) = &args.openpgp_signature_file {
    return read_signature_file(path);
  }
  let signature_url = args
    .openpgp_signature_url
    .as_ref()
    .context("rulepack OpenPGP signature URL is missing")?;
  let token_env = args
    .token_env
    .as_deref()
    .filter(|_| same_origin(rulepack_url, signature_url));
  download_url_bytes(
    signature_url,
    &args.ca_certs,
    token_env,
    timeout,
    MAX_OPENPGP_SIGNATURE_BYTES,
    "application/pgp-signature, application/octet-stream, text/plain",
    "rulepack OpenPGP signature",
  )
  .await
}

pub(crate) async fn download_url_bytes(
  url: &Url,
  ca_certs: &[PathBuf],
  token_env: Option<&str>,
  timeout: Duration,
  max_bytes: usize,
  accept: &'static str,
  label: &'static str,
) -> anyhow::Result<Vec<u8>> {
  let client = ControlHttpClient::new(ca_certs).context("failed to build rulepack HTTP client")?;
  let uri = oxibelt::control_http::uri_from_url(&request_url(url))?;
  let mut builder = Request::builder()
    .method(Method::GET)
    .uri(uri)
    .header(http::header::ACCEPT, accept);
  if let Some(token_env) = token_env {
    builder = builder.header(http::header::AUTHORIZATION, bearer_header(token_env)?);
  }
  let request = builder
    .body(empty_body())
    .context("failed to build rulepack request")?;
  let response = client
    .request(request, timeout, max_bytes)
    .await
    .with_context(|| format!("failed to download {label} from {}", diagnostic_url(url)))?;
  if !response.status.is_success() {
    bail!(
      "{label} download from {} failed with {}",
      diagnostic_url(url),
      response.status
    );
  }
  Ok(response.body.to_vec())
}

pub(crate) fn validate_rulepack_url(url: &Url, allow_insecure: bool) -> anyhow::Result<()> {
  if !url.username().is_empty() || url.password().is_some() {
    bail!("rulepack URL must not include username or password; use --rulepack-token-env");
  }
  match url.scheme() {
    "https" => Ok(()),
    "http" if allow_insecure => Ok(()),
    "http" => bail!("rulepack URL requires https unless --allow-insecure-rulepack-url is set"),
    scheme => bail!("rulepack URL must use http or https, got {scheme}"),
  }
}

pub(crate) fn validate_rulepack_signature_url(
  url: &Url,
  allow_insecure: bool,
) -> anyhow::Result<()> {
  if !url.username().is_empty() || url.password().is_some() {
    bail!("rulepack OpenPGP signature URL must not include username or password");
  }
  match url.scheme() {
    "https" => Ok(()),
    "http" if allow_insecure => Ok(()),
    "http" => {
      bail!(
        "rulepack OpenPGP signature URL requires https unless --allow-insecure-rulepack-url is set"
      )
    }
    scheme => bail!("rulepack OpenPGP signature URL must use http or https, got {scheme}"),
  }
}

fn requires_rulepack_openpgp_signature(args: &RulepackSourceArgs, url: &Url) -> bool {
  url.scheme() == "http"
    || args.require_openpgp_signature
    || args.openpgp_signature_url.is_some()
    || args.openpgp_signature_file.is_some()
    || !args.openpgp_key_files.is_empty()
    || !args.openpgp_keyring_dirs.is_empty()
    || !args.openpgp_fingerprints.is_empty()
}

pub(crate) fn ensure_manifest_url_suffix(url: &Url) -> anyhow::Result<()> {
  if !url.path().ends_with(RULEPACK_FILE_SUFFIX) {
    bail!("rulepack URL path must end with {RULEPACK_FILE_SUFFIX}");
  }
  Ok(())
}

fn verify_sha256_digest(expected: &str, actual: &str) -> anyhow::Result<()> {
  let expected = expected.trim();
  if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    bail!("--sha256 must be a 64-character hex SHA-256 digest");
  }
  if !actual.eq_ignore_ascii_case(expected) {
    bail!("rulepack SHA-256 mismatch: expected {expected}, got {actual}");
  }
  Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
  hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    use std::fmt::Write;
    write!(&mut out, "{byte:02x}").expect("hex write should succeed");
  }
  out
}

fn bearer_header(token_env: &str) -> anyhow::Result<HeaderValue> {
  let token = std::env::var(token_env)
    .with_context(|| format!("rulepack token environment variable {token_env} is not set"))?;
  let token = token.trim();
  if token.is_empty() {
    bail!("rulepack token environment variable {token_env} is empty");
  }
  HeaderValue::from_str(&format!("Bearer {token}"))
    .context("rulepack bearer token is not header-safe")
}

fn request_url(url: &Url) -> Url {
  let mut request_url = url.clone();
  request_url.set_fragment(None);
  request_url
}

pub(crate) fn same_origin(left: &Url, right: &Url) -> bool {
  left.scheme() == right.scheme()
    && left.host_str() == right.host_str()
    && left.port_or_known_default() == right.port_or_known_default()
}

pub(crate) fn diagnostic_url(url: &Url) -> String {
  let mut diagnostic_url = url.clone();
  let _ = diagnostic_url.set_username("");
  let _ = diagnostic_url.set_password(None);
  diagnostic_url.set_query(None);
  diagnostic_url.set_fragment(None);
  diagnostic_url.to_string()
}
