use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, bail};
use http::{HeaderValue, Request};
use oxibelt::control_http::{ControlHttpClient, empty_body};
use ring::digest;
use serde::Deserialize;

use crate::cli::MitigateArgs;

const MAX_PROFILE_CATALOG_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
pub(crate) struct MitigationProfileCatalog {
  pub(crate) profiles: BTreeMap<String, MitigationProfile>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct MitigationProfile {
  pub(crate) action: String,
  #[serde(default)]
  pub(crate) source: Option<String>,
  #[serde(default)]
  pub(crate) priority: Option<i32>,
  #[serde(default)]
  pub(crate) route_name: Option<String>,
  #[serde(default)]
  pub(crate) path_prefix: Option<String>,
  #[serde(default)]
  pub(crate) method: Option<String>,
  #[serde(default)]
  pub(crate) rate: Option<String>,
  #[serde(default)]
  pub(crate) burst: Option<i32>,
  #[serde(default)]
  pub(crate) status: Option<i32>,
  #[serde(default)]
  pub(crate) body: Option<String>,
  #[serde(default)]
  pub(crate) reason: Option<String>,
  #[serde(default)]
  pub(crate) code: Option<String>,
  #[serde(default)]
  pub(crate) ttl_seconds: Option<i64>,
  #[serde(default)]
  pub(crate) mode: Option<String>,
}

pub(crate) async fn load_mitigation_profile_catalog(
  args: &MitigateArgs,
  timeout: Duration,
) -> anyhow::Result<MitigationProfileCatalog> {
  match (&args.profile_file, &args.profile_url) {
    (Some(path), None) => {
      let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read mitigation profile file {}", path.display()))?;
      parse_catalog(&bytes, &format!("file {}", path.display()))
    }
    (None, Some(url)) => {
      validate_profile_url(url, args.allow_insecure_profile_url)?;
      let bytes = download_profile_catalog(args, timeout).await?;
      if let Some(expected) = args.profile_sha256.as_deref() {
        verify_sha256(expected, &bytes)?;
      }
      parse_catalog(&bytes, &format!("URL {}", diagnostic_profile_url(url)))
    }
    (None, None) => bail!("mitigate requires --profile-file or --profile-url"),
    (Some(_), Some(_)) => bail!("mitigate accepts only one of --profile-file or --profile-url"),
  }
}

fn parse_catalog(bytes: &[u8], source: &str) -> anyhow::Result<MitigationProfileCatalog> {
  serde_json::from_slice(bytes)
    .with_context(|| format!("failed to parse mitigation profile catalog from {source}"))
}

async fn download_profile_catalog(
  args: &MitigateArgs,
  timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
  let url = args
    .profile_url
    .as_ref()
    .context("mitigation profile URL is missing")?;
  let diagnostic_url = diagnostic_profile_url(url);
  let request_url = request_profile_url(url);
  let uri = request_url
    .as_str()
    .parse::<http::Uri>()
    .with_context(|| format!("invalid mitigation profile URL {diagnostic_url}"))?;
  let client = ControlHttpClient::new(&args.profile_ca_certs)
    .context("failed to build mitigation profile HTTP client")?;
  let mut builder = Request::builder()
    .method(http::Method::GET)
    .uri(uri)
    .header(http::header::ACCEPT, "application/json");
  if let Some(token_env) = args.profile_token_env.as_deref() {
    builder = builder.header(
      http::header::AUTHORIZATION,
      profile_bearer_header(token_env)?,
    );
  }
  let request = builder
    .body(empty_body())
    .context("failed to build mitigation profile request")?;
  let response = client
    .request(request, timeout, MAX_PROFILE_CATALOG_BYTES)
    .await
    .with_context(|| {
      format!("failed to download mitigation profile catalog from {diagnostic_url}")
    })?;
  if !response.status.is_success() {
    bail!(
      "mitigation profile catalog download from {diagnostic_url} failed with {}",
      response.status
    );
  }
  Ok(response.body.to_vec())
}

fn validate_profile_url(url: &url::Url, allow_insecure: bool) -> anyhow::Result<()> {
  if !url.username().is_empty() || url.password().is_some() {
    bail!("--profile-url must not include username or password; use --profile-token-env");
  }
  match url.scheme() {
    "https" => Ok(()),
    "http" if allow_insecure => Ok(()),
    "http" => {
      bail!("--profile-url requires https unless --allow-insecure-profile-url is set")
    }
    scheme => bail!("--profile-url must use http or https, got {scheme}"),
  }
}

fn request_profile_url(url: &url::Url) -> url::Url {
  let mut request_url = url.clone();
  request_url.set_fragment(None);
  request_url
}

fn diagnostic_profile_url(url: &url::Url) -> String {
  let mut diagnostic_url = url.clone();
  let _ = diagnostic_url.set_username("");
  let _ = diagnostic_url.set_password(None);
  diagnostic_url.set_query(None);
  diagnostic_url.set_fragment(None);
  diagnostic_url.to_string()
}

fn profile_bearer_header(token_env: &str) -> anyhow::Result<HeaderValue> {
  let token = std::env::var(token_env).with_context(|| {
    format!("mitigation profile token environment variable {token_env} is not set")
  })?;
  let token = token.trim();
  if token.is_empty() {
    bail!("mitigation profile token environment variable {token_env} is empty");
  }
  HeaderValue::from_str(&format!("Bearer {token}"))
    .context("mitigation profile bearer token is not header-safe")
}

fn verify_sha256(expected: &str, bytes: &[u8]) -> anyhow::Result<()> {
  let expected = expected.trim();
  if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    bail!("--profile-sha256 must be a 64-character hex SHA-256 digest");
  }
  let actual = hex_encode(digest::digest(&digest::SHA256, bytes).as_ref());
  if !actual.eq_ignore_ascii_case(expected) {
    bail!("mitigation profile SHA-256 mismatch: expected {expected}, got {actual}");
  }
  Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    use std::fmt::Write;
    write!(&mut out, "{byte:02x}").expect("hex write should succeed");
  }
  out
}
