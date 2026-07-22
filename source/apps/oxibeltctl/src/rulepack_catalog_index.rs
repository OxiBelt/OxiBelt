use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::rulepack_catalog_registry::RulepackRepoConfig;

const MAX_RULEPACK_INDEX_BYTES: usize = 1024 * 1024;
const SUPPORTED_INDEX_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Compatibility {
  Compatible,
  TooOld,
  UnverifiedDevelopment,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CatalogRulepack {
  pub(crate) name: String,
  pub(crate) version: String,
  pub(crate) targets: Vec<String>,
  pub(crate) source: Url,
  pub(crate) sha256: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) signature_type: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) signature: Option<Url>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) min_oxibelt_version: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) license: Option<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub(crate) maintainers: Vec<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) description: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct LoadedCatalog {
  pub(crate) repo: String,
  pub(crate) entries: Vec<CatalogRulepack>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogDocument {
  index: CatalogIndex,
  #[serde(default)]
  rulepacks: Vec<CatalogRulepackRaw>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogIndex {
  schema_version: u32,
  #[serde(default)]
  generated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogRulepackRaw {
  name: String,
  version: String,
  #[serde(default)]
  targets: Vec<String>,
  source: Url,
  sha256: String,
  #[serde(default)]
  signature_type: Option<String>,
  #[serde(default)]
  signature: Option<Url>,
  #[serde(default)]
  min_oxibelt_version: Option<String>,
  #[serde(default)]
  license: Option<String>,
  #[serde(default)]
  maintainers: Vec<String>,
  #[serde(default)]
  description: Option<String>,
}

pub(crate) async fn load_repo_catalog(
  repo_name: &str,
  repo: &RulepackRepoConfig,
  timeout: Duration,
) -> anyhow::Result<LoadedCatalog> {
  validate_catalog_url(&repo.url, repo.allow_insecure_rulepack_url)?;
  let bytes = crate::rulepack_url::download_url_bytes(
    &repo.url,
    &repo.ca_certs,
    repo.token_env.as_deref(),
    timeout,
    MAX_RULEPACK_INDEX_BYTES,
    "application/toml, application/json, text/plain",
    "rulepack catalog index",
  )
  .await?;
  let source = format!(
    "rulepack catalog {}",
    crate::rulepack_url::diagnostic_url(&repo.url)
  );
  let entries = parse_catalog_bytes(&bytes, &source, repo.allow_insecure_rulepack_url)?;
  Ok(LoadedCatalog {
    repo: repo_name.to_string(),
    entries,
  })
}

pub(crate) fn parse_catalog_bytes(
  bytes: &[u8],
  source: &str,
  allow_insecure_rulepack_url: bool,
) -> anyhow::Result<Vec<CatalogRulepack>> {
  let raw = std::str::from_utf8(bytes).with_context(|| format!("{source} was not UTF-8"))?;
  let document = parse_catalog_document(raw, source)?;
  validate_catalog_document(document, source, allow_insecure_rulepack_url)
}

pub(crate) fn is_compatible(entry: &CatalogRulepack) -> bool {
  compatibility(entry) == Compatibility::Compatible
}

pub(crate) fn compatibility_error(entry: &CatalogRulepack) -> Option<String> {
  let minimum = entry.min_oxibelt_version.as_ref()?;
  let identity = oxibelt_build_identity::current();
  match compatibility(entry) {
    Compatibility::Compatible => None,
    Compatibility::TooOld => Some(format!(
      "rulepack {} {} requires OxiBelt >= {}, current compatible version is {}",
      entry.name,
      entry.version,
      minimum,
      identity
        .compatibility_version()
        .expect("too-old result requires a comparable build")
    )),
    Compatibility::UnverifiedDevelopment => Some(format!(
      "rulepack {} {} requires OxiBelt >= {}, but build {} ({}) has no verified compatibility version; use an official release or clean exact-tag build",
      entry.name,
      entry.version,
      minimum,
      identity.effective_version,
      identity.kind.as_str(),
    )),
  }
}

fn compatibility(entry: &CatalogRulepack) -> Compatibility {
  compatibility_for(
    entry.min_oxibelt_version.as_deref(),
    oxibelt_build_identity::current().compatibility_version(),
  )
}

fn compatibility_for(minimum: Option<&str>, current: Option<&str>) -> Compatibility {
  let Some(minimum) = minimum else {
    return Compatibility::Compatible;
  };
  let Some(current) = current else {
    return Compatibility::UnverifiedDevelopment;
  };
  match oxibelt_build_identity::compare_semver(current, minimum)
    .expect("catalog minimums are validated during ingestion")
  {
    Ordering::Less => Compatibility::TooOld,
    Ordering::Equal | Ordering::Greater => Compatibility::Compatible,
  }
}

pub(crate) fn compare_versions(left: &str, right: &str) -> Ordering {
  let left_parts = version_parts(left);
  let right_parts = version_parts(right);
  for index in 0..left_parts.len().max(right_parts.len()) {
    let left = left_parts.get(index).unwrap_or(&VersionPart::Number(0));
    let right = right_parts.get(index).unwrap_or(&VersionPart::Number(0));
    match left.cmp(right) {
      Ordering::Equal => {}
      ordering => return ordering,
    }
  }
  Ordering::Equal
}

fn parse_catalog_document(raw: &str, source: &str) -> anyhow::Result<CatalogDocument> {
  let json_first = raw.trim_start().starts_with('{');
  if json_first {
    serde_json::from_str(raw)
      .with_context(|| format!("failed to parse {source} as JSON rulepack catalog"))
  } else {
    toml::from_str(raw)
      .with_context(|| format!("failed to parse {source} as TOML rulepack catalog"))
  }
}

fn validate_catalog_document(
  document: CatalogDocument,
  source: &str,
  allow_insecure_rulepack_url: bool,
) -> anyhow::Result<Vec<CatalogRulepack>> {
  if document.index.schema_version != SUPPORTED_INDEX_SCHEMA_VERSION {
    bail!(
      "{source} uses unsupported rulepack catalog schema_version {}; only schema_version {SUPPORTED_INDEX_SCHEMA_VERSION} is supported",
      document.index.schema_version
    );
  }
  if let Some(generated_at) = &document.index.generated_at {
    validate_non_empty(source, "index.generated_at", generated_at)?;
  }
  let mut seen = BTreeSet::new();
  let mut entries = Vec::new();
  for raw in document.rulepacks {
    validate_label(source, "rulepacks.name", &raw.name)?;
    validate_non_empty(source, "rulepacks.version", &raw.version)?;
    validate_sha256(source, &raw.sha256)?;
    for target in &raw.targets {
      validate_label(source, "rulepacks.targets", target)?;
    }
    for maintainer in &raw.maintainers {
      validate_non_empty(source, "rulepacks.maintainers", maintainer)?;
    }
    if let Some(value) = &raw.license {
      validate_non_empty(source, "rulepacks.license", value)?;
    }
    if let Some(value) = &raw.description {
      validate_non_empty(source, "rulepacks.description", value)?;
    }
    if let Some(value) = &raw.min_oxibelt_version {
      validate_non_empty(source, "rulepacks.min_oxibelt_version", value)?;
      oxibelt_build_identity::parse_semver(value).map_err(|error| {
        anyhow::anyhow!("{source} rulepacks.min_oxibelt_version must be strict SemVer: {error}")
      })?;
    }
    validate_rulepack_source_url(&raw.source, allow_insecure_rulepack_url)?;
    if let Some(signature_type) = &raw.signature_type
      && signature_type != "openpgp"
    {
      bail!(
        "{source} rulepack {} uses unsupported signature_type {signature_type}",
        raw.name
      );
    }
    if let Some(signature) = &raw.signature {
      crate::rulepack_url::validate_rulepack_signature_url(signature, allow_insecure_rulepack_url)?;
    }
    if !seen.insert((raw.name.clone(), raw.version.clone())) {
      bail!(
        "{source} contains duplicate rulepack entry {} {}",
        raw.name,
        raw.version
      );
    }
    entries.push(CatalogRulepack {
      name: raw.name,
      version: raw.version,
      targets: raw.targets,
      source: raw.source,
      sha256: raw.sha256,
      signature_type: raw.signature_type,
      signature: raw.signature,
      min_oxibelt_version: raw.min_oxibelt_version,
      license: raw.license,
      maintainers: raw.maintainers,
      description: raw.description,
    });
  }
  Ok(entries)
}

pub(crate) fn validate_catalog_url(url: &Url, allow_insecure: bool) -> anyhow::Result<()> {
  if !url.username().is_empty() || url.password().is_some() {
    bail!("rulepack catalog URL must not include username or password; use --rulepack-token-env");
  }
  match url.scheme() {
    "https" => Ok(()),
    "http" if allow_insecure => Ok(()),
    "http" => {
      bail!("rulepack catalog URL requires https unless --allow-insecure-rulepack-url is set")
    }
    scheme => bail!("rulepack catalog URL must use http or https, got {scheme}"),
  }
}

fn validate_rulepack_source_url(url: &Url, allow_insecure: bool) -> anyhow::Result<()> {
  crate::rulepack_url::validate_rulepack_url(url, allow_insecure)?;
  crate::rulepack_url::ensure_manifest_url_suffix(url)
}

fn validate_label(source: &str, field: &str, value: &str) -> anyhow::Result<()> {
  validate_non_empty(source, field, value)?;
  if value.len() > 128
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
  {
    bail!("{source} {field} may contain only ASCII letters, digits, '.', '-', '_', and ':'");
  }
  Ok(())
}

fn validate_non_empty(source: &str, field: &str, value: &str) -> anyhow::Result<()> {
  if value.trim().is_empty() {
    bail!("{source} {field} must not be empty");
  }
  Ok(())
}

fn validate_sha256(source: &str, value: &str) -> anyhow::Result<()> {
  if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    bail!("{source} rulepacks.sha256 must be a 64-character hex SHA-256 digest");
  }
  Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum VersionPart {
  Number(u64),
  Text(String),
}

impl Ord for VersionPart {
  fn cmp(&self, other: &Self) -> Ordering {
    match (self, other) {
      (Self::Number(left), Self::Number(right)) => left.cmp(right),
      (Self::Text(left), Self::Text(right)) => left.cmp(right),
      (Self::Number(_), Self::Text(_)) => Ordering::Greater,
      (Self::Text(_), Self::Number(_)) => Ordering::Less,
    }
  }
}

impl PartialOrd for VersionPart {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

fn version_parts(version: &str) -> Vec<VersionPart> {
  version
    .split(['.', '-', '_', '+'])
    .filter(|part| !part.is_empty())
    .map(|part| {
      part
        .parse::<u64>()
        .map(VersionPart::Number)
        .unwrap_or_else(|_| VersionPart::Text(part.to_ascii_lowercase()))
    })
    .collect()
}

#[cfg(test)]
mod compatibility_tests {
  use super::{Compatibility, compatibility_for};

  #[test]
  fn fails_closed_when_a_declared_minimum_cannot_be_verified() {
    assert_eq!(
      compatibility_for(Some("0.0.0"), None),
      Compatibility::UnverifiedDevelopment
    );
    assert_eq!(compatibility_for(None, None), Compatibility::Compatible);
  }

  #[test]
  fn compares_only_verified_semver_identities() {
    assert_eq!(
      compatibility_for(Some("1.2.3"), Some("1.2.3")),
      Compatibility::Compatible
    );
    assert_eq!(
      compatibility_for(Some("1.2.4"), Some("1.2.3")),
      Compatibility::TooOld
    );
  }
}
