//! Managed resumable-upload storage and policy configuration.
//!
//! Profiles are operator-owned.  Routes can only refer to a profile by name;
//! they cannot select object-store credentials or destinations.

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use url::Url;

use super::validate_runtime_identifier;

pub(crate) const UPLOAD_STORE_CONFIG_KEYS: &[&str] = &["kind", "name", "local", "postgres_s3"];
pub(crate) const UPLOAD_STORE_LOCAL_CONFIG_KEYS: &[&str] = &["root"];
pub(crate) const UPLOAD_STORE_POSTGRES_S3_CONFIG_KEYS: &[&str] = &[
  "max_connections",
  "postgres_url_env",
  "s3_access_key_env",
  "s3_bucket",
  "s3_endpoint",
  "s3_prefix",
  "s3_region",
  "s3_root_certificate",
  "s3_secret_key_env",
  "s3_session_token_env",
  "s3_virtual_hosted_style",
];
pub(crate) const UPLOAD_PROFILE_CONFIG_KEYS: &[&str] = &[
  "control_path_prefix",
  "destination",
  "identity",
  "inspection_bytes",
  "max_concurrent_parts",
  "max_concurrent_uploads",
  "max_part_bytes",
  "max_parts",
  "max_sessions",
  "max_storage_bytes",
  "max_upload_bytes",
  "name",
  "object_path_prefix",
  "object_ttl_seconds",
  "public_base_url",
  "staging_dir",
  "max_staging_bytes",
  "store",
  "ttl_seconds",
];
pub(crate) const UPLOAD_DESTINATION_CONFIG_KEYS: &[&str] = &["kind", "upstream"];
pub(crate) const UPLOAD_IDENTITY_CONFIG_KEYS: &[&str] = &["kind", "source", "subject_field"];

const MAX_STORES: usize = 64;
const MAX_PROFILES: usize = 256;
const MAX_UPLOAD_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_TTL_SECONDS: u64 = 366 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UploadStoreKind {
  Local,
  PostgresS3,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UploadStoreConfig {
  pub name: String,
  pub kind: UploadStoreKind,
  #[serde(default)]
  pub local: Option<LocalUploadStoreConfig>,
  #[serde(default)]
  pub postgres_s3: Option<PostgresS3UploadStoreConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalUploadStoreConfig {
  pub root: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PostgresS3UploadStoreConfig {
  pub postgres_url_env: String,
  #[serde(default = "default_postgres_connections")]
  pub max_connections: u32,
  pub s3_bucket: String,
  pub s3_region: String,
  #[serde(default)]
  pub s3_root_certificate: Option<PathBuf>,
  pub s3_endpoint: String,
  pub s3_prefix: String,
  pub s3_access_key_env: String,
  pub s3_secret_key_env: String,
  #[serde(default)]
  pub s3_session_token_env: Option<String>,
  #[serde(default = "default_true")]
  pub s3_virtual_hosted_style: bool,
}

const fn default_postgres_connections() -> u32 {
  8
}

const fn default_true() -> bool {
  true
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UploadProfileConfig {
  pub name: String,
  pub store: String,
  pub public_base_url: Url,
  pub staging_dir: PathBuf,
  pub max_staging_bytes: u64,
  pub control_path_prefix: String,
  pub object_path_prefix: String,
  pub destination: UploadDestinationConfig,
  pub identity: UploadIdentityConfig,
  pub max_upload_bytes: u64,
  pub max_part_bytes: u64,
  pub max_storage_bytes: u64,
  pub max_sessions: u32,
  pub max_parts: u32,
  pub inspection_bytes: u64,
  pub ttl_seconds: u64,
  pub object_ttl_seconds: u64,
  pub max_concurrent_uploads: u32,
  pub max_concurrent_parts: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UploadDestinationConfig {
  Upstream { upstream: String },
  Object,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UploadIdentityKind {
  Ipm,
  ExternalAuth,
  Mtls,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UploadIdentityConfig {
  pub kind: UploadIdentityKind,
  pub source: String,
  #[serde(default)]
  pub subject_field: Option<String>,
}

impl UploadStoreConfig {
  fn validate(&self, index: usize) -> anyhow::Result<()> {
    let prefix = format!("upload_stores[{index}]");
    validate_runtime_identifier(&format!("{prefix}.name"), &self.name)?;
    match self.kind {
      UploadStoreKind::Local => {
        let local = self
          .local
          .as_ref()
          .ok_or_else(|| anyhow::anyhow!("{prefix}.local is required when kind = local"))?;
        if self.postgres_s3.is_some() {
          bail!("{prefix}.postgres_s3 is only allowed when kind = postgres_s3");
        }
        if !local.root.is_absolute()
          || local.root.parent().is_none()
          || local.root.components().any(|part| {
            matches!(
              part,
              std::path::Component::ParentDir | std::path::Component::CurDir
            )
          })
        {
          bail!("{prefix}.local.root must be an absolute dedicated directory without dot segments");
        }
      }
      UploadStoreKind::PostgresS3 => {
        let store = self.postgres_s3.as_ref().ok_or_else(|| {
          anyhow::anyhow!("{prefix}.postgres_s3 is required when kind = postgres_s3")
        })?;
        if self.local.is_some() {
          bail!("{prefix}.local is only allowed when kind = local");
        }
        validate_environment_name(
          &format!("{prefix}.postgres_s3.postgres_url_env"),
          &store.postgres_url_env,
        )?;
        validate_environment_name(
          &format!("{prefix}.postgres_s3.s3_access_key_env"),
          &store.s3_access_key_env,
        )?;
        validate_environment_name(
          &format!("{prefix}.postgres_s3.s3_secret_key_env"),
          &store.s3_secret_key_env,
        )?;
        if let Some(name) = &store.s3_session_token_env {
          validate_environment_name(&format!("{prefix}.postgres_s3.s3_session_token_env"), name)?;
        }
        if store.max_connections == 0 || store.max_connections > 64 {
          bail!("{prefix}.postgres_s3.max_connections must be within 1..=64");
        }
        if store.s3_bucket.is_empty() || store.s3_bucket.len() > 255 {
          bail!("{prefix}.postgres_s3.s3_bucket must be non-empty and bounded");
        }
        if store.s3_region.is_empty()
          || !store
            .s3_region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
          bail!("{prefix}.postgres_s3.s3_region must be a lowercase region identifier");
        }
        let endpoint = Url::parse(&store.s3_endpoint)
          .with_context(|| format!("{prefix}.postgres_s3.s3_endpoint is invalid"))?;
        if endpoint.scheme() != "https"
          || endpoint.host_str().is_none()
          || endpoint.query().is_some()
          || endpoint.fragment().is_some()
          || !endpoint.username().is_empty()
          || endpoint.password().is_some()
        {
          bail!(
            "{prefix}.postgres_s3.s3_endpoint must be an absolute HTTPS URL without query or fragment"
          );
        }
        validate_object_prefix(&format!("{prefix}.postgres_s3.s3_prefix"), &store.s3_prefix)?;
        if store
          .s3_root_certificate
          .as_ref()
          .is_some_and(|path| !path.is_absolute())
        {
          bail!("{prefix}.postgres_s3.s3_root_certificate must be absolute");
        }
      }
    }
    Ok(())
  }
}

impl UploadProfileConfig {
  fn validate(
    &self,
    index: usize,
    stores: &HashSet<&str>,
    upstreams: &HashSet<&str>,
  ) -> anyhow::Result<()> {
    let prefix = format!("upload_profiles[{index}]");
    validate_runtime_identifier(&format!("{prefix}.name"), &self.name)?;
    if !stores.contains(self.store.as_str()) {
      bail!(
        "{prefix}.store references unknown upload store {}",
        self.store
      );
    }
    if self.public_base_url.scheme() != "https"
      || self.public_base_url.host_str().is_none()
      || self.public_base_url.query().is_some()
      || self.public_base_url.fragment().is_some()
      || !self.public_base_url.username().is_empty()
      || self.public_base_url.password().is_some()
      || self.public_base_url.path() != "/"
    {
      bail!("{prefix}.public_base_url must be an absolute HTTPS URL without query or fragment");
    }
    if !self.staging_dir.is_absolute() {
      bail!("{prefix}.staging_dir must be absolute");
    }
    validate_path_prefix(
      &format!("{prefix}.control_path_prefix"),
      &self.control_path_prefix,
    )?;
    validate_path_prefix(
      &format!("{prefix}.object_path_prefix"),
      &self.object_path_prefix,
    )?;
    if prefixes_overlap(&self.control_path_prefix, &self.object_path_prefix) {
      bail!("{prefix}.control_path_prefix and object_path_prefix must not overlap");
    }
    match &self.destination {
      UploadDestinationConfig::Upstream { upstream } => {
        if !upstreams.contains(upstream.as_str()) {
          bail!("{prefix}.destination.upstream references unknown upstream {upstream}");
        }
      }
      UploadDestinationConfig::Object => {}
    }
    validate_runtime_identifier(&format!("{prefix}.identity.source"), &self.identity.source)?;
    match (&self.identity.kind, &self.identity.subject_field) {
      (UploadIdentityKind::ExternalAuth, Some(field))
        if !field.is_empty()
          && field.len() <= 128
          && field
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') => {}
      (UploadIdentityKind::ExternalAuth, _) => {
        bail!("{prefix}.identity.subject_field must select a verified provider subject field")
      }
      (_, Some(_)) => bail!("{prefix}.identity.subject_field is only allowed for external_auth"),
      _ => {}
    }
    if self.max_upload_bytes == 0 || self.max_upload_bytes > MAX_UPLOAD_BYTES {
      bail!("{prefix}.max_upload_bytes must be within 1..={MAX_UPLOAD_BYTES}");
    }
    if self.max_part_bytes == 0 || self.max_part_bytes > self.max_upload_bytes {
      bail!("{prefix}.max_part_bytes must be within 1..=max_upload_bytes");
    }
    if self.max_staging_bytes < self.max_upload_bytes || self.max_staging_bytes > MAX_UPLOAD_BYTES {
      bail!("{prefix}.max_staging_bytes must reserve at least max_upload_bytes and remain bounded");
    }
    if self.max_storage_bytes < self.max_upload_bytes
      || self.max_storage_bytes > MAX_UPLOAD_BYTES.saturating_mul(2)
    {
      bail!("{prefix}.max_storage_bytes must reserve at least max_upload_bytes and remain bounded");
    }
    if self.max_sessions == 0
      || self.max_parts == 0
      || self.max_concurrent_uploads == 0
      || self.max_concurrent_parts == 0
    {
      bail!("{prefix} session, part, and concurrency limits must be nonzero");
    }
    if self.inspection_bytes == 0 || self.inspection_bytes > self.max_upload_bytes {
      bail!("{prefix}.inspection_bytes must be within 1..=max_upload_bytes");
    }
    if self.ttl_seconds == 0
      || self.ttl_seconds > MAX_TTL_SECONDS
      || self.object_ttl_seconds == 0
      || self.object_ttl_seconds > MAX_TTL_SECONDS
    {
      bail!("{prefix} ttl_seconds and object_ttl_seconds must be within 1..={MAX_TTL_SECONDS}");
    }
    Ok(())
  }
}

pub(crate) fn validate_uploads(
  stores: &[UploadStoreConfig],
  profiles: &[UploadProfileConfig],
  routes: &[super::RouteConfig],
  upstreams: &[super::UpstreamConfig],
  external_auth: &[super::ExternalAuthConfig],
  ipm: &super::IpmConfig,
) -> anyhow::Result<()> {
  if stores.len() > MAX_STORES || profiles.len() > MAX_PROFILES {
    bail!("upload_stores and upload_profiles exceed their configured maximum counts");
  }
  let mut names = HashSet::new();
  for (index, store) in stores.iter().enumerate() {
    store.validate(index)?;
    if !names.insert(store.name.as_str()) {
      bail!("duplicate upload store name {}", store.name);
    }
  }
  let upstream_names = upstreams
    .iter()
    .map(|item| item.name.as_str())
    .collect::<HashSet<_>>();
  let mut profile_names = HashSet::new();
  for (index, profile) in profiles.iter().enumerate() {
    profile.validate(index, &names, &upstream_names)?;
    if profile.identity.kind == UploadIdentityKind::ExternalAuth
      && !external_auth
        .iter()
        .any(|auth| auth.name == profile.identity.source)
    {
      bail!(
        "upload profile {} references unknown external_auth {}",
        profile.name,
        profile.identity.source
      );
    }
    if !profile_names.insert(profile.name.as_str()) {
      bail!("duplicate upload profile name {}", profile.name);
    }
  }
  for route in routes {
    let Some(profile_name) = &route.resumable_upload else {
      continue;
    };
    let profile = profiles
      .iter()
      .find(|profile| profile.name == *profile_name)
      .ok_or_else(|| {
        anyhow::anyhow!(
          "route {} references unknown resumable_upload profile {}",
          route.name,
          profile_name
        )
      })?;
    validate_managed_route(route, profile)?;
    if route.cache.is_some()
      || route.retry.is_some()
      || route.static_root.is_some()
      || route.ct_log.is_some()
      || route.actions.redirect.is_some()
      || route.actions.direct_response.is_some()
      || route.connect_tunneling
      || route.generic_http_upgrade
      || route.grpc_web
    {
      bail!(
        "route {} resumable_upload is incompatible with cache, retry, tunnels, upgrades, or grpc_web",
        route.name
      );
    }
    if route.external_auth.as_ref().is_some_and(|provider| {
      external_auth
        .iter()
        .any(|auth| &auth.name == provider && auth.max_request_body_bytes > 0)
    }) {
      bail!(
        "route {} managed upload authorization must not consume the part body",
        route.name
      );
    }
    // Managed delivery is selected exclusively by the operator profile. The
    // ordinary route backend remains available for non-upload requests (and
    // can be controller-generated); it cannot redirect managed completion.
    match profile.identity.kind {
      UploadIdentityKind::Ipm
        if !route.ipm.enabled || !ipm.enabled || profile.identity.source != ipm.namespace =>
      {
        bail!(
          "route {} resumable_upload IPM identity requires route.ipm.enabled",
          route.name
        );
      }
      UploadIdentityKind::ExternalAuth
        if route.external_auth.as_deref() != Some(profile.identity.source.as_str()) =>
      {
        bail!(
          "route {} resumable_upload external_auth identity must match route.external_auth",
          route.name
        );
      }
      UploadIdentityKind::Mtls
        if !route.r#match.tls.client_cert.has_conditions()
          || route.r#match.tls.client_cert.present == Some(false) =>
      {
        bail!(
          "route {} resumable_upload mTLS identity requires a client certificate matcher",
          route.name
        );
      }
      _ => {}
    }
  }
  for (index, left) in profiles.iter().enumerate() {
    for right in profiles.iter().skip(index + 1) {
      if same_origin(&left.public_base_url, &right.public_base_url)
        && (prefixes_overlap(&left.control_path_prefix, &right.object_path_prefix)
          || prefixes_overlap(&left.object_path_prefix, &right.control_path_prefix))
      {
        bail!(
          "upload profiles {} and {} have overlapping control and object prefixes",
          left.name,
          right.name
        );
      }
      if same_origin(&left.public_base_url, &right.public_base_url)
        && prefixes_overlap(&left.control_path_prefix, &right.control_path_prefix)
      {
        bail!(
          "upload profiles {} and {} have overlapping control prefixes",
          left.name,
          right.name
        );
      }
      if same_origin(&left.public_base_url, &right.public_base_url)
        && prefixes_overlap(&left.object_path_prefix, &right.object_path_prefix)
      {
        bail!(
          "upload profiles {} and {} have overlapping object prefixes",
          left.name,
          right.name
        );
      }
    }
  }
  Ok(())
}

fn validate_managed_route(
  route: &super::RouteConfig,
  profile: &UploadProfileConfig,
) -> anyhow::Result<()> {
  let host = profile
    .public_base_url
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("upload public base URL is missing host"))?;
  if !route
    .hosts
    .iter()
    .any(|pattern| host_matches(pattern, host))
  {
    bail!(
      "route {} resumable_upload public_base_url host is not covered by route hosts",
      route.name
    );
  }
  let route_prefix = route.effective_path_prefix();
  if !prefix_contains(route_prefix, &profile.control_path_prefix)
    || !prefix_contains(route_prefix, &profile.object_path_prefix)
  {
    bail!(
      "route {} resumable_upload control and object prefixes must lie below its path prefix",
      route.name
    );
  }
  if !route.r#match.methods.is_empty()
    || !route.r#match.headers.is_empty()
    || !route.r#match.queries.is_empty()
    || !route.r#match.source_cidrs.is_empty()
    || !route.r#match.protocols.is_empty()
    || route.r#match.path.exact.is_some()
    || route.r#match.path.regex.is_some()
  {
    bail!(
      "route {} resumable_upload requires a prefix-only route matcher without method or conditional filters",
      route.name
    );
  }
  Ok(())
}

fn host_matches(pattern: &str, host: &str) -> bool {
  pattern == "*"
    || pattern.eq_ignore_ascii_case(host)
    || pattern.strip_prefix("*.").is_some_and(|suffix| {
      host
        .to_ascii_lowercase()
        .strip_suffix(&suffix.to_ascii_lowercase())
        .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
    })
}

fn same_origin(left: &Url, right: &Url) -> bool {
  left.scheme() == right.scheme()
    && left.host_str() == right.host_str()
    && left.port_or_known_default() == right.port_or_known_default()
}

fn prefix_contains(parent: &str, child: &str) -> bool {
  parent == "/"
    || child == parent
    || child
      .strip_prefix(parent)
      .is_some_and(|rest| rest.starts_with('/'))
}

fn prefixes_overlap(left: &str, right: &str) -> bool {
  prefix_contains(left, right) || prefix_contains(right, left)
}

fn validate_path_prefix(field: &str, value: &str) -> anyhow::Result<()> {
  if value.len() > 1024
    || !value.starts_with('/')
    || value.contains('?')
    || value.contains('#')
    || value.split('/').any(|part| part == "." || part == "..")
  {
    bail!("{field} must be a bounded absolute path prefix without dot segments");
  }
  Ok(())
}

fn validate_object_prefix(field: &str, value: &str) -> anyhow::Result<()> {
  if value.is_empty()
    || value.len() > 1024
    || value.starts_with('/')
    || value
      .split('/')
      .any(|part| part.is_empty() || part == "." || part == "..")
  {
    bail!("{field} must be a bounded relative object prefix");
  }
  Ok(())
}

fn validate_environment_name(field: &str, value: &str) -> anyhow::Result<()> {
  if value.is_empty()
    || value.len() > 128
    || !value.bytes().enumerate().all(|(index, byte)| {
      byte == b'_' || byte.is_ascii_uppercase() || (index > 0 && byte.is_ascii_digit())
    })
  {
    bail!("{field} must be a conventional environment variable name");
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn public_origin_coverage_requires_a_hostname_label_boundary() {
    assert!(host_matches("*.example.com", "uploads.example.com"));
    assert!(host_matches("*.EXAMPLE.COM", "uploads.example.com"));
    assert!(!host_matches("*.example.com", "evilexample.com"));
    assert!(!host_matches("*.example.com", "example.com"));
    assert!(!host_matches("uploads.example.com", "other.example.com"));
  }

  #[test]
  fn local_store_requires_a_dedicated_non_root_path() {
    for root in ["/", "/tmp/..", "relative"] {
      let store = UploadStoreConfig {
        name: "uploads".to_string(),
        kind: UploadStoreKind::Local,
        local: Some(LocalUploadStoreConfig { root: root.into() }),
        postgres_s3: None,
      };
      assert!(store.validate(0).is_err(), "{root}");
    }
  }
}
