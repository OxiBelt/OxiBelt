//! Storage-owned copy of validated managed-upload configuration values.
//! The host converts its operator configuration at the activation boundary.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

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
  /// Optional RFC 9842 request decoding policy for this managed profile.
  #[serde(default)]
  pub compression_dictionary: Option<ManagedUploadDictionaryConfig>,
}

/// A managed upload can pin exactly one public configured dictionary.  The
/// referenced dictionary profile controls decode limits and must explicitly
/// allow request decoding.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManagedUploadDictionaryConfig {
  pub profile: String,
  pub dictionary: String,
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
