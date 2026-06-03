//! Serializable Admin API types for IPM resources.
//! Request and response shapes stay here so handlers do not duplicate wire contracts.

use serde::{Deserialize, Serialize};

use crate::config::IpmPolicyStatementConfig;

use super::{IpmEntrySource, IpmSnapshotCounts, RedactedIpmCredential};

/// Admin-visible IPM status snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct IpmAdminStatus {
  pub enabled: bool,
  pub store_enabled: bool,
  pub namespace: String,
  pub generation: i64,
  pub etag: String,
  pub counts: IpmSnapshotCounts,
  pub last_refresh: IpmAdminRefreshStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpmAdminRefreshStatus {
  pub ok: bool,
  pub generation: i64,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpmPrincipalRecord {
  pub id: String,
  pub subject: String,
  pub groups: Vec<String>,
  pub enabled: bool,
  pub source: IpmEntrySource,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpmCredentialCreateResponse {
  pub credential: RedactedIpmCredential,
  pub token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpmCredentialRotateResponse {
  pub credential: RedactedIpmCredential,
  pub token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpmAuditRecord {
  pub id: i64,
  pub namespace: String,
  pub actor: String,
  pub operation: String,
  pub target_kind: Option<String>,
  pub target_id: Option<String>,
  pub resource: Option<String>,
  pub outcome: String,
  pub error: Option<String>,
  pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpmPrincipalCreate {
  pub id: String,
  pub subject: String,
  #[serde(default)]
  pub groups: Vec<String>,
  #[serde(default)]
  pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpmPrincipalPatch {
  #[serde(default)]
  pub subject: Option<String>,
  #[serde(default)]
  pub groups: Option<Vec<String>>,
  #[serde(default)]
  pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpmCredentialCreate {
  #[serde(alias = "name", alias = "credential_id")]
  pub id: String,
  pub principal: String,
  #[serde(default)]
  pub expires_at: Option<String>,
  #[serde(default)]
  pub ttl_seconds: Option<i64>,
  #[serde(default)]
  pub no_expiry: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpmCredentialPatch {
  #[serde(default)]
  pub principal: Option<String>,
  #[serde(default)]
  pub enabled: Option<bool>,
  #[serde(default)]
  pub expires_at: Option<String>,
  #[serde(default)]
  pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpmCredentialRotate {
  #[serde(default = "default_rotation_overlap_seconds")]
  pub overlap_seconds: i64,
  #[serde(default)]
  pub expires_at: Option<String>,
  #[serde(default)]
  pub ttl_seconds: Option<i64>,
  #[serde(default)]
  pub no_expiry: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpmCredentialRevoke {
  #[serde(default)]
  pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpmPolicyCreate {
  pub name: String,
  #[serde(default = "default_policy_version")]
  pub version: String,
  #[serde(default)]
  pub statements: Vec<IpmPolicyStatementConfig>,
  #[serde(default)]
  pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpmPolicyPatch {
  #[serde(default)]
  pub version: Option<String>,
  #[serde(default)]
  pub statements: Option<Vec<IpmPolicyStatementConfig>>,
  #[serde(default)]
  pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpmBindingCreate {
  #[serde(default, alias = "binding_id")]
  pub id: Option<String>,
  #[serde(default)]
  pub principal: Option<String>,
  #[serde(default)]
  pub group: Option<String>,
  pub policy: String,
  #[serde(default)]
  pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Copy)]
pub enum IpmPreconditionError {
  Missing,
  Stale,
}

#[derive(Debug, Clone, Default)]
pub struct IpmAuditQuery {
  pub target_kind: Option<String>,
  pub target_id: Option<String>,
  pub outcome: Option<String>,
  pub actor: Option<String>,
  pub limit: i64,
}

pub fn default_rotation_overlap_seconds() -> i64 {
  86_400
}

fn default_policy_version() -> String {
  "2026-05-23".to_string()
}
