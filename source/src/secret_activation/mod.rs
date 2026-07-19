//! Versioned, redacted secret-reference activation metadata.
//!
//! Runtime snapshots own the resolved material through zeroizing buffers.  The
//! public and durable surfaces receive only revisions and keyed fingerprints.

mod field;
mod preflight;
mod resolver;

use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::config::{AdminMutationRolloutMode, Config};
use crate::state::AppSnapshot;

pub(crate) use field::SecretReferenceField;
use field::collect_reference_specs;
use preflight::{preflight_certificate_material, preflight_upstream_tls};
pub(crate) use resolver::SecretActivationError;
use resolver::{resolve_spec, verify_update_digest};

pub(crate) const SECRET_REFERENCE_SCHEMA_VERSION: u16 = 1;

pub(crate) fn new_local_request_id() -> Result<String, SecretActivationError> {
  let mut bytes = [0_u8; 16];
  crate::crypto::random_fill(&mut bytes).map_err(|_| SecretActivationError::EntropyUnavailable)?;
  Ok(format!("local-{}", lowercase_hex(&bytes)))
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecretReferenceUpdateRequest {
  #[serde(default = "default_schema_version")]
  pub(crate) schema_version: u16,
  pub(crate) field: String,
  pub(crate) reference: String,
  #[serde(default)]
  pub(crate) sha256: Option<String>,
}

impl fmt::Debug for SecretReferenceUpdateRequest {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("SecretReferenceUpdateRequest")
      .field("schema_version", &self.schema_version)
      .field("field", &self.field)
      .field("reference", &"[REDACTED]")
      .field("sha256", &self.sha256.as_ref().map(|_| "[REDACTED]"))
      .finish()
  }
}

const fn default_schema_version() -> u16 {
  SECRET_REFERENCE_SCHEMA_VERSION
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub(crate) enum SecretProviderIdentity {
  Environment = 1,
  ContainedFile = 2,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub(crate) enum SecretMaterialType {
  RemoteSignerToken32 = 1,
  BearerToken = 2,
  OAuthClientId = 3,
  OAuthClientSecret = 4,
  DiscoveryToken = 5,
  TurnSharedSecret = 6,
  TurnPassword = 7,
}

#[derive(Clone)]
struct ResolvedSecretReference {
  field: String,
  _reference: String,
  provider: SecretProviderIdentity,
  material_type: SecretMaterialType,
  reference_fingerprint: [u8; 32],
  material_fingerprint: [u8; 32],
  _material: Arc<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for ResolvedSecretReference {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ResolvedSecretReference")
      .field("field", &self.field)
      .field("reference", &"[REDACTED]")
      .field("provider", &self.provider)
      .field("material_type", &self.material_type)
      .field("reference_fingerprint", &"[REDACTED]")
      .field("material_fingerprint", &"[REDACTED]")
      .field("material", &"[REDACTED]")
      .finish()
  }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SecretActivationBinding {
  pub(crate) mutation_request_id: String,
  pub(crate) config_logical_revision: String,
  pub(crate) reference_set_digest: String,
  pub(crate) runtime_snapshot_revision: String,
  pub(crate) target_revision: String,
}

#[derive(Clone)]
pub(crate) struct SecretReferenceRuntime {
  fingerprint_key: Arc<Zeroizing<[u8; 32]>>,
  entries: Arc<[ResolvedSecretReference]>,
  reference_set_digest: String,
  binding: Option<SecretActivationBinding>,
}

impl fmt::Debug for SecretReferenceRuntime {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("SecretReferenceRuntime")
      .field("entry_count", &self.entries.len())
      .field("reference_set_digest", &self.reference_set_digest)
      .field("binding", &self.binding)
      .finish_non_exhaustive()
  }
}

impl SecretReferenceRuntime {
  pub(crate) fn from_config(
    config: &Config,
    previous: Option<&Self>,
  ) -> Result<Self, SecretActivationError> {
    let fingerprint_key = match fingerprint_key_for_config(config, previous)? {
      Some(key) => key,
      None => {
        let mut key = Zeroizing::new([0_u8; 32]);
        crate::crypto::random_fill(key.as_mut())
          .map_err(|_| SecretActivationError::EntropyUnavailable)?;
        Arc::new(key)
      }
    };
    let mut entries = Vec::new();
    for spec in collect_reference_specs(config)? {
      let material = resolve_spec(&spec)?;
      let reference_fingerprint = fingerprint(
        &fingerprint_key[..],
        b"oxibelt.secret-reference.identity/v1\0",
        spec.reference.as_bytes(),
      );
      let material_fingerprint = fingerprint(
        &fingerprint_key[..],
        b"oxibelt.secret-reference.material/v1\0",
        material.as_slice(),
      );
      entries.push(ResolvedSecretReference {
        field: spec.field.canonical(),
        _reference: spec.reference,
        provider: spec.provider,
        material_type: spec.material_type,
        reference_fingerprint,
        material_fingerprint,
        _material: Arc::new(material),
      });
    }
    entries.sort_by(|left, right| left.field.cmp(&right.field));
    let reference_set_digest = reference_set_digest(&entries);
    Ok(Self {
      fingerprint_key,
      entries: entries.into(),
      reference_set_digest,
      binding: None,
    })
  }

  pub(crate) fn bind_with_runtime_revision(
    mut self,
    mutation_request_id: String,
    config_logical_revision: String,
    target_revision: String,
    assigned_runtime_revision: Option<String>,
  ) -> Self {
    let mut transcript = Zeroizing::new(Vec::new());
    transcript.extend_from_slice(b"OXIBELT-SECRET-RUNTIME-SNAPSHOT-V1\0");
    append_framed(&mut transcript, mutation_request_id.as_bytes());
    append_framed(&mut transcript, config_logical_revision.as_bytes());
    append_framed(&mut transcript, self.reference_set_digest.as_bytes());
    append_framed(&mut transcript, target_revision.as_bytes());
    let runtime_snapshot_revision =
      assigned_runtime_revision.unwrap_or_else(|| sha256_labelled(&transcript));
    self.binding = Some(SecretActivationBinding {
      mutation_request_id,
      config_logical_revision,
      reference_set_digest: self.reference_set_digest.clone(),
      runtime_snapshot_revision,
      target_revision,
    });
    self
  }

  pub(crate) fn reference_set_digest(&self) -> &str {
    &self.reference_set_digest
  }

  pub(crate) fn binding(&self) -> Option<&SecretActivationBinding> {
    self.binding.as_ref()
  }

  #[cfg(test)]
  pub(crate) fn material_lifetime_probe(&self) -> Option<std::sync::Weak<Zeroizing<Vec<u8>>>> {
    self
      .entries
      .first()
      .map(|entry| Arc::downgrade(&entry._material))
  }
}

pub(crate) async fn build_candidate_snapshot(
  active: &AppSnapshot,
  request: &SecretReferenceUpdateRequest,
  mutation_request_id: String,
  logical_revision: String,
  target_revision: String,
  assigned_runtime_revision: Option<String>,
) -> Result<AppSnapshot, SecretActivationError> {
  let mut config = active.config.clone();
  let field = apply_reference_update(&mut config, request)?;
  config
    .validate()
    .map_err(|error| SecretActivationError::classify_candidate_error(&error.to_string()))?;
  preflight_certificate_material(&config)?;
  // Resolve the complete candidate reference set before constructing any of
  // its dependent clients. This preserves the typed, redacted provider error
  // at the activation boundary and ensures every later build step consumes an
  // already validated set of references.
  let secret_references =
    SecretReferenceRuntime::from_config(&config, Some(&active.secret_references))?;
  let mut snapshot = AppSnapshot::new_with_previous(config, Some(active))
    .await
    .map_err(|error| SecretActivationError::classify_candidate_error(&error.to_string()))?;
  preflight_upstream_tls(&snapshot, &field).await?;
  snapshot.secret_references = secret_references.bind_with_runtime_revision(
    mutation_request_id,
    logical_revision,
    target_revision,
    assigned_runtime_revision,
  );
  Ok(snapshot)
}

pub(crate) fn apply_reference_update(
  config: &mut Config,
  update: &SecretReferenceUpdateRequest,
) -> Result<SecretReferenceField, SecretActivationError> {
  let field = validate_update_request(update)?;
  field.apply(config, update)?;
  if field.is_file() {
    let path = config
      .tls
      .remote_signer
      .token_file
      .as_deref()
      .ok_or(SecretActivationError::ProviderUnavailable)?;
    let digest = update
      .sha256
      .as_deref()
      .ok_or(SecretActivationError::InvalidReference)?;
    verify_update_digest(path, digest)?;
  }
  Ok(field)
}

pub(crate) fn validate_update_request(
  update: &SecretReferenceUpdateRequest,
) -> Result<SecretReferenceField, SecretActivationError> {
  if update.schema_version != SECRET_REFERENCE_SCHEMA_VERSION {
    return Err(SecretActivationError::UnsupportedVersion);
  }
  let field = SecretReferenceField::parse(&update.field)?;
  if update.reference.is_empty()
    || update.reference.len() > 512
    || update.reference.chars().any(char::is_control)
    || update.reference.contains("-----BEGIN")
    || update.reference.contains("-----END")
    || update.reference.contains("://")
  {
    return Err(SecretActivationError::InvalidReference);
  }
  if field.is_file() {
    let path = std::path::Path::new(&update.reference);
    if path.is_absolute()
      || path
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
      return Err(SecretActivationError::InvalidReference);
    }
    let digest = update
      .sha256
      .as_deref()
      .ok_or(SecretActivationError::InvalidReference)?;
    if digest.len() != 64
      || !digest
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
      return Err(SecretActivationError::InvalidReference);
    }
  } else {
    let mut bytes = update.reference.bytes();
    let first = bytes
      .next()
      .ok_or(SecretActivationError::InvalidReference)?;
    if update.reference.len() > 128
      || !(first == b'_' || first.is_ascii_uppercase())
      || !bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
      || update.sha256.is_some()
    {
      return Err(SecretActivationError::InvalidReference);
    }
  }
  Ok(field)
}

fn fingerprint_key_for_config(
  config: &Config,
  previous: Option<&SecretReferenceRuntime>,
) -> Result<Option<Arc<Zeroizing<[u8; 32]>>>, SecretActivationError> {
  if config.admin.mutations.rollout.mode != AdminMutationRolloutMode::AdminCluster {
    return Ok(previous.map(|runtime| runtime.fingerprint_key.clone()));
  }
  let encoded = Zeroizing::new(
    std::env::var(&config.admin.mutations.artifact_key_env)
      .map_err(|_| SecretActivationError::ProviderUnavailable)?,
  );
  let decoded = Zeroizing::new(
    base64::engine::general_purpose::STANDARD
      .decode(encoded.trim())
      .map_err(|_| SecretActivationError::WrongMaterialType)?,
  );
  if decoded.len() != 32 {
    return Err(SecretActivationError::WrongMaterialType);
  }
  let mut key = Zeroizing::new([0_u8; 32]);
  crate::crypto::hkdf_sha256(
    b"oxibelt.secret-reference.fingerprint-salt/v1",
    &decoded,
    b"oxibelt.secret-reference.fingerprint-key/v1",
    key.as_mut(),
  )
  .map_err(|_| SecretActivationError::EntropyUnavailable)?;
  Ok(Some(Arc::new(key)))
}

fn fingerprint(key: &[u8], domain: &[u8], value: &[u8]) -> [u8; 32] {
  let mut input = Zeroizing::new(Vec::with_capacity(domain.len() + value.len() + 8));
  input.extend_from_slice(domain);
  append_framed(&mut input, value);
  crate::crypto::hmac_sha256(key, &input)
}

fn reference_set_digest(entries: &[ResolvedSecretReference]) -> String {
  let mut input = Zeroizing::new(Vec::new());
  input.extend_from_slice(b"OXIBELT-SECRET-REFERENCE-SET-V1\0");
  for entry in entries {
    append_framed(&mut input, entry.field.as_bytes());
    input.push(entry.provider as u8);
    input.push(entry.material_type as u8);
    input.extend_from_slice(&entry.reference_fingerprint);
    input.extend_from_slice(&entry.material_fingerprint);
  }
  sha256_labelled(&input)
}

fn append_framed(target: &mut Vec<u8>, value: &[u8]) {
  target.extend_from_slice(&(value.len() as u64).to_be_bytes());
  target.extend_from_slice(value);
}

fn sha256_labelled(value: &[u8]) -> String {
  format!("sha256:{}", lowercase_hex(&Sha256::digest(value)))
}

fn lowercase_hex(value: &[u8]) -> String {
  let mut output = String::with_capacity(value.len() * 2);
  for byte in value {
    use std::fmt::Write as _;
    let _ = write!(output, "{byte:02x}");
  }
  output
}

#[cfg(test)]
mod tests;
