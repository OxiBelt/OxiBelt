//! Fail-closed handling for Gateway API backend client certificate references.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use rustls::sign::CertifiedKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::Decode;

use super::cli::SourceSecretAllowlistEntry;
use super::model::{KubernetesObject, ObjectKey};
use super::rollout::{
  MANAGED_BY_LABEL, ROLLOUT_TARGET_KIND_LABEL, ROLLOUT_TARGET_LABEL, RolloutTarget,
};

pub const CERTIFICATE_DATA_KEY: &str = "tls.crt";
pub const PRIVATE_KEY_DATA_KEY: &str = "tls.key";
pub const CLIENT_IDENTITY_MOUNT_DIRECTORY: &str = "upstream-client";
pub const DERIVED_SECRET_PREFIX: &str = "oxibelt-upstream-client-";
pub const DERIVED_SECRET_SOURCE_ANNOTATION: &str = "oxibelt.dev/upstream-client-source";
pub const DERIVED_SECRET_SOURCE_UID_ANNOTATION: &str = "oxibelt.dev/upstream-client-source-uid";
pub const DERIVED_SECRET_SOURCE_VERSION_ANNOTATION: &str =
  "oxibelt.dev/upstream-client-source-version";

const CONTROLLER_NAME: &str = "oxibelt-gateway-controller";
pub(crate) const MAX_CERTIFICATE_BYTES: usize = 256 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATES: usize = 16;

pub fn gateway_secret_reference(gateway: &KubernetesObject) -> Result<Option<ObjectKey>, String> {
  let Some(reference) = gateway.spec.pointer("/tls/backend/clientCertificateRef") else {
    return Ok(None);
  };
  let reference = reference
    .as_object()
    .ok_or_else(|| "spec.tls.backend.clientCertificateRef must be an object".to_string())?;
  if let Some(field) = reference
    .keys()
    .find(|field| !["group", "kind", "name", "namespace"].contains(&field.as_str()))
  {
    return Err(format!(
      "spec.tls.backend.clientCertificateRef.{field} is unsupported"
    ));
  }
  let group = reference.get("group").and_then(Value::as_str).unwrap_or("");
  let kind = reference
    .get("kind")
    .and_then(Value::as_str)
    .unwrap_or("Secret");
  if !group.is_empty() || kind != "Secret" {
    return Err("spec.tls.backend.clientCertificateRef must select a core Secret".to_string());
  }
  let name = reference
    .get("name")
    .and_then(Value::as_str)
    .ok_or_else(|| "spec.tls.backend.clientCertificateRef.name is required".to_string())?;
  let namespace = reference
    .get("namespace")
    .and_then(Value::as_str)
    .unwrap_or_else(|| gateway.namespace());
  super::rollout::validate_kubernetes_dns_label("client certificate Secret namespace", namespace)
    .map_err(|_| {
    "spec.tls.backend.clientCertificateRef.namespace is not a Kubernetes DNS label".to_string()
  })?;
  super::rollout::validate_kubernetes_dns_subdomain("client certificate Secret name", name)
    .map_err(|_| {
      "spec.tls.backend.clientCertificateRef.name is not a Kubernetes DNS subdomain".to_string()
    })?;
  Ok(Some(ObjectKey {
    namespace: namespace.to_string(),
    name: name.to_string(),
  }))
}

#[derive(Clone, Eq, PartialEq)]
pub struct ClientIdentityMaterial {
  pub derived_secret_name: String,
  pub source: ObjectKey,
  pub source_uid: String,
  pub source_resource_version: String,
  pub certificate_data: String,
  pub private_key_data: String,
}

impl std::fmt::Debug for ClientIdentityMaterial {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("ClientIdentityMaterial")
      .field("derived_secret_name", &self.derived_secret_name)
      .field("source", &self.source)
      .field("source_uid", &"[redacted]")
      .field("source_resource_version", &"[redacted]")
      .field("certificate_data", &"[redacted]")
      .field("private_key_data", &"[redacted]")
      .finish()
  }
}

impl ClientIdentityMaterial {
  pub fn cert_chain_path(&self) -> String {
    format!(
      "{CLIENT_IDENTITY_MOUNT_DIRECTORY}/{}/{CERTIFICATE_DATA_KEY}",
      self.derived_secret_name
    )
  }

  pub fn private_key_path(&self) -> String {
    format!(
      "{CLIENT_IDENTITY_MOUNT_DIRECTORY}/{}/{PRIVATE_KEY_DATA_KEY}",
      self.derived_secret_name
    )
  }

  pub fn manifest(&self, target: &RolloutTarget) -> Value {
    json!({
      "apiVersion": "v1",
      "kind": "Secret",
      "metadata": {
        "name": self.derived_secret_name,
        "namespace": target.namespace,
        "labels": {
          (MANAGED_BY_LABEL): CONTROLLER_NAME,
          (ROLLOUT_TARGET_LABEL): target.name,
          (ROLLOUT_TARGET_KIND_LABEL): target.kind.label_value(),
        },
        "annotations": {
          (DERIVED_SECRET_SOURCE_ANNOTATION): format!("{}/{}", self.source.namespace, self.source.name),
          (DERIVED_SECRET_SOURCE_UID_ANNOTATION): self.source_uid,
          (DERIVED_SECRET_SOURCE_VERSION_ANNOTATION): self.source_resource_version,
        },
      },
      "immutable": true,
      "type": "kubernetes.io/tls",
      "data": {
        (CERTIFICATE_DATA_KEY): self.certificate_data,
        (PRIVATE_KEY_DATA_KEY): self.private_key_data,
      },
    })
  }

  pub fn matches_existing(&self, target: &RolloutTarget, existing: &Value) -> bool {
    existing.pointer("/metadata/name").and_then(Value::as_str)
      == Some(self.derived_secret_name.as_str())
      && existing
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        == Some(target.namespace.as_str())
      && existing.get("immutable").and_then(Value::as_bool) == Some(true)
      && existing.get("type").and_then(Value::as_str) == Some("kubernetes.io/tls")
      && existing
        .pointer(&format!("/data/{CERTIFICATE_DATA_KEY}"))
        .and_then(Value::as_str)
        == Some(self.certificate_data.as_str())
      && existing
        .pointer(&format!("/data/{PRIVATE_KEY_DATA_KEY}"))
        .and_then(Value::as_str)
        == Some(self.private_key_data.as_str())
      && metadata_value(existing, "labels", MANAGED_BY_LABEL) == Some(CONTROLLER_NAME)
      && metadata_value(existing, "labels", ROLLOUT_TARGET_LABEL) == Some(target.name.as_str())
      && metadata_value(existing, "labels", ROLLOUT_TARGET_KIND_LABEL)
        == Some(target.kind.label_value())
  }
}

fn metadata_value<'a>(object: &'a Value, field: &str, key: &str) -> Option<&'a str> {
  object.get("metadata")?.get(field)?.get(key)?.as_str()
}

pub fn allowlist_by_source(
  entries: &[SourceSecretAllowlistEntry],
) -> BTreeMap<ObjectKey, &SourceSecretAllowlistEntry> {
  entries
    .iter()
    .map(|entry| {
      (
        ObjectKey {
          namespace: entry.namespace.clone(),
          name: entry.name.clone(),
        },
        entry,
      )
    })
    .collect()
}

pub fn validate_source_secret(
  secret: &KubernetesObject,
  allowlist: &SourceSecretAllowlistEntry,
) -> anyhow::Result<ClientIdentityMaterial> {
  if secret.kind != "Secret"
    || !matches!(
      secret.resource_type.as_deref(),
      Some("kubernetes.io/tls" | "Opaque")
    )
  {
    bail!("client certificate Secret must use type kubernetes.io/tls or Opaque");
  }
  let certificate_data = secret
    .data
    .get(&allowlist.certificate_key)
    .context("client certificate Secret is missing the configured certificate key")?;
  let private_key_data = secret
    .data
    .get(&allowlist.private_key_key)
    .context("client certificate Secret is missing the configured private-key key")?;
  let certificate_bytes = decode_base64_bounded(certificate_data, MAX_CERTIFICATE_BYTES)
    .context("client certificate Secret certificate value is invalid")?;
  let private_key_bytes = decode_base64_bounded(private_key_data, MAX_PRIVATE_KEY_BYTES)
    .context("client certificate Secret private-key value is invalid")?;

  let certificates = CertificateDer::pem_slice_iter(&certificate_bytes)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| anyhow::anyhow!("client certificate Secret certificate chain is malformed"))?;
  if certificates.is_empty() || certificates.len() > MAX_CERTIFICATES {
    bail!(
      "client certificate Secret certificate chain must contain 1 to {MAX_CERTIFICATES} certificates"
    );
  }
  let mut private_keys = PrivateKeyDer::pem_slice_iter(&private_key_bytes)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| {
      anyhow::anyhow!("client certificate Secret private key is malformed or encrypted")
    })?;
  if private_keys.len() != 1 {
    bail!("client certificate Secret must contain exactly one unencrypted private key");
  }
  let private_key = private_keys.pop().context("private key disappeared")?;
  CertifiedKey::from_der(
    certificates.clone(),
    private_key,
    &rustls::crypto::aws_lc_rs::default_provider(),
  )
  .map_err(|_| {
    anyhow::anyhow!("client certificate Secret certificate and private key do not match")
  })?;

  let leaf = Certificate::from_der(certificates[0].as_ref())
    .map_err(|_| anyhow::anyhow!("client certificate Secret leaf certificate is malformed"))?;
  let validity = leaf.tbs_certificate().validity();
  let not_before = validity.not_before.to_unix_duration().as_secs();
  let not_after = validity.not_after.to_unix_duration().as_secs();
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_err(|_| anyhow::anyhow!("client certificate Secret validity could not be evaluated"))?
    .as_secs();
  if now < not_before {
    bail!("client certificate Secret leaf certificate is not yet valid");
  }
  if now > not_after {
    bail!("client certificate Secret leaf certificate is expired");
  }

  let source_uid = secret
    .metadata
    .uid
    .as_deref()
    .filter(|value| !value.is_empty())
    .context("client certificate Secret metadata.uid is required")?;
  let source_resource_version = secret
    .metadata
    .resource_version
    .as_deref()
    .filter(|value| !value.is_empty())
    .context("client certificate Secret metadata.resourceVersion is required")?;
  let derived_secret_name = derived_secret_name(secret, &certificate_bytes);
  Ok(ClientIdentityMaterial {
    derived_secret_name,
    source: secret.key(),
    source_uid: source_uid.to_string(),
    source_resource_version: source_resource_version.to_string(),
    certificate_data: certificate_data.to_string(),
    private_key_data: private_key_data.to_string(),
  })
}

fn derived_secret_name(secret: &KubernetesObject, certificate_bytes: &[u8]) -> String {
  derived_secret_name_for_source(
    secret.namespace(),
    secret.name(),
    secret.metadata.uid.as_deref().unwrap_or(""),
    secret.metadata.resource_version.as_deref().unwrap_or(""),
    certificate_bytes,
  )
}

pub(crate) fn derived_secret_name_for_source(
  namespace: &str,
  name: &str,
  source_uid: &str,
  source_resource_version: &str,
  certificate_bytes: &[u8],
) -> String {
  let certificate_digest = hex_digest(&Sha256::digest(certificate_bytes));
  let mut identity = Sha256::new();
  identity.update(b"oxibelt-gateway-upstream-client-v1\0");
  for value in [
    namespace,
    name,
    source_uid,
    source_resource_version,
    &certificate_digest,
  ] {
    identity.update(value.as_bytes());
    identity.update(b"\0");
  }
  let identity = hex_digest(&identity.finalize());
  format!("{DERIVED_SECRET_PREFIX}{}", &identity[..32])
}

pub(crate) fn decode_base64_bounded(value: &str, maximum: usize) -> anyhow::Result<Vec<u8>> {
  if value.is_empty() || value.len() > maximum.saturating_mul(4).saturating_add(4) {
    bail!("encoded value is empty or exceeds its limit");
  }
  if !value.len().is_multiple_of(4) || !value.is_ascii() {
    bail!("encoded value is not canonical base64");
  }
  let mut decoded = Vec::with_capacity(value.len() / 4 * 3);
  for (chunk_index, chunk) in value.as_bytes().chunks_exact(4).enumerate() {
    let last = chunk_index + 1 == value.len() / 4;
    let padding = usize::from(chunk[3] == b'=') + usize::from(chunk[2] == b'=');
    if (!last && padding != 0) || padding > 2 || (chunk[2] == b'=' && chunk[3] != b'=') {
      bail!("encoded value has invalid padding");
    }
    let a = base64_value(chunk[0]).context("encoded value contains an invalid character")?;
    let b = base64_value(chunk[1]).context("encoded value contains an invalid character")?;
    let c = if chunk[2] == b'=' {
      0
    } else {
      base64_value(chunk[2]).context("encoded value contains an invalid character")?
    };
    let d = if chunk[3] == b'=' {
      0
    } else {
      base64_value(chunk[3]).context("encoded value contains an invalid character")?
    };
    if (padding == 2 && b & 0x0f != 0) || (padding == 1 && c & 0x03 != 0) {
      bail!("encoded value is not canonical base64");
    }
    decoded.push((a << 2) | (b >> 4));
    if padding < 2 {
      decoded.push((b << 4) | (c >> 2));
    }
    if padding == 0 {
      decoded.push((c << 6) | d);
    }
    if decoded.len() > maximum {
      bail!("decoded value exceeds its limit");
    }
  }
  Ok(decoded)
}

fn base64_value(byte: u8) -> Option<u8> {
  match byte {
    b'A'..=b'Z' => Some(byte - b'A'),
    b'a'..=b'z' => Some(byte - b'a' + 26),
    b'0'..=b'9' => Some(byte - b'0' + 52),
    b'+' => Some(62),
    b'/' => Some(63),
    _ => None,
  }
}

fn hex_digest(digest: &[u8]) -> String {
  digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn base64_decoder_rejects_noncanonical_and_oversized_values() {
    assert_eq!(decode_base64_bounded("dGVzdA==", 4).unwrap(), b"test");
    assert!(decode_base64_bounded("dGVzdA", 8).is_err());
    assert!(decode_base64_bounded("dGVzdB==", 8).is_err());
    assert!(decode_base64_bounded("dGVzdA==", 3).is_err());
  }

  #[test]
  fn material_debug_output_is_redacted() {
    let material = ClientIdentityMaterial {
      derived_secret_name: "oxibelt-upstream-client-example".to_string(),
      source: ObjectKey {
        namespace: "secret-ns".to_string(),
        name: "source".to_string(),
      },
      source_uid: "sensitive-uid".to_string(),
      source_resource_version: "sensitive-version".to_string(),
      certificate_data: "sensitive-certificate".to_string(),
      private_key_data: "sensitive-private-key".to_string(),
    };
    let output = format!("{material:?}");
    assert!(!output.contains("sensitive"));
    assert!(output.contains("[redacted]"));
  }

  #[test]
  fn source_resource_version_rotation_changes_derived_secret_reference() {
    let source = |resource_version: &str| {
      KubernetesObject::from_value(json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
          "namespace": "client-secrets",
          "name": "orders-client",
          "uid": "source-uid",
          "resourceVersion": resource_version,
        },
      }))
      .unwrap()
      .pop()
      .unwrap()
    };

    let first = derived_secret_name(&source("17"), b"same-public-certificate");
    let rotated = derived_secret_name(&source("18"), b"same-public-certificate");
    assert_ne!(first, rotated);
    assert!(first.starts_with(DERIVED_SECRET_PREFIX));
    assert!(rotated.starts_with(DERIVED_SECRET_PREFIX));
  }
}
