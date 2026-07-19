use std::fmt;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::field::SecretReferenceSpec;
use super::{SecretMaterialType, SecretProviderIdentity};

const MAX_SECRET_BYTES: u64 = 1024 * 1024;
const MAX_TEXT_SECRET_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SecretActivationError {
  UnsupportedVersion,
  FieldNotAllowlisted,
  InvalidReference,
  TargetNotFound,
  TargetAmbiguous,
  ReferenceMissing,
  ReferenceUnauthorized,
  ProviderUnavailable,
  WrongMaterialType,
  MaterialTooLarge,
  DigestMismatch,
  CandidateInvalid,
  CertificateKeyMismatch,
  CertificateExpired,
  CertificateNotYetValid,
  CaBundleInvalid,
  UpstreamTlsPreflightFailed,
  HostnameValidationFailed,
  ClientIdentityUnusable,
  ActivationConflict,
  ValidationEvidenceMismatch,
  RollbackFailed,
  EntropyUnavailable,
}

impl fmt::Display for SecretActivationError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.code())
  }
}

impl std::error::Error for SecretActivationError {}

impl SecretActivationError {
  pub(crate) const fn code(self) -> &'static str {
    match self {
      Self::UnsupportedVersion => "secret_reference_version_unsupported",
      Self::FieldNotAllowlisted => "secret_reference_field_not_allowlisted",
      Self::InvalidReference => "secret_reference_invalid",
      Self::TargetNotFound => "secret_reference_target_not_found",
      Self::TargetAmbiguous => "secret_reference_target_ambiguous",
      Self::ReferenceMissing => "secret_reference_missing",
      Self::ReferenceUnauthorized => "secret_reference_unauthorized",
      Self::ProviderUnavailable => "secret_reference_provider_unavailable",
      Self::WrongMaterialType => "secret_reference_type_mismatch",
      Self::MaterialTooLarge => "secret_reference_size_exceeded",
      Self::DigestMismatch => "secret_reference_digest_mismatch",
      Self::CandidateInvalid => "secret_material_invalid_format",
      Self::CertificateKeyMismatch => "secret_certificate_key_mismatch",
      Self::CertificateExpired => "secret_certificate_expired",
      Self::CertificateNotYetValid => "secret_certificate_not_yet_valid",
      Self::CaBundleInvalid => "secret_ca_bundle_invalid",
      Self::UpstreamTlsPreflightFailed => "secret_upstream_tls_preflight_failed",
      Self::HostnameValidationFailed => "secret_hostname_validation_failed",
      Self::ClientIdentityUnusable => "secret_client_identity_unusable",
      Self::ActivationConflict => "secret_activation_snapshot_conflict",
      Self::ValidationEvidenceMismatch => "secret_activation_validation_evidence_mismatch",
      Self::RollbackFailed => "secret_activation_rollback_failed",
      Self::EntropyUnavailable => "secret_activation_entropy_unavailable",
    }
  }

  pub(crate) fn classify_candidate_error(message: &str) -> Self {
    let message = message.to_ascii_lowercase();
    if message.contains("expired") {
      Self::CertificateExpired
    } else if message.contains("not yet valid") || message.contains("not-before") {
      Self::CertificateNotYetValid
    } else if (message.contains("private key") && message.contains("certificate"))
      || message.contains("keysmismatch")
      || message.contains("keys mismatch")
      || message.contains("key mismatch")
      || message.contains("key does not match")
    {
      Self::CertificateKeyMismatch
    } else if message.contains("ca bundle") || message.contains("ca certificate") {
      Self::CaBundleInvalid
    } else if message.contains("client identity") || message.contains("client certificate") {
      Self::ClientIdentityUnusable
    } else if message.contains("hostname") || message.contains("sni") {
      Self::HostnameValidationFailed
    } else if message.contains("tls handshake") || message.contains("tls connect") {
      Self::UpstreamTlsPreflightFailed
    } else {
      Self::CandidateInvalid
    }
  }
}

pub(super) fn resolve_spec(
  spec: &SecretReferenceSpec,
) -> Result<Zeroizing<Vec<u8>>, SecretActivationError> {
  let raw = match spec.provider {
    SecretProviderIdentity::Environment => resolve_environment(&spec.reference)?,
    SecretProviderIdentity::ContainedFile => {
      let path = spec
        .file_path
        .as_ref()
        .ok_or(SecretActivationError::ProviderUnavailable)?;
      read_bounded_file(path)?
    }
  };
  normalize_material(spec.material_type, raw)
}

pub(super) fn resolve_contained_file_path(
  base: &Path,
  relative: &Path,
) -> Result<PathBuf, SecretActivationError> {
  if relative.as_os_str().is_empty()
    || relative.is_absolute()
    || relative
      .components()
      .any(|component| !matches!(component, Component::Normal(_)))
  {
    return Err(SecretActivationError::InvalidReference);
  }
  let base = base
    .canonicalize()
    .map_err(|_| SecretActivationError::ProviderUnavailable)?;
  let mut current = base.clone();
  for component in relative.components() {
    let Component::Normal(component) = component else {
      return Err(SecretActivationError::InvalidReference);
    };
    current.push(component);
    let metadata = std::fs::symlink_metadata(&current).map_err(map_io_error)?;
    if metadata.file_type().is_symlink() {
      return Err(SecretActivationError::ReferenceUnauthorized);
    }
  }
  let resolved = current.canonicalize().map_err(map_io_error)?;
  if !resolved.starts_with(&base) {
    return Err(SecretActivationError::ReferenceUnauthorized);
  }
  Ok(resolved)
}

pub(crate) fn verify_update_digest(
  path: &Path,
  expected: &str,
) -> Result<(), SecretActivationError> {
  let bytes = read_bounded_file(path)?;
  let actual = lowercase_hex(&crate::crypto::sha256(&bytes));
  if actual.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
    return Err(SecretActivationError::DigestMismatch);
  }
  Ok(())
}

fn resolve_environment(reference: &str) -> Result<Zeroizing<Vec<u8>>, SecretActivationError> {
  let value = std::env::var_os(reference).ok_or(SecretActivationError::ReferenceMissing)?;
  let bytes = value.into_vec();
  if bytes.len() > MAX_TEXT_SECRET_BYTES {
    return Err(SecretActivationError::MaterialTooLarge);
  }
  Ok(Zeroizing::new(bytes))
}

pub(super) fn read_bounded_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, SecretActivationError> {
  let mut options = OpenOptions::new();
  options
    .read(true)
    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
  let file = options.open(path).map_err(map_io_error)?;
  let metadata = file.metadata().map_err(map_io_error)?;
  if !metadata.is_file() {
    return Err(SecretActivationError::WrongMaterialType);
  }
  if metadata.len() > MAX_SECRET_BYTES {
    return Err(SecretActivationError::MaterialTooLarge);
  }
  let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len().try_into().unwrap_or(0)));
  file
    .take(MAX_SECRET_BYTES + 1)
    .read_to_end(&mut bytes)
    .map_err(map_io_error)?;
  if bytes.len() as u64 > MAX_SECRET_BYTES {
    return Err(SecretActivationError::MaterialTooLarge);
  }
  Ok(bytes)
}

fn normalize_material(
  material_type: SecretMaterialType,
  raw: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, SecretActivationError> {
  if raw.is_empty() {
    return Err(SecretActivationError::WrongMaterialType);
  }
  match material_type {
    SecretMaterialType::RemoteSignerToken32 => {
      let text = std::str::from_utf8(&raw).map_err(|_| SecretActivationError::WrongMaterialType)?;
      let decoded = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|_| SecretActivationError::WrongMaterialType)?;
      if decoded.len() != 32 {
        return Err(SecretActivationError::WrongMaterialType);
      }
      Ok(Zeroizing::new(decoded))
    }
    SecretMaterialType::BearerToken
    | SecretMaterialType::OAuthClientId
    | SecretMaterialType::OAuthClientSecret
    | SecretMaterialType::DiscoveryToken => {
      if raw.len() > MAX_TEXT_SECRET_BYTES
        || raw
          .iter()
          .any(|byte| matches!(*byte, b'\0' | b'\r' | b'\n'))
      {
        return Err(SecretActivationError::WrongMaterialType);
      }
      Ok(raw)
    }
    SecretMaterialType::TurnSharedSecret | SecretMaterialType::TurnPassword => {
      if raw.len() > MAX_TEXT_SECRET_BYTES || raw.contains(&b'\0') {
        return Err(SecretActivationError::WrongMaterialType);
      }
      Ok(raw)
    }
  }
}

fn map_io_error(error: std::io::Error) -> SecretActivationError {
  match error.kind() {
    std::io::ErrorKind::NotFound => SecretActivationError::ReferenceMissing,
    std::io::ErrorKind::PermissionDenied => SecretActivationError::ReferenceUnauthorized,
    _ => SecretActivationError::ProviderUnavailable,
  }
}

fn lowercase_hex(value: &[u8]) -> String {
  let mut output = String::with_capacity(value.len() * 2);
  for byte in value {
    use std::fmt::Write as _;
    let _ = write!(output, "{byte:02x}");
  }
  output
}
