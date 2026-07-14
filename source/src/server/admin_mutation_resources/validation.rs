use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use ::http::StatusCode;
use sha2::{Digest, Sha256};

use super::{
  BreakGlassActivationRequest, KeyRotationRequest, KeyRotationTarget, SecretReferenceField,
  SecretReferenceUpdateRequest, constant_time_ascii_eq,
};

const MAX_PINNED_KEY_BYTES: u64 = 1024 * 1024;

pub(super) fn validate_key_rotation(body: &KeyRotationRequest) -> Result<(), &'static str> {
  validate_digest(&body.sha256)?;
  validate_safe_reference(&body.reference)?;
  validate_relative_path(&body.reference)?;
  match body.target {
    KeyRotationTarget::DownstreamTlsSni => {
      let name = body
        .name
        .as_deref()
        .ok_or("SNI key rotation requires name")?;
      validate_name(name)?;
    }
    _ if body.name.is_some() => return Err("name is not valid for this key target"),
    _ => {}
  }
  Ok(())
}

pub(super) fn validate_secret_reference(
  body: &SecretReferenceUpdateRequest,
) -> Result<SecretReferenceField, &'static str> {
  let field = SecretReferenceField::parse(&body.field)?;
  validate_safe_reference(&body.reference)?;
  if field.is_file() {
    validate_relative_path(&body.reference)?;
    validate_digest(
      body
        .sha256
        .as_deref()
        .ok_or("file references require sha256")?,
    )?;
  } else {
    validate_environment_name(&body.reference)?;
    if body.sha256.is_some() {
      return Err("environment references must not include sha256");
    }
  }
  Ok(field)
}

pub(super) fn validate_break_glass_activation(
  body: &BreakGlassActivationRequest,
  maximum_ttl: u64,
) -> Result<(), &'static str> {
  if body.ttl_seconds == 0 || body.ttl_seconds > maximum_ttl {
    return Err("ttl_seconds is outside the configured activation bound");
  }
  if let Some(reason) = body.reason.as_deref()
    && (reason.is_empty()
      || reason.len() > 512
      || reason.chars().any(|character| character.is_control()))
  {
    return Err("reason must be 1 to 512 printable characters");
  }
  Ok(())
}

pub(super) fn active_key_path(
  snapshot: &crate::state::AppSnapshot,
  body: &KeyRotationRequest,
) -> Result<PathBuf, (StatusCode, &'static str)> {
  let actual = match body.target {
    KeyRotationTarget::DownstreamTlsDefault => snapshot.config.tls.private_key.as_ref(),
    KeyRotationTarget::DownstreamTlsSni => {
      let name = body.name.as_deref().unwrap_or_default();
      snapshot
        .config
        .tls
        .certificates
        .iter()
        .find(|certificate| {
          certificate
            .server_names
            .iter()
            .any(|server_name| server_name.eq_ignore_ascii_case(name))
        })
        .and_then(|certificate| certificate.private_key.as_ref())
    }
  }
  .ok_or((StatusCode::NOT_FOUND, "configured key target was not found"))?;
  active_contained_reference(snapshot, actual, &body.reference)
}

fn active_contained_reference(
  snapshot: &crate::state::AppSnapshot,
  actual: &Path,
  reference: &str,
) -> Result<PathBuf, (StatusCode, &'static str)> {
  let cert_dir = snapshot
    .config
    .source_paths
    .cert_dir
    .as_ref()
    .ok_or((StatusCode::CONFLICT, "certificate root is unavailable"))?;
  let requested = cert_dir.join(reference);
  let requested = requested.canonicalize().map_err(|_| {
    (
      StatusCode::CONFLICT,
      "pre-provisioned key reference is unavailable",
    )
  })?;
  let actual = actual
    .canonicalize()
    .map_err(|_| (StatusCode::CONFLICT, "active key reference is unavailable"))?;
  if requested != actual {
    return Err((
      StatusCode::CONFLICT,
      "key reference is not the active pre-provisioned target",
    ));
  }
  Ok(actual)
}

pub(super) fn verify_file_digest(path: &Path, expected: &str) -> Result<(), String> {
  let mut options = OpenOptions::new();
  options.read(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
  }
  let file = options
    .open(path)
    .map_err(|_| "pre-provisioned key reference is unavailable".to_string())?;
  let metadata = file
    .metadata()
    .map_err(|_| "pre-provisioned key reference is unavailable".to_string())?;
  if !metadata.is_file() || metadata.len() > MAX_PINNED_KEY_BYTES {
    return Err("pre-provisioned key reference is not a regular file".to_string());
  }
  let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(0));
  file
    .take(MAX_PINNED_KEY_BYTES + 1)
    .read_to_end(&mut bytes)
    .map_err(|_| "pre-provisioned key reference could not be read".to_string())?;
  if bytes.len() as u64 > MAX_PINNED_KEY_BYTES {
    return Err("pre-provisioned key reference exceeds the size limit".to_string());
  }
  let actual = lowercase_hex(&Sha256::digest(&bytes));
  if !constant_time_ascii_eq(actual.as_bytes(), expected.as_bytes()) {
    return Err("pre-provisioned key reference digest does not match sha256".to_string());
  }
  Ok(())
}

pub(super) fn validate_safe_reference(raw: &str) -> Result<(), &'static str> {
  if raw.is_empty()
    || raw.len() > 512
    || raw.chars().any(|character| character.is_control())
    || raw.contains("-----BEGIN")
    || raw.contains("-----END")
    || raw.contains("://")
  {
    return Err("reference must identify bounded pre-provisioned material");
  }
  Ok(())
}

pub(super) fn validate_relative_path(raw: &str) -> Result<(), &'static str> {
  let path = Path::new(raw);
  if path.is_absolute()
    || path
      .components()
      .any(|component| !matches!(component, Component::Normal(_)))
  {
    return Err("file reference must be a contained relative path");
  }
  Ok(())
}

fn validate_digest(raw: &str) -> Result<(), &'static str> {
  if raw.len() != 64
    || !raw
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    return Err("sha256 must contain 64 lowercase hexadecimal characters");
  }
  Ok(())
}

fn validate_environment_name(raw: &str) -> Result<(), &'static str> {
  let mut bytes = raw.bytes();
  let Some(first) = bytes.next() else {
    return Err("environment reference is invalid");
  };
  if raw.len() > 128
    || !(first == b'_' || first.is_ascii_uppercase())
    || !bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
  {
    return Err("environment reference is invalid");
  }
  Ok(())
}

pub(super) fn validate_name(raw: &str) -> Result<(), &'static str> {
  if raw.is_empty() || raw.len() > 256 || raw.chars().any(|character| character.is_control()) {
    return Err("name is invalid");
  }
  Ok(())
}

fn lowercase_hex(bytes: &[u8]) -> String {
  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    let _ = write!(output, "{byte:02x}");
  }
  output
}
