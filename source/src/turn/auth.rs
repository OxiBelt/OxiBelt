//! TURN long-term credential validation.
//! Authentication is fail-closed: malformed RFC 8489 extensions and stale or source-mismatched
//! nonces are never treated as an unauthenticated request.

use std::fmt;
use std::io::Read;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use base64::Engine;
use md5::{Digest, Md5};
use precis_profiles::OpaqueString;
use precis_profiles::precis_core::profile::PrecisFastInvocation;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::{TurnAuthConfig, TurnAuthMode, TurnPasswordAlgorithm};

use super::protocol::{
  ATTR_FINGERPRINT, ATTR_MESSAGE_INTEGRITY, ATTR_MESSAGE_INTEGRITY_SHA256, ATTR_NONCE,
  ATTR_PASSWORD_ALGORITHM, ATTR_PASSWORD_ALGORITHMS, ATTR_REALM, ATTR_USERHASH, ATTR_USERNAME,
  PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256, StunMessage, attr_bytes, attr_string,
  password_algorithm_selection, password_algorithms_contains, semantic_attributes,
  validate_attribute_ordering, verify_fingerprint, verify_message_integrity,
  verify_message_integrity_sha256, with_message_integrity, with_message_integrity_sha256,
};

const MAX_TURN_SECRET_FILE_BYTES: usize = 4_096;
const MAX_TURN_NONCE_SECRET_ENCODED_BYTES: usize = 256;
const RFC8489_NONCE_COOKIE: &str = "obMatJos2";
const TURN_NONCE_RANDOM_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuthDecision {
  Pass,
  Missing,
  Invalid,
}

/// Authentication context retained for a TURN transaction after credentials verify.
/// The derived integrity key is private, zeroized on drop, and deliberately omitted from
/// `Debug`; callers can only use it through `with_response_integrity`.
pub struct AuthenticatedContext {
  username: String,
  integrity_key: zeroize::Zeroizing<Vec<u8>>,
  password_algorithm: TurnPasswordAlgorithm,
  response_integrity: ResponseIntegrity,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ResponseIntegrity {
  LegacySha1,
  Sha256,
}

impl fmt::Debug for AuthenticatedContext {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("AuthenticatedContext")
      .field("username", &self.username)
      .field("password_algorithm", &self.password_algorithm)
      .finish_non_exhaustive()
  }
}

impl AuthenticatedContext {
  pub fn username(&self) -> &str {
    &self.username
  }

  #[cfg(test)]
  pub fn password_algorithm(&self) -> TurnPasswordAlgorithm {
    self.password_algorithm
  }

  pub(crate) fn has_same_credentials(&self, other: &Self) -> bool {
    self.password_algorithm == other.password_algorithm
      && self.response_integrity == other.response_integrity
      && constant_time_eq(self.username.as_bytes(), other.username.as_bytes())
      && constant_time_eq(&self.integrity_key, &other.integrity_key)
  }

  /// Adds the selected integrity attribute. Call before appending a final FINGERPRINT.
  pub fn with_response_integrity(&self, message: Vec<u8>) -> Vec<u8> {
    match self.response_integrity {
      ResponseIntegrity::LegacySha1 => with_message_integrity(message, &self.integrity_key),
      ResponseIntegrity::Sha256 => with_message_integrity_sha256(message, &self.integrity_key),
    }
  }
}

pub enum AuthenticatedContextDecision {
  Pass(AuthenticatedContext),
  PassThrough,
  BadRequest,
  BadRequestAuthenticated(AuthenticatedContext),
  StaleNonce(AuthenticatedContext),
  Missing,
  Invalid,
}

impl AuthenticatedContextDecision {
  fn decision(&self) -> AuthDecision {
    match self {
      Self::Pass(_) | Self::PassThrough => AuthDecision::Pass,
      Self::Missing => AuthDecision::Missing,
      Self::BadRequest | Self::BadRequestAuthenticated(_) | Self::StaleNonce(_) | Self::Invalid => {
        AuthDecision::Invalid
      }
    }
  }
}

/// Stable source identity for a nonce. Callers bind this to the peer socket, never to a
/// caller-controlled STUN address attribute.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NonceSourceBinding {
  peer: SocketAddr,
}

impl NonceSourceBinding {
  pub fn from_peer(peer: SocketAddr) -> Self {
    Self { peer }
  }

  fn material(self) -> String {
    self.peer.to_string()
  }
}

pub fn validate_message(
  auth: &TurnAuthConfig,
  realm: &str,
  message: &StunMessage<'_>,
) -> anyhow::Result<AuthDecision> {
  validate_message_for_source(auth, realm, None, message)
}

pub fn validate_message_for_source(
  auth: &TurnAuthConfig,
  realm: &str,
  source: Option<NonceSourceBinding>,
  message: &StunMessage<'_>,
) -> anyhow::Result<AuthDecision> {
  Ok(authenticated_context_for_source(auth, realm, source, message)?.decision())
}

/// Validates long-term credentials and returns a response-signing context on success.
/// The source argument is accepted for API symmetry; nonce validation belongs to
/// `enforce_authenticated_context_for_source`.
pub fn authenticated_context_for_source(
  auth: &TurnAuthConfig,
  realm: &str,
  _source: Option<NonceSourceBinding>,
  message: &StunMessage<'_>,
) -> anyhow::Result<AuthenticatedContextDecision> {
  if auth.mode == TurnAuthMode::PassThrough {
    return Ok(AuthenticatedContextDecision::PassThrough);
  }
  if validate_attribute_ordering(message).is_err() {
    return Ok(AuthenticatedContextDecision::BadRequest);
  }
  if message
    .attrs
    .iter()
    .any(|attr| attr.kind == ATTR_FINGERPRINT)
    && !verify_fingerprint(message)?
  {
    return Ok(AuthenticatedContextDecision::BadRequest);
  }
  let has_sha256 = message
    .attrs
    .iter()
    .any(|attr| attr.kind == ATTR_MESSAGE_INTEGRITY_SHA256);
  let has_sha1 = message
    .attrs
    .iter()
    .any(|attr| attr.kind == ATTR_MESSAGE_INTEGRITY);
  if !has_sha256 && !has_sha1 {
    return Ok(AuthenticatedContextDecision::Missing);
  }
  let modern = has_sha256
    || attr_bytes(message, ATTR_PASSWORD_ALGORITHMS).is_some()
    || attr_bytes(message, ATTR_PASSWORD_ALGORITHM).is_some()
    || attr_bytes(message, ATTR_USERHASH).is_some();
  let (algorithm, response_integrity) = if modern {
    let (Some(advertised), Some(selection)) = (
      attr_bytes(message, ATTR_PASSWORD_ALGORITHMS),
      attr_bytes(message, ATTR_PASSWORD_ALGORITHM),
    ) else {
      return Ok(AuthenticatedContextDecision::BadRequest);
    };
    let expected = password_algorithms_challenge_value(auth);
    let Some(selected) = password_algorithm_selection(selection) else {
      return Ok(AuthenticatedContextDecision::BadRequest);
    };
    if !has_sha256
      || !constant_time_eq(advertised, &expected)
      || !password_algorithms_contains(advertised, selected)
    {
      return Ok(AuthenticatedContextDecision::BadRequest);
    }
    let algorithm = match turn_password_algorithm_from_wire(selected) {
      Some(algorithm) if auth.password_algorithms.contains(&algorithm) => algorithm,
      _ => return Ok(AuthenticatedContextDecision::BadRequest),
    };
    (algorithm, ResponseIntegrity::Sha256)
  } else {
    (TurnPasswordAlgorithm::Md5, ResponseIntegrity::LegacySha1)
  };
  let Some(message_realm) = attr_string(message, ATTR_REALM).filter(|realm| !realm.is_empty())
  else {
    return Ok(AuthenticatedContextDecision::BadRequest);
  };
  let Ok(message_realm) = opaque_realm(&message_realm) else {
    return Ok(AuthenticatedContextDecision::BadRequest);
  };
  let expected_realm = opaque_realm(realm).context("configured TURN realm violates RFC 8265")?;
  if message_realm != expected_realm {
    return Ok(AuthenticatedContextDecision::Invalid);
  }
  if !auth.password_algorithms.contains(&algorithm) {
    return Ok(AuthenticatedContextDecision::Invalid);
  }
  let username = match message_username(auth, realm, message) {
    MessageUsername::Known(username) => username,
    MessageUsername::MissingOrMalformed => return Ok(AuthenticatedContextDecision::BadRequest),
    MessageUsername::Unknown => return Ok(AuthenticatedContextDecision::Invalid),
  };
  for password in candidate_passwords(auth, &username)? {
    let key = long_term_key_checked(&username, realm, &password, algorithm)?;
    let verified = if has_sha256 {
      verify_message_integrity_sha256(message, &key)?
    } else {
      verify_message_integrity(message, &key)?
    };
    if verified {
      return Ok(AuthenticatedContextDecision::Pass(AuthenticatedContext {
        username,
        integrity_key: zeroize::Zeroizing::new(key),
        password_algorithm: algorithm,
        response_integrity,
      }));
    }
  }
  Ok(AuthenticatedContextDecision::Invalid)
}

#[cfg(feature = "fuzzing")]
pub fn enforce_message(
  auth: &TurnAuthConfig,
  realm: &str,
  message: &StunMessage<'_>,
) -> anyhow::Result<AuthDecision> {
  enforce_message_for_source(auth, realm, legacy_source_binding(), message)
}

#[cfg(feature = "fuzzing")]
pub fn enforce_message_for_source(
  auth: &TurnAuthConfig,
  realm: &str,
  source: NonceSourceBinding,
  message: &StunMessage<'_>,
) -> anyhow::Result<AuthDecision> {
  Ok(enforce_authenticated_context_for_source(auth, realm, source, message)?.decision())
}

/// Validates credentials and the source-bound nonce, returning the response-signing context.
pub fn enforce_authenticated_context_for_source(
  auth: &TurnAuthConfig,
  realm: &str,
  source: NonceSourceBinding,
  message: &StunMessage<'_>,
) -> anyhow::Result<AuthenticatedContextDecision> {
  let context = match authenticated_context_for_source(auth, realm, Some(source), message)? {
    AuthenticatedContextDecision::Pass(context) => context,
    decision => return Ok(decision),
  };
  let Some(nonce) = attr_string(message, ATTR_NONCE) else {
    return Ok(AuthenticatedContextDecision::BadRequestAuthenticated(
      context,
    ));
  };
  if verify_nonce_for_source(&nonce, realm, source, auth)? {
    Ok(AuthenticatedContextDecision::Pass(context))
  } else {
    Ok(AuthenticatedContextDecision::StaleNonce(context))
  }
}

/// Compatibility nonce API. New runtime call sites must use `create_nonce_for_source`.
#[cfg(feature = "fuzzing")]
pub fn create_nonce(realm: &str, auth: &TurnAuthConfig) -> anyhow::Result<String> {
  create_nonce_for_source(realm, legacy_source_binding(), auth)
}

pub fn create_nonce_for_source(
  realm: &str,
  source: NonceSourceBinding,
  auth: &TurnAuthConfig,
) -> anyhow::Result<String> {
  let issued = unix_time()?;
  let key = nonce_secrets(auth)?
    .into_iter()
    .next()
    .context("TURN auth requires a nonce secret")?;
  let mut random = [0_u8; TURN_NONCE_RANDOM_BYTES];
  crate::crypto::random_fill(&mut random).context("TURN nonce CSPRNG failed")?;
  let random = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
  let prefix = rfc8489_nonce_prefix(auth);
  let material = nonce_material_v2(issued, realm, source, auth, &prefix, &random);
  let signature = crate::crypto::hmac_sha256(&key, material.as_bytes());
  let nonce = format!(
    "{prefix}:v2:{issued}:{random}:{}",
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
  );
  if nonce.len() >= 128 {
    bail!("TURN nonce exceeds RFC 8656 size guidance");
  }
  Ok(nonce)
}

fn verify_nonce_for_source(
  raw: &str,
  realm: &str,
  source: NonceSourceBinding,
  auth: &TurnAuthConfig,
) -> anyhow::Result<bool> {
  let Some((version, rest)) = raw.split_once(':') else {
    return Ok(false);
  };
  let (issued, random, signature) = match version {
    value if value == rfc8489_nonce_prefix(auth) => {
      let Some(("v2", rest)) = rest.split_once(':') else {
        return Ok(false);
      };
      let Some((issued, rest)) = rest.split_once(':') else {
        return Ok(false);
      };
      let Some((random, signature)) = rest.split_once(':') else {
        return Ok(false);
      };
      if signature.contains(':') {
        return Ok(false);
      }
      let Ok(random_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(random) else {
        return Ok(false);
      };
      if random_bytes.len() != TURN_NONCE_RANDOM_BYTES {
        return Ok(false);
      }
      (issued, Some(random), signature)
    }
    // OxiBelt v1 nonces remain valid for their configured lifetime so rolling
    // upgrades do not strand coturn-compatible long-term-auth clients.
    "v1" => {
      let Some((issued, signature)) = rest.split_once(':') else {
        return Ok(false);
      };
      if signature.contains(':') {
        return Ok(false);
      }
      (issued, None, signature)
    }
    _ => return Ok(false),
  };
  let Ok(issued) = issued.parse::<u64>() else {
    return Ok(false);
  };
  let now = unix_time()?;
  if issued > now || now.saturating_sub(issued) > auth.nonce_ttl_seconds {
    return Ok(false);
  }
  let Ok(actual) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signature) else {
    return Ok(false);
  };
  let material = match random {
    Some(random) => nonce_material_v2(issued, realm, source, auth, version, random),
    None => nonce_material_v1(issued, realm, source, auth),
  };
  for secret in nonce_secrets(auth)? {
    if constant_time_eq(
      &crate::crypto::hmac_sha256(&secret, material.as_bytes()),
      &actual,
    ) {
      return Ok(true);
    }
  }
  Ok(false)
}

fn nonce_material_v2(
  issued: u64,
  realm: &str,
  source: NonceSourceBinding,
  auth: &TurnAuthConfig,
  prefix: &str,
  random: &str,
) -> String {
  format!(
    "OXIBELT-TURN-NONCE-V2\n{issued}\n{realm}\n{}\n{}\n{prefix}\n{random}",
    source.material(),
    base64::engine::general_purpose::STANDARD_NO_PAD
      .encode(password_algorithms_challenge_value(auth))
  )
}

/// RFC 8489 feature set: Password Algorithms is always enabled; Username Anonymity is
/// advertised only when static credentials make USERHASH lookup meaningful.
fn rfc8489_nonce_prefix(auth: &TurnAuthConfig) -> String {
  let features = if auth.static_credentials.is_empty() {
    [0x80, 0, 0]
  } else {
    [0xc0, 0, 0]
  };
  format!(
    "{RFC8489_NONCE_COOKIE}{}",
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(features)
  )
}

fn nonce_material_v1(
  issued: u64,
  realm: &str,
  source: NonceSourceBinding,
  auth: &TurnAuthConfig,
) -> String {
  format!(
    "OXIBELT-TURN-NONCE-V1\n{issued}\n{realm}\n{}\n{}",
    source.material(),
    advertised_password_algorithms(auth)
  )
}

/// Encodes the PASSWORD-ALGORITHMS attribute for a 401/438 challenge. The nonce binds this
/// exact ordered selection, preventing it from being replayed after an algorithm downgrade.
pub fn password_algorithms_challenge_attribute(auth: &TurnAuthConfig) -> (u16, Vec<u8>) {
  (
    super::protocol::ATTR_PASSWORD_ALGORITHMS,
    password_algorithms_challenge_value(auth),
  )
}

fn password_algorithms_challenge_value(auth: &TurnAuthConfig) -> Vec<u8> {
  let algorithms = auth
    .password_algorithms
    .iter()
    .map(|algorithm| match algorithm {
      TurnPasswordAlgorithm::Md5 => PASSWORD_ALGORITHM_MD5,
      TurnPasswordAlgorithm::Sha256 => PASSWORD_ALGORITHM_SHA256,
    })
    .collect::<Vec<_>>();
  super::protocol::encode_password_algorithms(&algorithms)
}

fn advertised_password_algorithms(auth: &TurnAuthConfig) -> String {
  auth
    .password_algorithms
    .iter()
    .map(|algorithm| match algorithm {
      TurnPasswordAlgorithm::Md5 => "md5",
      TurnPasswordAlgorithm::Sha256 => "sha256",
    })
    .collect::<Vec<_>>()
    .join(",")
}

#[cfg(feature = "fuzzing")]
fn legacy_source_binding() -> NonceSourceBinding {
  NonceSourceBinding::from_peer("0.0.0.0:0".parse().expect("fixed socket address"))
}

fn turn_password_algorithm_from_wire(value: u16) -> Option<TurnPasswordAlgorithm> {
  match value {
    PASSWORD_ALGORITHM_MD5 => Some(TurnPasswordAlgorithm::Md5),
    PASSWORD_ALGORITHM_SHA256 => Some(TurnPasswordAlgorithm::Sha256),
    _ => None,
  }
}

enum MessageUsername {
  Known(String),
  MissingOrMalformed,
  Unknown,
}

fn message_username(
  auth: &TurnAuthConfig,
  realm: &str,
  message: &StunMessage<'_>,
) -> MessageUsername {
  let username = semantic_attributes(message)
    .iter()
    .find(|attribute| attribute.kind == ATTR_USERNAME);
  let userhash = semantic_attributes(message)
    .iter()
    .find(|attribute| attribute.kind == ATTR_USERHASH);
  match (username, userhash) {
    (Some(_), Some(_)) | (None, None) => MessageUsername::MissingOrMalformed,
    (Some(username), None) => std::str::from_utf8(username.value)
      .ok()
      .and_then(|username| opaque_username(username).ok())
      .filter(|username| !username.is_empty())
      .map_or(MessageUsername::Unknown, MessageUsername::Known),
    (None, Some(userhash)) if userhash.value.len() == 32 => {
      let Ok(realm) = opaque_realm(realm) else {
        return MessageUsername::Unknown;
      };
      auth
        .static_credentials
        .iter()
        .find_map(|credential| {
          let username = opaque_username(&credential.username).ok()?;
          let digest = Sha256::digest(format!("{username}:{realm}").as_bytes());
          constant_time_eq(&digest, userhash.value).then_some(username)
        })
        .map_or(MessageUsername::Unknown, MessageUsername::Known)
    }
    _ => MessageUsername::MissingOrMalformed,
  }
}

fn candidate_passwords(auth: &TurnAuthConfig, username: &str) -> anyhow::Result<Vec<String>> {
  let mut passwords = Vec::new();
  for credential in &auth.static_credentials {
    if opaque_username(&credential.username).is_ok_and(|candidate| candidate == username) {
      if let Some(password) = &credential.password {
        passwords.push(password.clone())
      }
      if let Some(env) = &credential.password_env {
        passwords.push(std::env::var(env).with_context(|| {
          format!("TURN static credential password environment variable {env} is not set")
        })?);
      }
      if let Some(file) = &credential.password_file {
        passwords.push(read_secret_file(
          file,
          "TURN static credential password file",
          MAX_TURN_SECRET_FILE_BYTES,
        )?);
      }
    }
  }
  if let Some(secret) = rest_secret(auth)?
    && let Some(expiry) = rest_username_expiry(username)
    && expiry >= unix_time()?
  {
    passwords.push(
      base64::engine::general_purpose::STANDARD.encode(crate::crypto::hmac_sha1(
        secret.as_bytes(),
        username.as_bytes(),
      )),
    );
  }
  Ok(passwords)
}

fn rest_username_expiry(username: &str) -> Option<u64> {
  let (expiry, _) = username.split_once(':')?;
  expiry.parse::<u64>().ok()
}

fn rest_secret(auth: &TurnAuthConfig) -> anyhow::Result<Option<String>> {
  if let Some(secret) = &auth.rest_shared_secret {
    return Ok(Some(secret.clone()));
  }
  if let Some(env) = &auth.rest_shared_secret_env {
    return Ok(Some(std::env::var(env).with_context(|| {
      format!("TURN REST shared secret environment variable {env} is not set")
    })?));
  }
  if let Some(file) = &auth.rest_shared_secret_file {
    return Ok(Some(read_secret_file(
      file,
      "TURN REST shared secret file",
      MAX_TURN_SECRET_FILE_BYTES,
    )?));
  }
  Ok(None)
}

fn nonce_secrets(auth: &TurnAuthConfig) -> anyhow::Result<Vec<Vec<u8>>> {
  let mut secrets = Vec::new();
  for (file, env, label) in [
    (
      &auth.nonce_secret_file,
      &auth.nonce_secret_env,
      "nonce secret",
    ),
    (
      &auth.previous_nonce_secret_file,
      &auth.previous_nonce_secret_env,
      "previous nonce secret",
    ),
  ] {
    if let Some(file) = file {
      secrets.push(decode_nonce_secret(
        &read_secret_file(file, label, MAX_TURN_NONCE_SECRET_ENCODED_BYTES)?,
        label,
      )?)
    } else if let Some(env) = env {
      secrets.push(decode_nonce_secret(
        &std::env::var(env)
          .with_context(|| format!("TURN {label} environment variable {env} is not set"))?,
        label,
      )?)
    }
  }
  if !secrets.is_empty() {
    return Ok(secrets);
  }
  // Deprecated compatibility fallback for existing deployments.
  if let Some(secret) = rest_secret(auth)? {
    return Ok(vec![secret.into_bytes()]);
  }
  if let Some(credential) = auth.static_credentials.first() {
    if let Some(password) = &credential.password {
      return Ok(vec![password.as_bytes().to_vec()]);
    }
    if let Some(env) = &credential.password_env {
      return Ok(vec![
        std::env::var(env)
          .with_context(|| format!("TURN nonce secret environment variable {env} is not set"))?
          .into_bytes(),
      ]);
    }
    if let Some(file) = &credential.password_file {
      return Ok(vec![
        read_secret_file(
          file,
          "TURN nonce compatibility password file",
          MAX_TURN_SECRET_FILE_BYTES,
        )?
        .into_bytes(),
      ]);
    }
  }
  bail!("TURN auth requires a nonce secret")
}

fn decode_nonce_secret(value: &str, label: &str) -> anyhow::Result<Vec<u8>> {
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(value.trim())
    .with_context(|| format!("TURN {label} must be standard-base64"))?;
  if decoded.len() != 32 {
    bail!("TURN {label} must decode to exactly 32 bytes")
  }
  Ok(decoded)
}

fn read_secret_file(
  path: &std::path::Path,
  label: &str,
  maximum_bytes: usize,
) -> anyhow::Result<String> {
  let mut file = std::fs::File::open(path).with_context(|| format!("failed to read {label}"))?;
  let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(maximum_bytes.saturating_add(1)));
  file
    .by_ref()
    .take((maximum_bytes.saturating_add(1)) as u64)
    .read_to_end(&mut bytes)
    .with_context(|| format!("failed to read {label}"))?;
  if bytes.len() > maximum_bytes {
    bail!("{label} exceeds the permitted size");
  }
  let value = String::from_utf8(std::mem::take(&mut *bytes))
    .with_context(|| format!("{label} must be valid UTF-8"))?;
  Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}

fn long_term_key_checked(
  username: &str,
  realm: &str,
  password: &str,
  algorithm: TurnPasswordAlgorithm,
) -> anyhow::Result<Vec<u8>> {
  let username = opaque_username(username).context("TURN username violates RFC 8265")?;
  let realm = opaque_realm(realm).context("TURN realm violates RFC 8265")?;
  let password = opaque_password(password).context("TURN password violates RFC 8265")?;
  let material = format!("{username}:{realm}:{password}");
  Ok(match algorithm {
    TurnPasswordAlgorithm::Md5 => Md5::digest(material.as_bytes()).to_vec(),
    TurnPasswordAlgorithm::Sha256 => Sha256::digest(material.as_bytes()).to_vec(),
  })
}

#[cfg(test)]
fn long_term_key(
  username: &str,
  realm: &str,
  password: &str,
  algorithm: TurnPasswordAlgorithm,
) -> Vec<u8> {
  long_term_key_checked(username, realm, password, algorithm)
    .expect("test credential must satisfy RFC 8265")
}

fn opaque_username(value: &str) -> anyhow::Result<String> {
  opaque_string(strip_quotes_and_trailing_nuls(value))
}

fn opaque_realm(value: &str) -> anyhow::Result<String> {
  opaque_string(strip_quotes_and_trailing_nuls(value))
}

fn opaque_password(value: &str) -> anyhow::Result<String> {
  opaque_string(value.trim_end_matches('\0'))
}

fn opaque_string(value: &str) -> anyhow::Result<String> {
  OpaqueString::enforce(value)
    .map(|value| value.into_owned())
    .map_err(|_| anyhow::anyhow!("disallowed RFC 8265 OpaqueString value"))
}

fn strip_quotes_and_trailing_nuls(value: &str) -> &str {
  let value = value.trim_end_matches('\0');
  value
    .strip_prefix('"')
    .and_then(|value| value.strip_suffix('"'))
    .unwrap_or(value)
}

fn unix_time() -> anyhow::Result<u64> {
  Ok(
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .context("system clock is before UNIX epoch")?
      .as_secs(),
  )
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
  left.len() == right.len() && bool::from(left.ct_eq(right))
}

#[cfg(test)]
#[path = "auth/tests.rs"]
mod tests;
