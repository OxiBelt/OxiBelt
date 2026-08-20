//! TURN credential validation.
//! Time-bound credentials are checked before relay state is allocated.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use base64::Engine;
use md5::{Digest, Md5};
use subtle::ConstantTimeEq;

use crate::config::{TurnAuthConfig, TurnAuthMode};

use super::protocol::{
  ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM, ATTR_USERNAME, StunMessage, attr_string,
  hmac_sha1, verify_fingerprint, verify_message_integrity,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuthDecision {
  Pass,
  Missing,
  Invalid,
}

pub fn validate_message(
  auth: &TurnAuthConfig,
  realm: &str,
  message: &StunMessage<'_>,
) -> anyhow::Result<AuthDecision> {
  if auth.mode == TurnAuthMode::PassThrough {
    return Ok(AuthDecision::Pass);
  }
  if message
    .attrs
    .iter()
    .any(|attr| attr.kind == super::protocol::ATTR_FINGERPRINT)
    && !verify_fingerprint(message)?
  {
    return Ok(AuthDecision::Invalid);
  }
  if !message
    .attrs
    .iter()
    .any(|attr| attr.kind == ATTR_MESSAGE_INTEGRITY)
  {
    return Ok(AuthDecision::Missing);
  }
  let Some(username) = attr_string(message, ATTR_USERNAME) else {
    return Ok(AuthDecision::Invalid);
  };
  let message_realm = attr_string(message, ATTR_REALM).unwrap_or_else(|| realm.to_string());
  let passwords = candidate_passwords(auth, &username)?;
  for password in passwords {
    let key = long_term_key(&username, &message_realm, &password);
    if verify_message_integrity(message, &key)? {
      return Ok(AuthDecision::Pass);
    }
  }
  Ok(AuthDecision::Invalid)
}

pub fn enforce_message(
  auth: &TurnAuthConfig,
  realm: &str,
  message: &StunMessage<'_>,
) -> anyhow::Result<AuthDecision> {
  let decision = validate_message(auth, realm, message)?;
  if decision != AuthDecision::Pass {
    return Ok(decision);
  }
  let Some(nonce) = attr_string(message, ATTR_NONCE) else {
    return Ok(AuthDecision::Missing);
  };
  if verify_nonce(&nonce, realm, auth)? {
    Ok(AuthDecision::Pass)
  } else {
    Ok(AuthDecision::Invalid)
  }
}

pub fn create_nonce(realm: &str, auth: &TurnAuthConfig) -> anyhow::Result<String> {
  let issued = unix_time()?;
  let key = nonce_secret(auth)?;
  let value = format!("{issued}:{realm}");
  let signature = hmac_sha1(key.as_bytes(), value.as_bytes());
  Ok(format!(
    "{value}:{}",
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(signature)
  ))
}

fn verify_nonce(raw: &str, realm: &str, auth: &TurnAuthConfig) -> anyhow::Result<bool> {
  let Some((issued, rest)) = raw.split_once(':') else {
    return Ok(false);
  };
  let Some((nonce_realm, signature)) = rest.rsplit_once(':') else {
    return Ok(false);
  };
  if nonce_realm != realm {
    return Ok(false);
  }
  let Ok(issued) = issued.parse::<u64>() else {
    return Ok(false);
  };
  let now = unix_time()?;
  if issued > now || now.saturating_sub(issued) > auth.nonce_ttl_seconds {
    return Ok(false);
  }
  let key = nonce_secret(auth)?;
  let value = format!("{issued}:{realm}");
  let expected = base64::engine::general_purpose::STANDARD_NO_PAD
    .encode(hmac_sha1(key.as_bytes(), value.as_bytes()));
  Ok(constant_time_eq(expected.as_bytes(), signature.as_bytes()))
}

fn candidate_passwords(auth: &TurnAuthConfig, username: &str) -> anyhow::Result<Vec<String>> {
  let mut passwords = Vec::new();
  for credential in &auth.static_credentials {
    if credential.username == username {
      if let Some(password) = &credential.password {
        passwords.push(password.clone());
      }
      if let Some(env) = &credential.password_env {
        passwords.push(std::env::var(env).with_context(|| {
          format!("TURN static credential password environment variable {env} is not set")
        })?);
      }
    }
  }
  if let Some(secret) = rest_secret(auth)?
    && let Some(expiry) = rest_username_expiry(username)
    && expiry >= unix_time()?
  {
    let signature = hmac_sha1(secret.as_bytes(), username.as_bytes());
    passwords.push(base64::engine::general_purpose::STANDARD.encode(signature));
  }
  Ok(passwords)
}

fn rest_username_expiry(username: &str) -> Option<u64> {
  let (expiry, _rest) = username.split_once(':')?;
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
  Ok(None)
}

fn nonce_secret(auth: &TurnAuthConfig) -> anyhow::Result<String> {
  if let Some(secret) = rest_secret(auth)? {
    return Ok(secret);
  }
  if let Some(credential) = auth.static_credentials.first() {
    if let Some(password) = &credential.password {
      return Ok(password.clone());
    }
    if let Some(env) = &credential.password_env {
      return std::env::var(env)
        .with_context(|| format!("TURN nonce secret environment variable {env} is not set"));
    }
  }
  bail!("TURN auth requires a secret");
}

fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
  let mut md5 = Md5::new();
  md5.update(username.as_bytes());
  md5.update(b":");
  md5.update(realm.as_bytes());
  md5.update(b":");
  md5.update(password.as_bytes());
  md5.finalize().into()
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
  if left.len() != right.len() {
    return false;
  }
  bool::from(left.ct_eq(right))
}

#[allow(dead_code)]
fn _hmac_sha256(key: &[u8], value: &[u8]) -> Vec<u8> {
  crate::crypto::hmac_sha256(key, value).to_vec()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{TurnAuthConfig, TurnAuthMode};
  use crate::turn::protocol::{
    ALLOCATE_REQUEST, encode_message, parse_stun, with_message_integrity,
  };

  #[test]
  fn constant_time_equality_preserves_length_and_content_checks() {
    assert!(constant_time_eq(b"same", b"same"));
    assert!(!constant_time_eq(b"same", b"diff"));
    assert!(!constant_time_eq(b"same", b"same-length-mismatch"));
  }

  #[test]
  fn validate_mode_reports_missing_integrity() {
    let auth = TurnAuthConfig {
      mode: TurnAuthMode::Validate,
      ..TurnAuthConfig::default()
    };
    let raw = encode_message(ALLOCATE_REQUEST, [1u8; 12], &[]);
    let message = parse_stun(&raw).expect("STUN request should parse");
    assert_eq!(
      validate_message(&auth, "example.test", &message).unwrap(),
      AuthDecision::Missing
    );
  }

  #[test]
  fn rest_username_expiry_is_parsed() {
    assert_eq!(rest_username_expiry("1:user"), Some(1));
  }

  #[test]
  fn username_without_rest_separator_has_no_expiry() {
    assert_eq!(rest_username_expiry("user"), None);
  }

  #[test]
  fn malformed_rest_username_is_an_invalid_credential_not_an_error() {
    let auth = TurnAuthConfig {
      mode: TurnAuthMode::Enforce,
      rest_shared_secret: Some("test-secret".to_string()),
      ..TurnAuthConfig::default()
    };
    let raw = with_message_integrity(
      encode_message(
        ALLOCATE_REQUEST,
        [2u8; 12],
        &[(ATTR_USERNAME, b"not-a-number:attacker".to_vec())],
      ),
      b"irrelevant-integrity-key",
    );
    let message = parse_stun(&raw).expect("STUN request should parse");
    assert_eq!(
      validate_message(&auth, "example.test", &message).expect("malformed credentials fail closed"),
      AuthDecision::Invalid
    );
  }

  #[test]
  fn malformed_nonce_timestamp_is_invalid_not_an_error() {
    let auth = TurnAuthConfig {
      rest_shared_secret: Some("test-secret".to_string()),
      ..TurnAuthConfig::default()
    };
    assert!(
      !verify_nonce("not-a-number:example.test:signature", "example.test", &auth)
        .expect("malformed nonce fails closed")
    );
  }
}
