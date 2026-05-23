use anyhow::{Context, bail};
use base64::Engine;
use ring::signature;
use serde::{Deserialize, Serialize};

use crate::config::AdminTokenStoreConfig;

const MAX_COMPACT_TOKEN_BYTES: usize = 4096;
const MAX_HEADER_SEGMENT_BYTES: usize = 512;
const MAX_CLAIMS_SEGMENT_BYTES: usize = 2048;
const MAX_SIGNATURE_SEGMENT_BYTES: usize = 256;
const ED25519_SIGNATURE_BYTES: usize = 64;

#[derive(Debug, Clone)]
pub(crate) struct VerifiedTokenClaims {
  pub(crate) token_id: String,
  pub(crate) subject: String,
  pub(crate) expires_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct TokenHeader {
  alg: String,
  #[serde(default)]
  typ: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TokenClaims {
  iss: String,
  aud: String,
  sub: String,
  jti: String,
  iat: i64,
  exp: i64,
  #[serde(default)]
  nbf: Option<i64>,
}

pub(crate) fn verify_bearer_token(
  config: &AdminTokenStoreConfig,
  public_key: &[u8; 32],
  token: &str,
  now_unix: i64,
) -> anyhow::Result<VerifiedTokenClaims> {
  if token.len() > MAX_COMPACT_TOKEN_BYTES {
    bail!("admin token is too long");
  }
  let mut parts = token.split('.');
  let Some(encoded_header) = parts.next() else {
    bail!("admin token is missing header");
  };
  let Some(encoded_claims) = parts.next() else {
    bail!("admin token is missing claims");
  };
  let Some(encoded_signature) = parts.next() else {
    bail!("admin token is missing signature");
  };
  if parts.next().is_some()
    || encoded_header.is_empty()
    || encoded_claims.is_empty()
    || encoded_signature.is_empty()
  {
    bail!("admin token must have exactly three compact segments");
  }
  validate_segment_len("header", encoded_header, MAX_HEADER_SEGMENT_BYTES)?;
  validate_segment_len("claims", encoded_claims, MAX_CLAIMS_SEGMENT_BYTES)?;
  validate_segment_len("signature", encoded_signature, MAX_SIGNATURE_SEGMENT_BYTES)?;

  let header: TokenHeader =
    serde_json::from_slice(&decode_url_segment(encoded_header)?).context("invalid token header")?;
  if header.alg != "EdDSA" {
    bail!("admin token uses unsupported alg");
  }
  if let Some(typ) = header.typ.as_deref()
    && typ != "oxibelt-admin-token+jwt"
    && typ != "JWT"
  {
    bail!("admin token uses unsupported typ");
  }

  let claims: TokenClaims =
    serde_json::from_slice(&decode_url_segment(encoded_claims)?).context("invalid token claims")?;
  validate_claims(config, &claims, now_unix)?;
  let signature = decode_url_segment(encoded_signature)?;
  if signature.len() != ED25519_SIGNATURE_BYTES {
    bail!("admin token signature length is invalid");
  }
  let signed = format!("{encoded_header}.{encoded_claims}");
  let verifier = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
  verifier
    .verify(signed.as_bytes(), &signature)
    .map_err(|_| anyhow::anyhow!("admin token signature is invalid"))?;

  Ok(VerifiedTokenClaims {
    token_id: claims.jti,
    subject: claims.sub,
    expires_at: claims.exp,
  })
}

fn validate_claims(
  config: &AdminTokenStoreConfig,
  claims: &TokenClaims,
  now_unix: i64,
) -> anyhow::Result<()> {
  if claims.iss != config.issuer {
    bail!("admin token issuer is invalid");
  }
  if claims.aud != config.audience {
    bail!("admin token audience is invalid");
  }
  if claims.sub.trim().is_empty() || claims.jti.trim().is_empty() {
    bail!("admin token subject and token id must not be empty");
  }
  if claims.exp <= now_unix {
    bail!("admin token is expired");
  }
  if let Some(nbf) = claims.nbf
    && nbf > now_unix
  {
    bail!("admin token is not valid yet");
  }
  if claims.iat > now_unix + 60 {
    bail!("admin token issued-at time is in the future");
  }
  if claims.exp <= claims.iat {
    bail!("admin token expires before issued-at time");
  }
  if claims.exp.saturating_sub(claims.iat) > config.token_ttl_seconds as i64 {
    bail!("admin token ttl exceeds admin.token_store.token_ttl_seconds");
  }
  Ok(())
}

fn validate_segment_len(segment: &str, value: &str, max: usize) -> anyhow::Result<()> {
  if value.len() > max {
    bail!("admin token {segment} segment is too long");
  }
  Ok(())
}

fn decode_url_segment(value: &str) -> anyhow::Result<Vec<u8>> {
  base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(value)
    .context("admin token segment must be base64url without padding")
}

#[cfg(test)]
pub(crate) fn sign_for_tests(
  key_pair: &signature::Ed25519KeyPair,
  issuer: &str,
  audience: &str,
  subject: &str,
  token_id: &str,
  issued_at: i64,
  expires_at: i64,
) -> anyhow::Result<String> {
  let header = TokenHeader {
    alg: "EdDSA".to_string(),
    typ: Some("oxibelt-admin-token+jwt".to_string()),
  };
  let claims = TokenClaims {
    iss: issuer.to_string(),
    aud: audience.to_string(),
    sub: subject.to_string(),
    jti: token_id.to_string(),
    iat: issued_at,
    exp: expires_at,
    nbf: None,
  };
  let encoded_header = encode_url_segment(&serde_json::to_vec(&header)?);
  let encoded_claims = encode_url_segment(&serde_json::to_vec(&claims)?);
  let signed = format!("{encoded_header}.{encoded_claims}");
  let signature = key_pair.sign(signed.as_bytes());
  Ok(format!(
    "{signed}.{}",
    encode_url_segment(signature.as_ref())
  ))
}

#[cfg(test)]
fn encode_url_segment(value: &[u8]) -> String {
  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn test_config() -> AdminTokenStoreConfig {
    AdminTokenStoreConfig {
      enabled: true,
      issuer: "issuer".to_string(),
      audience: "audience".to_string(),
      token_ttl_seconds: 60,
      ..AdminTokenStoreConfig::default()
    }
  }

  #[test]
  fn oversized_compact_tokens_are_rejected_before_decoding() {
    let token = "a".repeat(MAX_COMPACT_TOKEN_BYTES + 1);
    let error = verify_bearer_token(&test_config(), &[0; 32], &token, 1)
      .expect_err("oversized token should fail");

    assert!(
      error.to_string().contains("too long"),
      "unexpected error: {error:#}"
    );
  }

  #[test]
  fn oversized_compact_segments_are_rejected_before_decoding() {
    let token = format!(
      "{}.{}.{}",
      "a",
      "b".repeat(MAX_CLAIMS_SEGMENT_BYTES + 1),
      "c"
    );
    let error = verify_bearer_token(&test_config(), &[0; 32], &token, 1)
      .expect_err("oversized segment should fail");

    assert!(
      error.to_string().contains("segment is too long"),
      "unexpected error: {error:#}"
    );
  }
}
