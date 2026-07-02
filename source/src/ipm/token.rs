//! IPM bearer-token hashing and verification.
//! Token material is compared through hashes so plaintext credentials do not enter snapshots.

use base64::Engine;
use subtle::ConstantTimeEq;

pub(super) const TOKEN_HASH_ALG: &str = "sha256-v1";
const TOKEN_PREFIX: &str = "obt_v1_";
const TOKEN_BYTES: usize = 32;
const TOKEN_LIST_PREFIX_BYTES: usize = 18;

pub(super) fn generate_token() -> anyhow::Result<GeneratedToken> {
  let mut bytes = [0_u8; TOKEN_BYTES];
  crate::crypto::random_fill(&mut bytes)
    .map_err(|_| anyhow::anyhow!("failed to generate IPM credential token"))?;
  let token = format!(
    "{TOKEN_PREFIX}{}",
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
  );
  Ok(GeneratedToken {
    prefix: token_prefix(&token),
    hash: hash_token(&token),
    token,
  })
}

pub(super) fn hash_token(token: &str) -> String {
  hex_encode(&crate::crypto::sha256(token.as_bytes()))
}

pub(super) fn token_prefix(token: &str) -> String {
  token.chars().take(TOKEN_LIST_PREFIX_BYTES).collect()
}

pub(super) fn token_hash_matches(alg: Option<&str>, expected_hash: &str, token: &str) -> bool {
  if alg.is_some_and(|alg| alg != TOKEN_HASH_ALG) || expected_hash.trim().is_empty() {
    return false;
  }
  let actual = hash_token(token);
  expected_hash.as_bytes().ct_eq(actual.as_bytes()).into()
}

pub(super) fn validate_hash_alg(alg: &str) -> anyhow::Result<()> {
  if alg == TOKEN_HASH_ALG {
    Ok(())
  } else {
    anyhow::bail!("unsupported IPM credential token hash algorithm {alg}");
  }
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    output.push(char::from(HEX[(byte >> 4) as usize]));
    output.push(char::from(HEX[(byte & 0x0f) as usize]));
  }
  output
}

#[derive(Debug, Clone)]
pub(super) struct GeneratedToken {
  pub token: String,
  pub prefix: String,
  pub hash: String,
}

pub(super) fn expires_clause(
  ttl_seconds: Option<i64>,
  expires_at: &Option<String>,
) -> anyhow::Result<()> {
  if let Some(ttl_seconds) = ttl_seconds
    && ttl_seconds <= 0
  {
    anyhow::bail!("ttl_seconds must be greater than 0");
  }
  if let Some(expires_at) = expires_at
    && expires_at.trim().is_empty()
  {
    anyhow::bail!("expires_at must not be empty");
  }
  if ttl_seconds.is_some() && expires_at.is_some() {
    anyhow::bail!("set only one of ttl_seconds or expires_at");
  }
  Ok(())
}

pub(super) fn require_expiry(
  ttl_seconds: Option<i64>,
  expires_at: &Option<String>,
  no_expiry: bool,
) -> anyhow::Result<()> {
  if no_expiry {
    if ttl_seconds.is_some() || expires_at.is_some() {
      anyhow::bail!("--no-expiry cannot be combined with --expires or expires_at");
    }
    return Ok(());
  }
  expires_clause(ttl_seconds, expires_at)?;
  if ttl_seconds.is_none() && expires_at.is_none() {
    anyhow::bail!("credential create/rotate requires expires_at, ttl_seconds, or no_expiry");
  }
  Ok(())
}
