use anyhow::{Context, bail};
use base64::Engine;
use ring::hmac;

pub const SIGNATURE_VERSION: &str = "hmac-sha256-v1";

#[derive(Debug, Clone)]
pub struct DynamicPolicySignatureFields<'a> {
  pub namespace: &'a str,
  pub enabled: bool,
  pub priority: i32,
  pub name: &'a str,
  pub source: &'a str,
  pub action: &'a str,
  pub subject_type: &'a str,
  pub subject: &'a str,
  pub route_name: Option<&'a str>,
  pub method: Option<&'a str>,
  pub path_prefix: Option<&'a str>,
  pub rate: Option<&'a str>,
  pub burst: Option<i32>,
  pub status: Option<i32>,
  pub body: Option<&'a str>,
  pub reason: Option<&'a str>,
  pub code: Option<&'a str>,
  pub mode: &'a str,
  pub writer_identity: Option<&'a str>,
  pub expires_at: Option<&'a str>,
}

pub fn load_key(env_name: &str) -> anyhow::Result<[u8; 32]> {
  let raw = std::env::var(env_name)
    .with_context(|| format!("failed to read signature key env {env_name}"))?;
  let bytes = base64::engine::general_purpose::STANDARD
    .decode(raw.trim())
    .context("dynamic policy signature key must contain base64")?;
  bytes
    .try_into()
    .map_err(|_| anyhow::anyhow!("dynamic policy signature key must contain exactly 32 bytes"))
}

pub fn sign(key: &[u8; 32], fields: &DynamicPolicySignatureFields<'_>) -> String {
  let payload = payload(fields);
  let key = hmac::Key::new(hmac::HMAC_SHA256, key);
  hex_encode(hmac::sign(&key, payload.as_bytes()).as_ref())
}

pub fn verify(
  key: &[u8; 32],
  fields: &DynamicPolicySignatureFields<'_>,
  signature: &str,
) -> anyhow::Result<()> {
  let signature = hex_decode(signature)?;
  let payload = payload(fields);
  let key = hmac::Key::new(hmac::HMAC_SHA256, key);
  hmac::verify(&key, payload.as_bytes(), &signature)
    .map_err(|_| anyhow::anyhow!("dynamic policy row signature is invalid"))
}

fn payload(fields: &DynamicPolicySignatureFields<'_>) -> String {
  let mut payload = String::from("oxibelt.dynamic_policy.v1\n");
  push_field(&mut payload, Some(fields.namespace));
  push_field(
    &mut payload,
    Some(if fields.enabled { "true" } else { "false" }),
  );
  push_field(&mut payload, Some(&fields.priority.to_string()));
  push_field(&mut payload, Some(fields.name));
  push_field(&mut payload, Some(fields.source));
  push_field(&mut payload, Some(fields.action));
  push_field(&mut payload, Some(fields.subject_type));
  push_field(&mut payload, Some(fields.subject));
  push_field(&mut payload, fields.route_name);
  push_field(&mut payload, fields.method);
  push_field(&mut payload, fields.path_prefix);
  push_field(&mut payload, fields.rate);
  push_field(
    &mut payload,
    fields
      .burst
      .as_ref()
      .map(|value| value.to_string())
      .as_deref(),
  );
  push_field(
    &mut payload,
    fields
      .status
      .as_ref()
      .map(|value| value.to_string())
      .as_deref(),
  );
  push_field(&mut payload, fields.body);
  push_field(&mut payload, fields.reason);
  push_field(&mut payload, fields.code);
  push_field(&mut payload, Some(fields.mode));
  push_field(&mut payload, fields.writer_identity);
  push_field(&mut payload, fields.expires_at);
  payload
}

fn push_field(payload: &mut String, value: Option<&str>) {
  match value {
    Some(value) => {
      payload.push_str(&value.len().to_string());
      payload.push(':');
      payload.push_str(value);
      payload.push('\n');
    }
    None => payload.push_str("-\n"),
  }
}

fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut encoded = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    encoded.push(HEX[(byte >> 4) as usize] as char);
    encoded.push(HEX[(byte & 0x0f) as usize] as char);
  }
  encoded
}

fn hex_decode(value: &str) -> anyhow::Result<Vec<u8>> {
  if !value.len().is_multiple_of(2) {
    bail!("hex value has odd length");
  }
  let mut bytes = Vec::with_capacity(value.len() / 2);
  for pair in value.as_bytes().chunks_exact(2) {
    bytes.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
  }
  Ok(bytes)
}

fn hex_nibble(byte: u8) -> anyhow::Result<u8> {
  match byte {
    b'0'..=b'9' => Ok(byte - b'0'),
    b'a'..=b'f' => Ok(byte - b'a' + 10),
    b'A'..=b'F' => Ok(byte - b'A' + 10),
    _ => bail!("invalid hex digit"),
  }
}
