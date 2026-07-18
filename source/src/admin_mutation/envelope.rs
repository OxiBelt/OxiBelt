use std::fmt::Write as _;

use base64::Engine;
use http::{HeaderMap, Method};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::MUTATION_HEADER;
use super::error::{MutationProtocolError, MutationProtocolErrorKind as ErrorKind};

const PROTOCOL_VERSION: &str = "1";
const TRANSCRIPT_DOMAIN: &[u8] = b"OXIBELT-ADMIN-MUTATION-TRANSCRIPT\0";
const MAX_ENCODED_HEADER_BYTES: usize = 8 * 1024;
const MAX_DECODED_HEADER_BYTES: usize = 6 * 1024;
const ED25519_SIGNATURE_BYTES: usize = 64;
#[cfg(feature = "mutation-pqc")]
const ML_DSA_44_SIGNATURE_BYTES: usize = 2_420;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationTarget {
  pub cluster_id: String,
  pub membership_revision: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedMutationEnvelope {
  pub version: String,
  pub signer_id: String,
  pub request_id: String,
  pub issued_at: String,
  pub expires_at: String,
  pub expected_previous_revision: String,
  pub new_revision: String,
  pub content_digest: String,
  pub target: MutationTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureSuite {
  Ed25519,
  #[cfg(feature = "mutation-pqc")]
  Ed25519MlDsa44,
}

impl SignatureSuite {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Ed25519 => "ed25519",
      #[cfg(feature = "mutation-pqc")]
      Self::Ed25519MlDsa44 => "ed25519_ml_dsa_44",
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationSignature {
  Ed25519([u8; ED25519_SIGNATURE_BYTES]),
  #[cfg(feature = "mutation-pqc")]
  Ed25519MlDsa44 {
    ed25519: [u8; ED25519_SIGNATURE_BYTES],
    ml_dsa_44: Vec<u8>,
  },
}

impl MutationSignature {
  pub const fn suite(&self) -> SignatureSuite {
    match self {
      Self::Ed25519(_) => SignatureSuite::Ed25519,
      #[cfg(feature = "mutation-pqc")]
      Self::Ed25519MlDsa44 { .. } => SignatureSuite::Ed25519MlDsa44,
    }
  }

  pub fn encoded(&self) -> String {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    match self {
      Self::Ed25519(signature) => format!("ed25519:{}", engine.encode(signature)),
      #[cfg(feature = "mutation-pqc")]
      Self::Ed25519MlDsa44 { ed25519, ml_dsa_44 } => format!(
        "ed25519_ml_dsa_44:{}.{}",
        engine.encode(ed25519),
        engine.encode(ml_dsa_44)
      ),
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationEnvelope {
  pub unsigned: UnsignedMutationEnvelope,
  pub signature: MutationSignature,
}

#[derive(Clone, Copy, Debug)]
pub struct TranscriptContext<'a> {
  pub method: &'a Method,
  pub path_and_query: &'a str,
  pub ipm_namespace: &'a str,
  pub authenticated_principal: &'a str,
  pub body: &'a [u8],
  pub precondition_revision: &'a str,
  pub now_unix_seconds: i64,
  pub maximum_validity_seconds: u64,
  pub maximum_clock_skew_seconds: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEnvelope {
  version: String,
  signer_id: String,
  request_id: String,
  issued_at: String,
  expires_at: String,
  expected_previous_revision: String,
  new_revision: String,
  content_digest: String,
  target: MutationTarget,
  signature: String,
}

pub fn parse_mutation_header(
  headers: &HeaderMap,
) -> Result<MutationEnvelope, MutationProtocolError> {
  let mut values = headers.get_all(MUTATION_HEADER).iter();
  let value = values.next().ok_or_else(|| {
    MutationProtocolError::new(
      ErrorKind::MissingHeader,
      "mutation envelope header is required",
    )
  })?;
  if values.next().is_some() {
    return Err(invalid("mutation envelope header must occur exactly once"));
  }
  let encoded = value
    .to_str()
    .map_err(|_| invalid("mutation envelope header must contain visible ASCII"))?;
  parse_encoded_header(encoded)
}

fn parse_encoded_header(encoded: &str) -> Result<MutationEnvelope, MutationProtocolError> {
  if encoded.is_empty() || encoded.len() > MAX_ENCODED_HEADER_BYTES {
    return Err(invalid("mutation envelope header has an invalid size"));
  }
  if encoded
    .bytes()
    .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
  {
    return Err(invalid("mutation envelope must be unpadded base64url"));
  }

  let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(encoded)
    .map_err(|_| invalid("mutation envelope must be unpadded base64url"))?;
  if decoded.len() > MAX_DECODED_HEADER_BYTES
    || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != encoded
  {
    return Err(invalid("mutation envelope base64url is not canonical"));
  }
  let wire: WireEnvelope =
    serde_json::from_slice(&decoded).map_err(|_| invalid("mutation envelope JSON is invalid"))?;
  let signature = parse_signature(&wire.signature)?;
  Ok(MutationEnvelope {
    unsigned: UnsignedMutationEnvelope {
      version: wire.version,
      signer_id: wire.signer_id,
      request_id: wire.request_id,
      issued_at: wire.issued_at,
      expires_at: wire.expires_at,
      expected_previous_revision: wire.expected_previous_revision,
      new_revision: wire.new_revision,
      content_digest: wire.content_digest,
      target: wire.target,
    },
    signature,
  })
}

pub fn encode_mutation_header(
  unsigned: &UnsignedMutationEnvelope,
  signature: &MutationSignature,
) -> Result<String, MutationProtocolError> {
  #[cfg(feature = "mutation-pqc")]
  if let MutationSignature::Ed25519MlDsa44 { ml_dsa_44, .. } = signature
    && ml_dsa_44.len() != ML_DSA_44_SIGNATURE_BYTES
  {
    return Err(invalid("ML-DSA-44 mutation signature length is invalid"));
  }
  let wire = WireEnvelope {
    version: unsigned.version.clone(),
    signer_id: unsigned.signer_id.clone(),
    request_id: unsigned.request_id.clone(),
    issued_at: unsigned.issued_at.clone(),
    expires_at: unsigned.expires_at.clone(),
    expected_previous_revision: unsigned.expected_previous_revision.clone(),
    new_revision: unsigned.new_revision.clone(),
    content_digest: unsigned.content_digest.clone(),
    target: unsigned.target.clone(),
    signature: signature.encoded(),
  };
  let json = serde_json::to_vec(&wire)
    .map_err(|_| invalid("mutation envelope JSON could not be encoded"))?;
  let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
  if encoded.len() > MAX_ENCODED_HEADER_BYTES {
    return Err(invalid("mutation envelope header has an invalid size"));
  }
  Ok(encoded)
}

pub fn mutation_transcript(
  unsigned: &UnsignedMutationEnvelope,
  suite: SignatureSuite,
  context: &TranscriptContext<'_>,
) -> Result<Vec<u8>, MutationProtocolError> {
  validate_unsigned(unsigned, context)?;
  validate_context(context)?;
  verify_content_digest(unsigned, context.body)?;

  let mut transcript = Vec::with_capacity(512);
  transcript.extend_from_slice(TRANSCRIPT_DOMAIN);
  append_field(&mut transcript, unsigned.version.as_bytes())?;
  append_field(&mut transcript, suite.as_str().as_bytes())?;
  append_field(&mut transcript, unsigned.signer_id.as_bytes())?;
  append_field(&mut transcript, context.ipm_namespace.as_bytes())?;
  append_field(&mut transcript, context.authenticated_principal.as_bytes())?;
  append_field(&mut transcript, context.method.as_str().as_bytes())?;
  append_field(&mut transcript, context.path_and_query.as_bytes())?;
  append_field(&mut transcript, context.precondition_revision.as_bytes())?;
  append_field(&mut transcript, unsigned.request_id.as_bytes())?;
  append_field(&mut transcript, unsigned.issued_at.as_bytes())?;
  append_field(&mut transcript, unsigned.expires_at.as_bytes())?;
  append_field(
    &mut transcript,
    unsigned.expected_previous_revision.as_bytes(),
  )?;
  append_field(&mut transcript, unsigned.new_revision.as_bytes())?;
  append_field(&mut transcript, unsigned.content_digest.as_bytes())?;
  append_field(&mut transcript, unsigned.target.cluster_id.as_bytes())?;
  append_field(
    &mut transcript,
    unsigned.target.membership_revision.as_bytes(),
  )?;
  Ok(transcript)
}

fn validate_unsigned(
  unsigned: &UnsignedMutationEnvelope,
  context: &TranscriptContext<'_>,
) -> Result<(), MutationProtocolError> {
  if unsigned.version != PROTOCOL_VERSION {
    return Err(MutationProtocolError::new(
      ErrorKind::UnsupportedVersion,
      "mutation envelope version is unsupported",
    ));
  }
  validate_identifier("signer_id", &unsigned.signer_id, 128)?;
  validate_uuid(&unsigned.request_id)?;
  validate_revision(
    "expected_previous_revision",
    &unsigned.expected_previous_revision,
  )?;
  validate_revision("new_revision", &unsigned.new_revision)?;
  if unsigned.expected_previous_revision == unsigned.new_revision {
    return Err(invalid("mutation revisions must differ"));
  }
  validate_identifier("cluster_id", &unsigned.target.cluster_id, 128)?;
  validate_digest("membership_revision", &unsigned.target.membership_revision)?;
  validate_digest("content_digest", &unsigned.content_digest)?;

  let issued = parse_timestamp(&unsigned.issued_at)?;
  let expires = parse_timestamp(&unsigned.expires_at)?;
  if expires <= issued {
    return Err(MutationProtocolError::new(
      ErrorKind::InvalidTimestamp,
      "mutation expiration must be after issuance",
    ));
  }
  let validity = u64::try_from(expires - issued).map_err(|_| {
    MutationProtocolError::new(ErrorKind::InvalidTimestamp, "mutation timestamp is invalid")
  })?;
  if validity > context.maximum_validity_seconds {
    return Err(MutationProtocolError::new(
      ErrorKind::ValidityWindowTooLong,
      "mutation validity window exceeds policy",
    ));
  }
  let skew = i64::try_from(context.maximum_clock_skew_seconds).unwrap_or(i64::MAX);
  if issued > context.now_unix_seconds.saturating_add(skew) {
    return Err(MutationProtocolError::new(
      ErrorKind::NotYetValid,
      "mutation issuance is in the future",
    ));
  }
  if expires <= context.now_unix_seconds {
    return Err(MutationProtocolError::new(
      ErrorKind::Expired,
      "mutation envelope has expired",
    ));
  }
  Ok(())
}

fn validate_context(context: &TranscriptContext<'_>) -> Result<(), MutationProtocolError> {
  if context.path_and_query.is_empty()
    || !context.path_and_query.starts_with('/')
    || context.path_and_query.contains('#')
    || has_control(context.path_and_query)
    || context.path_and_query.len() > 4_096
  {
    return Err(invalid("mutation request path and query are invalid"));
  }
  validate_text("IPM namespace", context.ipm_namespace, 256)?;
  validate_text(
    "authenticated principal",
    context.authenticated_principal,
    1_024,
  )?;
  validate_revision("If-Match precondition", context.precondition_revision)
}

fn verify_content_digest(
  unsigned: &UnsignedMutationEnvelope,
  body: &[u8],
) -> Result<(), MutationProtocolError> {
  let expected = decode_digest(&unsigned.content_digest)?;
  let actual: [u8; 32] = Sha256::digest(body).into();
  if expected.ct_eq(&actual).unwrap_u8() != 1 {
    return Err(MutationProtocolError::new(
      ErrorKind::DigestMismatch,
      "mutation content digest does not match the request body",
    ));
  }
  Ok(())
}

fn parse_signature(value: &str) -> Result<MutationSignature, MutationProtocolError> {
  let (suite, encoded) = value
    .split_once(':')
    .ok_or_else(|| invalid("mutation signature is invalid"))?;
  match suite {
    "ed25519" => Ok(MutationSignature::Ed25519(decode_exact_base64url(encoded)?)),
    #[cfg(feature = "mutation-pqc")]
    "ed25519_ml_dsa_44" => {
      let (ed25519, ml_dsa_44) = encoded
        .split_once('.')
        .ok_or_else(|| invalid("hybrid mutation signature is invalid"))?;
      if ml_dsa_44.contains('.') {
        return Err(invalid("hybrid mutation signature is invalid"));
      }
      let ml_dsa_44 = decode_base64url(ml_dsa_44)?;
      if ml_dsa_44.len() != ML_DSA_44_SIGNATURE_BYTES {
        return Err(invalid("ML-DSA-44 mutation signature length is invalid"));
      }
      Ok(MutationSignature::Ed25519MlDsa44 {
        ed25519: decode_exact_base64url(ed25519)?,
        ml_dsa_44,
      })
    }
    #[cfg(not(feature = "mutation-pqc"))]
    "ed25519_ml_dsa_44" => Err(MutationProtocolError::new(
      ErrorKind::SignatureSuiteMismatch,
      "hybrid mutation signatures are not supported by this build",
    )),
    _ => Err(MutationProtocolError::new(
      ErrorKind::SignatureSuiteMismatch,
      "mutation signature suite is unsupported",
    )),
  }
}

fn decode_exact_base64url<const N: usize>(value: &str) -> Result<[u8; N], MutationProtocolError> {
  let decoded = decode_base64url(value)?;
  decoded
    .try_into()
    .map_err(|_| invalid("mutation signature length is invalid"))
}

fn decode_base64url(value: &str) -> Result<Vec<u8>, MutationProtocolError> {
  if value.is_empty()
    || value
      .bytes()
      .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
  {
    return Err(invalid("mutation signature must be unpadded base64url"));
  }
  let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(value)
    .map_err(|_| invalid("mutation signature must be unpadded base64url"))?;
  if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value {
    return Err(invalid("mutation signature base64url is not canonical"));
  }
  Ok(decoded)
}

fn validate_uuid(value: &str) -> Result<(), MutationProtocolError> {
  if value.len() != 36
    || value.as_bytes().get(8) != Some(&b'-')
    || value.as_bytes().get(13) != Some(&b'-')
    || value.as_bytes().get(18) != Some(&b'-')
    || value.as_bytes().get(23) != Some(&b'-')
  {
    return Err(invalid("mutation request_id must be a canonical UUID"));
  }
  let compact: String = value
    .chars()
    .filter(|character| *character != '-')
    .collect();
  if compact.len() != 32
    || compact
      .bytes()
      .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
  {
    return Err(invalid("mutation request_id must be a canonical UUID"));
  }
  let mut bytes = [0_u8; 16];
  for (index, pair) in compact.as_bytes().chunks_exact(2).enumerate() {
    bytes[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
  }
  let version = bytes[6] >> 4;
  if !(1..=8).contains(&version) || bytes[8] & 0b1100_0000 != 0b1000_0000 || bytes == [0; 16] {
    return Err(invalid("mutation request_id must be an RFC 9562 UUID"));
  }
  Ok(())
}

fn validate_revision(field: &'static str, value: &str) -> Result<(), MutationProtocolError> {
  if value.is_empty()
    || value.len() > 128
    || value
      .bytes()
      .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b':' | b'-'))
  {
    return Err(invalid(field));
  }
  Ok(())
}

fn validate_identifier(
  field: &'static str,
  value: &str,
  maximum: usize,
) -> Result<(), MutationProtocolError> {
  if value.is_empty()
    || value.len() > maximum
    || value.bytes().any(|byte| {
      !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b':' | b'-' | b'/')
    })
  {
    return Err(invalid(field));
  }
  Ok(())
}

fn validate_text(
  field: &'static str,
  value: &str,
  maximum: usize,
) -> Result<(), MutationProtocolError> {
  if value.is_empty() || value.len() > maximum || has_control(value) {
    return Err(invalid(field));
  }
  Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), MutationProtocolError> {
  if value.len() != 71
    || !value.starts_with("sha256:")
    || value[7..]
      .bytes()
      .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
  {
    return Err(invalid(field));
  }
  Ok(())
}

fn decode_digest(value: &str) -> Result<[u8; 32], MutationProtocolError> {
  validate_digest("content_digest", value)?;
  let mut digest = [0_u8; 32];
  for (index, pair) in value.as_bytes()[7..].chunks_exact(2).enumerate() {
    digest[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
  }
  Ok(digest)
}

fn hex_nibble(byte: u8) -> u8 {
  match byte {
    b'0'..=b'9' => byte - b'0',
    b'a'..=b'f' => byte - b'a' + 10,
    _ => 0,
  }
}

pub(super) fn parse_timestamp(value: &str) -> Result<i64, MutationProtocolError> {
  let bytes = value.as_bytes();
  if bytes.len() != 20
    || bytes.get(4) != Some(&b'-')
    || bytes.get(7) != Some(&b'-')
    || bytes.get(10) != Some(&b'T')
    || bytes.get(13) != Some(&b':')
    || bytes.get(16) != Some(&b':')
    || bytes.get(19) != Some(&b'Z')
  {
    return Err(invalid_timestamp());
  }
  let year = decimal(bytes, 0, 4)?;
  let month = decimal(bytes, 5, 2)?;
  let day = decimal(bytes, 8, 2)?;
  let hour = decimal(bytes, 11, 2)?;
  let minute = decimal(bytes, 14, 2)?;
  let second = decimal(bytes, 17, 2)?;
  if !(1970..=9999).contains(&year)
    || !(1..=12).contains(&month)
    || day == 0
    || day > days_in_month(year, month)
    || hour > 23
    || minute > 59
    || second > 59
  {
    return Err(invalid_timestamp());
  }
  let days = days_before_year(year) - days_before_year(1970)
    + days_before_month(year, month)
    + i64::from(day - 1);
  Ok(days * 86_400 + i64::from(hour * 3_600 + minute * 60 + second))
}

fn decimal(bytes: &[u8], offset: usize, length: usize) -> Result<u32, MutationProtocolError> {
  let mut value = 0_u32;
  for byte in bytes
    .get(offset..offset + length)
    .ok_or_else(invalid_timestamp)?
  {
    if !byte.is_ascii_digit() {
      return Err(invalid_timestamp());
    }
    value = value * 10 + u32::from(*byte - b'0');
  }
  Ok(value)
}

fn days_before_year(year: u32) -> i64 {
  let previous = i64::from(year - 1);
  previous * 365 + previous / 4 - previous / 100 + previous / 400
}

fn days_before_month(year: u32, month: u32) -> i64 {
  const OFFSETS: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
  let mut days = OFFSETS[(month - 1) as usize];
  if month > 2 && is_leap_year(year) {
    days += 1;
  }
  days
}

fn days_in_month(year: u32, month: u32) -> u32 {
  match month {
    2 if is_leap_year(year) => 29,
    2 => 28,
    4 | 6 | 9 | 11 => 30,
    _ => 31,
  }
}

fn is_leap_year(year: u32) -> bool {
  year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), MutationProtocolError> {
  let length =
    u32::try_from(value.len()).map_err(|_| invalid("mutation transcript field is too long"))?;
  output.extend_from_slice(&length.to_be_bytes());
  output.extend_from_slice(value);
  Ok(())
}

pub(crate) fn sha256_labelled(domain: &[u8], value: &[u8]) -> String {
  let mut hasher = Sha256::new();
  hasher.update(domain);
  hasher.update(value);
  let digest = hasher.finalize();
  let mut output = String::with_capacity(71);
  output.push_str("sha256:");
  for byte in digest {
    let _ = write!(output, "{byte:02x}");
  }
  output
}

fn has_control(value: &str) -> bool {
  value.chars().any(char::is_control)
}

fn invalid(detail: &'static str) -> MutationProtocolError {
  MutationProtocolError::new(ErrorKind::InvalidEnvelope, detail)
}

fn invalid_timestamp() -> MutationProtocolError {
  MutationProtocolError::new(
    ErrorKind::InvalidTimestamp,
    "mutation timestamp must be canonical UTC RFC 3339",
  )
}
