//! Purpose-bound remote signing client and transcript validation for CT log keys.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ED25519, UnparsedPublicKey};
use base64::Engine;
use tokio::net::UnixStream;

use super::protocol::{
  RemoteSignerRequest, RemoteSignerResponse, read_async_frame_with_timeout,
  write_async_frame_with_timeout,
};
use super::token::{RemoteSignerTokenProvider, token_to_wire};

pub use super::protocol::{CtLogProfile, CtTranscriptClass};

/// Fixed domain for the repository's non-RFC, operator-generated static checkpoint artifact.
pub const STATIC_CHECKPOINT_TRANSCRIPT_DOMAIN: &[u8] =
  b"oxibelt.ct.static-checkpoint.transcript/v1\0";

/// Maximum accepted serialized CT signature input. This is intentionally smaller than an IPC frame.
pub const MAX_CT_TRANSCRIPT_BYTES: usize = 64 * 1024;

/// Connection and token settings for a CT-log-purpose signer.
#[derive(Clone, Debug)]
pub struct CtLogSignerConfig {
  pub socket_path: PathBuf,
  pub key_id: String,
  pub profile: CtLogProfile,
  pub token_env: String,
  pub token_file: Option<PathBuf>,
  pub token_file_reload_base_dir: Option<PathBuf>,
  pub token_reload_interval: Duration,
  pub connect_timeout: Duration,
  pub sign_timeout: Duration,
}

/// Narrow async client that can sign only validated CT signature inputs for one immutable profile.
#[derive(Clone)]
pub struct CtLogSigner {
  socket_path: PathBuf,
  key_id: String,
  profile: CtLogProfile,
  public_key: Vec<u8>,
  token_provider: RemoteSignerTokenProvider,
  connect_timeout: Duration,
  sign_timeout: Duration,
}

impl CtLogSigner {
  pub async fn connect(config: CtLogSignerConfig) -> anyhow::Result<Self> {
    if config.key_id.trim().is_empty() {
      bail!("CT log signer key id must not be empty");
    }
    if config.connect_timeout.is_zero() {
      bail!("CT log signer connect timeout must be greater than 0");
    }
    if config.sign_timeout.is_zero() {
      bail!("CT log signer sign timeout must be greater than 0");
    }
    let signer = Self {
      socket_path: config.socket_path,
      key_id: config.key_id,
      profile: config.profile,
      public_key: Vec::new(),
      token_provider: RemoteSignerTokenProvider::from_sources(
        config.token_file,
        config.token_file_reload_base_dir,
        &config.token_env,
        config.token_reload_interval,
      )?,
      connect_timeout: config.connect_timeout,
      sign_timeout: config.sign_timeout,
    };
    let (profile, public_key) = signer.describe_key().await?;
    if profile != signer.profile {
      bail!("CT log signer profile does not match the configured immutable profile");
    }
    Ok(Self {
      public_key,
      ..signer
    })
  }

  pub fn key_id(&self) -> &str {
    &self.key_id
  }

  pub fn profile(&self) -> CtLogProfile {
    self.profile
  }

  /// Returns the DER SubjectPublicKeyInfo advertised by the signer, never private material.
  pub fn public_key_spki(&self) -> &[u8] {
    &self.public_key
  }

  pub async fn sign_transcript(
    &self,
    transcript_class: CtTranscriptClass,
    transcript: &[u8],
  ) -> anyhow::Result<Vec<u8>> {
    validate_ct_transcript(self.profile, transcript_class, transcript)?;
    match self
      .request_authenticated(|token| RemoteSignerRequest::SignCtLogTranscript {
        token: token_to_wire(&token),
        key_id: self.key_id.clone(),
        transcript_class,
        transcript: base64::engine::general_purpose::STANDARD.encode(transcript),
      })
      .await?
    {
      RemoteSignerResponse::SignCtLogTranscript { signature } => {
        let signature = base64::engine::general_purpose::STANDARD
          .decode(signature)
          .context("CT log signer signature must contain base64")?;
        verify_ct_log_signature(self.profile, &self.public_key, transcript, &signature)?;
        Ok(signature)
      }
      RemoteSignerResponse::Error { code, message } => {
        bail!("CT log signing failed: {code}: {message}")
      }
      _ => bail!("CT log signer returned an unexpected sign response"),
    }
  }

  async fn describe_key(&self) -> anyhow::Result<(CtLogProfile, Vec<u8>)> {
    match self
      .request_authenticated(|token| RemoteSignerRequest::DescribeCtLogKey {
        token: token_to_wire(&token),
        key_id: self.key_id.clone(),
      })
      .await?
    {
      RemoteSignerResponse::DescribeCtLogKey {
        public_key,
        profile,
      } => {
        let public_key = base64::engine::general_purpose::STANDARD
          .decode(public_key)
          .context("CT log signer public key must contain base64")?;
        if public_key.is_empty() || public_key.len() > 1024 {
          bail!("CT log signer public key has an invalid length");
        }
        validate_ct_log_public_key(profile, &public_key)?;
        Ok((profile, public_key))
      }
      RemoteSignerResponse::Error { code, message } => {
        bail!("CT log key description failed: {code}: {message}")
      }
      _ => bail!("CT log signer returned an unexpected describe response"),
    }
  }

  async fn request_authenticated<F>(&self, make_request: F) -> anyhow::Result<RemoteSignerResponse>
  where
    F: Fn([u8; 32]) -> RemoteSignerRequest,
  {
    let response = self
      .request(make_request(self.token_provider.current_token()))
      .await?;
    if !super::is_unauthorized_response(&response) || !self.token_provider.reloadable() {
      return Ok(response);
    }
    self.token_provider.force_refresh();
    self
      .request(make_request(self.token_provider.current_token()))
      .await
  }

  async fn request(&self, request: RemoteSignerRequest) -> anyhow::Result<RemoteSignerResponse> {
    let mut stream =
      tokio::time::timeout(self.connect_timeout, UnixStream::connect(&self.socket_path))
        .await
        .map_err(|_| anyhow::anyhow!("CT log signer connect timed out"))?
        .with_context(|| format!("failed to connect to {}", self.socket_path.display()))?;
    write_async_frame_with_timeout(&mut stream, &request, self.sign_timeout).await?;
    read_async_frame_with_timeout(&mut stream, self.sign_timeout).await
  }
}

/// Verifies a CT log signature against the activation-time pinned SPKI and exact transcript.
///
/// This is deliberately shared by the client response path and durable-receipt recovery: a
/// well-formed IPC response or persisted receipt is not trusted until its signature verifies.
pub(crate) fn verify_ct_log_signature(
  profile: CtLogProfile,
  public_key_spki: &[u8],
  transcript: &[u8],
  signature: &[u8],
) -> anyhow::Result<()> {
  if signature.is_empty() || signature.len() > 80 {
    bail!("CT log signature has an invalid length");
  }
  match profile {
    CtLogProfile::Rfc9162Ed25519 => {
      if signature.len() != 64 {
        bail!("CT log Ed25519 signature must be 64 bytes");
      }
      let public_key = super::keys::ed25519_public_key_from_spki(public_key_spki)
        .context("CT log signer Ed25519 public key is malformed")?;
      UnparsedPublicKey::new(&ED25519, public_key)
        .verify(transcript, signature)
        .map_err(|_| anyhow::anyhow!("CT log signature verification failed"))
    }
    CtLogProfile::Rfc6962P256Sha256 | CtLogProfile::Rfc9162P256Sha256 => {
      validate_ct_log_public_key(profile, public_key_spki)?;
      let point = public_key_spki
        .get(26..)
        .ok_or_else(|| anyhow::anyhow!("CT log signer P-256 public key is malformed"))?;
      UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(transcript, signature)
        .map_err(|_| anyhow::anyhow!("CT log signature verification failed"))
    }
  }
}

impl fmt::Debug for CtLogSigner {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("CtLogSigner")
      .field("socket_path", &self.socket_path)
      .field("key_id", &self.key_id)
      .field("profile", &self.profile)
      .field("public_key", &"[REDACTED]")
      .field("token_source", &self.token_provider.source_label())
      .finish()
  }
}

pub(crate) fn validate_ct_log_public_key(
  profile: CtLogProfile,
  public_key: &[u8],
) -> anyhow::Result<()> {
  match profile {
    CtLogProfile::Rfc9162Ed25519 => {
      super::keys::ed25519_public_key_from_spki(public_key)
        .context("CT log signer Ed25519 public key must be an Ed25519 SPKI")?;
    }
    CtLogProfile::Rfc6962P256Sha256 | CtLogProfile::Rfc9162P256Sha256 => {
      // DER SubjectPublicKeyInfo for id-ecPublicKey + prime256v1 followed by one uncompressed
      // SEC1 P-256 point. The exact fixed prefix prevents profile substitution at activation.
      const P256_SPKI_PREFIX: &[u8; 26] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
      ];
      if public_key.len() != 91
        || !public_key.starts_with(P256_SPKI_PREFIX)
        || public_key[26] != 0x04
      {
        bail!("CT log signer P-256 public key must be a prime256v1 SPKI");
      }
    }
  }
  Ok(())
}

/// Validates an exact CT signature input shape before it can reach private-key operations.
pub fn validate_ct_transcript(
  profile: CtLogProfile,
  transcript_class: CtTranscriptClass,
  transcript: &[u8],
) -> anyhow::Result<()> {
  if transcript.is_empty() || transcript.len() > MAX_CT_TRANSCRIPT_BYTES {
    bail!("CT transcript must be nonempty and no more than {MAX_CT_TRANSCRIPT_BYTES} bytes");
  }
  match (profile, transcript_class) {
    (CtLogProfile::Rfc6962P256Sha256, CtTranscriptClass::V1Sct | CtTranscriptClass::V1Sth)
    | (
      CtLogProfile::Rfc9162P256Sha256 | CtLogProfile::Rfc9162Ed25519,
      CtTranscriptClass::V2Sct | CtTranscriptClass::V2Sth | CtTranscriptClass::V2FinalSth,
    )
    | (_, CtTranscriptClass::StaticCheckpoint) => {}
    _ => bail!("CT transcript class is incompatible with the immutable log profile"),
  }
  match transcript_class {
    CtTranscriptClass::V1Sct => validate_sct_input(transcript, 0),
    CtTranscriptClass::V1Sth => validate_sth_input(transcript, 0, 1),
    CtTranscriptClass::StaticCheckpoint => validate_static_checkpoint(transcript),
    CtTranscriptClass::V2Sct => validate_v2_sct_input(transcript),
    CtTranscriptClass::V2Sth | CtTranscriptClass::V2FinalSth => {
      validate_v2_tree_head_input(transcript)
    }
  }
}

fn validate_v2_sct_input(transcript: &[u8]) -> anyhow::Result<()> {
  let item = crate::ct::rfc9162::TransItemV2::decode(transcript)
    .map_err(|error| anyhow::anyhow!("invalid RFC 9162 SCT transcript: {error}"))?;
  if !matches!(
    &item,
    crate::ct::rfc9162::TransItemV2::X509Entry(_)
      | crate::ct::rfc9162::TransItemV2::PrecertificateEntry(_)
  ) {
    bail!("RFC 9162 SCT transcript must be an entry TransItem");
  }
  if item
    .encode()
    .map_err(|error| anyhow::anyhow!("failed to re-encode RFC 9162 SCT transcript: {error}"))?
    != transcript
  {
    bail!("RFC 9162 SCT transcript is not canonical");
  }
  Ok(())
}

fn validate_v2_tree_head_input(transcript: &[u8]) -> anyhow::Result<()> {
  // TreeHeadDataV2: timestamp, tree_size, Hash<32..255>, Extension<0..65535>.
  if transcript.len() < 8 + 8 + 1 + 32 + 2 {
    bail!("RFC 9162 tree-head transcript is truncated");
  }
  let mut offset = 16;
  let hash_len = usize::from(transcript[offset]);
  offset += 1;
  if hash_len < 32 || transcript.len() < offset.saturating_add(hash_len) {
    bail!("RFC 9162 tree-head transcript has an invalid root hash");
  }
  offset += hash_len;
  let extensions_len = read_u16(transcript, &mut offset)?;
  let end = offset
    .checked_add(extensions_len)
    .ok_or_else(|| anyhow::anyhow!("RFC 9162 extension length overflows"))?;
  if end != transcript.len() {
    bail!("RFC 9162 tree-head transcript has trailing bytes");
  }
  let mut previous = None;
  while offset < end {
    let extension_type = read_u16(transcript, &mut offset)?;
    if previous.is_some_and(|value| extension_type <= value) {
      bail!("RFC 9162 tree-head extensions are not canonical");
    }
    let length = read_u16(transcript, &mut offset)?;
    offset = offset
      .checked_add(length)
      .filter(|value| *value <= end)
      .ok_or_else(|| anyhow::anyhow!("RFC 9162 tree-head extension is truncated"))?;
    previous = Some(extension_type);
  }
  Ok(())
}

fn validate_sct_input(transcript: &[u8], version: u8) -> anyhow::Result<()> {
  if transcript.len() < 14 || transcript[0] != version || transcript[1] != 0 {
    bail!("CT SCT transcript has an invalid version or signature type");
  }
  let entry_type = u16::from_be_bytes([transcript[10], transcript[11]]);
  let mut offset = 12;
  match entry_type {
    0 => {
      let certificate_len = read_u24(transcript, &mut offset)?;
      if certificate_len == 0 || offset.checked_add(certificate_len).is_none() {
        bail!("CT SCT transcript has an invalid X.509 entry length");
      }
      offset += certificate_len;
    }
    1 => {
      let Some(next) = offset.checked_add(32) else {
        bail!("CT SCT transcript precertificate hash length overflows");
      };
      if transcript.len() < next {
        bail!("CT SCT transcript is missing the precertificate issuer hash");
      }
      offset = next;
      let certificate_len = read_u24(transcript, &mut offset)?;
      if certificate_len == 0 || offset.checked_add(certificate_len).is_none() {
        bail!("CT SCT transcript has an invalid precertificate entry length");
      }
      offset += certificate_len;
    }
    _ => bail!("CT SCT transcript has an unsupported log entry type"),
  }
  let extensions_len = read_u16(transcript, &mut offset)?;
  if offset.checked_add(extensions_len) != Some(transcript.len()) {
    bail!("CT SCT transcript has noncanonical trailing bytes");
  }
  Ok(())
}

fn validate_sth_input(transcript: &[u8], version: u8, signature_type: u8) -> anyhow::Result<()> {
  if transcript.len() != 50 || transcript[0] != version || transcript[1] != signature_type {
    bail!("CT tree-head transcript has an invalid canonical framing");
  }
  Ok(())
}

fn validate_static_checkpoint(transcript: &[u8]) -> anyhow::Result<()> {
  const STATIC_CHECKPOINT_LEN: usize = STATIC_CHECKPOINT_TRANSCRIPT_DOMAIN.len() + 1 + 8 + 8 + 32;
  if transcript.len() != STATIC_CHECKPOINT_LEN
    || !transcript.starts_with(STATIC_CHECKPOINT_TRANSCRIPT_DOMAIN)
    || transcript[STATIC_CHECKPOINT_TRANSCRIPT_DOMAIN.len()] != 1
  {
    bail!("CT static checkpoint transcript has an invalid canonical framing");
  }
  Ok(())
}

fn read_u16(input: &[u8], offset: &mut usize) -> anyhow::Result<usize> {
  let end = offset
    .checked_add(2)
    .ok_or_else(|| anyhow::anyhow!("CT transcript length overflows"))?;
  let bytes = input
    .get(*offset..end)
    .ok_or_else(|| anyhow::anyhow!("CT transcript is truncated"))?;
  *offset = end;
  Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
}

fn read_u24(input: &[u8], offset: &mut usize) -> anyhow::Result<usize> {
  let end = offset
    .checked_add(3)
    .ok_or_else(|| anyhow::anyhow!("CT transcript length overflows"))?;
  let bytes = input
    .get(*offset..end)
    .ok_or_else(|| anyhow::anyhow!("CT transcript is truncated"))?;
  *offset = end;
  Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use aws_lc_rs::rand::SystemRandom;
  use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _,
  };
  use base64::Engine as _;
  use tokio::net::UnixListener;

  use super::super::protocol::{
    RemoteSignerRequest, RemoteSignerResponse, read_async_frame_with_timeout,
    write_async_frame_with_timeout,
  };
  use super::{
    CtLogProfile, CtLogSigner, CtLogSignerConfig, CtTranscriptClass, verify_ct_log_signature,
  };

  const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  ];
  const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
  ];

  #[test]
  fn ct_log_response_verification_rejects_ed25519_forgery_key_and_transcript_confusion() {
    let key = Ed25519KeyPair::generate().expect("test key should generate");
    let other_key = Ed25519KeyPair::generate().expect("second test key should generate");
    let mut spki = ED25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(key.public_key().as_ref());
    let mut other_spki = ED25519_SPKI_PREFIX.to_vec();
    other_spki.extend_from_slice(other_key.public_key().as_ref());
    let transcript = b"exact CT signer transcript";
    let signature = key.sign(transcript);

    verify_ct_log_signature(
      CtLogProfile::Rfc9162Ed25519,
      &spki,
      transcript,
      signature.as_ref(),
    )
    .expect("valid Ed25519 signer response must verify");
    assert!(
      verify_ct_log_signature(
        CtLogProfile::Rfc9162Ed25519,
        &spki,
        b"different CT signer transcript",
        signature.as_ref(),
      )
      .is_err()
    );
    assert!(
      verify_ct_log_signature(
        CtLogProfile::Rfc9162Ed25519,
        &other_spki,
        transcript,
        signature.as_ref(),
      )
      .is_err()
    );
    assert!(
      verify_ct_log_signature(CtLogProfile::Rfc9162Ed25519, &spki, transcript, &[0x5a; 64],)
        .is_err()
    );
  }

  #[test]
  fn ct_log_response_verification_rejects_malformed_or_forged_p256_signatures() {
    let random = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
      .expect("test key should generate");
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
      .expect("test key should parse");
    let other_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
      .expect("second test key should generate");
    let other_key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, other_pkcs8.as_ref())
      .expect("second test key should parse");
    let mut spki = P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(key.public_key().as_ref());
    let mut other_spki = P256_SPKI_PREFIX.to_vec();
    other_spki.extend_from_slice(other_key.public_key().as_ref());
    let transcript = b"exact P-256 CT signer transcript";
    let signature = key
      .sign(&random, transcript)
      .expect("test transcript should sign");

    verify_ct_log_signature(
      CtLogProfile::Rfc6962P256Sha256,
      &spki,
      transcript,
      signature.as_ref(),
    )
    .expect("valid P-256 signer response must verify");
    for (public_key, candidate) in [
      (spki.as_slice(), b"malformed".as_slice()),
      (other_spki.as_slice(), signature.as_ref()),
    ] {
      assert!(
        verify_ct_log_signature(
          CtLogProfile::Rfc6962P256Sha256,
          public_key,
          transcript,
          candidate,
        )
        .is_err()
      );
    }
    assert!(
      verify_ct_log_signature(
        CtLogProfile::Rfc6962P256Sha256,
        &spki,
        b"different P-256 CT signer transcript",
        signature.as_ref(),
      )
      .is_err()
    );
  }

  #[tokio::test]
  async fn ct_log_client_rejects_a_well_formed_forged_ed25519_signer_response() {
    let temp_dir = tempfile::tempdir().expect("temporary signer directory should create");
    let socket_path = temp_dir.path().join("forged-ct-signer.sock");
    let token_path = temp_dir.path().join("token.b64");
    std::fs::write(
      &token_path,
      base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
    )
    .expect("signer token should write");
    let key = Ed25519KeyPair::generate().expect("test key should generate");
    let mut public_key = ED25519_SPKI_PREFIX.to_vec();
    public_key.extend_from_slice(key.public_key().as_ref());
    let listener = UnixListener::bind(&socket_path).expect("forged signer listener should bind");
    let server = tokio::spawn(async move {
      let (mut describe_stream, _) = listener.accept().await.expect("describe connection");
      assert!(matches!(
        read_async_frame_with_timeout::<RemoteSignerRequest>(
          &mut describe_stream,
          Duration::from_secs(1),
        )
        .await
        .expect("describe request"),
        RemoteSignerRequest::DescribeCtLogKey { .. }
      ));
      write_async_frame_with_timeout(
        &mut describe_stream,
        &RemoteSignerResponse::DescribeCtLogKey {
          public_key: base64::engine::general_purpose::STANDARD.encode(&public_key),
          profile: CtLogProfile::Rfc9162Ed25519,
        },
        Duration::from_secs(1),
      )
      .await
      .expect("describe response");

      let (mut sign_stream, _) = listener.accept().await.expect("sign connection");
      assert!(matches!(
        read_async_frame_with_timeout::<RemoteSignerRequest>(
          &mut sign_stream,
          Duration::from_secs(1)
        )
        .await
        .expect("sign request"),
        RemoteSignerRequest::SignCtLogTranscript { .. }
      ));
      write_async_frame_with_timeout(
        &mut sign_stream,
        &RemoteSignerResponse::SignCtLogTranscript {
          signature: base64::engine::general_purpose::STANDARD.encode([0x5a; 64]),
        },
        Duration::from_secs(1),
      )
      .await
      .expect("forged sign response");
    });

    let client = CtLogSigner::connect(CtLogSignerConfig {
      socket_path,
      key_id: "ct-key".to_string(),
      profile: CtLogProfile::Rfc9162Ed25519,
      token_env: "UNUSED_CT_TEST_TOKEN".to_string(),
      token_file: Some(token_path),
      token_file_reload_base_dir: None,
      token_reload_interval: Duration::from_secs(1),
      connect_timeout: Duration::from_secs(1),
      sign_timeout: Duration::from_secs(1),
    })
    .await
    .expect("client should pin the described CT identity");
    let transcript = {
      let mut value = Vec::new();
      value.extend_from_slice(&1_u64.to_be_bytes());
      value.extend_from_slice(&1_u64.to_be_bytes());
      value.push(32);
      value.extend_from_slice(&[0x5a; 32]);
      value.extend_from_slice(&0_u16.to_be_bytes());
      value
    };
    assert!(
      client
        .sign_transcript(CtTranscriptClass::V2Sth, &transcript)
        .await
        .is_err(),
      "a correct-length signature that does not authenticate the transcript must not escape"
    );
    server.await.expect("forged signer task should finish");
  }
}
