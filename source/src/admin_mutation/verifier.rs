use std::collections::BTreeMap;

use aws_lc_rs::signature::{ED25519, ParsedPublicKey, UnparsedPublicKey};

use super::envelope::{
  MutationEnvelope, MutationSignature, SignatureSuite, TranscriptContext, mutation_transcript,
  parse_mutation_header, sha256_labelled,
};
use super::error::{MutationProtocolError, MutationProtocolErrorKind as ErrorKind};

const FINGERPRINT_DOMAIN: &[u8] = b"OXIBELT-ADMIN-MUTATION-FINGERPRINT\0";

#[derive(Clone, Debug)]
pub struct SignerBinding {
  signer_id: String,
  principal: String,
  suite: SignatureSuite,
  ed25519_public_key: Vec<u8>,
  #[cfg(feature = "mutation-pqc")]
  ml_dsa_44_public_key_der: Option<Vec<u8>>,
}

impl SignerBinding {
  pub fn ed25519(
    signer_id: impl Into<String>,
    principal: impl Into<String>,
    public_key: impl Into<Vec<u8>>,
  ) -> Result<Self, MutationProtocolError> {
    let binding = Self {
      signer_id: signer_id.into(),
      principal: principal.into(),
      suite: SignatureSuite::Ed25519,
      ed25519_public_key: public_key.into(),
      #[cfg(feature = "mutation-pqc")]
      ml_dsa_44_public_key_der: None,
    };
    binding.validate()?;
    Ok(binding)
  }

  #[cfg(feature = "mutation-pqc")]
  pub fn ed25519_ml_dsa_44(
    signer_id: impl Into<String>,
    principal: impl Into<String>,
    ed25519_public_key: impl Into<Vec<u8>>,
    ml_dsa_44_public_key_der: Vec<u8>,
  ) -> Result<Self, MutationProtocolError> {
    let binding = Self {
      signer_id: signer_id.into(),
      principal: principal.into(),
      suite: SignatureSuite::Ed25519MlDsa44,
      ed25519_public_key: ed25519_public_key.into(),
      ml_dsa_44_public_key_der: Some(ml_dsa_44_public_key_der),
    };
    binding.validate()?;
    Ok(binding)
  }

  pub fn signer_id(&self) -> &str {
    &self.signer_id
  }

  pub fn principal(&self) -> &str {
    &self.principal
  }

  pub const fn suite(&self) -> SignatureSuite {
    self.suite
  }

  fn validate(&self) -> Result<(), MutationProtocolError> {
    if !is_safe_identifier(&self.signer_id, 128) {
      return Err(invalid("mutation signer ID is invalid"));
    }
    if self.principal.is_empty()
      || self.principal.len() > 1_024
      || self.principal.chars().any(char::is_control)
    {
      return Err(invalid("mutation signer principal is invalid"));
    }
    ParsedPublicKey::new(&ED25519, &self.ed25519_public_key)
      .map_err(|_| invalid("Ed25519 public key is invalid"))?;
    #[cfg(feature = "mutation-pqc")]
    if self.suite == SignatureSuite::Ed25519MlDsa44 {
      let public_key = self
        .ml_dsa_44_public_key_der
        .as_ref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("ML-DSA-44 public key is required"))?;
      ParsedPublicKey::new(&aws_lc_rs::unstable::signature::ML_DSA_44, public_key)
        .map_err(|_| invalid("ML-DSA-44 public key is invalid"))?;
    }
    Ok(())
  }
}

#[derive(Clone, Debug, Default)]
pub struct SignerRegistry {
  bindings: BTreeMap<String, SignerBinding>,
}

#[derive(Clone, Debug)]
pub struct VerifiedMutation {
  pub envelope: MutationEnvelope,
  pub fingerprint: String,
  pub signer_principal: String,
}

impl SignerRegistry {
  pub fn new(
    bindings: impl IntoIterator<Item = SignerBinding>,
  ) -> Result<Self, MutationProtocolError> {
    let mut registry = Self::default();
    for binding in bindings {
      binding.validate()?;
      let signer_id = binding.signer_id.clone();
      if registry.bindings.insert(signer_id, binding).is_some() {
        return Err(MutationProtocolError::new(
          ErrorKind::DuplicateSigner,
          "mutation signer IDs must be unique",
        ));
      }
    }
    Ok(registry)
  }

  pub fn verify(
    &self,
    headers: &http::HeaderMap,
    context: &TranscriptContext<'_>,
  ) -> Result<VerifiedMutation, MutationProtocolError> {
    let envelope = parse_mutation_header(headers)?;
    let binding = self
      .bindings
      .get(&envelope.unsigned.signer_id)
      .ok_or_else(|| {
        MutationProtocolError::new(ErrorKind::UnknownSigner, "mutation signer is not trusted")
      })?;
    if binding.principal != context.authenticated_principal {
      return Err(MutationProtocolError::new(
        ErrorKind::PrincipalMismatch,
        "mutation signer is not bound to the authenticated principal",
      ));
    }
    if binding.suite != envelope.signature.suite() {
      return Err(MutationProtocolError::new(
        ErrorKind::SignatureSuiteMismatch,
        "mutation signature suite does not match signer policy",
      ));
    }

    let transcript = mutation_transcript(&envelope.unsigned, binding.suite, context)?;
    verify_signature(binding, &envelope.signature, &transcript)?;
    Ok(VerifiedMutation {
      fingerprint: sha256_labelled(FINGERPRINT_DOMAIN, &transcript),
      signer_principal: binding.principal.clone(),
      envelope,
    })
  }
}

fn verify_signature(
  binding: &SignerBinding,
  signature: &MutationSignature,
  transcript: &[u8],
) -> Result<(), MutationProtocolError> {
  match signature {
    MutationSignature::Ed25519(signature) => verify_ed25519(binding, signature, transcript),
    #[cfg(feature = "mutation-pqc")]
    MutationSignature::Ed25519MlDsa44 { ed25519, ml_dsa_44 } => {
      // Authenticate with the inexpensive classical component before spending
      // substantially more CPU on ML-DSA. A valid classical signature still
      // requires a valid post-quantum signature, so this is not a downgrade.
      verify_ed25519(binding, ed25519, transcript)?;
      let ml_dsa_valid = binding
        .ml_dsa_44_public_key_der
        .as_ref()
        .is_some_and(|public_key| {
          UnparsedPublicKey::new(&aws_lc_rs::unstable::signature::ML_DSA_44, public_key)
            .verify(transcript, ml_dsa_44)
            .is_ok()
        });
      if ml_dsa_valid {
        Ok(())
      } else {
        Err(invalid_signature())
      }
    }
  }
}

fn verify_ed25519(
  binding: &SignerBinding,
  signature: &[u8],
  transcript: &[u8],
) -> Result<(), MutationProtocolError> {
  UnparsedPublicKey::new(&ED25519, &binding.ed25519_public_key)
    .verify(transcript, signature)
    .map_err(|_| invalid_signature())
}

fn is_safe_identifier(value: &str, maximum: usize) -> bool {
  !value.is_empty()
    && value.len() <= maximum
    && value
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/'))
}

fn invalid(detail: &'static str) -> MutationProtocolError {
  MutationProtocolError::new(ErrorKind::InvalidEnvelope, detail)
}

fn invalid_signature() -> MutationProtocolError {
  MutationProtocolError::new(
    ErrorKind::InvalidSignature,
    "mutation signature verification failed",
  )
}
