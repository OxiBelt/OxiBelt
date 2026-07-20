//! Purpose-dispatched remote signer request handling.

use std::collections::HashMap;

use base64::Engine;
use rustls::SignatureScheme;

use super::audit_checkpoint::{AUDIT_CHECKPOINT_SIGNING_DOMAIN, signing_message};
use super::keys::{AuditCheckpointKey, ServerKey};
use super::protocol::{RemoteSignerRequest, RemoteSignerResponse, SignContext};
use super::token::{RemoteSignerTokenProvider, request_token_is_valid};
use super::{decode_base64, is_tls13_server_certificate_verify_message, signature_algorithm_name};

#[cfg(test)]
pub(super) fn process_request(
  request: RemoteSignerRequest,
  keys: &HashMap<String, ServerKey>,
  token_provider: &RemoteSignerTokenProvider,
  allow_tls12_unstructured_signing: bool,
) -> RemoteSignerResponse {
  process_request_with_audit_keys(
    request,
    keys,
    &HashMap::new(),
    token_provider,
    allow_tls12_unstructured_signing,
  )
}

pub(super) fn process_request_with_audit_keys(
  request: RemoteSignerRequest,
  keys: &HashMap<String, ServerKey>,
  audit_checkpoint_keys: &HashMap<String, AuditCheckpointKey>,
  token_provider: &RemoteSignerTokenProvider,
  allow_tls12_unstructured_signing: bool,
) -> RemoteSignerResponse {
  let token = token_provider.current_token();
  if !request_token_is_valid(request.token(), &token) {
    return RemoteSignerResponse::Error {
      code: "unauthorized".to_string(),
      message: "invalid signer token".to_string(),
    };
  }

  match request {
    RemoteSignerRequest::DescribeKey { key_id, .. } => match keys.get(&key_id) {
      Some(key) => RemoteSignerResponse::DescribeKey {
        public_key: base64::engine::general_purpose::STANDARD.encode(&key.public_key),
        algorithm: signature_algorithm_name(key.algorithm).to_string(),
        schemes: key.schemes.iter().copied().map(u16::from).collect(),
      },
      None => RemoteSignerResponse::Error {
        code: "unknown_key".to_string(),
        message: "unknown key id".to_string(),
      },
    },
    RemoteSignerRequest::Sign {
      key_id,
      scheme,
      context,
      message,
      ..
    } => process_tls_sign(
      keys,
      &key_id,
      scheme,
      context,
      &message,
      allow_tls12_unstructured_signing,
    ),
    RemoteSignerRequest::DescribeAuditCheckpointKey { key_id, .. } => {
      match audit_checkpoint_keys.get(&key_id) {
        Some(key) => RemoteSignerResponse::DescribeAuditCheckpointKey {
          public_key: base64::engine::general_purpose::STANDARD.encode(key.public_key),
          algorithm: "ed25519".to_string(),
          signing_domain: AUDIT_CHECKPOINT_SIGNING_DOMAIN.to_string(),
        },
        None => RemoteSignerResponse::Error {
          code: "unknown_audit_checkpoint_key".to_string(),
          message: "unknown audit checkpoint key id".to_string(),
        },
      }
    }
    RemoteSignerRequest::SignAuditCheckpointDigest { key_id, digest, .. } => {
      process_audit_checkpoint_sign(audit_checkpoint_keys, &key_id, &digest)
    }
  }
}

fn process_tls_sign(
  keys: &HashMap<String, ServerKey>,
  key_id: &str,
  scheme: u16,
  context: SignContext,
  message: &str,
  allow_tls12_unstructured_signing: bool,
) -> RemoteSignerResponse {
  let Some(key) = keys.get(key_id) else {
    return RemoteSignerResponse::Error {
      code: "unknown_key".to_string(),
      message: "unknown key id".to_string(),
    };
  };
  let Ok(message) = decode_base64("signing message", message) else {
    return RemoteSignerResponse::Error {
      code: "invalid_request".to_string(),
      message: "signing message must be base64".to_string(),
    };
  };
  match context {
    SignContext::Tls13ServerCertificateVerify => {
      if !is_tls13_server_certificate_verify_message(&message) {
        return RemoteSignerResponse::Error {
          code: "invalid_tls13_message".to_string(),
          message: "message is not a TLS 1.3 server CertificateVerify input".to_string(),
        };
      }
    }
    SignContext::Tls12Unstructured => {
      if !allow_tls12_unstructured_signing {
        return RemoteSignerResponse::Error {
          code: "tls12_disabled".to_string(),
          message: "TLS 1.2 unstructured signing is disabled".to_string(),
        };
      }
    }
  }
  let scheme = SignatureScheme::from(scheme);
  let Some(signer) = key.key.choose_scheme(&[scheme]) else {
    return RemoteSignerResponse::Error {
      code: "unsupported_scheme".to_string(),
      message: "key does not support requested signature scheme".to_string(),
    };
  };
  match signer.sign(&message) {
    Ok(signature) => RemoteSignerResponse::Sign {
      signature: base64::engine::general_purpose::STANDARD.encode(signature),
    },
    Err(error) => RemoteSignerResponse::Error {
      code: "signing_failed".to_string(),
      message: error.to_string(),
    },
  }
}

fn process_audit_checkpoint_sign(
  keys: &HashMap<String, AuditCheckpointKey>,
  key_id: &str,
  digest: &str,
) -> RemoteSignerResponse {
  let Some(key) = keys.get(key_id) else {
    return RemoteSignerResponse::Error {
      code: "unknown_audit_checkpoint_key".to_string(),
      message: "unknown audit checkpoint key id".to_string(),
    };
  };
  let Ok(digest) = decode_base64("audit checkpoint digest", digest) else {
    return RemoteSignerResponse::Error {
      code: "invalid_audit_checkpoint_digest".to_string(),
      message: "audit checkpoint digest must be base64".to_string(),
    };
  };
  let Ok(digest) = <[u8; 32]>::try_from(digest) else {
    return RemoteSignerResponse::Error {
      code: "invalid_audit_checkpoint_digest".to_string(),
      message: "audit checkpoint digest must be exactly 32 bytes".to_string(),
    };
  };
  let Some(signer) = key.key.choose_scheme(&[SignatureScheme::ED25519]) else {
    return RemoteSignerResponse::Error {
      code: "invalid_audit_checkpoint_key".to_string(),
      message: "audit checkpoint key does not support Ed25519".to_string(),
    };
  };
  match signer.sign(&signing_message(&digest)) {
    Ok(signature) => RemoteSignerResponse::SignAuditCheckpointDigest {
      signature: base64::engine::general_purpose::STANDARD.encode(signature),
    },
    Err(error) => RemoteSignerResponse::Error {
      code: "audit_checkpoint_signing_failed".to_string(),
      message: error.to_string(),
    },
  }
}
