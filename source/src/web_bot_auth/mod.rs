//! Opt-in verification of Web Bot Auth HTTP Message Signatures.

mod body_digest;
mod crypto;
mod discovery;
mod protocol;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use http_body_util::BodyExt;
use hyper::body::Body;
use tokio::sync::Semaphore;

use crate::config::WebBotAuthConfig;

pub(crate) use discovery::DiscoveryRuntime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationStatus {
  Absent,
  Verified,
  Invalid,
  Unverified,
}

impl VerificationStatus {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Absent => "absent",
      Self::Verified => "verified",
      Self::Invalid => "invalid",
      Self::Unverified => "unverified",
    }
  }
}

#[derive(Clone, Debug)]
pub struct WebBotAuthResult {
  pub status: VerificationStatus,
  pub verified_urls: Vec<String>,
}

impl WebBotAuthResult {
  pub fn verified(&self) -> bool {
    self.status == VerificationStatus::Verified
  }
}

pub(crate) struct WebBotAuthRuntime {
  discovery: Arc<DiscoveryRuntime>,
  admissions: Semaphore,
}

impl WebBotAuthRuntime {
  pub fn new(config: &WebBotAuthConfig) -> anyhow::Result<Self> {
    Ok(Self {
      discovery: Arc::new(DiscoveryRuntime::new(config)?),
      admissions: Semaphore::new(32),
    })
  }

  pub async fn verify<B>(
    &self,
    request: &Request<B>,
    scheme: &str,
    config: &WebBotAuthConfig,
    digest_valid: bool,
  ) -> WebBotAuthResult {
    let parsed = protocol::parse_request(request, scheme, config.max_signature_age_seconds, 60);
    if parsed.absent {
      return result(VerificationStatus::Absent);
    }
    if scheme != "https" {
      return result(VerificationStatus::Unverified);
    }
    if crate::proxy::http::headers::validate_authority_host_consistency(request).is_err() {
      return result(VerificationStatus::Invalid);
    }
    if parsed.candidates.is_empty() {
      return result(VerificationStatus::Invalid);
    }
    let Ok(_permit) = self.admissions.try_acquire() else {
      return result(VerificationStatus::Unverified);
    };
    self
      .verify_with_deadline(request, scheme, config, digest_valid)
      .await
  }

  async fn verify_with_deadline<B>(
    &self,
    request: &Request<B>,
    scheme: &str,
    config: &WebBotAuthConfig,
    digest_valid: bool,
  ) -> WebBotAuthResult {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(config.discovery_timeout_ms);
    self
      .verify_inner(request, scheme, config, digest_valid, deadline)
      .await
  }

  async fn verify_inner<B>(
    &self,
    request: &Request<B>,
    scheme: &str,
    config: &WebBotAuthConfig,
    digest_valid: bool,
    deadline: tokio::time::Instant,
  ) -> WebBotAuthResult {
    let parsed = protocol::parse_request(request, scheme, config.max_signature_age_seconds, 60);
    if parsed.absent {
      return WebBotAuthResult {
        status: VerificationStatus::Absent,
        verified_urls: Vec::new(),
      };
    }
    if scheme != "https" {
      return WebBotAuthResult {
        status: VerificationStatus::Unverified,
        verified_urls: Vec::new(),
      };
    }
    let mut verified_urls = Vec::new();
    let mut unverified = false;
    for candidate in parsed.candidates {
      if candidate.covers_content_digest && !digest_valid {
        continue;
      }
      let discovery =
        tokio::time::timeout_at(deadline, self.discovery.resolve(&candidate.reference)).await;
      match discovery {
        Ok(Ok(keys)) => {
          let matching_key = keys
            .iter()
            .find(|key| crypto::jwk_thumbprint(key).as_deref() == Some(candidate.keyid.as_str()));
          if matching_key.is_none() {
            unverified = true;
          }
          if matching_key.is_some_and(|key| crypto::verify_candidate(&candidate, key)) {
            let mut url = candidate.reference.url;
            if candidate.reference.kind == protocol::DiscoveryKind::Directory {
              url.set_path("/.well-known/http-message-signatures-directory");
            }
            url.set_query(None);
            url.set_fragment(None);
            let identity = url.to_string();
            if !verified_urls.contains(&identity) {
              verified_urls.push(identity);
            }
          }
        }
        Ok(Err(_)) => unverified = true,
        Err(_) => {
          unverified = true;
          break;
        }
      }
    }
    let status = if !verified_urls.is_empty() {
      VerificationStatus::Verified
    } else if unverified {
      VerificationStatus::Unverified
    } else {
      VerificationStatus::Invalid
    };
    WebBotAuthResult {
      status,
      verified_urls,
    }
  }
}

fn result(status: VerificationStatus) -> WebBotAuthResult {
  WebBotAuthResult {
    status,
    verified_urls: Vec::new(),
  }
}

/// Verify before WAF evaluation and retain the trusted result in a private
/// request extension. Only requests covering Content-Digest consume the body.
pub(crate) async fn prepare_request<B>(
  request: Request<B>,
  scheme: &str,
  runtime: &WebBotAuthRuntime,
  config: &WebBotAuthConfig,
) -> Request<crate::proxy::http::body::ProxyBody>
where
  B: Body<Data = Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<crate::proxy::http::body::BoxError> + Send + Sync + Unpin + 'static,
{
  let parsed = protocol::parse_request(&request, scheme, config.max_signature_age_seconds, 60);
  let immediate = if parsed.absent {
    Some(VerificationStatus::Absent)
  } else if scheme != "https" {
    Some(VerificationStatus::Unverified)
  } else if crate::proxy::http::headers::validate_authority_host_consistency(&request).is_err()
    || parsed.candidates.is_empty()
  {
    Some(VerificationStatus::Invalid)
  } else {
    None
  };
  if let Some(status) = immediate {
    let mut request = request.map(|body| {
      body
        .map_err(|error| -> crate::proxy::http::body::BoxError { error.into() })
        .boxed()
    });
    request.extensions_mut().insert(result(status));
    return request;
  }
  let Ok(_permit) = runtime.admissions.try_acquire() else {
    let mut request = request.map(|body| {
      body
        .map_err(|error| -> crate::proxy::http::body::BoxError { error.into() })
        .boxed()
    });
    request
      .extensions_mut()
      .insert(result(VerificationStatus::Unverified));
    return request;
  };
  let digest_covered = parsed
    .candidates
    .iter()
    .any(|candidate| candidate.covers_content_digest);
  let (mut request, digest_valid) = if digest_covered {
    body_digest::inspect(request, config.max_body_digest_bytes).await
  } else {
    (
      request.map(|body| {
        body
          .map_err(|error| -> crate::proxy::http::body::BoxError { error.into() })
          .boxed()
      }),
      false,
    )
  };
  let result = runtime
    .verify_with_deadline(&request, scheme, config, digest_valid)
    .await;
  request.extensions_mut().insert(result);
  request
}
