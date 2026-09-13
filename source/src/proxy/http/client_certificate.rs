//! Route-local projection of verified TLS identity at the upstream boundary.

use http::header::{ACCEPT_ENCODING, CACHE_CONTROL, VARY};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};

use crate::cache::CacheCertificateIdentity;
use crate::config::{ClientCertificateForwardingFormat, LimitsConfig, RouteConfig};
use crate::state::AppSnapshot;
use crate::tls::{ForwardedClientCertificate, ForwardedClientCertificateCaptureError};

#[derive(Clone)]
pub(crate) struct PreparedCertificateForwarding {
  header: HeaderName,
  value: Option<HeaderValue>,
  pub(crate) cache_identity: CacheCertificateIdentity,
}

impl PreparedCertificateForwarding {
  pub(crate) fn prepare<B>(
    request: &Request<B>,
    route: &RouteConfig,
  ) -> Result<Option<Self>, StatusCode> {
    let Some(config) = &route.client_certificate_forwarding else {
      return Ok(None);
    };
    let header = HeaderName::from_bytes(config.header.as_bytes())
      .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let certificate = request.extensions().get::<ForwardedClientCertificate>();
    let value = certificate
      .map(|certificate| certificate.encode(config.format))
      .transpose()
      .map_err(capture_error_status)?;
    let fingerprint = certificate
      .map(ForwardedClientCertificate::fingerprint)
      .transpose()
      .map_err(capture_error_status)?;
    let format = match config.format {
      ClientCertificateForwardingFormat::UrlEncodedPem => "url_encoded_pem",
      ClientCertificateForwardingFormat::Rfc9440 => "rfc9440",
    };
    let cache_identity = CacheCertificateIdentity::new(header.as_str(), format, fingerprint)
      .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Some(Self {
      header,
      value,
      cache_identity,
    }))
  }

  pub(crate) fn apply(
    &self,
    headers: &mut HeaderMap,
    limits: &LimitsConfig,
  ) -> Result<(), StatusCode> {
    headers.remove(&self.header);
    if let Some(value) = &self.value {
      if value.as_bytes().len() > limits.max_header_value_bytes {
        return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
      }
      headers.remove(ACCEPT_ENCODING);
      headers.insert(self.header.clone(), value.clone());
      if headers.len() > limits.max_headers {
        return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
      }
      let total = headers.iter().try_fold(0usize, |total, (name, value)| {
        total
          .checked_add(name.as_str().len())?
          .checked_add(value.as_bytes().len())
      });
      if total.is_none_or(|total| total > limits.max_total_header_bytes) {
        return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
      }
    }
    Ok(())
  }
}

fn capture_error_status(error: ForwardedClientCertificateCaptureError) -> StatusCode {
  match error {
    ForwardedClientCertificateCaptureError::Oversized => {
      StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    }
    ForwardedClientCertificateCaptureError::Encoding => StatusCode::INTERNAL_SERVER_ERROR,
  }
}

pub(crate) fn strip_reserved(headers: &mut HeaderMap, state: &AppSnapshot) {
  for name in state.client_certificate_forwarding_headers.iter() {
    headers.remove(name);
  }
}

pub(crate) fn apply_upstream<B>(
  request: &mut Request<B>,
  state: &AppSnapshot,
) -> Result<(), StatusCode> {
  // Clone only the cheap prepared value; it owns no per-request copy of the DER.
  let prepared = request
    .extensions()
    .get::<PreparedCertificateForwarding>()
    .cloned();
  strip_reserved(request.headers_mut(), state);
  if let Some(prepared) = prepared {
    prepared.apply(request.headers_mut(), &state.config.limits)?;
  }
  Ok(())
}

pub(crate) fn cache_identity<B>(request: &Request<B>) -> Option<&CacheCertificateIdentity> {
  request
    .extensions()
    .get::<PreparedCertificateForwarding>()
    .map(|value| &value.cache_identity)
}

pub(crate) fn finalize_response<B>(response: &mut Response<B>, enabled: bool, state: &AppSnapshot) {
  if !enabled {
    return;
  }
  // These are delivery directives, applied only after internal cache admission.
  response
    .headers_mut()
    .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
  let certificate_vary = response.headers().get_all(VARY).iter().any(|value| {
    value.to_str().ok().is_some_and(|value| {
      value.split(',').any(|token| {
        state
          .client_certificate_forwarding_headers
          .iter()
          .any(|name| name.as_str().eq_ignore_ascii_case(token.trim()))
      })
    })
  });
  if certificate_vary {
    response
      .headers_mut()
      .insert(VARY, HeaderValue::from_static("*"));
  }
}

#[cfg(test)]
#[path = "client_certificate_tests.rs"]
mod tests;
