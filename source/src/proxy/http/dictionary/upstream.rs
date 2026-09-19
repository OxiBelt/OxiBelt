//! Independent upstream dictionary negotiation and identity response decoding.
use super::super::{body::ProxyBody, dictionary_body, integrity_digest};
use crate::cache::CacheDictionaryIdentity;
use crate::compression_dictionary::{
  codec::DictionaryCoding,
  fields::{AvailableDictionary, DictionaryEncoding},
  runtime::{Dictionary, DictionaryDirection, DictionaryScope, ProfileRuntime},
};
use crate::{
  config::{RouteConfig, UpstreamConfig},
  state::AppSnapshot,
};
use http::{HeaderMap, Request, Response, StatusCode};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub(in crate::proxy::http) struct Negotiation {
  pub dictionary: Option<Arc<Dictionary>>,
  pub profile: Arc<ProfileRuntime>,
  pub scope: DictionaryScope,
  pub url: url::Url,
  /// Final outbound headers, captured after dictionary negotiation for origin
  /// `Vary` evaluation. They are never copied into downstream cache keys.
  pub request_headers: HeaderMap,
}

/// Replay attempts retain only this safety bit; every target receives a new
/// negotiation and never inherits a selected dictionary from another origin.
#[derive(Clone, Copy)]
pub(in crate::proxy::http) struct RetryContext {
  pub authenticated: bool,
}

impl Negotiation {
  pub(in crate::proxy::http) fn representation_identity(
    &self,
  ) -> anyhow::Result<CacheDictionaryIdentity> {
    let scope = self.scope.key()?;
    let selected_dictionary_sha256 = self.dictionary.as_ref().map(|dictionary| {
      dictionary
        .hash
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
    });
    CacheDictionaryIdentity::new(
      scope.as_bytes(),
      selected_dictionary_sha256.as_deref(),
      &self.request_headers,
    )
  }
}

pub(in crate::proxy::http) fn public_headers(headers: &HeaderMap) -> bool {
  !["authorization", "proxy-authorization", "cookie"]
    .iter()
    .any(|name| headers.contains_key(*name))
}

pub(in crate::proxy::http) async fn prepare(
  request: &mut Request<ProxyBody>,
  route: &RouteConfig,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
  authenticated: bool,
) {
  let authenticated = authenticated
    || !public_headers(request.headers())
    || route.external_auth.is_some()
    || upstream.tls.client_identity.is_some()
    || request
      .extensions()
      .get::<super::PrivateRequest>()
      .is_some();
  request
    .extensions_mut()
    .insert(RetryContext { authenticated });
  let Some(profile) = route
    .compression_dictionary_profile
    .as_deref()
    .and_then(|name| state.compression_dictionary.profile(name))
  else {
    return;
  };
  if !profile.config.upstream {
    return;
  }
  // Client assertions never select the proxy's upstream representation.
  request.headers_mut().remove("available-dictionary");
  request.headers_mut().remove("dictionary-id");
  request.headers_mut().insert(
    http::header::ACCEPT_ENCODING,
    http::HeaderValue::from_static("identity"),
  );
  if authenticated
    || !public_headers(request.headers())
    || upstream.origin.scheme() != "https"
    || upstream.tls.client_identity.is_some()
    || request.method() != http::Method::GET
    || request.headers().contains_key(http::header::RANGE)
    || request
      .headers()
      .contains_key("upload-draft-interop-version")
  {
    return;
  }
  let Ok(url) = url::Url::parse(&request.uri().to_string()) else {
    return;
  };
  let scope = DictionaryScope {
    direction: DictionaryDirection::Upstream,
    origin: url.clone(),
    profile: profile.config.name.clone(),
    route_policy_fingerprint: super::fingerprint(route, state),
    upstream_fingerprint: Some(super::digest(format!("{upstream:?}").as_bytes())),
  };
  let dictionary = state
    .compression_dictionary
    .lookup(&profile.config.name, &scope, None, &url, None)
    .await
    .ok()
    .flatten();
  if let Some(dictionary) = &dictionary {
    let available = AvailableDictionary {
      hash: dictionary.hash,
      id: Some(dictionary.declaration.id.clone()),
    };
    if let Ok(headers) =
      available.canonical_headers(&[DictionaryEncoding::Dcb, DictionaryEncoding::Dcz])
    {
      if let Ok(value) = http::HeaderValue::from_str(&headers.available_dictionary) {
        request.headers_mut().insert("available-dictionary", value);
      }
      if let Some(value) = headers
        .dictionary_id
        .and_then(|value| http::HeaderValue::from_str(&value).ok())
      {
        request.headers_mut().insert("dictionary-id", value);
      }
      request.headers_mut().insert(
        http::header::ACCEPT_ENCODING,
        http::HeaderValue::from_static("dcb, dcz, identity"),
      );
    }
  }
  let request_headers = request.headers().clone();
  request.extensions_mut().insert(Negotiation {
    dictionary,
    profile,
    scope,
    url,
    request_headers,
  });
}

pub(in crate::proxy::http) fn decode(
  response: Response<ProxyBody>,
  negotiation: Option<&Negotiation>,
  managed: bool,
  metrics: Arc<crate::metrics::Metrics>,
) -> Result<Response<ProxyBody>, StatusCode> {
  let action = decode_action(
    response.status(),
    response.headers(),
    managed,
    negotiation.is_some_and(|value| value.dictionary.is_some()),
  )?;
  let coding = match action {
    DecodeAction::Passthrough | DecodeAction::Identity => return Ok(response),
    DecodeAction::NormalizeRevalidation => {
      let (mut parts, body) = response.into_parts();
      normalize_revalidation_metadata(&mut parts.headers);
      return Ok(Response::from_parts(parts, body));
    }
    DecodeAction::Decode(coding) => coding,
  };
  let negotiation = negotiation.ok_or(StatusCode::BAD_GATEWAY)?;
  let dictionary = negotiation
    .dictionary
    .as_ref()
    .ok_or(StatusCode::BAD_GATEWAY)?;
  let (mut parts, body) = response.into_parts();
  normalize_decoded_metadata(&mut parts.headers);
  if parts.status == StatusCode::NOT_MODIFIED || parts.status == StatusCode::NO_CONTENT {
    return Ok(Response::from_parts(parts, body));
  }
  let permit = negotiation
    .profile
    .codec_permits
    .clone()
    .try_acquire_owned()
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
  let config = &negotiation.profile.config;
  let max_decoded_bytes = usize::try_from(config.max_decoded_size_bytes).unwrap_or(usize::MAX);
  parts
    .extensions
    .insert(super::DecodedUpstreamResponse { max_decoded_bytes });
  let body = dictionary_body::transform(
    body,
    dictionary.bytes.clone(),
    dictionary_body::CodecBodyOptions {
      metrics: Some(metrics),
      coding,
      decode: true,
      level: 0,
      timeout: Duration::from_millis(config.codec_timeout_ms),
      max_decoded_bytes,
      max_expansion_ratio: config.max_expansion_ratio as usize,
    },
    permit,
  );
  Ok(Response::from_parts(parts, body))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodeAction {
  /// Dictionary upstream handling did not own the request, so preserve every
  /// response coding as it arrived.
  Passthrough,
  Identity,
  /// A 304 for a request that advertised a dictionary can carry validators for
  /// a coded variant even when it has no Content-Encoding field.
  NormalizeRevalidation,
  Decode(DictionaryCoding),
}

fn decode_action(
  status: StatusCode,
  headers: &HeaderMap,
  managed: bool,
  dictionary_available: bool,
) -> Result<DecodeAction, StatusCode> {
  if !managed {
    return Ok(DecodeAction::Passthrough);
  }
  let values = headers.get_all(http::header::CONTENT_ENCODING);
  if values.iter().count() > 1 {
    return Err(StatusCode::BAD_GATEWAY);
  }
  let coding = values
    .iter()
    .next()
    .map(|value| {
      value
        .to_str()
        .map(str::trim)
        .map_err(|_| StatusCode::BAD_GATEWAY)
    })
    .transpose()?;
  match coding {
    Some(value) if value.eq_ignore_ascii_case("dcb") => dictionary_available
      .then_some(DecodeAction::Decode(DictionaryCoding::Dcb))
      .ok_or(StatusCode::BAD_GATEWAY),
    Some(value) if value.eq_ignore_ascii_case("dcz") => dictionary_available
      .then_some(DecodeAction::Decode(DictionaryCoding::Dcz))
      .ok_or(StatusCode::BAD_GATEWAY),
    Some(value) if value.eq_ignore_ascii_case("identity") => Ok(DecodeAction::Identity),
    Some(_) => Err(StatusCode::BAD_GATEWAY),
    None if status == StatusCode::NOT_MODIFIED && dictionary_available => {
      Ok(DecodeAction::NormalizeRevalidation)
    }
    None => Ok(DecodeAction::Identity),
  }
}

fn normalize_decoded_metadata(headers: &mut HeaderMap) {
  headers.remove(http::header::CONTENT_ENCODING);
  headers.remove(http::header::CONTENT_LENGTH);
  normalize_revalidation_metadata(headers);
}

fn normalize_revalidation_metadata(headers: &mut HeaderMap) {
  super::super::compression::weaken_strong_etag(headers);
  integrity_digest::invalidate(headers, true);
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::{HeaderValue, header::ETAG};

  #[test]
  fn unmanaged_responses_are_transparent_but_managed_codings_are_strict() {
    let mut headers = HeaderMap::new();
    headers.insert(
      http::header::CONTENT_ENCODING,
      HeaderValue::from_static("dcb"),
    );
    assert_eq!(
      decode_action(StatusCode::OK, &headers, false, false),
      Ok(DecodeAction::Passthrough)
    );
    assert_eq!(
      decode_action(StatusCode::OK, &headers, true, false),
      Err(StatusCode::BAD_GATEWAY)
    );
    assert_eq!(
      decode_action(StatusCode::OK, &headers, true, true),
      Ok(DecodeAction::Decode(DictionaryCoding::Dcb))
    );
    headers.insert(
      http::header::CONTENT_ENCODING,
      HeaderValue::from_static("gzip"),
    );
    assert_eq!(
      decode_action(StatusCode::OK, &headers, true, true),
      Err(StatusCode::BAD_GATEWAY)
    );
    headers.append(
      http::header::CONTENT_ENCODING,
      HeaderValue::from_static("identity"),
    );
    assert_eq!(
      decode_action(StatusCode::OK, &headers, true, true),
      Err(StatusCode::BAD_GATEWAY)
    );
  }

  #[test]
  fn disabled_upstream_dictionary_handling_preserves_dcb_response() {
    let response = Response::builder()
      .header(http::header::CONTENT_ENCODING, "dcb")
      .header(ETAG, "\"coded\"")
      .body(crate::proxy::http::body::known_small_no_trailers_body(
        bytes::Bytes::from_static(b"opaque coded response"),
      ))
      .unwrap();
    let response = decode(response, None, false, crate::metrics::Metrics::new()).unwrap();
    assert_eq!(
      response
        .headers()
        .get(http::header::CONTENT_ENCODING)
        .unwrap(),
      "dcb"
    );
    assert_eq!(response.headers().get(ETAG).unwrap(), "\"coded\"");
  }

  #[test]
  fn enabled_profile_rejects_dcb_without_a_negotiation() {
    let response = Response::builder()
      .header(http::header::CONTENT_ENCODING, "dcb")
      .body(crate::proxy::http::body::known_small_no_trailers_body(
        bytes::Bytes::from_static(b"unsolicited coded response"),
      ))
      .unwrap();
    assert!(matches!(
      decode(response, None, true, crate::metrics::Metrics::new()),
      Err(StatusCode::BAD_GATEWAY)
    ));
  }

  #[test]
  fn dictionary_304_without_content_encoding_normalizes_representation_metadata() {
    let mut headers = HeaderMap::new();
    headers.insert(ETAG, HeaderValue::from_static("\"coded\""));
    headers.insert("content-digest", HeaderValue::from_static("sha-256=:AA==:"));
    headers.insert("repr-digest", HeaderValue::from_static("sha-256=:AA==:"));
    assert_eq!(
      decode_action(StatusCode::NOT_MODIFIED, &headers, true, true),
      Ok(DecodeAction::NormalizeRevalidation)
    );
    normalize_revalidation_metadata(&mut headers);
    assert_eq!(headers.get(ETAG).unwrap(), "W/\"coded\"");
    assert!(!headers.contains_key("content-digest"));
    assert!(!headers.contains_key("repr-digest"));
  }
}
