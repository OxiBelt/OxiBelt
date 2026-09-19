//! Inbound RFC 9842 dictionary-content-coding validation and decoding.
//!
//! Only an operator-provisioned, public dictionary is eligible. The fixed
//! codec prelude is captured and checked before a dictionary is selected, so a
//! peer cannot turn request decoding into an arbitrary dictionary fetch.

use std::sync::Arc;
use std::time::Duration;

use http::{Request, StatusCode, header};

use crate::compression_dictionary::{
  codec::{DCB_PRELUDE_LEN, DCZ_PRELUDE_LEN, DictionaryCoding},
  fields::{self, DictionaryHash},
};
use crate::config::RouteConfig;
use crate::state::AppSnapshot;

use super::{
  body::{BodyTimeoutKind, ProxyBody, error_is_body_length_limit, error_is_timeout},
  dictionary_body::{self, CodecBodyOptions},
};

const DCB_MAGIC: &[u8] = b"\xffDCB";
const DCZ_MAGIC: &[u8] = b"^*M\x18 \0\0\0";

/// A terminal validation failure that can still be reported before forwarding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DictionaryRequestError {
  pub(super) status: StatusCode,
  pub(super) message: &'static str,
}

impl DictionaryRequestError {
  const fn new(status: StatusCode, message: &'static str) -> Self {
    Self { status, message }
  }
}

/// Converts a complete, eligible `dcb` or `dcz` request body to identity.
///
/// Calls for non-dictionary codings and excluded request surfaces are no-ops.
/// The body supplied here must already have the ordinary encoded-byte limit and
/// client read timeout applied by the pipeline.
#[allow(clippy::too_many_arguments)]
pub(super) async fn decode(
  request: Request<ProxyBody>,
  route: &RouteConfig,
  state: &AppSnapshot,
  tls: &crate::waf::WafTlsMetadata,
  client: std::net::SocketAddr,
) -> Result<Request<ProxyBody>, DictionaryRequestError> {
  // Routes outside the opt-in retain opaque content-coding forwarding.
  if route
    .compression_dictionary_profile
    .as_deref()
    .and_then(|name| state.compression_dictionary.profile(name))
    .is_none()
  {
    return Ok(request);
  }
  let Some(coding) = content_coding(request.headers())? else {
    return Ok(request);
  };
  if excluded(&request, state) {
    return Ok(request);
  }
  if !secure(&request, tls, client) {
    return Err(DictionaryRequestError::new(
      StatusCode::UNSUPPORTED_MEDIA_TYPE,
      "dictionary request decoding requires a secure connection",
    ));
  }
  let profile_name =
    route
      .compression_dictionary_profile
      .as_deref()
      .ok_or(DictionaryRequestError::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "dictionary request decoding is not configured for this route",
      ))?;
  let profile =
    state
      .compression_dictionary
      .profile(profile_name)
      .ok_or(DictionaryRequestError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "dictionary request profile is unavailable",
      ))?;
  if !profile.config.request_decode {
    return Err(DictionaryRequestError::new(
      StatusCode::UNSUPPORTED_MEDIA_TYPE,
      "dictionary request decoding is disabled for this profile",
    ));
  }
  let advertised = fields::parse_available_dictionary(request.headers())
    .map_err(|_| invalid("invalid Available-Dictionary request field"))?
    .ok_or_else(|| invalid("dictionary request is missing Available-Dictionary"))?;

  let prelude_len = match coding {
    DictionaryCoding::Dcb => DCB_PRELUDE_LEN,
    DictionaryCoding::Dcz => DCZ_PRELUDE_LEN,
  };
  let (request, captured) = super::body::capture_proxy_request_prefix(request, prelude_len)
    .await
    .map_err(capture_error)?;
  let framed_hash = prelude_hash(coding, &captured.bytes)?;
  if framed_hash != advertised.hash {
    return Err(invalid(
      "dictionary request prelude does not match Available-Dictionary",
    ));
  }
  let dictionary = profile
    .config
    .dictionaries
    .iter()
    .filter_map(|name| state.compression_dictionary.configured(name))
    .find(|dictionary| dictionary.public && dictionary.hash == framed_hash)
    .ok_or_else(|| {
      DictionaryRequestError::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "dictionary request references an unavailable public dictionary",
      )
    })?;
  let permit = profile
    .codec_permits
    .clone()
    .try_acquire_owned()
    .map_err(|_| {
      DictionaryRequestError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "dictionary request decoder is at capacity",
      )
    })?;
  let (mut parts, body) = request.into_parts();
  parts.headers.remove(header::CONTENT_ENCODING);
  parts.headers.remove(header::CONTENT_LENGTH);
  parts.headers.remove("available-dictionary");
  parts.headers.remove("dictionary-id");
  super::integrity_digest::invalidate(&mut parts.headers, false);
  let options = CodecBodyOptions {
    metrics: Some(state.metrics.clone()),
    coding,
    decode: true,
    level: 1,
    timeout: Duration::from_millis(profile.config.codec_timeout_ms),
    max_decoded_bytes: usize::try_from(profile.config.max_decoded_size_bytes).unwrap_or(usize::MAX),
    max_expansion_ratio: usize::try_from(profile.config.max_expansion_ratio).unwrap_or(usize::MAX),
  };
  Ok(Request::from_parts(
    parts,
    dictionary_body::transform(body, Arc::clone(&dictionary.bytes), options, permit),
  ))
}

fn content_coding(
  headers: &http::HeaderMap,
) -> Result<Option<DictionaryCoding>, DictionaryRequestError> {
  let values = headers
    .get_all(header::CONTENT_ENCODING)
    .iter()
    .map(|value| {
      value
        .to_str()
        .map_err(|_| unsupported("invalid Content-Encoding"))
    })
    .collect::<Result<Vec<_>, _>>()?;
  if values.is_empty() {
    return Ok(None);
  }
  let tokens = values
    .iter()
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .collect::<Vec<_>>();
  let dictionary_named = tokens.iter().any(|value| {
    value.to_ascii_lowercase().contains("dcb") || value.to_ascii_lowercase().contains("dcz")
  });
  if !dictionary_named {
    return Ok(None);
  }
  if tokens.len() != 1 {
    return Err(unsupported(
      "dictionary requests require exactly one Content-Encoding",
    ));
  }
  match tokens[0] {
    value if value.eq_ignore_ascii_case("dcb") => Ok(Some(DictionaryCoding::Dcb)),
    value if value.eq_ignore_ascii_case("dcz") => Ok(Some(DictionaryCoding::Dcz)),
    _ => Err(unsupported("unsupported dictionary Content-Encoding")),
  }
}

fn excluded(request: &Request<ProxyBody>, state: &AppSnapshot) -> bool {
  request.method() == http::Method::CONNECT
    || super::headers::is_upgrade_request(request)
    || super::managed_upload::relay_request(request.method(), request.headers())
    || super::resumable::request_marked(request)
    || super::semantics::is_native_grpc_request(request.headers(), &state.config)
    || super::grpc_web::request_mode(request.headers()).is_some()
    || request
      .headers()
      .get(header::CONTENT_TYPE)
      .and_then(|value| value.to_str().ok())
      .is_some_and(|value| {
        value
          .split(';')
          .next()
          .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/grpc"))
      })
}

fn secure(
  request: &Request<ProxyBody>,
  tls: &crate::waf::WafTlsMetadata,
  client: std::net::SocketAddr,
) -> bool {
  let evidence = request
    .extensions()
    .get::<crate::proxy_protocol_egress::tls::ConnectionTlsEvidence>()
    .and_then(|evidence| evidence.received.as_deref())
    .filter(|metadata| metadata.source.ip() == client.ip())
    .and_then(|metadata| metadata.ssl.as_deref());
  tls.enabled || evidence.is_some_and(|ssl| ssl.client & 1 != 0)
}

fn prelude_hash(
  coding: DictionaryCoding,
  bytes: &[u8],
) -> Result<DictionaryHash, DictionaryRequestError> {
  let (magic, length) = match coding {
    DictionaryCoding::Dcb => (DCB_MAGIC, DCB_PRELUDE_LEN),
    DictionaryCoding::Dcz => (DCZ_MAGIC, DCZ_PRELUDE_LEN),
  };
  if bytes.len() < length || !bytes.starts_with(magic) {
    return Err(invalid("invalid RFC 9842 dictionary-coding prelude"));
  }
  DictionaryHash::from_slice(&bytes[magic.len()..length])
    .map_err(|_| invalid("invalid dictionary prelude hash"))
}

fn capture_error(error: super::body::BoxError) -> DictionaryRequestError {
  if error_is_body_length_limit(&error) {
    DictionaryRequestError::new(
      StatusCode::PAYLOAD_TOO_LARGE,
      "dictionary request body is too large",
    )
  } else if error_is_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) {
    DictionaryRequestError::new(
      StatusCode::REQUEST_TIMEOUT,
      "dictionary request body timed out",
    )
  } else {
    invalid("invalid dictionary request body")
  }
}

const fn invalid(message: &'static str) -> DictionaryRequestError {
  DictionaryRequestError::new(StatusCode::BAD_REQUEST, message)
}

const fn unsupported(message: &'static str) -> DictionaryRequestError {
  DictionaryRequestError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, message)
}

#[cfg(test)]
mod tests {
  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }
  use http::{HeaderMap, HeaderValue, header};

  use super::*;

  #[tokio::test]
  async fn unconfigured_routes_preserve_opaque_dictionary_requests() {
    use http_body_util::BodyExt;
    let temp = common::TempDir::new("dictionary-disabled-request");
    let (cert, key) = common::create_self_signed_cert(temp.path(), "dictionary-disabled");
    let config = toml::from_str(&common::minimal_config_toml(&cert, &key)).unwrap();
    let state = AppSnapshot::new(config).await.unwrap();
    for coding in ["dcb", "dcz", "dcb, gzip"] {
      let request = Request::builder()
        .method("POST")
        .header(header::CONTENT_ENCODING, coding)
        .body(super::super::full_body(bytes::Bytes::from_static(
          b"opaque",
        )))
        .unwrap();
      let result = decode(
        request,
        &state.config.routes[0],
        &state,
        &crate::waf::WafTlsMetadata::default(),
        "127.0.0.1:1234".parse().unwrap(),
      )
      .await
      .unwrap();
      assert_eq!(result.headers()[header::CONTENT_ENCODING], coding);
      assert_eq!(
        result.into_body().collect().await.unwrap().to_bytes(),
        "opaque"
      );
    }
  }

  #[test]
  fn dictionary_coding_must_be_the_only_content_coding() {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("dcb"));
    assert_eq!(
      content_coding(&headers).unwrap(),
      Some(DictionaryCoding::Dcb)
    );
    headers.insert(
      header::CONTENT_ENCODING,
      HeaderValue::from_static("dcb, gzip"),
    );
    assert_eq!(
      content_coding(&headers).unwrap_err().status,
      StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    assert_eq!(content_coding(&headers).unwrap(), None);
  }

  #[test]
  fn prelude_selects_only_the_hash_framed_by_the_coding() {
    let digest = [9_u8; 32];
    let mut dcb = DCB_MAGIC.to_vec();
    dcb.extend_from_slice(&digest);
    assert_eq!(
      prelude_hash(DictionaryCoding::Dcb, &dcb)
        .unwrap()
        .as_bytes(),
      &digest
    );
    assert_eq!(
      prelude_hash(DictionaryCoding::Dcz, &dcb)
        .unwrap_err()
        .status,
      StatusCode::BAD_REQUEST
    );
  }
}
