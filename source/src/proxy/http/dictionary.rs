//! Dictionary negotiation at the shared HTTP policy boundary.

use super::{body::ProxyBody, compression, dictionary_body, integrity_digest};
use crate::compression_dictionary::{
  codec::DictionaryCoding,
  fields,
  runtime::{DictionaryDirection, DictionaryScope},
};
use crate::config::RouteConfig;
use crate::state::AppSnapshot;
use http::{HeaderMap, Method, Response};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

pub(super) mod learning;
pub(super) mod prefetch;
pub(super) mod sidecars;
pub(super) mod upstream;

/// Original credentials remain private even if policy strips their headers.
#[derive(Clone, Copy)]
pub(super) struct PrivateRequest;

/// The upstream response body was decoded from a dictionary coding.  Its
/// decoder enforces this identity-byte ceiling, so the cache can safely
/// collect an otherwise lengthless response only when the ceiling fits its
/// own bounded collection budget.
#[derive(Clone, Copy)]
pub(in crate::proxy::http) struct DecodedUpstreamResponse {
  pub(in crate::proxy::http) max_decoded_bytes: usize,
}

pub(super) fn digest(bytes: &[u8]) -> String {
  Sha256::digest(bytes)
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}
pub(super) fn fingerprint(route: &RouteConfig, state: &AppSnapshot) -> String {
  let mut route = route.clone();
  let route_waf = route.waf.stable_policy_projection();
  route.waf = Default::default();
  // Static MIME maps do not affect dictionary authority. Identity bytes are
  // verified separately before using a precomputed sidecar.
  route.static_files = Default::default();
  let projections = [
    format!("{route:?}"),
    route_waf,
    state.config.waf.stable_policy_projection(),
    state.waf.crs_content_fingerprint().to_owned(),
    format!("{:?}", state.config.external_auth),
    format!("{:?}", state.config.security),
    format!("{:?}", state.config.tls.client_auth),
    format!("{:?}", state.config.compression_dictionary),
    format!("{:016x}", state.ipm.snapshot().content_fingerprint()),
    format!("{:?}", state.dynamic_policy.snapshot_identity()),
  ];
  let mut hash = Sha256::new();
  for projection in projections {
    hash.update((projection.len() as u64).to_be_bytes());
    hash.update(projection.as_bytes());
  }
  hash
    .finalize()
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}

pub(super) struct Downstream {
  headers: HeaderMap,
  method: Method,
  url: Url,
  secure: bool,
  authenticated: bool,
}

impl Downstream {
  pub(super) fn new<B>(
    request: &http::Request<B>,
    host: &str,
    port: u16,
    scheme: &str,
    tls: &crate::waf::WafTlsMetadata,
    client: std::net::SocketAddr,
  ) -> Option<Self> {
    let evidence = request
      .extensions()
      .get::<crate::proxy_protocol_egress::tls::ConnectionTlsEvidence>()
      .and_then(|evidence| evidence.received.as_deref())
      .filter(|metadata| metadata.source.ip() == client.ip())
      .and_then(|metadata| metadata.ssl.as_deref());
    let secure = tls.enabled || evidence.is_some_and(|ssl| ssl.client & 1 != 0);
    let authenticated = tls.client_certificate.is_some()
      || tls.client_certificate_details.is_some()
      || evidence.is_some_and(|ssl| {
        ssl.client & 6 != 0 || ssl.common_name.is_some() || ssl.certificate.is_some()
      });
    let scheme = if secure { "https" } else { scheme };
    let mut url = Url::parse(&format!("{scheme}://{host}")).ok()?;
    if url.port().is_none() {
      url.set_port(Some(port)).ok()?;
    }
    url.set_path(request.uri().path());
    url.set_query(request.uri().query());
    Some(Self {
      headers: request.headers().clone(),
      method: request.method().clone(),
      url,
      secure,
      authenticated,
    })
  }

  pub(super) async fn finish(
    self,
    mut response: Response<ProxyBody>,
    route: &RouteConfig,
    state: &Arc<AppSnapshot>,
  ) -> Response<ProxyBody> {
    let private_response = response.extensions().get::<PrivateRequest>().is_some();
    if !self.authenticated
      && !private_response
      && route.external_auth.is_none()
      && self.secure
      && self.method == Method::GET
      && upstream::public_headers(&self.headers)
      && let Some(profile) = route.compression_dictionary_profile.as_deref()
    {
      let scope = DictionaryScope {
        direction: DictionaryDirection::Downstream,
        origin: self.url.clone(),
        profile: profile.to_owned(),
        route_policy_fingerprint: fingerprint(route, state),
        upstream_fingerprint: None,
      };
      response = learning::attach(response, state, &scope, &self.url).await;
    }

    if !self.authenticated
      && !private_response
      && route.external_auth.is_none()
      && self.secure
      && route.dictionary.is_none()
      && let Some((dictionary, coding, level, profile)) = self.select(&response, route, state).await
    {
      if let Some(sidecar) =
        sidecars::select(route, state, &self.url, dictionary.hash, coding, &response).await
      {
        let (mut parts, _) = response.into_parts();
        parts
          .extensions
          .remove::<super::body::KnownSmallResponseBody>();
        parts
          .extensions
          .remove::<super::body::InlinedKnownSmallResponseBody>();
        parts
          .extensions
          .remove::<integrity_digest::AvailableRepresentation>();
        compression::dictionary_invalidate(&mut parts.headers);
        parts.headers.insert(
          http::header::CONTENT_ENCODING,
          http::HeaderValue::from_static(match sidecar.coding {
            DictionaryCoding::Dcb => "dcb",
            DictionaryCoding::Dcz => "dcz",
          }),
        );
        if let Ok(length) = http::HeaderValue::from_str(&sidecar.bytes.len().to_string()) {
          parts.headers.insert(http::header::CONTENT_LENGTH, length);
        }
        let bytes = if self.method == Method::HEAD {
          bytes::Bytes::new()
        } else {
          sidecar.bytes
        };
        return Response::from_parts(
          parts,
          super::body::with_drop_guard(
            super::body::known_small_no_trailers_body(bytes),
            sidecar.permit,
          ),
        );
      }
      if let Ok(permit) = profile.codec_permits.clone().try_acquire_owned() {
        let (mut parts, body) = response.into_parts();
        parts
          .extensions
          .remove::<super::body::KnownSmallResponseBody>();
        parts
          .extensions
          .remove::<super::body::InlinedKnownSmallResponseBody>();
        parts
          .extensions
          .remove::<integrity_digest::AvailableRepresentation>();
        compression::dictionary_invalidate(&mut parts.headers);
        parts.headers.insert(
          http::header::CONTENT_ENCODING,
          http::HeaderValue::from_static(match coding {
            DictionaryCoding::Dcb => "dcb",
            DictionaryCoding::Dcz => "dcz",
          }),
        );
        if self.method == Method::HEAD {
          return Response::from_parts(
            parts,
            super::body::known_small_no_trailers_body(bytes::Bytes::new()),
          );
        }
        let config = &profile.config;
        let body = integrity_digest::invalidate_body(body, true);
        let options = dictionary_body::CodecBodyOptions {
          metrics: Some(state.metrics.clone()),
          coding,
          decode: false,
          level: level as i32,
          timeout: Duration::from_millis(config.codec_timeout_ms),
          max_decoded_bytes: usize::try_from(config.max_decoded_size_bytes).unwrap_or(usize::MAX),
          max_expansion_ratio: config.max_expansion_ratio as usize,
        };
        response = Response::from_parts(
          parts,
          dictionary_body::transform(body, dictionary.bytes.clone(), options, permit),
        );
        return response;
      }
    }
    compression::maybe_compress_response(
      response,
      &self.method,
      &self.headers,
      route.compression.as_deref(),
      &state.config.compression,
      &state.compression,
    )
  }

  async fn select(
    &self,
    response: &Response<ProxyBody>,
    route: &RouteConfig,
    state: &AppSnapshot,
  ) -> Option<(
    Arc<crate::compression_dictionary::runtime::Dictionary>,
    DictionaryCoding,
    u32,
    Arc<crate::compression_dictionary::runtime::ProfileRuntime>,
  )> {
    let name = route.compression_dictionary_profile.as_deref()?;
    let profile = state.compression_dictionary.profile(name)?;
    if !profile.config.downstream {
      return None;
    }
    let level = compression::dictionary_level(
      response,
      &self.method,
      &self.headers,
      route.compression.as_deref(),
      &state.config.compression,
      &state.compression,
    )?;
    let available = fields::parse_available_dictionary(&self.headers).ok()??;
    if !fields::server_dictionary_compression_eligible(
      &self.headers,
      response.headers(),
      Some(&available.hash),
    ) {
      return None;
    }
    let mut choices = [
      fields::DictionaryEncoding::Dcb,
      fields::DictionaryEncoding::Dcz,
    ];
    choices.sort_by(|a, b| {
      compression::accepted_encoding_quality(&self.headers, b.as_str()).total_cmp(
        &compression::accepted_encoding_quality(&self.headers, a.as_str()),
      )
    });
    let encoding = fields::negotiate_dictionary_encoding(
      Some(
        self
          .headers
          .get(http::header::ACCEPT_ENCODING)?
          .to_str()
          .ok()?,
      ),
      Some(&available.hash),
      &choices,
    )?;
    let fingerprint = fingerprint(route, state);
    let scope = DictionaryScope {
      direction: DictionaryDirection::Downstream,
      origin: self.url.clone(),
      profile: name.to_owned(),
      route_policy_fingerprint: fingerprint,
      upstream_fingerprint: None,
    };
    let dictionary = state
      .compression_dictionary
      .lookup(
        name,
        &scope,
        Some(&available.hash),
        &self.url,
        self
          .headers
          .get("sec-fetch-dest")
          .and_then(|value| value.to_str().ok()),
      )
      .await
      .ok()??;
    let coding = match encoding {
      fields::DictionaryEncoding::Dcb => DictionaryCoding::Dcb,
      fields::DictionaryEncoding::Dcz => DictionaryCoding::Dcz,
    };
    Some((dictionary, coding, level, profile))
  }
}

pub(super) fn serve<B>(
  request: &http::Request<B>,
  name: &str,
  route: &RouteConfig,
  state: &AppSnapshot,
  context: Option<Downstream>,
) -> Response<ProxyBody> {
  use http::StatusCode;
  let error = super::response::text_response;
  let Some(context) = context.filter(|context| context.secure) else {
    return error(
      StatusCode::BAD_REQUEST,
      "dictionary transport requires a secure connection",
    );
  };
  if request.method() != Method::GET && request.method() != Method::HEAD {
    let mut response = error(
      StatusCode::METHOD_NOT_ALLOWED,
      "dictionary resources support GET and HEAD",
    );
    response.headers_mut().insert(
      http::header::ALLOW,
      http::HeaderValue::from_static("GET, HEAD"),
    );
    return response;
  }
  let Some(dictionary) = state.compression_dictionary.configured(name) else {
    return error(StatusCode::SERVICE_UNAVAILABLE, "dictionary unavailable");
  };
  if context.url != dictionary.url {
    return error(StatusCode::NOT_FOUND, "dictionary not found");
  }
  let Some(profile) = route
    .compression_dictionary_profile
    .as_deref()
    .and_then(|name| state.compression_dictionary.profile(name))
  else {
    return error(
      StatusCode::SERVICE_UNAVAILABLE,
      "dictionary profile unavailable",
    );
  };
  let Some(advertise) = &profile.config.advertise else {
    return error(
      StatusCode::SERVICE_UNAVAILABLE,
      "dictionary advertisement unavailable",
    );
  };
  let declaration = fields::UseAsDictionary {
    match_pattern: advertise.r#match.clone(),
    match_destinations: advertise.match_dest.clone(),
    id: advertise.id.clone(),
    dictionary_type: fields::DictionaryType::Raw,
  };
  let Some(value) = declaration
    .to_header_value()
    .ok()
    .and_then(|value| http::HeaderValue::from_str(&value).ok())
  else {
    return error(
      StatusCode::SERVICE_UNAVAILABLE,
      "dictionary advertisement unavailable",
    );
  };
  let bytes = if request.method() == Method::HEAD {
    bytes::Bytes::new()
  } else {
    bytes::Bytes::copy_from_slice(&dictionary.bytes)
  };
  let mut response = Response::new(super::body::known_small_no_trailers_body(bytes));
  response.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::HeaderValue::from_static("application/octet-stream"),
  );
  response.headers_mut().insert("use-as-dictionary", value);
  if let Ok(length) = http::HeaderValue::from_str(&dictionary.bytes.len().to_string()) {
    response
      .headers_mut()
      .insert(http::header::CONTENT_LENGTH, length);
  }
  response
}
