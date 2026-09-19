//! Bounded, same-origin RFC 9842 dictionary prefetches.
//!
//! A prefetch deliberately uses the client already configured for the selected
//! upstream. It never follows a `Link` target with a general-purpose URL
//! client, so route, TLS, and origin selection cannot be escaped by a response.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::BodyExt;
use url::Url;

use crate::compression_dictionary::{fields, runtime::DictionaryScope};
use crate::config::{HttpVersion, ProxyProtocolEgressMode, UpstreamConfig};
use crate::state::AppSnapshot;

use super::super::{
  EffectiveRetryPolicy, EffectiveTimeouts,
  body::{ProxyBody, boxed_error},
  cache_operations::full_body,
  retry::{send_h3_with_retry, send_one_shot_with_state},
};
use super::{learning, upstream::Negotiation};

const MAX_LINK_HEADER_VALUES: usize = 8;
const MAX_LINK_HEADER_BYTES: usize = 16 * 1024;
const MAX_LINK_MEMBER_BYTES: usize = 4 * 1024;
const MAX_LINK_TARGETS: usize = 8;
const MAX_TARGET_URL_BYTES: usize = 4 * 1024;

/// Immutable transport choices captured before the primary exchange starts.
pub(in crate::proxy::http) struct Plan {
  state: std::sync::Arc<AppSnapshot>,
  scope: DictionaryScope,
  profile: std::sync::Arc<crate::compression_dictionary::runtime::ProfileRuntime>,
  upstream: UpstreamConfig,
  upstream_version: HttpVersion,
  timeouts: EffectiveTimeouts,
  request_url: Url,
  request_method: Method,
  request_version: Version,
  host: Option<HeaderValue>,
}

impl Plan {
  #[allow(clippy::too_many_arguments)]
  pub(in crate::proxy::http) fn capture(
    state: std::sync::Arc<AppSnapshot>,
    negotiation: Negotiation,
    upstream: UpstreamConfig,
    upstream_version: HttpVersion,
    timeouts: EffectiveTimeouts,
    request_uri: Uri,
    request_method: Method,
    request_version: Version,
    host: Option<HeaderValue>,
  ) -> Option<Self> {
    let prefetch = negotiation.profile.config.prefetch.as_ref()?;
    if prefetch.max_bytes == 0 || prefetch.timeout_ms == 0 {
      return None;
    }
    // A prefetch has no caller identity. Do not run it through an upstream
    // that could present one, emit PROXY metadata, or use cleartext transport.
    if upstream.origin.scheme() != "https"
      || upstream.origin.username() != ""
      || upstream.origin.password().is_some()
      || upstream.tls.client_identity.is_some()
      || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
    {
      return None;
    }
    let request_url = selected_request_url(&upstream, &request_uri)?;
    if negotiation.url != request_url {
      return None;
    }
    Some(Self {
      state,
      scope: negotiation.scope,
      profile: negotiation.profile,
      upstream,
      upstream_version,
      timeouts,
      request_url,
      request_method,
      request_version,
      host,
    })
  }

  /// Schedule bounded work only after the response has passed response WAF.
  pub(in crate::proxy::http) fn schedule(self, response: &Response<ProxyBody>) {
    let Some(prefetch) = self.profile.config.prefetch.as_ref() else {
      return;
    };
    if !response_is_eligible(response.status(), response.headers(), &self.request_method)
      || !same_negotiation(
        &self.scope,
        &self.request_url,
        response.extensions().get::<Negotiation>(),
      )
    {
      return;
    }
    let targets = dictionary_links(response.headers(), &self.request_url);
    for target in targets {
      let plan = self.clone_for_target();
      let deadline = Instant::now()
        .checked_add(Duration::from_millis(prefetch.timeout_ms))
        .unwrap_or_else(Instant::now);
      tokio::spawn(async move {
        let _ = plan.fetch(target, deadline).await;
      });
    }
  }

  fn clone_for_target(&self) -> Self {
    Self {
      state: self.state.clone(),
      scope: self.scope.clone(),
      profile: self.profile.clone(),
      upstream: self.upstream.clone(),
      upstream_version: self.upstream_version,
      timeouts: self.timeouts,
      request_url: self.request_url.clone(),
      request_method: self.request_method.clone(),
      request_version: self.request_version,
      host: self.host.clone(),
    }
  }

  async fn fetch(self, target: Url, deadline: Instant) -> anyhow::Result<()> {
    let prefetch = self
      .profile
      .config
      .prefetch
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("dictionary prefetch is disabled"))?;
    if target.origin() != self.request_url.origin()
      || target.scheme() != "https"
      || target.username() != ""
      || target.password().is_some()
      || target.fragment().is_some()
    {
      anyhow::bail!("dictionary prefetch target escaped the selected origin");
    }
    let permit = self.profile.prefetch_permits.clone().try_acquire_owned()?;
    // Reserve the complete configured maximum before the response body starts
    // arriving. `commit` accepts a shorter, unknown-length completed body.
    let reservation = self
      .state
      .compression_dictionary
      .begin_learning(&self.scope.profile, &self.scope, prefetch.max_bytes)
      .await?;
    let request = self.request(target.as_str())?;
    let timeouts = self.timeouts.cap_upstream_to_deadline(deadline);
    let response = if self.upstream_version == HttpVersion::H3 {
      send_h3_with_retry(
        request,
        &self.upstream,
        timeouts,
        self.state.as_ref(),
        &EffectiveRetryPolicy::disabled_direct(),
        None,
      )
      .await?
    } else {
      let client = self
        .state
        .clients
        .for_upstream_version(
          &self.upstream.name,
          self.upstream.origin.scheme(),
          self.upstream_version,
        )
        .ok_or_else(|| anyhow::anyhow!("upstream client is not configured"))?;
      send_one_shot_with_state(client, request, timeouts, self.state.as_ref(), None)
        .await?
        .map(|body| body.map_err(boxed_error).boxed())
    };
    learn_response(response, reservation, target, prefetch.max_bytes, deadline).await?;
    drop(permit);
    Ok(())
  }

  fn request(&self, target: &str) -> anyhow::Result<Request<ProxyBody>> {
    let mut request = Request::builder()
      .method(http::Method::GET)
      .version(self.request_version)
      .uri(target)
      .header(http::header::ACCEPT_ENCODING, "identity")
      .body(full_body(bytes::Bytes::new()))?;
    // `Host` is the only routing value copied from the accepted request, and
    // only for HTTP/1 where it is meaningful. It cannot carry credentials.
    if self.upstream_version == HttpVersion::H1
      && let Some(host) = self.host.as_ref()
    {
      request
        .headers_mut()
        .insert(http::header::HOST, host.clone());
    }
    Ok(request)
  }
}

/// A Link may be acted on only for the successful, public representation that
/// belongs to the exact target selected before the primary exchange. A retry
/// can replace the final negotiation with one for another pool member.
fn same_negotiation(scope: &DictionaryScope, url: &Url, response: Option<&Negotiation>) -> bool {
  response.is_some_and(|response| same_scope_and_url(scope, url, &response.scope, &response.url))
}

fn same_scope_and_url(
  expected_scope: &DictionaryScope,
  expected_url: &Url,
  actual_scope: &DictionaryScope,
  actual_url: &Url,
) -> bool {
  actual_scope == expected_scope && actual_url == expected_url
}

fn response_is_eligible(status: StatusCode, headers: &HeaderMap, method: &Method) -> bool {
  *method == Method::GET
    && status == StatusCode::OK
    // This rejects Set-Cookie, private and no-store responses, and also makes
    // a prefetch require the same explicit freshness proof as learning.
    && learning::freshness(headers).is_some()
}

async fn learn_response(
  response: Response<ProxyBody>,
  reservation: crate::compression_dictionary::runtime::DictionaryLearningReservation,
  target: Url,
  maximum_bytes: u64,
  deadline: Instant,
) -> anyhow::Result<()> {
  if response.status() != http::StatusCode::OK {
    anyhow::bail!("dictionary prefetch did not return 200");
  }
  let fresh_until = learning::freshness(response.headers())
    .ok_or_else(|| anyhow::anyhow!("dictionary prefetch response is not explicitly fresh"))?;
  let declaration = fields::parse_use_as_dictionary_header(response.headers(), &target)?
    .filter(fields::UseAsDictionary::is_supported)
    .ok_or_else(|| anyhow::anyhow!("dictionary prefetch lacks a supported Use-As-Dictionary"))?;
  if response
    .headers()
    .get(http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<u64>().ok())
    .is_some_and(|length| length > maximum_bytes)
  {
    anyhow::bail!("dictionary prefetch body exceeds its configured bound");
  }
  let bytes = collect_complete_body(response.into_body(), maximum_bytes, deadline).await?;
  reservation
    .commit(target, declaration, bytes, fresh_until)
    .await?;
  Ok(())
}

async fn collect_complete_body(
  mut body: ProxyBody,
  maximum_bytes: u64,
  deadline: Instant,
) -> anyhow::Result<Vec<u8>> {
  let mut bytes = BytesMut::new();
  loop {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
      anyhow::bail!("dictionary prefetch timed out while reading its body");
    }
    let frame = tokio::time::timeout(remaining, body.frame())
      .await
      .map_err(|_| anyhow::anyhow!("dictionary prefetch timed out while reading its body"))?
      .transpose()
      .map_err(|error| anyhow::anyhow!("dictionary prefetch body read failed: {error}"))?;
    let Some(frame) = frame else { break };
    let data = frame
      .into_data()
      .map_err(|_| anyhow::anyhow!("dictionary prefetch response contains trailers"))?;
    let next = u64::try_from(bytes.len())?.saturating_add(u64::try_from(data.len())?);
    if next > maximum_bytes {
      anyhow::bail!("dictionary prefetch body exceeds its configured bound");
    }
    bytes.extend_from_slice(&data);
  }
  Ok(bytes.to_vec())
}

fn selected_request_url(upstream: &UpstreamConfig, request_uri: &Uri) -> Option<Url> {
  let candidate = Url::parse(&request_uri.to_string())
    .ok()
    .or_else(|| upstream.origin.join(&request_uri.to_string()).ok())?;
  (candidate.scheme() == "https"
    && candidate.origin() == upstream.origin.origin()
    && candidate.username().is_empty()
    && candidate.password().is_none()
    && candidate.fragment().is_none())
  .then_some(candidate)
}

pub(super) fn dictionary_links(headers: &HeaderMap, base: &Url) -> Vec<Url> {
  let mut links = Vec::new();
  let mut seen = HashSet::new();
  let mut total = 0_usize;
  for value in headers
    .get_all(http::header::LINK)
    .iter()
    .take(MAX_LINK_HEADER_VALUES)
  {
    let Ok(value) = value.to_str() else { continue };
    total = total.saturating_add(value.len());
    if total > MAX_LINK_HEADER_BYTES {
      break;
    }
    for member in split_members(value) {
      if member.len() > MAX_LINK_MEMBER_BYTES {
        continue;
      }
      let Some((target, parameters)) = member.split_once('>') else {
        continue;
      };
      let Some(target) = target.trim().strip_prefix('<') else {
        continue;
      };
      if target.len() > MAX_TARGET_URL_BYTES || !dictionary_relation(parameters) {
        continue;
      }
      let Ok(url) = base.join(target.trim()) else {
        continue;
      };
      if url.origin() != base.origin()
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
      {
        continue;
      }
      if seen.insert(url.as_str().to_owned()) {
        links.push(url);
        if links.len() == MAX_LINK_TARGETS {
          return links;
        }
      }
    }
  }
  links
}

fn dictionary_relation(parameters: &str) -> bool {
  parameters.split(';').skip(1).any(|parameter| {
    let Some((name, value)) = parameter.trim().split_once('=') else {
      return false;
    };
    name.trim().eq_ignore_ascii_case("rel")
      && value
        .trim()
        .trim_matches('"')
        .split_ascii_whitespace()
        .any(|relation| relation.eq_ignore_ascii_case("compression-dictionary"))
  })
}

fn split_members(value: &str) -> impl Iterator<Item = &str> {
  struct Members<'a> {
    rest: &'a str,
  }
  impl<'a> Iterator for Members<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
      let value = self.rest.trim_start();
      if value.is_empty() {
        self.rest = "";
        return None;
      }
      let mut quote = false;
      let mut escape = false;
      for (index, byte) in value.bytes().enumerate() {
        if escape {
          escape = false;
          continue;
        }
        if quote && byte == b'\\' {
          escape = true;
          continue;
        }
        if byte == b'"' {
          quote = !quote;
          continue;
        }
        if byte == b',' && !quote {
          self.rest = &value[index + 1..];
          return Some(value[..index].trim());
        }
      }
      self.rest = "";
      Some(value.trim())
    }
  }
  Members { rest: value }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn accepts_same_origin_quoted_commas_and_deduplicates() {
    let mut headers = HeaderMap::new();
    headers.insert(
      http::header::LINK,
      "</ignore>; rel=preload, </d>; title=\"a,b\"; rel=\"compression-dictionary preload\", </d>; rel=compression-dictionary"
        .parse()
        .unwrap(),
    );
    let links = dictionary_links(&headers, &Url::parse("https://a.test/path").unwrap());
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].as_str(), "https://a.test/d");
  }

  #[test]
  fn rejects_cross_origin_credentials_and_fragments() {
    let mut headers = HeaderMap::new();
    headers.insert(
      http::header::LINK,
      "<https://b.test/d>; rel=compression-dictionary, <https://user@a.test/d>; rel=compression-dictionary, </d#part>; rel=compression-dictionary"
        .parse()
        .unwrap(),
    );
    assert!(dictionary_links(&headers, &Url::parse("https://a.test/").unwrap()).is_empty());
  }

  #[tokio::test]
  async fn complete_body_collection_enforces_the_reservation_bound() {
    let deadline = Instant::now() + Duration::from_secs(1);
    assert!(
      collect_complete_body(full_body(bytes::Bytes::from_static(b"four")), 3, deadline,)
        .await
        .is_err()
    );
    assert_eq!(
      collect_complete_body(
        full_body(bytes::Bytes::from_static(b"three")),
        5,
        Instant::now() + Duration::from_secs(1),
      )
      .await
      .unwrap(),
      b"three",
    );
  }

  fn fresh_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
      http::header::DATE,
      http::HeaderValue::from_str(&httpdate::fmt_http_date(std::time::SystemTime::now())).unwrap(),
    );
    headers.insert(
      http::header::CACHE_CONTROL,
      http::HeaderValue::from_static("public, max-age=300"),
    );
    headers
  }

  #[test]
  fn final_response_must_be_public_and_get() {
    let headers = fresh_headers();
    assert!(response_is_eligible(StatusCode::OK, &headers, &Method::GET));
    assert!(!response_is_eligible(
      StatusCode::OK,
      &headers,
      &Method::HEAD
    ));
    assert!(!response_is_eligible(
      StatusCode::FOUND,
      &headers,
      &Method::GET
    ));
    for (name, value) in [
      (http::header::SET_COOKIE, "session=private"),
      (http::header::CACHE_CONTROL, "private, max-age=300"),
      (http::header::CACHE_CONTROL, "no-store, max-age=300"),
    ] {
      let mut headers = fresh_headers();
      headers.insert(name, value.parse().unwrap());
      assert!(!response_is_eligible(
        StatusCode::OK,
        &headers,
        &Method::GET
      ));
    }
  }

  #[test]
  fn final_scope_and_url_must_match_capture() {
    let scope = DictionaryScope {
      direction: crate::compression_dictionary::runtime::DictionaryDirection::Upstream,
      origin: Url::parse("https://a.test/path").unwrap(),
      profile: "site".to_owned(),
      route_policy_fingerprint: "route".to_owned(),
      upstream_fingerprint: Some("upstream".to_owned()),
    };
    let url = Url::parse("https://a.test/path").unwrap();
    assert!(same_scope_and_url(&scope, &url, &scope, &url));
    let retried_scope = DictionaryScope {
      origin: Url::parse("https://b.test/path").unwrap(),
      ..scope.clone()
    };
    assert!(!same_scope_and_url(&scope, &url, &retried_scope, &url));
  }
}
