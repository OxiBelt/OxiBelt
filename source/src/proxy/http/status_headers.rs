//! Request-local proxy/cache diagnostics, finalized after response policy.
//! Received chains are never used as evidence for locally generated parameters.
use std::fmt::Write;
use std::sync::OnceLock;
use std::time::SystemTime;

use http::{HeaderMap, HeaderValue, Response, Version};
use http_body_util::BodyExt;

use super::body::{InlinedKnownSmallResponseBody, ProxyBody};
use super::cache_status::StandardCacheStatus;
use crate::config::{StatusHeaderUpstream, StatusHeadersConfig};

mod codec;
#[cfg(test)]
mod tests;

const PROXY: &str = "proxy-status";
const CACHE: &str = "cache-status";
static IDENTIFIER: OnceLock<Result<String, getrandom::Error>> = OnceLock::new();

pub(crate) fn initialize() -> anyhow::Result<()> {
  identifier()
    .map(|_| ())
    .map_err(|error| anyhow::anyhow!("cannot initialize public proxy alias: {error}"))
}

fn identifier() -> Result<&'static str, &'static getrandom::Error> {
  IDENTIFIER
    .get_or_init(|| {
      let mut bytes = [0u8; 16];
      getrandom::fill(&mut bytes)?;
      let mut value = String::from("proxy-");
      for byte in bytes {
        let _ = write!(value, "{byte:02x}");
      }
      Ok(value)
    })
    .as_ref()
    .map(String::as_str)
}

#[derive(Clone, Default)]
struct Received {
  proxy: codec::Chain,
  cache: codec::Chain,
  status: Option<u16>,
  protocol: Option<&'static str>,
  cache_forward_reason: Option<&'static str>,
}

#[derive(Clone, Copy)]
pub(crate) struct OriginRole;
#[derive(Clone, Copy)]
pub(crate) struct IncrementalRefusal;
#[derive(Clone, Copy)]
pub(super) struct IncrementalCapacityRejection;
#[derive(Clone, Copy)]
struct Finalized;
#[derive(Clone, Copy)]
struct ProxyError(&'static str);

pub(crate) fn origin<B>(mut response: Response<B>) -> Response<B> {
  response.extensions_mut().insert(OriginRole);
  response
}

pub(crate) fn error<B>(mut response: Response<B>, token: &'static str) -> Response<B> {
  response.extensions_mut().insert(ProxyError(token));
  response
}

pub(crate) fn transport_error<B>(
  response: Response<B>,
  cause: &(dyn std::error::Error + 'static),
) -> Response<B> {
  match crate::upstream_failure::classify(cause) {
    Some(failure) => error(response, failure.as_str()),
    None => response,
  }
}

fn protocol(version: Version) -> Option<&'static str> {
  match version {
    Version::HTTP_10 => Some("http/1.0"),
    Version::HTTP_11 => Some("http/1.1"),
    Version::HTTP_2 => Some("h2"),
    Version::HTTP_3 => Some("h3"),
    _ => None,
  }
}

fn received(headers: &HeaderMap) -> Received {
  let chain = |name| {
    let hop_by_hop = headers
      .get_all(http::header::CONNECTION)
      .iter()
      .filter_map(|v| v.to_str().ok())
      .any(|value| {
        value
          .split(',')
          .any(|token| token.trim().eq_ignore_ascii_case(name))
      });
    if hop_by_hop {
      codec::Chain::default()
    } else {
      codec::Chain::read(headers, name)
    }
  };
  Received {
    proxy: chain(PROXY),
    cache: chain(CACHE),
    ..Received::default()
  }
}

pub(crate) fn complete_cache_forward<B>(response: &mut Response<B>, reason: Option<&'static str>) {
  let Some(reason) = reason else {
    return;
  };
  if response.extensions().get::<StandardCacheStatus>().is_none() {
    response
      .extensions_mut()
      .insert(StandardCacheStatus::default());
  }
  let Some(evidence) = response.extensions().get::<Received>() else {
    return;
  };
  let Some(status) = evidence.status else {
    return;
  };
  let reason = evidence.cache_forward_reason.unwrap_or(reason);
  if let Some(facts) = response.extensions_mut().get_mut::<StandardCacheStatus>() {
    facts.forwarded = Some(reason);
    facts.forwarded_status = Some(status);
  }
}

pub(crate) fn set_cache_forward_reason<B>(response: &mut Response<B>, reason: &'static str) {
  if let Some(evidence) = response.extensions_mut().get_mut::<Received>() {
    evidence.cache_forward_reason = Some(reason);
  }
}

pub(crate) fn capture_upstream<B>(response: &mut Response<B>) {
  let mut evidence = received(response.headers());
  evidence.status = Some(response.status().as_u16());
  evidence.protocol = protocol(response.version());
  response.extensions_mut().insert(evidence);
}

pub(crate) fn capture_upstream_parts(parts: &mut http::response::Parts) {
  let mut evidence = received(&parts.headers);
  evidence.status = Some(parts.status.as_u16());
  evidence.protocol = protocol(parts.version);
  parts.extensions.insert(evidence);
}

pub(crate) fn capture_cached<B>(response: &mut Response<B>) {
  let evidence = received(response.headers());
  response.extensions_mut().insert(evidence);
}

/// Restore only validated upstream values before storage, removing header-rule edits.
pub(crate) fn restore_received_headers(parts: &mut http::response::Parts) {
  let evidence = parts
    .extensions
    .get::<Received>()
    .cloned()
    .unwrap_or_default();
  replace(&mut parts.headers, PROXY, evidence.proxy.append(None));
  replace(&mut parts.headers, CACHE, evidence.cache.append(None));
}

fn replace(headers: &mut HeaderMap, name: &'static str, value: Option<HeaderValue>) {
  headers.remove(name);
  if let Some(value) = value {
    headers.insert(name, value);
  }
}

pub(crate) fn finalize_head<B>(response: &mut Response<B>, defaults: &StatusHeadersConfig) {
  if response.extensions().get::<Finalized>().is_some() {
    return;
  }
  let config = response
    .extensions()
    .get::<StatusHeadersConfig>()
    .unwrap_or(defaults)
    .clone();
  let own = response.extensions().get::<OriginRole>().is_none();
  let evidence = response
    .extensions()
    .get::<Received>()
    .cloned()
    .unwrap_or_default();
  let empty = codec::Chain::default();
  let preserve = config.upstream == StatusHeaderUpstream::Preserve;
  let public_id = config.identifier.as_deref().or_else(|| identifier().ok());
  let proxy = if response.extensions().get::<IncrementalRefusal>().is_some() {
    Some(HeaderValue::from_static(
      "oxibelt; error=incremental_refused",
    ))
  } else if response
    .extensions()
    .get::<IncrementalCapacityRejection>()
    .is_some()
  {
    Some(HeaderValue::from_static(
      "oxibelt; error=connection_limit_reached",
    ))
  } else if config.proxy_status {
    let local = public_id.filter(|_| own).map(|id| {
      let mut value = codec::quoted(id);
      if let Some(error) = response.extensions().get::<ProxyError>() {
        let _ = write!(value, "; error={}", error.0);
      }
      if let Some(status) = evidence.status {
        let _ = write!(value, "; received-status={status}");
      }
      if let Some(protocol) = evidence.protocol {
        let _ = write!(value, "; next-protocol={protocol}");
      }
      value
    });
    (if preserve { &evidence.proxy } else { &empty }).append(local.as_deref())
  } else {
    None
  };
  let cache = if config.cache_status {
    let local = public_id.filter(|_| own).and_then(|id| {
      response
        .extensions()
        .get::<StandardCacheStatus>()
        .map(|facts| cache_member(id, facts, SystemTime::now()))
    });
    (if preserve { &evidence.cache } else { &empty }).append(local.as_deref())
  } else {
    None
  };
  replace(response.headers_mut(), PROXY, proxy);
  replace(response.headers_mut(), CACHE, cache);
  if let Some(inlined) = response
    .extensions_mut()
    .get_mut::<InlinedKnownSmallResponseBody>()
    && let Some(trailers) = &mut inlined.trailers
  {
    filter_trailers(trailers, &config);
  }
  response.extensions_mut().insert(config);
  response.extensions_mut().insert(Finalized);
}

pub(crate) fn finalize(
  mut response: Response<ProxyBody>,
  defaults: &StatusHeadersConfig,
) -> Response<ProxyBody> {
  if super::response::is_silent_close_response(&response) {
    return response;
  }
  finalize_head(&mut response, defaults);
  let config = response
    .extensions()
    .get::<StatusHeadersConfig>()
    .unwrap_or(defaults)
    .clone();
  response.map(|body| {
    body
      .map_frame(move |mut frame| {
        if let Some(trailers) = frame.trailers_mut() {
          filter_trailers(trailers, &config);
        }
        frame
      })
      .boxed()
  })
}

fn filter_trailers(headers: &mut HeaderMap, config: &StatusHeadersConfig) {
  for (name, enabled) in [(PROXY, config.proxy_status), (CACHE, config.cache_status)] {
    let value = if enabled && config.upstream == StatusHeaderUpstream::Preserve {
      codec::Chain::read(headers, name).append(None)
    } else {
      None
    };
    replace(headers, name, value);
  }
}

fn cache_member(id: &str, facts: &StandardCacheStatus, now: SystemTime) -> String {
  let mut value = codec::quoted(id);
  if facts.hit {
    value.push_str("; hit");
  }
  // A missing fwd-status defaults to downstream status; never imply a response
  // was received for transport failures or shared fills with unknown receipts.
  if !facts.hit
    && let (Some(reason), Some(status)) = (facts.forwarded, facts.forwarded_status)
  {
    let _ = write!(value, "; fwd={reason}; fwd-status={status}");
    if let Some(stored) = facts.stored {
      value.push_str(if stored { "; stored" } else { "; stored=?0" });
    }
    if let Some(collapsed) = facts.collapsed {
      value.push_str(if collapsed {
        "; collapsed"
      } else {
        "; collapsed=?0"
      });
    }
  }
  if let Some(expiry) = facts.expires_at {
    let ttl = match expiry.duration_since(now) {
      Ok(duration) => i128::from(duration.as_secs()),
      Err(error) => {
        -i128::from(error.duration().as_secs()) - i128::from(error.duration().subsec_nanos() != 0)
      }
    }
    .clamp(-999_999_999_999_999, 999_999_999_999_999);
    let _ = write!(value, "; ttl={ttl}");
  }
  if let Some(detail) = facts.detail {
    let _ = write!(value, "; detail={detail}");
  }
  value
}
