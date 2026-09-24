//! Bounded, SSRF-resistant Web Bot Auth key discovery.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{
  ACCEPT, AGE, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST,
};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde_json::Value;
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::config::WebBotAuthConfig;
use crate::web_bot_auth::protocol::{DiscoveryKind, DiscoveryReference};

const DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";
const DIRECTORY_MIME: &str = "application/http-message-signatures-directory+json";
const MAX_BODY: usize = 256 * 1024;
const MAX_KEYS: usize = 64;
const MAX_URLS: usize = 1024;
const MAX_URL_LEN: usize = 2048;
const MAX_CONCURRENT: usize = 32;
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
const DEFAULT_TTL: Duration = Duration::from_secs(300);
const MAX_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryFailure {
  UnsafeUrl,
  Busy,
  Fetch,
  InvalidResponse,
  InvalidDocument,
}

impl std::fmt::Display for DiscoveryFailure {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(match self {
      Self::UnsafeUrl => "unsafe discovery URL",
      Self::Busy => "discovery fetch limit reached",
      Self::Fetch => "discovery fetch failed",
      Self::InvalidResponse => "invalid discovery HTTP response",
      Self::InvalidDocument => "invalid discovery document",
    })
  }
}

impl std::error::Error for DiscoveryFailure {}

#[derive(Clone, Eq, Hash, PartialEq)]
struct CacheKey {
  kind: u8,
  url: String,
}

struct CacheSlot {
  last_used: Instant,
  state: Arc<AsyncMutex<CacheEntry>>,
}

#[derive(Default)]
struct CacheEntry {
  keys: Option<Vec<Value>>,
  fresh_until: Option<Instant>,
  stale_until: Option<Instant>,
  retry_at: Option<Instant>,
  last_error: Option<DiscoveryFailure>,
}

struct FetchResult {
  keys: Vec<Value>,
  ttl: Duration,
  store: bool,
}

struct HttpDocument {
  value: Value,
  ttl: Duration,
  store: bool,
}

/// The runtime never sends discovery traffic through proxy connection pools.
/// Every fetch resolves, filters, and pins a public address before TLS.
pub struct DiscoveryRuntime {
  tls: Arc<rustls::ClientConfig>,
  nonstandard_origins: HashSet<String>,
  timeout: Duration,
  stale_if_error: Duration,
  fetches: Semaphore,
  cache: Mutex<HashMap<CacheKey, CacheSlot>>,
}

impl DiscoveryRuntime {
  pub fn new(config: &WebBotAuthConfig) -> anyhow::Result<Self> {
    let mut nonstandard_origins = HashSet::new();
    for origin in &config.nonstandard_port_origins {
      let parsed = Url::parse(origin)?;
      if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || parsed.port().is_none()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
      {
        anyhow::bail!("invalid Web Bot Auth nonstandard port origin");
      }
      nonstandard_origins.insert(parsed.origin().ascii_serialization());
    }

    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
      rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|_| anyhow::anyhow!("Web Bot Auth TLS protocol versions are unavailable"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Self {
      tls: Arc::new(tls),
      nonstandard_origins,
      timeout: Duration::from_millis(config.discovery_timeout_ms.max(1)),
      stale_if_error: Duration::from_secs(config.stale_if_error_seconds.min(300)),
      fetches: Semaphore::new(MAX_CONCURRENT),
      cache: Mutex::new(HashMap::new()),
    })
  }

  #[cfg(test)]
  pub(crate) fn seed_for_test(&self, reference: &DiscoveryReference, keys: Vec<Value>) {
    let mut url = reference.url.clone();
    let kind = match reference.kind {
      DiscoveryKind::Directory => {
        url.set_path(DIRECTORY_PATH);
        0
      }
      DiscoveryKind::JwksUri => 1,
      DiscoveryKind::Cimd => 2,
    };
    let now = Instant::now();
    let key = CacheKey {
      kind,
      url: url.as_str().to_owned(),
    };
    let entry = CacheEntry {
      keys: Some(keys),
      fresh_until: Some(now + Duration::from_secs(60)),
      ..CacheEntry::default()
    };
    self
      .cache
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .insert(
        key,
        CacheSlot {
          last_used: now,
          state: Arc::new(AsyncMutex::new(entry)),
        },
      );
  }

  pub async fn resolve(
    &self,
    reference: &DiscoveryReference,
  ) -> Result<Vec<Value>, DiscoveryFailure> {
    if reference.url.query().is_some() {
      return Err(DiscoveryFailure::UnsafeUrl);
    }
    let (url, kind) = match &reference.kind {
      DiscoveryKind::Directory => {
        self.check_url(&reference.url)?;
        if reference.url.path() != "/" || reference.url.fragment().is_some() {
          return Err(DiscoveryFailure::UnsafeUrl);
        }
        let mut url = reference.url.clone();
        url.set_path(DIRECTORY_PATH);
        (url, 0)
      }
      DiscoveryKind::JwksUri => (reference.url.clone(), 1),
      DiscoveryKind::Cimd => (reference.url.clone(), 2),
    };
    self.check_url(&url)?;

    let key = CacheKey {
      kind,
      url: url.as_str().to_owned(),
    };
    let slot = {
      let mut cache = self
        .cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
      if let Some(slot) = cache.get_mut(&key) {
        slot.last_used = Instant::now();
        Arc::clone(&slot.state)
      } else {
        if cache.len() == MAX_URLS
          && let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, slot)| slot.last_used)
            .map(|(k, _)| k.clone())
        {
          cache.remove(&oldest);
        }
        let state = Arc::new(AsyncMutex::new(CacheEntry::default()));
        cache.insert(
          key,
          CacheSlot {
            last_used: Instant::now(),
            state: Arc::clone(&state),
          },
        );
        state
      }
    };

    // One in-flight refresh per URL. The second waiter observes the new cache.
    let mut entry = slot.lock().await;
    let now = Instant::now();
    if let (Some(keys), Some(fresh_until)) = (&entry.keys, entry.fresh_until)
      && now < fresh_until
    {
      return Ok(keys.clone());
    }
    if entry.retry_at.is_some_and(|retry_at| now < retry_at) {
      if let (Some(keys), Some(stale_until)) = (&entry.keys, entry.stale_until)
        && now < stale_until
      {
        return Ok(keys.clone());
      }
      return Err(entry.last_error.unwrap_or(DiscoveryFailure::Fetch));
    }

    match self.fetch_keys(&url, kind).await {
      Ok(fetched) => {
        let now = Instant::now();
        let ttl = fetched.ttl.min(MAX_TTL);
        entry.keys = Some(fetched.keys.clone());
        entry.fresh_until = Some(now + ttl);
        entry.stale_until = Some(
          now
            + ttl
            + if fetched.store {
              self.stale_if_error
            } else {
              Duration::ZERO
            },
        );
        entry.retry_at = None;
        entry.last_error = None;
        Ok(fetched.keys)
      }
      Err(error) => {
        entry.retry_at = Some(Instant::now() + NEGATIVE_TTL);
        entry.last_error = Some(error);
        if let (Some(keys), Some(stale_until)) = (&entry.keys, entry.stale_until)
          && Instant::now() < stale_until
        {
          return Ok(keys.clone());
        }
        Err(error)
      }
    }
  }

  async fn fetch_keys(&self, url: &Url, kind: u8) -> Result<FetchResult, DiscoveryFailure> {
    match kind {
      0 | 1 => {
        let doc = self.fetch_json(url, kind == 0).await?;
        Ok(FetchResult {
          keys: parse_jwks(&doc.value)?,
          ttl: doc.ttl,
          store: doc.store,
        })
      }
      2 => {
        let doc = self.fetch_json(url, false).await?;
        let object = doc
          .value
          .as_object()
          .ok_or(DiscoveryFailure::InvalidDocument)?;
        if object.get("client_id").and_then(Value::as_str) != Some(url.as_str()) {
          return Err(DiscoveryFailure::InvalidDocument);
        }
        match (object.get("jwks"), object.get("jwks_uri")) {
          (Some(jwks), None) => Ok(FetchResult {
            keys: parse_jwks(jwks)?,
            ttl: doc.ttl,
            store: doc.store,
          }),
          (None, Some(Value::String(uri))) => {
            let jwks_url = Url::parse(uri).map_err(|_| DiscoveryFailure::UnsafeUrl)?;
            self.check_url(&jwks_url)?;
            let jwks = self.fetch_json(&jwks_url, false).await?;
            Ok(FetchResult {
              keys: parse_jwks(&jwks.value)?,
              ttl: doc.ttl.min(jwks.ttl),
              store: doc.store && jwks.store,
            })
          }
          _ => Err(DiscoveryFailure::InvalidDocument),
        }
      }
      _ => Err(DiscoveryFailure::InvalidDocument),
    }
  }

  fn check_url(&self, url: &Url) -> Result<(), DiscoveryFailure> {
    if url.scheme() != "https"
      || url.host_str().is_none()
      || url.as_str().len() > MAX_URL_LEN
      || url.fragment().is_some()
      || !url.username().is_empty()
      || url.password().is_some()
    {
      return Err(DiscoveryFailure::UnsafeUrl);
    }
    let port = url
      .port_or_known_default()
      .ok_or(DiscoveryFailure::UnsafeUrl)?;
    if port != 443
      && !self
        .nonstandard_origins
        .contains(&url.origin().ascii_serialization())
    {
      return Err(DiscoveryFailure::UnsafeUrl);
    }
    if let Some(host) = url.host() {
      match host {
        url::Host::Ipv4(ip) if !public_ipv4(ip) => return Err(DiscoveryFailure::UnsafeUrl),
        url::Host::Ipv6(ip) if !public_ipv6(ip) => return Err(DiscoveryFailure::UnsafeUrl),
        _ => {}
      }
    }
    Ok(())
  }

  async fn fetch_json(&self, url: &Url, directory: bool) -> Result<HttpDocument, DiscoveryFailure> {
    self.check_url(url)?;
    let _permit = self
      .fetches
      .try_acquire()
      .map_err(|_| DiscoveryFailure::Busy)?;
    tokio::time::timeout(self.timeout, self.fetch_json_inner(url, directory))
      .await
      .map_err(|_| DiscoveryFailure::Fetch)?
  }

  async fn fetch_json_inner(
    &self,
    url: &Url,
    directory: bool,
  ) -> Result<HttpDocument, DiscoveryFailure> {
    let host = url.host_str().ok_or(DiscoveryFailure::UnsafeUrl)?;
    let port = url
      .port_or_known_default()
      .ok_or(DiscoveryFailure::UnsafeUrl)?;
    let addresses: Vec<SocketAddr> = lookup_host((host, port))
      .await
      .map_err(|_| DiscoveryFailure::Fetch)?
      .filter(|address| public_ip(address.ip()))
      .take(16)
      .collect();
    if addresses.is_empty() {
      return Err(DiscoveryFailure::UnsafeUrl);
    }
    // DNS is never queried again by the transport. The certificate is checked
    // against the URL hostname while TCP uses exactly a vetted address.
    let mut stream = None;
    for address in addresses {
      if let Ok(socket) = TcpStream::connect(address).await {
        stream = Some(socket);
        break;
      }
    }
    let stream = stream.ok_or(DiscoveryFailure::Fetch)?;
    let server_name =
      ServerName::try_from(host.to_owned()).map_err(|_| DiscoveryFailure::UnsafeUrl)?;
    let tls = TlsConnector::from(Arc::clone(&self.tls))
      .connect(server_name, stream)
      .await
      .map_err(|_| DiscoveryFailure::Fetch)?;
    let (mut sender, connection) = http1::handshake::<_, Empty<Bytes>>(TokioIo::new(tls))
      .await
      .map_err(|_| DiscoveryFailure::Fetch)?;
    let driver = tokio::spawn(async move {
      let _ = connection.await;
    });
    let result = async {
      let mut target = url.path().to_owned();
      if target.is_empty() {
        target.push('/');
      }
      if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
      }
      let mut authority = match url.host() {
        Some(url::Host::Ipv6(ip)) => format!("[{ip}]"),
        _ => host.to_owned(),
      };
      if port != 443 {
        authority.push_str(&format!(":{port}"));
      }
      let accept = if directory {
        DIRECTORY_MIME
      } else {
        "application/json"
      };
      let request = Request::builder()
        .method(Method::GET)
        .uri(target)
        .header(HOST, authority)
        .header(ACCEPT, accept)
        .header(http::header::ACCEPT_ENCODING, "identity")
        .body(Empty::<Bytes>::new())
        .map_err(|_| DiscoveryFailure::Fetch)?;
      let response = sender
        .send_request(request)
        .await
        .map_err(|_| DiscoveryFailure::Fetch)?;
      if response.status() != StatusCode::OK {
        return Err(DiscoveryFailure::InvalidResponse);
      }
      if directory {
        let media_type = response
          .headers()
          .get(CONTENT_TYPE)
          .and_then(|v| v.to_str().ok())
          .and_then(|v| v.split(';').next())
          .map(str::trim);
        if !media_type.is_some_and(|value| value.eq_ignore_ascii_case(DIRECTORY_MIME)) {
          return Err(DiscoveryFailure::InvalidResponse);
        }
      }
      if response
        .headers()
        .get(CONTENT_ENCODING)
        .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
      {
        return Err(DiscoveryFailure::InvalidResponse);
      }
      if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|len| len > MAX_BODY)
      {
        return Err(DiscoveryFailure::InvalidResponse);
      }
      let (ttl, store) = cache_policy(response.headers());
      let mut body = response.into_body();
      let mut bytes = Vec::new();
      while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| DiscoveryFailure::Fetch)?;
        if let Ok(data) = frame.into_data() {
          if data.len() > MAX_BODY - bytes.len() {
            return Err(DiscoveryFailure::InvalidResponse);
          }
          bytes.extend_from_slice(&data);
        }
      }
      let value = serde_json::from_slice(&bytes).map_err(|_| DiscoveryFailure::InvalidDocument)?;
      Ok(HttpDocument { value, ttl, store })
    }
    .await;
    driver.abort();
    result
  }
}

fn parse_jwks(value: &Value) -> Result<Vec<Value>, DiscoveryFailure> {
  let keys = value
    .get("keys")
    .and_then(Value::as_array)
    .ok_or(DiscoveryFailure::InvalidDocument)?;
  if keys.is_empty() || keys.len() > MAX_KEYS || keys.iter().any(|key| !key.is_object()) {
    return Err(DiscoveryFailure::InvalidDocument);
  }
  Ok(keys.clone())
}

fn cache_policy(headers: &http::HeaderMap) -> (Duration, bool) {
  let mut ttl = DEFAULT_TTL;
  let mut store = true;
  let mut no_cache = false;
  for header in headers.get_all(CACHE_CONTROL) {
    if let Ok(value) = header.to_str() {
      for directive in value.split(',').map(str::trim) {
        if directive.eq_ignore_ascii_case("no-store") {
          store = false;
        }
        if directive.eq_ignore_ascii_case("no-cache") {
          no_cache = true;
        }
        if let Some((name, seconds)) = directive.split_once('=')
          && name.trim().eq_ignore_ascii_case("max-age")
          && let Ok(seconds) = seconds.trim().trim_matches('"').parse::<u64>()
        {
          ttl = Duration::from_secs(seconds).min(MAX_TTL);
        }
      }
    }
  }
  let age = headers
    .get_all(AGE)
    .iter()
    .filter_map(|value| value.to_str().ok()?.parse::<u64>().ok())
    .max()
    .unwrap_or(0);
  ttl = ttl.saturating_sub(Duration::from_secs(age));
  if !store || no_cache {
    ttl = Duration::ZERO;
    // no-cache requires revalidation; a failed refresh cannot authorize
    // stale keys from that response.
    store = false;
  }
  (ttl, store)
}

fn public_ip(ip: IpAddr) -> bool {
  match ip {
    IpAddr::V4(ip) => public_ipv4(ip),
    IpAddr::V6(ip) => public_ipv6(ip),
  }
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
  let x = u32::from(ip);
  let blocked = [
    (0x0000_0000, 8),
    (0x0a00_0000, 8),
    (0x6440_0000, 10),
    (0x7f00_0000, 8),
    (0xa9fe_0000, 16),
    (0xac10_0000, 12),
    (0xc000_0000, 24),
    (0xc000_0200, 24),
    (0xc058_6300, 24),
    (0xc0a8_0000, 16),
    (0xc612_0000, 15),
    (0xc633_6400, 24),
    (0xcb00_7100, 24),
    (0xe000_0000, 4),
    (0xf000_0000, 4),
  ];
  !blocked
    .into_iter()
    .any(|(base, prefix)| x >> (32 - prefix) == base >> (32 - prefix))
}

fn public_ipv6(ip: Ipv6Addr) -> bool {
  let x = u128::from(ip);
  let in_prefix = |base: u128, bits: u32| x >> (128 - bits) == base >> (128 - bits);
  // Only global unicast; reject documentation and special-purpose 2001::/32.
  in_prefix(0x2000_0000_0000_0000_0000_0000_0000_0000, 3)
    && !in_prefix(0x2001_0000_0000_0000_0000_0000_0000_0000, 32)
    && !in_prefix(0x2001_0db8_0000_0000_0000_0000_0000_0000, 32)
    && !in_prefix(0x2001_0002_0000_0000_0000_0000_0000_0000, 48)
    && !in_prefix(0x2001_0010_0000_0000_0000_0000_0000_0000, 28)
    && !in_prefix(0x2001_0020_0000_0000_0000_0000_0000_0000, 28)
    && !in_prefix(0x2002_0000_0000_0000_0000_0000_0000_0000, 16)
    && !in_prefix(0x3fff_0000_0000_0000_0000_0000_0000_0000, 20)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn document_fixture_enforces_key_bounds() {
    let fixture = serde_json::json!({"keys": [{"kty":"OKP","crv":"Ed25519","x":"a"}]});
    assert_eq!(parse_jwks(&fixture).unwrap().len(), 1);
    assert_eq!(
      parse_jwks(&serde_json::json!({"keys": []})).unwrap_err(),
      DiscoveryFailure::InvalidDocument
    );
    assert_eq!(
      parse_jwks(&serde_json::json!({"keys": [1]})).unwrap_err(),
      DiscoveryFailure::InvalidDocument
    );
  }

  #[test]
  fn private_and_special_addresses_are_rejected() {
    for ip in [
      "127.0.0.1",
      "10.0.0.1",
      "100.64.0.1",
      "169.254.1.1",
      "192.0.2.1",
      "198.18.0.1",
    ] {
      assert!(!public_ip(ip.parse().unwrap()), "{ip}");
    }
    assert!(public_ip("8.8.8.8".parse().unwrap()));
    assert!(!public_ip("::1".parse().unwrap()));
    assert!(!public_ip("2001:db8::1".parse().unwrap()));
    assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
  }

  #[test]
  fn no_cache_never_allows_stale_keys() {
    let mut headers = http::HeaderMap::new();
    headers.insert(CACHE_CONTROL, "no-cache, max-age=600".parse().unwrap());
    let (ttl, allow_stale) = cache_policy(&headers);
    assert_eq!(ttl, Duration::ZERO);
    assert!(!allow_stale);
  }

  #[test]
  fn intermediary_age_reduces_key_cache_lifetime() {
    let mut headers = http::HeaderMap::new();
    headers.insert(CACHE_CONTROL, "max-age=600".parse().unwrap());
    headers.insert(AGE, "599".parse().unwrap());
    assert_eq!(cache_policy(&headers), (Duration::from_secs(1), true));
    headers.insert(AGE, "700".parse().unwrap());
    assert_eq!(cache_policy(&headers), (Duration::ZERO, true));
  }
}
