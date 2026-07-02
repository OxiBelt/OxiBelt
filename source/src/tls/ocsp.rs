use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, anyhow, bail};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use url::Url;

use crate::config::{CryptoConfig, OcspMode, TlsConfig};
use crate::control_http::{ControlHttpClient, full_body, uri_from_url};
use crate::metrics::Metrics;

mod cert_id;
mod schedule;
mod status;
mod verify;
use super::certificate_io::load_ocsp_response;
use super::certificate_partition::normalize_server_names;
pub(super) use schedule::{classify_ocsp_error, failure_retry_time, next_refresh_time, unix_now};
pub use status::OcspRuntimeStatus;
use status::{OcspStatusState, system_time_to_unix};
pub(in crate::tls) use verify::{
  OcspRequestContext, OcspVerificationContext, VerifiedOcspResponse, build_ocsp_request_context,
  verify_ocsp_response,
};

const OCSP_REQUEST_CONTENT_TYPE: &str = "application/ocsp-request";
const OCSP_RESPONSE_CONTENT_TYPE: &str = "application/ocsp-response";
const FAILURE_RETRY_SECONDS: u64 = 300;

#[derive(Clone)]
pub(crate) struct OcspStapleRuntime {
  inner: Arc<OcspStapleRuntimeInner>,
}

struct OcspStapleRuntimeInner {
  live: Option<Arc<DownstreamCertResolverBundle>>,
  status: Arc<Mutex<OcspStatusState>>,
  worker: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Drop for OcspStapleRuntimeInner {
  fn drop(&mut self) {
    if let Ok(mut workers) = self.worker.lock() {
      for worker in workers.drain(..) {
        worker.abort();
      }
    }
  }
}

impl OcspStapleRuntime {
  pub(crate) async fn new(
    crypto: &CryptoConfig,
    tls: &TlsConfig,
    control_http: &ControlHttpClient,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    if tls.ocsp.mode == OcspMode::LiveFetch
      || tls
        .certificates
        .iter()
        .any(|certificate| certificate.ocsp.mode == OcspMode::LiveFetch)
    {
      return Self::live_fetch(crypto, tls, control_http.clone(), metrics).await;
    }

    match tls.ocsp.mode {
      OcspMode::Disabled => Ok(Self::inactive(OcspStatusState::disabled())),
      OcspMode::StaticFile => Ok(Self::inactive(OcspStatusState::static_file(
        tls.ocsp.response_file.is_some(),
      ))),
      OcspMode::LiveFetch => unreachable!("live fetch returned above"),
    }
  }

  fn inactive(status: OcspStatusState) -> Self {
    Self {
      inner: Arc::new(OcspStapleRuntimeInner {
        live: None,
        status: Arc::new(Mutex::new(status)),
        worker: Mutex::new(Vec::new()),
      }),
    }
  }

  async fn live_fetch(
    crypto: &CryptoConfig,
    tls: &TlsConfig,
    control_http: ControlHttpClient,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    let provider = Arc::new(super::negotiation::downstream_crypto_provider_for_policy(
      crypto,
      &tls.negotiation_policy(),
    )?);
    let mut workers = Vec::new();

    let base_key = super::load_downstream_certified_key(tls, &provider)
      .context("failed to create rustls certified key for OCSP live fetch")?;
    let default_identity = super::certificate_identity(&base_key.cert);
    let mut aggregate_certs = Vec::new();
    aggregate_certs.extend(base_key.cert.iter().cloned());
    let (default_resolver, status) = build_certificate_ocsp_resolver(
      "tls",
      &tls.ocsp,
      base_key,
      control_http.clone(),
      metrics.clone(),
      &mut workers,
    )
    .await?;

    let mut certificates = Vec::new();
    for (index, certificate) in tls.certificates.iter().enumerate() {
      let certified_key =
        super::load_downstream_certificate_certified_key(tls, certificate, &provider)
          .with_context(|| {
            format!("failed to create rustls certified key for tls.certificates[{index}]")
          })?;
      let identity = super::certificate_identity(&certified_key.cert);
      aggregate_certs.extend(certified_key.cert.iter().cloned());
      let (resolver, _status) = build_certificate_ocsp_resolver(
        &format!("tls.certificates[{index}]"),
        &certificate.ocsp,
        certified_key,
        control_http.clone(),
        metrics.clone(),
        &mut workers,
      )
      .await?;
      certificates.push(DownstreamCertResolverEntry {
        identity,
        server_names: normalize_server_names(&certificate.server_names),
        resolver,
        is_default: false,
      });
    }

    let aggregate_identity = super::certificate_identity(&aggregate_certs);
    let live = Arc::new(DownstreamCertResolverBundle {
      aggregate_identity,
      certificates,
      default: DownstreamCertResolverEntry {
        identity: default_identity,
        server_names: normalize_server_names(&tls.server_names),
        resolver: default_resolver,
        is_default: true,
      },
      require_sni: tls.require_sni,
      reject_unknown_sni: tls.reject_unknown_sni,
    });

    Ok(Self {
      inner: Arc::new(OcspStapleRuntimeInner {
        live: Some(live),
        status,
        worker: Mutex::new(workers),
      }),
    })
  }

  pub(in crate::tls) fn live_bundle(&self) -> Option<Arc<DownstreamCertResolverBundle>> {
    self.inner.live.as_ref().map(Arc::clone)
  }

  pub(crate) fn status(&self) -> OcspRuntimeStatus {
    self
      .inner
      .status
      .lock()
      .map(|status| status.to_public())
      .unwrap_or_else(|_| OcspStatusState::live_degraded(Some("status_lock")).to_public())
  }
}

async fn build_certificate_ocsp_resolver(
  field_name: &str,
  ocsp: &crate::config::OcspConfig,
  mut base_key: CertifiedKey,
  control_http: ControlHttpClient,
  metrics: Arc<Metrics>,
  workers: &mut Vec<tokio::task::JoinHandle<()>>,
) -> anyhow::Result<(Arc<dyn ResolvesServerCert>, Arc<Mutex<OcspStatusState>>)> {
  match ocsp.mode {
    OcspMode::Disabled => {
      base_key.ocsp = None;
      Ok((
        Arc::new(rustls::sign::SingleCertAndKey::from(base_key)),
        Arc::new(Mutex::new(OcspStatusState::disabled())),
      ))
    }
    OcspMode::StaticFile => {
      base_key.ocsp = load_ocsp_response(ocsp)?;
      Ok((
        Arc::new(rustls::sign::SingleCertAndKey::from(base_key)),
        Arc::new(Mutex::new(OcspStatusState::static_file(
          ocsp.response_file.is_some(),
        ))),
      ))
    }
    OcspMode::LiveFetch => {
      base_key.ocsp = None;
      let context = Arc::new(LiveOcspContext::new(
        field_name,
        ocsp,
        base_key,
        control_http,
        metrics.clone(),
      )?);
      let status = Arc::new(Mutex::new(OcspStatusState::live_degraded(None)));
      let live = Arc::new(LiveOcspResolver::new(
        context.base_key.clone(),
        status.clone(),
        metrics,
      ));

      refresh_once(context.clone(), live.clone(), status.clone()).await;

      let worker_live = live.clone();
      let worker_status = status.clone();
      let worker_context = context.clone();
      workers.push(tokio::spawn(async move {
        refresh_worker(worker_context, worker_live, worker_status).await;
      }));

      Ok((live, status))
    }
  }
}

#[derive(Clone)]
struct DownstreamCertResolverEntry {
  identity: String,
  server_names: Vec<String>,
  resolver: Arc<dyn ResolvesServerCert>,
  is_default: bool,
}

pub(in crate::tls) struct DownstreamCertResolverBundle {
  aggregate_identity: String,
  certificates: Vec<DownstreamCertResolverEntry>,
  default: DownstreamCertResolverEntry,
  require_sni: bool,
  reject_unknown_sni: bool,
}

impl DownstreamCertResolverBundle {
  pub(in crate::tls) fn aggregate_identity(&self) -> &str {
    &self.aggregate_identity
  }

  pub(in crate::tls) fn aggregate_resolver(&self) -> Arc<dyn ResolvesServerCert> {
    Arc::new(DownstreamCertResolver {
      certificates: self.certificates.clone(),
      default: self.default.clone(),
      require_sni: self.require_sni,
      reject_unknown_sni: self.reject_unknown_sni,
    })
  }

  pub(in crate::tls) fn resolver_for_identity(
    &self,
    identity: &str,
  ) -> Option<Arc<dyn ResolvesServerCert>> {
    let entries = self
      .entries_for_identity(identity)
      .into_iter()
      .cloned()
      .collect::<Vec<_>>();
    (!entries.is_empty()).then(|| {
      Arc::new(DownstreamIdentityCertResolver {
        entries,
        require_sni: self.require_sni,
        reject_unknown_sni: self.reject_unknown_sni,
      }) as Arc<dyn ResolvesServerCert>
    })
  }

  fn entries_for_identity(&self, identity: &str) -> Vec<&DownstreamCertResolverEntry> {
    std::iter::once(&self.default)
      .chain(self.certificates.iter())
      .filter(|entry| entry.identity == identity)
      .collect()
  }
}

struct DownstreamCertResolver {
  certificates: Vec<DownstreamCertResolverEntry>,
  default: DownstreamCertResolverEntry,
  require_sni: bool,
  reject_unknown_sni: bool,
}

impl std::fmt::Debug for DownstreamCertResolver {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("DownstreamCertResolver")
      .field("certificate_count", &self.certificates.len())
      .field("default_server_names", &self.default.server_names)
      .field("require_sni", &self.require_sni)
      .field("reject_unknown_sni", &self.reject_unknown_sni)
      .finish()
  }
}

impl DownstreamCertResolver {
  fn named_resolver_for(&self, server_name: &str) -> Option<Arc<dyn ResolvesServerCert>> {
    if self
      .default
      .server_names
      .iter()
      .any(|pattern| !pattern.starts_with("*.") && pattern.eq_ignore_ascii_case(server_name))
    {
      return Some(self.default.resolver.clone());
    }
    for certificate in &self.certificates {
      if certificate
        .server_names
        .iter()
        .any(|pattern| !pattern.starts_with("*.") && pattern.eq_ignore_ascii_case(server_name))
      {
        return Some(certificate.resolver.clone());
      }
    }
    if self
      .default
      .server_names
      .iter()
      .any(|pattern| pattern.starts_with("*.") && super::sni_matches(pattern, server_name))
    {
      return Some(self.default.resolver.clone());
    }
    for certificate in &self.certificates {
      if certificate
        .server_names
        .iter()
        .any(|pattern| pattern.starts_with("*.") && super::sni_matches(pattern, server_name))
      {
        return Some(certificate.resolver.clone());
      }
    }
    None
  }
}

impl ResolvesServerCert for DownstreamCertResolver {
  fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
    let selected = match client_hello.server_name() {
      Some(server_name) => self.named_resolver_for(server_name).or_else(|| {
        if self.reject_unknown_sni {
          None
        } else {
          Some(self.default.resolver.clone())
        }
      }),
      None => {
        if self.require_sni {
          None
        } else {
          Some(self.default.resolver.clone())
        }
      }
    }?;
    selected.resolve(client_hello)
  }
}

struct DownstreamIdentityCertResolver {
  entries: Vec<DownstreamCertResolverEntry>,
  require_sni: bool,
  reject_unknown_sni: bool,
}

impl std::fmt::Debug for DownstreamIdentityCertResolver {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("DownstreamIdentityCertResolver")
      .field("entry_count", &self.entries.len())
      .field("require_sni", &self.require_sni)
      .field("reject_unknown_sni", &self.reject_unknown_sni)
      .finish()
  }
}

impl DownstreamIdentityCertResolver {
  fn named_resolver_for(&self, server_name: &str) -> Option<Arc<dyn ResolvesServerCert>> {
    self
      .matching_entry(server_name, false, true)
      .or_else(|| self.matching_entry(server_name, false, false))
      .or_else(|| self.matching_entry(server_name, true, true))
      .or_else(|| self.matching_entry(server_name, true, false))
      .map(|entry| entry.resolver.clone())
  }

  fn matching_entry(
    &self,
    server_name: &str,
    wildcard: bool,
    default: bool,
  ) -> Option<&DownstreamCertResolverEntry> {
    self
      .entries
      .iter()
      .filter(|entry| entry.is_default == default)
      .find(|entry| {
        entry.server_names.iter().any(|pattern| {
          if pattern.starts_with("*.") != wildcard {
            return false;
          }
          if wildcard {
            super::sni_matches(pattern, server_name)
          } else {
            pattern.eq_ignore_ascii_case(server_name)
          }
        })
      })
  }
}

impl ResolvesServerCert for DownstreamIdentityCertResolver {
  fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
    let selected = match client_hello.server_name() {
      Some(server_name) => self.named_resolver_for(server_name).or_else(|| {
        if self.reject_unknown_sni {
          None
        } else {
          self.entries.first().map(|entry| entry.resolver.clone())
        }
      }),
      None => {
        if self.require_sni {
          None
        } else {
          self.entries.first().map(|entry| entry.resolver.clone())
        }
      }
    }?;
    selected.resolve(client_hello)
  }
}

pub(in crate::tls) fn downstream_cert_resolver_bundle(
  tls: &TlsConfig,
  provider: &rustls::crypto::CryptoProvider,
  runtime: Option<&OcspStapleRuntime>,
) -> anyhow::Result<Arc<DownstreamCertResolverBundle>> {
  if let Some(runtime) = runtime
    && let Some(bundle) = runtime.live_bundle()
  {
    return Ok(bundle);
  }

  let mut certified_key = super::load_downstream_certified_key(tls, provider)
    .context("failed to create rustls certified key")?;
  let default_identity = super::certificate_identity(&certified_key.cert);
  let mut aggregate_certs = Vec::new();
  aggregate_certs.extend(certified_key.cert.iter().cloned());
  certified_key.ocsp = load_ocsp_response(&tls.ocsp)?;
  let default = Arc::new(rustls::sign::SingleCertAndKey::from(certified_key));
  let mut certificates = Vec::new();
  for (index, certificate) in tls.certificates.iter().enumerate() {
    let mut certified_key =
      super::load_downstream_certificate_certified_key(tls, certificate, provider)
        .with_context(|| format!("failed to create tls.certificates[{index}] certified key"))?;
    let identity = super::certificate_identity(&certified_key.cert);
    aggregate_certs.extend(certified_key.cert.iter().cloned());
    certified_key.ocsp = load_ocsp_response(&certificate.ocsp)?;
    certificates.push(DownstreamCertResolverEntry {
      identity,
      server_names: normalize_server_names(&certificate.server_names),
      resolver: Arc::new(rustls::sign::SingleCertAndKey::from(certified_key)),
      is_default: false,
    });
  }
  let aggregate_identity = super::certificate_identity(&aggregate_certs);
  Ok(Arc::new(DownstreamCertResolverBundle {
    aggregate_identity,
    certificates,
    default: DownstreamCertResolverEntry {
      identity: default_identity,
      server_names: normalize_server_names(&tls.server_names),
      resolver: default,
      is_default: true,
    },
    require_sni: tls.require_sni,
    reject_unknown_sni: tls.reject_unknown_sni,
  }))
}

pub(in crate::tls) fn downstream_cert_resolver_for_identity(
  tls: &TlsConfig,
  provider: &rustls::crypto::CryptoProvider,
  runtime: Option<&OcspStapleRuntime>,
  identity: Option<&str>,
) -> anyhow::Result<(String, Arc<dyn ResolvesServerCert>)> {
  let bundle = downstream_cert_resolver_bundle(tls, provider, runtime)?;
  if let Some(identity) = identity {
    let resolver = bundle.resolver_for_identity(identity).ok_or_else(|| {
      anyhow!("downstream TLS certificate partition identity is missing from resolver bundle")
    })?;
    return Ok((identity.to_string(), resolver));
  }
  Ok((
    bundle.aggregate_identity().to_string(),
    bundle.aggregate_resolver(),
  ))
}

#[derive(Debug)]
struct LiveOcspResolver {
  current_key: ArcSwap<CertifiedKey>,
  base_key: Arc<CertifiedKey>,
  staple_present: AtomicBool,
  expires_at_unix: AtomicU64,
  status: Arc<Mutex<OcspStatusState>>,
  metrics: Arc<Metrics>,
}

impl LiveOcspResolver {
  fn new(
    base_key: Arc<CertifiedKey>,
    status: Arc<Mutex<OcspStatusState>>,
    metrics: Arc<Metrics>,
  ) -> Self {
    Self {
      current_key: ArcSwap::from(base_key.clone()),
      base_key,
      staple_present: AtomicBool::new(false),
      expires_at_unix: AtomicU64::new(0),
      status,
      metrics,
    }
  }

  fn install_staple(&self, response: VerifiedOcspResponse) {
    let mut certified_key = (*self.base_key).clone();
    certified_key.ocsp = Some(response.response_der);
    self.current_key.store(Arc::new(certified_key));
    self
      .expires_at_unix
      .store(system_time_to_unix(response.next_update), Ordering::Relaxed);
    self.staple_present.store(true, Ordering::Relaxed);
    self.metrics.set_ocsp_staple_present(true);
    self
      .metrics
      .set_ocsp_next_update_timestamp(system_time_to_unix(response.next_update));
  }

  fn clear_staple(&self, error_code: &'static str) {
    let was_present = self.staple_present.swap(false, Ordering::Relaxed);
    self.expires_at_unix.store(0, Ordering::Relaxed);
    self.current_key.store(self.base_key.clone());
    self.metrics.set_ocsp_staple_present(false);
    self.metrics.set_ocsp_next_update_timestamp(0);
    if was_present {
      self.metrics.record_ocsp_stale_drop();
    }
    if let Ok(mut status) = self.status.lock() {
      status.status = "degraded".to_string();
      status.staple_present = false;
      status.last_error_code = Some(error_code.to_string());
      status.next_update = None;
    }
  }

  fn drop_stale_if_needed(&self) {
    let expires_at = self.expires_at_unix.load(Ordering::Relaxed);
    if expires_at == 0 || unix_now() < expires_at {
      return;
    }
    self.clear_staple("stale_response");
  }
}

impl rustls::server::ResolvesServerCert for LiveOcspResolver {
  fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
    self.drop_stale_if_needed();
    Some(self.current_key.load_full())
  }
}

struct LiveOcspContext {
  responder_url: Url,
  request_der: Vec<u8>,
  verification: OcspVerificationContext,
  base_key: Arc<CertifiedKey>,
  control_http: ControlHttpClient,
  metrics: Arc<Metrics>,
  timeout: Duration,
  max_response_bytes: usize,
  refresh_jitter_pct: u8,
}

impl LiveOcspContext {
  fn new(
    field_name: &str,
    ocsp: &crate::config::OcspConfig,
    base_key: CertifiedKey,
    control_http: ControlHttpClient,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    let leaf_der = base_key
      .cert
      .first()
      .ok_or_else(|| anyhow!("{field_name}.cert_chain must include a leaf certificate"))?
      .as_ref()
      .to_vec();
    let issuer_der = base_key
      .cert
      .get(1)
      .ok_or_else(|| {
        anyhow!("{field_name}.cert_chain must include an issuer certificate for OCSP live fetch")
      })?
      .as_ref()
      .to_vec();
    let request_context = build_ocsp_request_context(
      &leaf_der,
      &issuer_der,
      ocsp.responder_url.as_deref(),
      Duration::from_secs(ocsp.clock_skew_seconds),
    )?;
    Ok(Self {
      responder_url: request_context.responder_url,
      request_der: request_context.request_der,
      verification: request_context.verification,
      base_key: Arc::new(base_key),
      control_http,
      metrics,
      timeout: Duration::from_millis(ocsp.request_timeout_ms),
      max_response_bytes: ocsp.max_response_bytes,
      refresh_jitter_pct: ocsp.refresh_jitter_pct,
    })
  }
}

async fn refresh_worker(
  context: Arc<LiveOcspContext>,
  resolver: Arc<LiveOcspResolver>,
  status: Arc<Mutex<OcspStatusState>>,
) {
  loop {
    resolver.drop_stale_if_needed();
    let sleep_until = status
      .lock()
      .ok()
      .and_then(|status| status.next_refresh_at_unix())
      .unwrap_or_else(|| unix_now().saturating_add(FAILURE_RETRY_SECONDS));
    let wait = sleep_until.saturating_sub(unix_now());
    tokio::time::sleep(Duration::from_secs(wait)).await;
    refresh_once(context.clone(), resolver.clone(), status.clone()).await;
  }
}

async fn refresh_once(
  context: Arc<LiveOcspContext>,
  resolver: Arc<LiveOcspResolver>,
  status: Arc<Mutex<OcspStatusState>>,
) {
  let fetch_started = SystemTime::now();
  if let Ok(mut current) = status.lock() {
    current.last_fetch_at = Some(fetch_started);
  }
  match fetch_and_verify(context.as_ref()).await {
    Ok(response) => {
      context.metrics.record_ocsp_fetch_success();
      resolver.install_staple(response.clone());
      if let Ok(mut current) = status.lock() {
        current.status = "fresh".to_string();
        current.staple_present = true;
        current.this_update = Some(response.this_update);
        current.next_update = Some(response.next_update);
        current.last_success_at = Some(SystemTime::now());
        current.last_error_code = None;
        current.next_refresh_at = Some(next_refresh_time(
          response.this_update,
          response.next_update,
          context.refresh_jitter_pct,
        ));
      }
    }
    Err(error) => {
      context.metrics.record_ocsp_fetch_error();
      let error_code = classify_ocsp_error(&error);
      resolver.drop_stale_if_needed();
      if let Ok(mut current) = status.lock() {
        current.status = "degraded".to_string();
        current.staple_present = resolver.staple_present.load(Ordering::Relaxed);
        current.last_error_code = Some(error_code.to_string());
        current.next_refresh_at = Some(failure_retry_time(current.next_update));
      }
    }
  }
}

async fn fetch_and_verify(context: &LiveOcspContext) -> anyhow::Result<VerifiedOcspResponse> {
  let request = http::Request::builder()
    .method(http::Method::POST)
    .uri(uri_from_url(&context.responder_url)?)
    .header(CONTENT_TYPE, OCSP_REQUEST_CONTENT_TYPE)
    .header(ACCEPT, OCSP_RESPONSE_CONTENT_TYPE)
    .body(full_body(Bytes::copy_from_slice(&context.request_der)))
    .context("failed to build OCSP HTTP request")?;
  let response = context
    .control_http
    .request(request, context.timeout, context.max_response_bytes)
    .await
    .context("ocsp_fetch")?;
  if response.status != http::StatusCode::OK {
    bail!("ocsp_http_status");
  }
  verify_ocsp_response(&context.verification, response.body.as_ref())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::UNIX_EPOCH;

  #[test]
  fn next_refresh_time_stays_before_expiry() {
    let this_update = UNIX_EPOCH + Duration::from_secs(1_000);
    let next_update = UNIX_EPOCH + Duration::from_secs(2_000);

    let refresh = next_refresh_time(this_update, next_update, 10);

    assert!(refresh > this_update);
    assert!(refresh < next_update);
  }
}
