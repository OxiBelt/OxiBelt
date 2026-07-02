use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, anyhow, bail};
use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
  CertificateError, DigitallySignedStruct, DistinguishedName, Error, OtherError, SignatureScheme,
};
use serde::Serialize;

use super::{crlite, crlite_managed, ocsp};
use crate::config::{
  Config, CrliteFailurePolicy, CrliteMode, OutboundOcspMode, OutboundTlsRevocationConfig,
};
use crate::control_http::{ControlHttpClient, full_body, uri_from_url};
use crate::metrics::Metrics;

const OCSP_REQUEST_CONTENT_TYPE: &str = "application/ocsp-request";
const OCSP_RESPONSE_CONTENT_TYPE: &str = "application/ocsp-response";

#[derive(Clone)]
pub(crate) struct OutboundRevocationRuntime {
  inner: Arc<OutboundRevocationInner>,
}

struct OutboundRevocationInner {
  enabled: bool,
  default_policy: Arc<OutboundTlsRevocationConfig>,
  control_http: ControlHttpClient,
  metrics: Arc<Metrics>,
  ocsp_cache: Mutex<HashMap<Vec<u8>, CachedOcspResponse>>,
  ocsp_contexts: Mutex<HashMap<Vec<u8>, CachedOcspContext>>,
  ocsp_fetches: Mutex<HashSet<Vec<u8>>>,
  managed_filters: Vec<ManagedCrlitePolicy>,
  status: Mutex<OutboundRevocationRuntimeStatus>,
}

#[derive(Clone, Debug)]
struct CachedOcspResponse {
  response_der: Vec<u8>,
  this_update: SystemTime,
  next_update: SystemTime,
}

#[derive(Clone)]
struct CachedOcspContext {
  policy: OutboundTlsRevocationConfig,
  context: ocsp::OcspRequestContext,
}

#[derive(Clone, Debug)]
struct ManagedCrlitePolicy {
  config: crate::config::CrliteConfig,
  filter: Arc<crlite_managed::ManagedFilter>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutboundRevocationRuntimeStatus {
  pub enabled: bool,
  pub ocsp_mode: String,
  pub crlite_mode: String,
  pub ocsp_cache_entries: usize,
  pub ocsp_fetch_in_flight: usize,
  pub last_ocsp_error_code: Option<String>,
  pub crlite_managed_filters: usize,
  pub last_crlite_error_code: Option<String>,
}

impl OutboundRevocationRuntime {
  pub(crate) async fn new(config: &Config, metrics: Arc<Metrics>) -> anyhow::Result<Self> {
    let default_policy = Arc::new(config.proxy.upstream_revocation.clone());
    let enabled = outbound_revocation_enabled(config);
    let control_http = ControlHttpClient::new(&config.proxy.trusted_ca_certs)
      .context("failed to build outbound revocation bootstrap HTTP client")?;
    let (managed_filters, initial_crlite_error_code) =
      load_managed_crlite_filters(config, &metrics).await?;
    let crlite_managed_filters = managed_filters.len();
    Ok(Self {
      inner: Arc::new(OutboundRevocationInner {
        enabled,
        default_policy: default_policy.clone(),
        control_http,
        metrics,
        ocsp_cache: Mutex::new(HashMap::new()),
        ocsp_contexts: Mutex::new(HashMap::new()),
        ocsp_fetches: Mutex::new(HashSet::new()),
        managed_filters,
        status: Mutex::new(OutboundRevocationRuntimeStatus {
          enabled,
          ocsp_mode: default_policy.ocsp.mode.as_str().to_string(),
          crlite_mode: default_policy.crlite.mode.as_str().to_string(),
          ocsp_cache_entries: 0,
          ocsp_fetch_in_flight: 0,
          last_ocsp_error_code: None,
          crlite_managed_filters,
          last_crlite_error_code: initial_crlite_error_code,
        }),
      }),
    })
  }

  pub(crate) fn default_policy(&self) -> Arc<OutboundTlsRevocationConfig> {
    self.inner.default_policy.clone()
  }

  pub(crate) fn policy_for_upstream(
    &self,
    upstream: &crate::config::UpstreamConfig,
  ) -> Arc<OutboundTlsRevocationConfig> {
    upstream
      .tls
      .upstream_revocation
      .as_ref()
      .map(|policy| Arc::new(policy.clone()))
      .unwrap_or_else(|| self.default_policy())
  }

  pub(crate) fn verifier(
    &self,
    inner: Arc<dyn ServerCertVerifier>,
    policy: Arc<OutboundTlsRevocationConfig>,
  ) -> Arc<dyn ServerCertVerifier> {
    if !self.inner.enabled || !policy.enabled() {
      return inner;
    }
    Arc::new(OutboundRevocationVerifier {
      inner,
      runtime: self.clone(),
      policy,
    })
  }

  pub(crate) fn status(&self) -> OutboundRevocationRuntimeStatus {
    let mut status = self
      .inner
      .status
      .lock()
      .map(|status| status.clone())
      .unwrap_or_else(|_| OutboundRevocationRuntimeStatus {
        enabled: self.inner.enabled,
        ocsp_mode: self.inner.default_policy.ocsp.mode.as_str().to_string(),
        crlite_mode: self.inner.default_policy.crlite.mode.as_str().to_string(),
        ocsp_cache_entries: 0,
        ocsp_fetch_in_flight: 0,
        last_ocsp_error_code: Some("status_lock".to_string()),
        crlite_managed_filters: self.inner.managed_filters.len(),
        last_crlite_error_code: None,
      });
    status.ocsp_cache_entries = self
      .inner
      .ocsp_cache
      .lock()
      .map(|cache| cache.len())
      .unwrap_or_default();
    status.ocsp_fetch_in_flight = self
      .inner
      .ocsp_fetches
      .lock()
      .map(|fetches| fetches.len())
      .unwrap_or_default();
    status.crlite_managed_filters = self.inner.managed_filters.len();
    status
  }

  pub(crate) async fn refresh(&self) {
    let contexts = self
      .inner
      .ocsp_contexts
      .lock()
      .map(|contexts| {
        contexts
          .iter()
          .map(|(key, context)| (key.clone(), context.clone()))
          .collect::<Vec<_>>()
      })
      .unwrap_or_default();
    for (key, cached) in contexts {
      let result = self
        .fetch_ocsp_once(&cached.policy, &key, &cached.context)
        .await;
      self.finish_ocsp_fetch(&key, result);
    }
  }

  fn verify_revocation(
    &self,
    policy: &OutboundTlsRevocationConfig,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    ocsp_response: &[u8],
  ) -> anyhow::Result<()> {
    self.verify_ocsp(policy, end_entity, intermediates, ocsp_response)?;
    self.verify_crlite(policy, end_entity, intermediates)?;
    Ok(())
  }

  fn verify_ocsp(
    &self,
    policy: &OutboundTlsRevocationConfig,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    ocsp_response: &[u8],
  ) -> anyhow::Result<()> {
    if policy.ocsp.mode == OutboundOcspMode::Disabled {
      return Ok(());
    }
    let issuer = intermediates
      .first()
      .ok_or_else(|| anyhow!("upstream_ocsp_missing_issuer_certificate"))?;
    let context = ocsp::build_ocsp_request_context(
      end_entity.as_ref(),
      issuer.as_ref(),
      None,
      Duration::from_secs(policy.ocsp.clock_skew_seconds),
    )
    .context("upstream_ocsp_context")?;

    if !ocsp_response.is_empty() {
      return match ocsp::verify_ocsp_response(&context.verification, ocsp_response) {
        Ok(_) => {
          self.inner.metrics.record_outbound_revocation_ocsp_success();
          Ok(())
        }
        Err(error) => self.handle_ocsp_error(policy, error),
      };
    }

    let key = certificate_cache_key(end_entity.as_ref());
    self.remember_ocsp_context(&key, policy, &context);
    if let Some(cached) = self.cached_ocsp_response(&key) {
      return match ocsp::verify_ocsp_response(&context.verification, &cached.response_der) {
        Ok(_) => {
          self.inner.metrics.record_outbound_revocation_ocsp_success();
          Ok(())
        }
        Err(error) => self.handle_ocsp_error(policy, error),
      };
    }

    self.spawn_ocsp_fetch(policy.clone(), key, context);
    self.handle_ocsp_error(policy, anyhow!("upstream_ocsp_cache_miss"))
  }

  fn verify_crlite(
    &self,
    policy: &OutboundTlsRevocationConfig,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
  ) -> anyhow::Result<()> {
    if policy.crlite.mode == CrliteMode::Disabled {
      return Ok(());
    }
    self.inner.metrics.record_outbound_revocation_crlite_check();
    let issuer = intermediates
      .first()
      .ok_or_else(|| anyhow!("upstream_crlite_missing_issuer_certificate"))?;
    let material = crlite::crlite_query_material_from_der(end_entity.as_ref(), issuer.as_ref())
      .context("upstream_crlite_query_material")?;
    let result = match policy.crlite.mode {
      CrliteMode::Disabled => return Ok(()),
      CrliteMode::Enforce => crlite::check_crlite_config(&policy.crlite, &material),
      CrliteMode::Managed => {
        let filter = self
          .inner
          .managed_filters
          .iter()
          .find(|managed| managed.config == policy.crlite)
          .ok_or_else(|| anyhow!("upstream_crlite_managed_filter_unavailable"))?;
        crlite::check_crlite_filter_bytes_for_material(
          &policy.crlite,
          &material,
          &filter.filter.bytes,
          filter.filter.filter_stale,
        )
      }
    };
    match result {
      Ok(outcome) => {
        if outcome.certificate_rejected {
          if outcome.result == Some("revoked") {
            self
              .inner
              .metrics
              .record_outbound_revocation_crlite_revoked();
            bail!("upstream_crlite_revoked_certificate");
          }
          if policy.crlite.failure_policy == CrliteFailurePolicy::FailClosed {
            bail!(
              "{}",
              outcome
                .error_code
                .unwrap_or("upstream_crlite_certificate_rejected")
            );
          }
        }
        if outcome.error_code.is_some()
          && policy.crlite.failure_policy == CrliteFailurePolicy::FailClosed
        {
          bail!("{}", outcome.error_code.unwrap_or("upstream_crlite_error"));
        }
        Ok(())
      }
      Err(error) => {
        let code = crlite::classify_crlite_error(&error);
        self.set_crlite_error(code);
        self.inner.metrics.record_outbound_revocation_crlite_error();
        if policy.crlite.failure_policy == CrliteFailurePolicy::FailClosed {
          bail!("{code}");
        }
        Ok(())
      }
    }
  }

  fn cached_ocsp_response(&self, key: &[u8]) -> Option<CachedOcspResponse> {
    let mut cache = self.inner.ocsp_cache.lock().ok()?;
    let cached = cache.get(key)?;
    if cached.next_update <= SystemTime::now() {
      cache.remove(key);
      self.inner.metrics.record_outbound_revocation_ocsp_error();
      return None;
    }
    Some(cached.clone())
  }

  fn remember_ocsp_context(
    &self,
    key: &[u8],
    policy: &OutboundTlsRevocationConfig,
    context: &ocsp::OcspRequestContext,
  ) {
    if let Ok(mut contexts) = self.inner.ocsp_contexts.lock() {
      contexts.insert(
        key.to_vec(),
        CachedOcspContext {
          policy: policy.clone(),
          context: context.clone(),
        },
      );
    }
  }

  fn spawn_ocsp_fetch(
    &self,
    policy: OutboundTlsRevocationConfig,
    key: Vec<u8>,
    context: ocsp::OcspRequestContext,
  ) {
    if !self.mark_ocsp_fetch_started(&key) {
      return;
    }
    let runtime = self.clone();
    match tokio::runtime::Handle::try_current() {
      Ok(handle) => {
        handle.spawn(async move {
          let result = runtime.fetch_ocsp_once(&policy, &key, &context).await;
          runtime.finish_ocsp_fetch(&key, result);
        });
      }
      Err(_) => {
        self.finish_ocsp_fetch(
          &key,
          Err(anyhow!("upstream_ocsp_fetch_runtime_unavailable")),
        );
      }
    }
  }

  async fn fetch_ocsp_once(
    &self,
    policy: &OutboundTlsRevocationConfig,
    key: &[u8],
    context: &ocsp::OcspRequestContext,
  ) -> anyhow::Result<CachedOcspResponse> {
    let request = http::Request::builder()
      .method(http::Method::POST)
      .uri(uri_from_url(&context.responder_url)?)
      .header(CONTENT_TYPE, OCSP_REQUEST_CONTENT_TYPE)
      .header(ACCEPT, OCSP_RESPONSE_CONTENT_TYPE)
      .body(full_body(Bytes::copy_from_slice(&context.request_der)))
      .context("upstream_ocsp_request_build")?;
    let response = self
      .inner
      .control_http
      .request(
        request,
        Duration::from_millis(policy.ocsp.request_timeout_ms),
        policy.ocsp.max_response_bytes,
      )
      .await
      .context("upstream_ocsp_fetch")?;
    if response.status != http::StatusCode::OK {
      bail!("upstream_ocsp_http_status");
    }
    let verified = ocsp::verify_ocsp_response(&context.verification, response.body.as_ref())?;
    let cached = CachedOcspResponse {
      response_der: verified.response_der,
      this_update: verified.this_update,
      next_update: verified.next_update,
    };
    let mut cache = self
      .inner
      .ocsp_cache
      .lock()
      .map_err(|_| anyhow!("upstream_ocsp_cache_lock"))?;
    cache.insert(key.to_vec(), cached.clone());
    Ok(cached)
  }

  fn mark_ocsp_fetch_started(&self, key: &[u8]) -> bool {
    self
      .inner
      .ocsp_fetches
      .lock()
      .map(|mut fetches| fetches.insert(key.to_vec()))
      .unwrap_or(false)
  }

  fn finish_ocsp_fetch(&self, key: &[u8], result: anyhow::Result<CachedOcspResponse>) {
    if let Ok(mut fetches) = self.inner.ocsp_fetches.lock() {
      fetches.remove(key);
    }
    match result {
      Ok(cached) => {
        self.inner.metrics.record_outbound_revocation_ocsp_success();
        if let Ok(mut status) = self.inner.status.lock() {
          status.last_ocsp_error_code = None;
          status.ocsp_cache_entries = self
            .inner
            .ocsp_cache
            .lock()
            .map(|cache| cache.len())
            .unwrap_or_default();
          let _ = ocsp::next_refresh_time(cached.this_update, cached.next_update, 10);
        }
      }
      Err(error) => {
        let code = ocsp::classify_ocsp_error(&error);
        self.set_ocsp_error(code);
        self.inner.metrics.record_outbound_revocation_ocsp_error();
      }
    }
  }

  fn handle_ocsp_error(
    &self,
    policy: &OutboundTlsRevocationConfig,
    error: anyhow::Error,
  ) -> anyhow::Result<()> {
    let code = ocsp::classify_ocsp_error(&error);
    self.set_ocsp_error(code);
    self.inner.metrics.record_outbound_revocation_ocsp_error();
    if code == "ocsp_cert_status" {
      bail!("{code}");
    }
    if policy.ocsp.failure_policy == CrliteFailurePolicy::FailClosed {
      bail!("{code}");
    }
    Ok(())
  }

  fn set_ocsp_error(&self, code: &'static str) {
    if let Ok(mut status) = self.inner.status.lock() {
      status.last_ocsp_error_code = Some(code.to_string());
    }
  }

  fn set_crlite_error(&self, code: &'static str) {
    if let Ok(mut status) = self.inner.status.lock() {
      status.last_crlite_error_code = Some(code.to_string());
    }
  }
}

impl fmt::Debug for OutboundRevocationRuntime {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("OutboundRevocationRuntime")
      .field("enabled", &self.inner.enabled)
      .finish_non_exhaustive()
  }
}

#[derive(Debug)]
struct OutboundRevocationVerifier {
  inner: Arc<dyn ServerCertVerifier>,
  runtime: OutboundRevocationRuntime,
  policy: Arc<OutboundTlsRevocationConfig>,
}

impl ServerCertVerifier for OutboundRevocationVerifier {
  fn verify_server_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    ocsp_response: &[u8],
    now: UnixTime,
  ) -> Result<ServerCertVerified, Error> {
    let verified =
      self
        .inner
        .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
    self
      .runtime
      .verify_revocation(&self.policy, end_entity, intermediates, ocsp_response)
      .map_err(revocation_error)?;
    Ok(verified)
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, Error> {
    self.inner.verify_tls12_signature(message, cert, dss)
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, Error> {
    self.inner.verify_tls13_signature(message, cert, dss)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.inner.supported_verify_schemes()
  }

  fn requires_raw_public_keys(&self) -> bool {
    self.inner.requires_raw_public_keys()
  }

  fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
    self.inner.root_hint_subjects()
  }
}

#[derive(Debug)]
struct RevocationError(String);

impl fmt::Display for RevocationError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.0)
  }
}

impl std::error::Error for RevocationError {}

fn revocation_error(error: anyhow::Error) -> Error {
  Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(
    RevocationError(format!("{error:#}")),
  ))))
}

fn certificate_cache_key(der: &[u8]) -> Vec<u8> {
  crate::crypto::sha256(der).to_vec()
}

fn outbound_revocation_enabled(config: &Config) -> bool {
  config.proxy.upstream_revocation.enabled()
    || config
      .upstreams
      .iter()
      .filter_map(|upstream| upstream.tls.upstream_revocation.as_ref())
      .any(OutboundTlsRevocationConfig::enabled)
    || config
      .upstream_pools
      .iter()
      .filter_map(|pool| pool.health_check.tls.upstream_revocation.as_ref())
      .any(OutboundTlsRevocationConfig::enabled)
}

async fn load_managed_crlite_filters(
  config: &Config,
  metrics: &Metrics,
) -> anyhow::Result<(Vec<ManagedCrlitePolicy>, Option<String>)> {
  let mut policies = Vec::new();
  collect_managed_crlite_policy(&mut policies, &config.proxy.upstream_revocation);
  for upstream in &config.upstreams {
    if let Some(policy) = &upstream.tls.upstream_revocation {
      collect_managed_crlite_policy(&mut policies, policy);
    }
  }
  for pool in &config.upstream_pools {
    if let Some(policy) = &pool.health_check.tls.upstream_revocation {
      collect_managed_crlite_policy(&mut policies, policy);
    }
  }
  if policies.is_empty() {
    return Ok((Vec::new(), None));
  }
  let remote_client = crlite_managed::ManagedCrliteRemoteClient::new_webpki_only()
    .context("failed to build outbound managed CRLite HTTP client")?;
  let mut loaded = Vec::new();
  let mut degraded_error = None;
  for policy in policies {
    match crlite_managed::load_or_fetch_filter_for_config(&policy.crlite, &remote_client)
      .await
      .context("failed to load outbound managed CRLite filter")
    {
      Ok(filter) => {
        loaded.push(ManagedCrlitePolicy {
          config: policy.crlite,
          filter: Arc::new(filter),
        });
      }
      Err(error) => {
        let code = crlite::classify_crlite_error(&error);
        if policy.crlite.failure_policy == CrliteFailurePolicy::FailClosed {
          bail!("{code}");
        }
        metrics.record_outbound_revocation_crlite_error();
        degraded_error = Some(code.to_string());
      }
    }
  }
  Ok((loaded, degraded_error))
}

fn collect_managed_crlite_policy(
  policies: &mut Vec<OutboundTlsRevocationConfig>,
  policy: &OutboundTlsRevocationConfig,
) {
  if policy.crlite.mode != CrliteMode::Managed {
    return;
  }
  if !policies
    .iter()
    .any(|existing| existing.crlite == policy.crlite)
  {
    policies.push(policy.clone());
  }
}
