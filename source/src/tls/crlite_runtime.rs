use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use serde::Serialize;

use super::crlite::{
  CrliteCheckOutcome, check_crlite, check_crlite_filter_bytes, classify_crlite_error,
  coverage_policy_name, failure_policy_name, unix_now,
};
use crate::config::{CrliteFailurePolicy, CrliteMode, TlsConfig};
use crate::control_http::ControlHttpClient;
use crate::metrics::Metrics;

#[derive(Clone, Debug)]
pub(crate) struct CrliteRuntime {
  inner: Arc<CrliteRuntimeInner>,
}

#[derive(Debug)]
struct CrliteRuntimeInner {
  status: Arc<Mutex<CrliteRuntimeStatus>>,
  reject_handshakes: Arc<AtomicBool>,
  worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for CrliteRuntimeInner {
  fn drop(&mut self) {
    if let Ok(mut worker) = self.worker.lock()
      && let Some(worker) = worker.take()
    {
      worker.abort();
    }
  }
}

#[derive(Clone, Debug, Serialize)]
pub struct CrliteRuntimeStatus {
  pub status: String,
  pub enabled: bool,
  pub filter_present: bool,
  pub filter_loaded: bool,
  pub filter_stale: bool,
  pub last_checked_at: Option<u64>,
  pub last_error_code: Option<String>,
  pub result: Option<String>,
  pub failure_policy: &'static str,
  pub coverage_policy: &'static str,
  pub managed: bool,
  pub storage: Option<String>,
  pub cache_present: bool,
  pub cache_fresh: bool,
  pub last_refresh_at: Option<u64>,
  pub next_refresh_at: Option<u64>,
  pub last_success_at: Option<u64>,
  pub last_error_kind: Option<String>,
}

impl CrliteRuntime {
  pub(crate) async fn new(tls: &TlsConfig, metrics: Arc<Metrics>) -> anyhow::Result<Self> {
    if tls.crlite.mode == CrliteMode::Disabled {
      metrics.set_crlite_enabled(false);
      metrics.set_crlite_filter_stale(false);
      metrics.set_crlite_managed_enabled(false);
      metrics.set_crlite_managed_cache_bytes(0);
      return Ok(Self::inactive(disabled_status(tls)));
    }

    metrics.set_crlite_enabled(true);
    metrics.set_crlite_managed_enabled(tls.crlite.mode == CrliteMode::Managed);
    metrics.record_crlite_check();
    let checked_at = Some(unix_now());
    match tls.crlite.mode {
      CrliteMode::Disabled => unreachable!("disabled CRLite returned above"),
      CrliteMode::Enforce => Self::from_local_filter(tls, metrics, checked_at),
      CrliteMode::Managed => Self::from_managed_filter(tls, metrics, checked_at).await,
    }
  }

  fn inactive(status: CrliteRuntimeStatus) -> Self {
    Self {
      inner: Arc::new(CrliteRuntimeInner {
        status: Arc::new(Mutex::new(status)),
        reject_handshakes: Arc::new(AtomicBool::new(false)),
        worker: Mutex::new(None),
      }),
    }
  }

  fn from_local_filter(
    tls: &TlsConfig,
    metrics: Arc<Metrics>,
    checked_at: Option<u64>,
  ) -> anyhow::Result<Self> {
    metrics.set_crlite_managed_enabled(false);
    let reject_handshakes = Arc::new(AtomicBool::new(false));
    let status = evaluate_crlite_result(
      tls,
      Ok(check_crlite(tls)),
      StatusContext {
        checked_at,
        filter_present: tls.crlite.filter_file.is_some(),
        managed: false,
        storage: None,
        cache_present: false,
        cache_fresh: false,
        last_refresh_at: None,
        next_refresh_at: None,
        last_success_at: None,
      },
      reject_handshakes.clone(),
      metrics,
    )?;
    Ok(Self {
      inner: Arc::new(CrliteRuntimeInner {
        status: Arc::new(Mutex::new(status)),
        reject_handshakes,
        worker: Mutex::new(None),
      }),
    })
  }

  async fn from_managed_filter(
    tls: &TlsConfig,
    metrics: Arc<Metrics>,
    checked_at: Option<u64>,
  ) -> anyhow::Result<Self> {
    let control_http =
      ControlHttpClient::new_webpki_only().context("failed to build managed CRLite HTTP client")?;
    let reject_handshakes = Arc::new(AtomicBool::new(false));
    let loaded = super::crlite_managed::load_or_fetch_filter(tls, &control_http).await;
    record_managed_load_metrics(&loaded, &metrics);
    let status_context = managed_status_context(tls, checked_at, loaded.as_ref().ok());
    let status = evaluate_crlite_result(
      tls,
      loaded.map(|filter| check_crlite_filter_bytes(tls, &filter.bytes, filter.filter_stale)),
      status_context,
      reject_handshakes.clone(),
      metrics.clone(),
    )?;
    let status = Arc::new(Mutex::new(status));
    let worker = spawn_managed_worker(
      tls.clone(),
      control_http,
      metrics,
      status.clone(),
      reject_handshakes.clone(),
    );
    Ok(Self {
      inner: Arc::new(CrliteRuntimeInner {
        status,
        reject_handshakes,
        worker: Mutex::new(Some(worker)),
      }),
    })
  }

  pub(crate) fn wrap_resolver(
    &self,
    resolver: Arc<dyn ResolvesServerCert>,
  ) -> Arc<dyn ResolvesServerCert> {
    if !self.status().enabled {
      return resolver;
    }
    Arc::new(CrliteCertResolver {
      inner: resolver,
      reject_handshakes: self.inner.reject_handshakes.clone(),
    })
  }

  pub(crate) fn status(&self) -> CrliteRuntimeStatus {
    self
      .inner
      .status
      .lock()
      .map(|status| status.clone())
      .unwrap_or_else(|_| CrliteRuntimeStatus {
        status: "degraded".to_string(),
        enabled: true,
        filter_present: false,
        filter_loaded: false,
        filter_stale: false,
        last_checked_at: Some(unix_now()),
        last_error_code: Some("crlite_status_lock".to_string()),
        result: None,
        failure_policy: "fail_closed",
        coverage_policy: "allow_unknown",
        managed: false,
        storage: None,
        cache_present: false,
        cache_fresh: false,
        last_refresh_at: None,
        next_refresh_at: None,
        last_success_at: None,
        last_error_kind: Some("crlite_status_lock".to_string()),
      })
  }
}

struct CrliteCertResolver {
  inner: Arc<dyn ResolvesServerCert>,
  reject_handshakes: Arc<AtomicBool>,
}

impl std::fmt::Debug for CrliteCertResolver {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("CrliteCertResolver")
      .field("reject_handshakes", &self.reject_handshakes)
      .finish_non_exhaustive()
  }
}

impl ResolvesServerCert for CrliteCertResolver {
  fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
    if self.reject_handshakes.load(Ordering::Relaxed) {
      return None;
    }
    self.inner.resolve(client_hello)
  }
}

struct StatusContext {
  checked_at: Option<u64>,
  filter_present: bool,
  managed: bool,
  storage: Option<String>,
  cache_present: bool,
  cache_fresh: bool,
  last_refresh_at: Option<u64>,
  next_refresh_at: Option<u64>,
  last_success_at: Option<u64>,
}

fn evaluate_crlite_result(
  tls: &TlsConfig,
  result: anyhow::Result<anyhow::Result<CrliteCheckOutcome>>,
  context: StatusContext,
  reject_handshakes: Arc<AtomicBool>,
  metrics: Arc<Metrics>,
) -> anyhow::Result<CrliteRuntimeStatus> {
  match result {
    Ok(Ok(outcome)) => {
      metrics.set_crlite_filter_stale(outcome.filter_stale);
      if outcome.certificate_rejected {
        reject_handshakes.store(true, Ordering::Relaxed);
        if outcome.result == Some("revoked") {
          metrics.record_crlite_revoked();
          bail!("crlite_revoked_certificate");
        }
        metrics.record_crlite_error();
        bail!(
          "{}",
          outcome.error_code.unwrap_or("crlite_certificate_rejected")
        );
      }
      if let Some(error_code) = outcome.error_code {
        metrics.record_crlite_error();
        if tls.crlite.failure_policy == CrliteFailurePolicy::FailClosed {
          bail!("{error_code}");
        }
      }
      Ok(status_from_outcome(tls, outcome, context))
    }
    Ok(Err(error)) | Err(error) => {
      metrics.record_crlite_error();
      metrics.set_crlite_filter_stale(false);
      let error_code = classify_crlite_error(&error);
      if tls.crlite.failure_policy == CrliteFailurePolicy::FailClosed {
        bail!("{error_code}");
      }
      Ok(degraded_status(tls, error_code, context))
    }
  }
}

fn disabled_status(tls: &TlsConfig) -> CrliteRuntimeStatus {
  CrliteRuntimeStatus {
    status: "disabled".to_string(),
    enabled: false,
    filter_present: false,
    filter_loaded: false,
    filter_stale: false,
    last_checked_at: None,
    last_error_code: None,
    result: None,
    failure_policy: failure_policy_name(tls.crlite.failure_policy),
    coverage_policy: coverage_policy_name(tls.crlite.coverage_policy),
    managed: false,
    storage: None,
    cache_present: false,
    cache_fresh: false,
    last_refresh_at: None,
    next_refresh_at: None,
    last_success_at: None,
    last_error_kind: None,
  }
}

fn status_from_outcome(
  tls: &TlsConfig,
  outcome: CrliteCheckOutcome,
  context: StatusContext,
) -> CrliteRuntimeStatus {
  CrliteRuntimeStatus {
    status: outcome.status.to_string(),
    enabled: true,
    filter_present: context.filter_present,
    filter_loaded: outcome.filter_loaded,
    filter_stale: outcome.filter_stale,
    last_checked_at: context.checked_at,
    last_error_code: outcome.error_code.map(str::to_string),
    result: outcome.result.map(str::to_string),
    failure_policy: failure_policy_name(tls.crlite.failure_policy),
    coverage_policy: coverage_policy_name(tls.crlite.coverage_policy),
    managed: context.managed,
    storage: context.storage,
    cache_present: context.cache_present,
    cache_fresh: context.cache_fresh,
    last_refresh_at: context.last_refresh_at,
    next_refresh_at: context.next_refresh_at,
    last_success_at: context.last_success_at,
    last_error_kind: outcome.error_code.map(str::to_string),
  }
}

fn degraded_status(
  tls: &TlsConfig,
  error_code: &'static str,
  context: StatusContext,
) -> CrliteRuntimeStatus {
  CrliteRuntimeStatus {
    status: "degraded".to_string(),
    enabled: true,
    filter_present: context.filter_present,
    filter_loaded: false,
    filter_stale: false,
    last_checked_at: context.checked_at,
    last_error_code: Some(error_code.to_string()),
    result: None,
    failure_policy: failure_policy_name(tls.crlite.failure_policy),
    coverage_policy: coverage_policy_name(tls.crlite.coverage_policy),
    managed: context.managed,
    storage: context.storage,
    cache_present: context.cache_present,
    cache_fresh: context.cache_fresh,
    last_refresh_at: context.last_refresh_at,
    next_refresh_at: context.next_refresh_at,
    last_success_at: context.last_success_at,
    last_error_kind: Some(error_code.to_string()),
  }
}

fn managed_status_context(
  tls: &TlsConfig,
  checked_at: Option<u64>,
  filter: Option<&super::crlite_managed::ManagedFilter>,
) -> StatusContext {
  StatusContext {
    checked_at,
    filter_present: filter.is_some(),
    managed: true,
    storage: Some(super::crlite_managed::storage_name(tls.crlite.managed.storage).to_string()),
    cache_present: filter.is_some_and(|filter| filter.cache_present),
    cache_fresh: filter.is_some_and(|filter| filter.cache_fresh),
    last_refresh_at: checked_at,
    next_refresh_at: checked_at
      .map(|now| now.saturating_add(tls.crlite.managed.refresh_interval_seconds)),
    last_success_at: filter.and_then(|filter| filter.last_success_at),
  }
}

fn record_managed_load_metrics(
  loaded: &anyhow::Result<super::crlite_managed::ManagedFilter>,
  metrics: &Metrics,
) {
  match loaded {
    Ok(filter) => {
      metrics.record_crlite_managed_refresh_success();
      metrics.set_crlite_managed_cache_bytes(filter.bytes.len() as u64);
      if let Some(success_at) = filter.last_success_at {
        metrics.set_crlite_managed_last_success_timestamp(success_at);
      }
    }
    Err(_) => {
      metrics.record_crlite_managed_refresh_error();
      metrics.set_crlite_managed_cache_bytes(0);
    }
  }
}

fn spawn_managed_worker(
  tls: TlsConfig,
  control_http: ControlHttpClient,
  metrics: Arc<Metrics>,
  status: Arc<Mutex<CrliteRuntimeStatus>>,
  reject_handshakes: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
  tokio::spawn(async move {
    loop {
      tokio::time::sleep(Duration::from_secs(
        tls.crlite.managed.refresh_interval_seconds,
      ))
      .await;
      refresh_managed_once(
        &tls,
        &control_http,
        metrics.clone(),
        status.clone(),
        reject_handshakes.clone(),
      )
      .await;
    }
  })
}

async fn refresh_managed_once(
  tls: &TlsConfig,
  control_http: &ControlHttpClient,
  metrics: Arc<Metrics>,
  status: Arc<Mutex<CrliteRuntimeStatus>>,
  reject_handshakes: Arc<AtomicBool>,
) {
  metrics.record_crlite_check();
  let checked_at = Some(unix_now());
  let loaded = super::crlite_managed::fetch_and_store_filter(tls, control_http).await;
  record_managed_load_metrics(&loaded, &metrics);
  let context = managed_status_context(tls, checked_at, loaded.as_ref().ok());
  let evaluated = evaluate_crlite_refresh_result(
    tls,
    loaded.map(|filter| check_crlite_filter_bytes(tls, &filter.bytes, filter.filter_stale)),
    context,
    reject_handshakes,
    metrics,
  );
  if let Ok(new_status) = evaluated
    && let Ok(mut current) = status.lock()
  {
    *current = new_status;
  }
}

fn evaluate_crlite_refresh_result(
  tls: &TlsConfig,
  result: anyhow::Result<anyhow::Result<CrliteCheckOutcome>>,
  context: StatusContext,
  reject_handshakes: Arc<AtomicBool>,
  metrics: Arc<Metrics>,
) -> anyhow::Result<CrliteRuntimeStatus> {
  match result {
    Ok(Ok(outcome)) => {
      metrics.set_crlite_filter_stale(outcome.filter_stale);
      if outcome.certificate_rejected {
        reject_handshakes.store(true, Ordering::Relaxed);
        if outcome.result == Some("revoked") {
          metrics.record_crlite_revoked();
        } else {
          metrics.record_crlite_error();
        }
      } else {
        reject_handshakes.store(false, Ordering::Relaxed);
      }
      if outcome.error_code.is_some() && !outcome.certificate_rejected {
        metrics.record_crlite_error();
      }
      Ok(status_from_outcome(tls, outcome, context))
    }
    Ok(Err(error)) | Err(error) => {
      metrics.record_crlite_error();
      let error_code = classify_crlite_error(&error);
      Ok(degraded_status(tls, error_code, context))
    }
  }
}
