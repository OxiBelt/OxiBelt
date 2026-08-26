use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use base64::Engine as _;
use http::header::ACCEPT;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use url::Url;

use super::log_list::{
  CtLogListSnapshot, LOG_LIST_MAX_AGE_SECONDS, parse_and_verify_log_list, parse_version,
};
use super::{CertificateEvaluation, classify_error, evaluate_certificate_chain, policy};
use crate::config::{DownstreamCtLogListMode, DownstreamCtMode, TlsConfig};
use crate::control_http::{ControlHttpClient, empty_body, uri_from_url};
use crate::metrics::Metrics;

const LOG_LIST_URL: &str = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
const LOG_LIST_SIGNATURE_URL: &str = "https://www.gstatic.com/ct/log_list/v3/log_list.sig";
const CACHE_FILE: &str = "ct-log-list-lkg.json";
const CACHE_LOCK_FILE: &str = ".ct-log-list.lock";
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const REFRESH_RETRY_SECONDS: u64 = 300;
const CACHE_FUTURE_SKEW_SECONDS: u64 = 300;

#[derive(Clone)]
pub(crate) struct DownstreamCtRuntime {
  inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
  status: Arc<Mutex<DownstreamCtRuntimeStatus>>,
  gates: Arc<HashMap<String, Arc<AtomicBool>>>,
  certificate_bindings: Arc<HashMap<String, CertificateBinding>>,
  list_stale_at: Arc<AtomicU64>,
  partitions: super::super::certificate_partition::DownstreamCertificatePartitions,
  worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
  metrics: Arc<Metrics>,
}

impl std::fmt::Debug for DownstreamCtRuntime {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("DownstreamCtRuntime")
      .field("status", &self.status())
      .finish_non_exhaustive()
  }
}

impl Drop for RuntimeInner {
  fn drop(&mut self) {
    if let Ok(mut worker) = self.worker.lock()
      && let Some(worker) = worker.take()
    {
      worker.abort();
    }
  }
}

#[derive(Clone, Debug, Serialize)]
pub struct DownstreamCtRuntimeStatus {
  pub enabled: bool,
  pub mode: &'static str,
  pub policy: &'static str,
  pub policy_revision: &'static str,
  pub failure_policy: &'static str,
  pub log_list_mode: &'static str,
  pub log_list_source: &'static str,
  pub log_list_version: Option<String>,
  pub log_list_timestamp: Option<u64>,
  pub log_list_age_seconds: Option<u64>,
  pub cache_present: bool,
  pub cache_persistent: bool,
  pub last_refresh_at: Option<u64>,
  pub next_refresh_at: Option<u64>,
  pub last_error_code: Option<String>,
  pub certificates: Vec<CertificateCtStatus>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CertificateCtStatus {
  pub index: usize,
  pub default: bool,
  pub enabled: bool,
  pub mode: &'static str,
  pub status: &'static str,
  pub compliant: Option<bool>,
  pub embedded_sct_count: usize,
  pub verified_sct_count: usize,
  pub invalid_sct_count: usize,
  pub distinct_log_count: usize,
  pub distinct_operator_count: usize,
  pub required_log_count: usize,
  pub last_checked_at: Option<u64>,
  pub last_error_code: Option<String>,
}

#[derive(Clone)]
struct CertificateContext {
  index: usize,
  default: bool,
  mode: DownstreamCtMode,
  identity: String,
  chain: Vec<rustls::pki_types::CertificateDer<'static>>,
}

#[derive(Clone)]
struct CertificateBinding {
  enforce: bool,
  chain: Vec<rustls::pki_types::CertificateDer<'static>>,
}

struct LoadedList {
  snapshot: CtLogListSnapshot,
  cache_present: bool,
  fetched_at: Option<u64>,
  json: Vec<u8>,
  signature: Vec<u8>,
}

impl DownstreamCtRuntime {
  pub(crate) async fn new(tls: &TlsConfig, metrics: Arc<Metrics>) -> anyhow::Result<Self> {
    let contexts = certificate_contexts(tls)?;
    let partitions = certificate_partitions(tls, &contexts);
    reject_ambiguous_identity_modes(&contexts)?;
    let enabled = contexts
      .iter()
      .any(|context| context.mode != DownstreamCtMode::Disabled);
    metrics.set_downstream_ct_enabled(enabled);
    if !enabled {
      metrics.set_downstream_ct_noncompliant_certificates(0);
      metrics.set_downstream_ct_log_list_age(0);
      return Ok(Self::inactive(tls, partitions, contexts, metrics));
    }

    let now = unix_now();
    let initial_list = load_initial_list(tls, now).await;
    let (list, cache_present, fetched_at, initial_error) = match initial_list {
      Ok(loaded) => (
        Some(loaded.snapshot),
        loaded.cache_present,
        loaded.fetched_at,
        None,
      ),
      Err(error) => {
        if contexts
          .iter()
          .any(|context| context.mode == DownstreamCtMode::Enforce)
        {
          return Err(error).context("failed to initialize enforced downstream CT");
        }
        (None, false, None, Some(classify_error(&error).to_string()))
      }
    };

    let gates = Arc::new(build_gates(&contexts));
    let certificate_bindings = Arc::new(build_certificate_bindings(&contexts));
    let list_stale_at = Arc::new(AtomicU64::new(list.as_ref().map_or(0, |list| {
      list.timestamp.saturating_add(LOG_LIST_MAX_AGE_SECONDS)
    })));
    let status = Arc::new(Mutex::new(evaluate_all(
      tls,
      &contexts,
      &gates,
      list.as_ref(),
      now,
      cache_present,
      fetched_at,
      initial_error,
      &metrics,
      true,
    )?));
    let worker = if tls.ct.log_list.mode == DownstreamCtLogListMode::Managed {
      Some(spawn_refresh_worker(
        tls.clone(),
        contexts,
        gates.clone(),
        list_stale_at.clone(),
        status.clone(),
        metrics.clone(),
        list,
      )?)
    } else {
      None
    };
    Ok(Self {
      inner: Arc::new(RuntimeInner {
        status,
        gates,
        certificate_bindings,
        list_stale_at,
        partitions,
        worker: Mutex::new(worker),
        metrics,
      }),
    })
  }

  fn inactive(
    tls: &TlsConfig,
    partitions: super::super::certificate_partition::DownstreamCertificatePartitions,
    contexts: Vec<CertificateContext>,
    metrics: Arc<Metrics>,
  ) -> Self {
    let status = disabled_status(tls, &contexts);
    Self {
      inner: Arc::new(RuntimeInner {
        status: Arc::new(Mutex::new(status)),
        gates: Arc::new(build_gates(&contexts)),
        certificate_bindings: Arc::new(build_certificate_bindings(&contexts)),
        list_stale_at: Arc::new(AtomicU64::new(u64::MAX)),
        partitions,
        worker: Mutex::new(None),
        metrics,
      }),
    }
  }

  pub(crate) fn wrap_resolver(
    &self,
    resolver: Arc<dyn ResolvesServerCert>,
    fixed_identity: Option<&str>,
  ) -> Arc<dyn ResolvesServerCert> {
    if !self.status().enabled {
      return resolver;
    }
    Arc::new(CtCertResolver {
      inner: resolver,
      gates: self.inner.gates.clone(),
      certificate_bindings: self.inner.certificate_bindings.clone(),
      list_stale_at: self.inner.list_stale_at.clone(),
      partitions: self.inner.partitions.clone(),
      fixed_identity: fixed_identity.map(str::to_string),
      metrics: self.inner.metrics.clone(),
    })
  }

  pub(crate) fn status(&self) -> DownstreamCtRuntimeStatus {
    self
      .inner
      .status
      .lock()
      .map(|status| {
        let mut status = status.clone();
        if let Some(timestamp) = status.log_list_timestamp {
          status.log_list_age_seconds = Some(unix_now().saturating_sub(timestamp));
        }
        status
      })
      .unwrap_or_else(|_| DownstreamCtRuntimeStatus {
        enabled: true,
        mode: "enforce",
        policy: "chrome",
        policy_revision: "chrome-v1",
        failure_policy: "reject_handshake",
        log_list_mode: "managed",
        log_list_source: "chromium_v3",
        log_list_version: None,
        log_list_timestamp: None,
        log_list_age_seconds: None,
        cache_present: false,
        cache_persistent: true,
        last_refresh_at: None,
        next_refresh_at: None,
        last_error_code: Some("ct_status_lock".to_string()),
        certificates: Vec::new(),
      })
  }
}

struct CtCertResolver {
  inner: Arc<dyn ResolvesServerCert>,
  gates: Arc<HashMap<String, Arc<AtomicBool>>>,
  certificate_bindings: Arc<HashMap<String, CertificateBinding>>,
  list_stale_at: Arc<AtomicU64>,
  partitions: super::super::certificate_partition::DownstreamCertificatePartitions,
  fixed_identity: Option<String>,
  metrics: Arc<Metrics>,
}

impl std::fmt::Debug for CtCertResolver {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("CtCertResolver")
      .field("fixed_identity", &self.fixed_identity)
      .finish_non_exhaustive()
  }
}

impl ResolvesServerCert for CtCertResolver {
  fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
    let identity = self
      .fixed_identity
      .as_deref()
      .or_else(|| self.partitions.identity_for_sni(client_hello.server_name()));
    let binding = identity.and_then(|identity| self.certificate_bindings.get(identity));
    if identity
      .and_then(|identity| self.gates.get(identity))
      .is_some_and(|gate| gate.load(Ordering::Acquire))
      || binding.is_some_and(|binding| {
        binding.enforce && unix_now() >= self.list_stale_at.load(Ordering::Acquire)
      })
    {
      self.metrics.record_downstream_ct_handshake_reject();
      return None;
    }
    let resolved = self.inner.resolve(client_hello)?;
    if binding.is_some_and(|binding| {
      binding.enforce && !certificate_chain_matches(&resolved.cert, &binding.chain)
    }) {
      self.metrics.record_downstream_ct_handshake_reject();
      return None;
    }
    Some(resolved)
  }
}

fn certificate_contexts(tls: &TlsConfig) -> anyhow::Result<Vec<CertificateContext>> {
  let mut contexts = Vec::with_capacity(tls.certificates.len() + 1);
  let default_chain = super::super::certificate_io::load_certs(&tls.cert_chain)
    .context("ct_default_cert_chain_read")?;
  contexts.push(CertificateContext {
    index: 0,
    default: true,
    mode: tls.ct.mode,
    identity: super::super::resumption::certificate_identity(&default_chain),
    chain: default_chain,
  });
  for (index, certificate) in tls.certificates.iter().enumerate() {
    let chain = super::super::certificate_io::load_certs(&certificate.cert_chain)
      .with_context(|| format!("ct_certificate_{}_chain_read", index + 1))?;
    contexts.push(CertificateContext {
      index: index + 1,
      default: false,
      mode: tls.ct.effective_mode(&certificate.ct),
      identity: super::super::resumption::certificate_identity(&chain),
      chain,
    });
  }
  Ok(contexts)
}

fn certificate_partitions(
  tls: &TlsConfig,
  contexts: &[CertificateContext],
) -> super::super::certificate_partition::DownstreamCertificatePartitions {
  let mut partitions = Vec::with_capacity(contexts.len());
  for (context, certificate) in contexts.iter().skip(1).zip(&tls.certificates) {
    partitions.push(
      super::super::certificate_partition::DownstreamCertificatePartition {
        identity: context.identity.clone(),
        server_names: super::super::certificate_partition::normalize_server_names(
          &certificate.server_names,
        ),
        is_default: false,
      },
    );
  }
  partitions.insert(
    0,
    super::super::certificate_partition::DownstreamCertificatePartition {
      identity: contexts[0].identity.clone(),
      server_names: super::super::certificate_partition::normalize_server_names(&tls.server_names),
      is_default: true,
    },
  );
  super::super::certificate_partition::DownstreamCertificatePartitions::new(
    partitions,
    tls.require_sni,
    tls.reject_unknown_sni,
  )
}

fn reject_ambiguous_identity_modes(contexts: &[CertificateContext]) -> anyhow::Result<()> {
  let mut modes = HashMap::new();
  for context in contexts {
    if let Some(existing) = modes.insert(context.identity.clone(), context.mode)
      && existing != context.mode
    {
      bail!("tls.ct per-certificate modes must match when certificate identities are reused");
    }
  }
  Ok(())
}

fn build_gates(contexts: &[CertificateContext]) -> HashMap<String, Arc<AtomicBool>> {
  contexts
    .iter()
    .map(|context| (context.identity.clone(), Arc::new(AtomicBool::new(false))))
    .collect()
}

fn build_certificate_bindings(
  contexts: &[CertificateContext],
) -> HashMap<String, CertificateBinding> {
  contexts
    .iter()
    .map(|context| {
      (
        context.identity.clone(),
        CertificateBinding {
          enforce: context.mode == DownstreamCtMode::Enforce,
          chain: context.chain.clone(),
        },
      )
    })
    .collect()
}

fn certificate_chain_matches(
  resolved: &[rustls::pki_types::CertificateDer<'static>],
  evaluated: &[rustls::pki_types::CertificateDer<'static>],
) -> bool {
  resolved.len() == evaluated.len()
    && resolved
      .iter()
      .zip(evaluated)
      .all(|(resolved, evaluated)| resolved.as_ref() == evaluated.as_ref())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_all(
  tls: &TlsConfig,
  contexts: &[CertificateContext],
  gates: &HashMap<String, Arc<AtomicBool>>,
  list: Option<&CtLogListSnapshot>,
  now: u64,
  cache_present: bool,
  fetched_at: Option<u64>,
  list_error: Option<String>,
  metrics: &Metrics,
  initial: bool,
) -> anyhow::Result<DownstreamCtRuntimeStatus> {
  let stale = list.is_some_and(|list| list.is_stale_at(now));
  let mut certificates = Vec::with_capacity(contexts.len());
  let mut noncompliant = 0_u64;
  for context in contexts {
    let gate = gates
      .get(&context.identity)
      .ok_or_else(|| anyhow!("ct_gate_missing"))?;
    let status = if context.mode == DownstreamCtMode::Disabled {
      gate.store(false, Ordering::Release);
      disabled_certificate_status(context)
    } else if list.is_none() || stale {
      let code = if stale {
        "ct_log_list_stale"
      } else {
        "ct_log_list_missing"
      };
      let reject = context.mode == DownstreamCtMode::Enforce;
      gate.store(reject, Ordering::Release);
      noncompliant += 1;
      if initial && reject {
        bail!(code);
      }
      error_certificate_status(context, code, now)
    } else {
      let list = list.ok_or_else(|| anyhow!("ct_log_list_missing"))?;
      match evaluate_certificate_chain(&context.chain, list, now) {
        Ok(evaluation) => {
          metrics.record_downstream_ct_sct_verification(
            evaluation.verified.len() as u64,
            evaluation.invalid_count as u64,
          );
          let result = policy::evaluate(
            tls.ct.policy,
            list,
            &evaluation.verified,
            evaluation.not_before,
            evaluation.not_after,
          );
          metrics.record_downstream_ct_check(result.compliant);
          let reject = context.mode == DownstreamCtMode::Enforce && !result.compliant;
          gate.store(reject, Ordering::Release);
          if !result.compliant {
            noncompliant += 1;
            if initial && reject {
              bail!(result.reason);
            }
          }
          status_from_evaluation(context, evaluation, result, now)
        }
        Err(error) => {
          metrics.record_downstream_ct_error();
          let code = classify_error(&error);
          let reject = context.mode == DownstreamCtMode::Enforce;
          gate.store(reject, Ordering::Release);
          noncompliant += 1;
          if initial && reject {
            return Err(error);
          }
          error_certificate_status(context, code, now)
        }
      }
    };
    certificates.push(status);
  }
  metrics.set_downstream_ct_noncompliant_certificates(noncompliant);
  metrics.set_downstream_ct_log_list_age(list.map_or(0, |list| now.saturating_sub(list.timestamp)));
  Ok(DownstreamCtRuntimeStatus {
    enabled: true,
    mode: tls.ct.mode.as_str(),
    policy: tls.ct.policy.as_str(),
    policy_revision: tls.ct.policy.revision(),
    failure_policy: tls.ct.failure_policy.as_str(),
    log_list_mode: tls.ct.log_list.mode.as_str(),
    log_list_source: "chromium_v3",
    log_list_version: list.map(|list| list.version.clone()),
    log_list_timestamp: list.map(|list| list.timestamp),
    log_list_age_seconds: list.map(|list| now.saturating_sub(list.timestamp)),
    cache_present,
    cache_persistent: tls.ct.log_list.mode == DownstreamCtLogListMode::Managed,
    last_refresh_at: fetched_at,
    next_refresh_at: (tls.ct.log_list.mode == DownstreamCtLogListMode::Managed)
      .then(|| now.saturating_add(tls.ct.log_list.refresh_interval_seconds)),
    last_error_code: list_error.or_else(|| stale.then(|| "ct_log_list_stale".to_string())),
    certificates,
  })
}

fn status_from_evaluation(
  context: &CertificateContext,
  evaluation: CertificateEvaluation,
  result: policy::CtComplianceResult,
  now: u64,
) -> CertificateCtStatus {
  let _identity_binding = evaluation.identity;
  CertificateCtStatus {
    index: context.index,
    default: context.default,
    enabled: true,
    mode: context.mode.as_str(),
    status: if result.compliant {
      "compliant"
    } else {
      "noncompliant"
    },
    compliant: Some(result.compliant),
    embedded_sct_count: evaluation.present_count,
    verified_sct_count: evaluation.verified.len(),
    invalid_sct_count: evaluation.invalid_count,
    distinct_log_count: result.distinct_log_count,
    distinct_operator_count: result.distinct_operator_count,
    required_log_count: result.required_log_count,
    last_checked_at: Some(now),
    last_error_code: (!result.compliant).then(|| result.reason.to_string()),
  }
}

fn error_certificate_status(
  context: &CertificateContext,
  code: &'static str,
  now: u64,
) -> CertificateCtStatus {
  CertificateCtStatus {
    index: context.index,
    default: context.default,
    enabled: true,
    mode: context.mode.as_str(),
    status: "degraded",
    compliant: None,
    embedded_sct_count: 0,
    verified_sct_count: 0,
    invalid_sct_count: 0,
    distinct_log_count: 0,
    distinct_operator_count: 0,
    required_log_count: 0,
    last_checked_at: Some(now),
    last_error_code: Some(code.to_string()),
  }
}

fn disabled_certificate_status(context: &CertificateContext) -> CertificateCtStatus {
  CertificateCtStatus {
    index: context.index,
    default: context.default,
    enabled: false,
    mode: "disabled",
    status: "disabled",
    compliant: None,
    embedded_sct_count: 0,
    verified_sct_count: 0,
    invalid_sct_count: 0,
    distinct_log_count: 0,
    distinct_operator_count: 0,
    required_log_count: 0,
    last_checked_at: None,
    last_error_code: None,
  }
}

fn disabled_status(tls: &TlsConfig, contexts: &[CertificateContext]) -> DownstreamCtRuntimeStatus {
  DownstreamCtRuntimeStatus {
    enabled: false,
    mode: tls.ct.mode.as_str(),
    policy: tls.ct.policy.as_str(),
    policy_revision: tls.ct.policy.revision(),
    failure_policy: tls.ct.failure_policy.as_str(),
    log_list_mode: tls.ct.log_list.mode.as_str(),
    log_list_source: "chromium_v3",
    log_list_version: None,
    log_list_timestamp: None,
    log_list_age_seconds: None,
    cache_present: false,
    cache_persistent: tls.ct.log_list.mode == DownstreamCtLogListMode::Managed,
    last_refresh_at: None,
    next_refresh_at: None,
    last_error_code: None,
    certificates: contexts.iter().map(disabled_certificate_status).collect(),
  }
}

async fn load_initial_list(tls: &TlsConfig, now: u64) -> anyhow::Result<LoadedList> {
  match tls.ct.log_list.mode {
    DownstreamCtLogListMode::StaticFile => load_static_list(tls, now),
    DownstreamCtLogListMode::Managed => {
      let cached = load_cached_list(tls, now).ok();
      match fetch_and_store_list(tls, now, cached.as_ref().map(|loaded| &loaded.snapshot)).await {
        Ok(loaded) => Ok(loaded),
        Err(error) => cached
          .filter(|loaded| !loaded.snapshot.is_stale_at(now))
          .ok_or(error),
      }
    }
  }
}

fn load_static_list(tls: &TlsConfig, now: u64) -> anyhow::Result<LoadedList> {
  let file = tls
    .ct
    .log_list
    .file
    .as_ref()
    .ok_or_else(|| anyhow!("ct_log_list_missing"))?;
  let signature_file = tls
    .ct
    .log_list
    .signature_file
    .as_ref()
    .ok_or_else(|| anyhow!("ct_log_list_missing"))?;
  let json = read_bounded(file, tls.ct.log_list.max_download_bytes, "ct_log_list_read")?;
  let signature = read_bounded(
    signature_file,
    MAX_SIGNATURE_BYTES,
    "ct_log_list_signature_read",
  )?;
  let snapshot = parse_and_verify_log_list(&json, &signature, now)?;
  Ok(LoadedList {
    snapshot,
    cache_present: false,
    fetched_at: None,
    json,
    signature,
  })
}

fn spawn_refresh_worker(
  tls: TlsConfig,
  contexts: Vec<CertificateContext>,
  gates: Arc<HashMap<String, Arc<AtomicBool>>>,
  list_stale_at: Arc<AtomicU64>,
  status: Arc<Mutex<DownstreamCtRuntimeStatus>>,
  metrics: Arc<Metrics>,
  mut current: Option<CtLogListSnapshot>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
  // Build this before spawning so startup reports WebPKI bootstrap failures.
  let client = ControlHttpClient::new_webpki_only()
    .context("failed to build managed CT WebPKI-only client")?;
  Ok(tokio::spawn(async move {
    loop {
      let now = unix_now();
      let until_refresh = status
        .lock()
        .ok()
        .and_then(|status| status.next_refresh_at)
        .unwrap_or_else(|| now.saturating_add(tls.ct.log_list.refresh_interval_seconds))
        .saturating_sub(now);
      let until_stale = current
        .as_ref()
        .map(|list| {
          list
            .timestamp
            .saturating_add(LOG_LIST_MAX_AGE_SECONDS)
            .saturating_sub(now)
        })
        .unwrap_or(until_refresh);
      tokio::time::sleep(Duration::from_secs(until_refresh.min(until_stale).max(1))).await;
      let now = unix_now();
      let refresh = fetch_list(&tls, &client, now).await.and_then(|loaded| {
        if let Some(old) = current.as_ref() {
          reject_rollback(old, &loaded.snapshot)?;
        }
        store_cached_list(&tls, &loaded.snapshot, &loaded.json, &loaded.signature, now)?;
        Ok(loaded)
      });
      let previous = status.lock().ok().map(|status| status.clone());
      let (list_error, cache_present, fetched_at, next_refresh_at) = match refresh {
        Ok(loaded) => {
          current = Some(loaded.snapshot);
          if let Some(list) = current.as_ref() {
            list_stale_at.store(
              list.timestamp.saturating_add(LOG_LIST_MAX_AGE_SECONDS),
              Ordering::Release,
            );
          }
          metrics.record_downstream_ct_log_list_refresh_success();
          (
            None,
            true,
            Some(now),
            now.saturating_add(tls.ct.log_list.refresh_interval_seconds),
          )
        }
        Err(error) => {
          metrics.record_downstream_ct_log_list_refresh_error();
          (
            Some(classify_error(&error).to_string()),
            previous.as_ref().is_some_and(|status| status.cache_present),
            previous.as_ref().and_then(|status| status.last_refresh_at),
            now.saturating_add(REFRESH_RETRY_SECONDS),
          )
        }
      };
      match evaluate_all(
        &tls,
        &contexts,
        &gates,
        current.as_ref(),
        now,
        cache_present,
        fetched_at,
        list_error,
        &metrics,
        false,
      ) {
        Ok(new_status) => {
          if let Ok(mut locked) = status.lock() {
            *locked = new_status;
            locked.next_refresh_at = Some(next_refresh_at);
          }
        }
        Err(error) => {
          metrics.record_downstream_ct_error();
          if let Ok(mut locked) = status.lock() {
            locked.last_error_code = Some(classify_error(&error).to_string());
          }
        }
      }
    }
  }))
}

async fn fetch_and_store_list(
  tls: &TlsConfig,
  now: u64,
  previous: Option<&CtLogListSnapshot>,
) -> anyhow::Result<LoadedList> {
  let client = ControlHttpClient::new_webpki_only()
    .context("failed to build managed CT WebPKI-only client")?;
  let loaded = fetch_list(tls, &client, now).await?;
  if let Some(previous) = previous {
    reject_rollback(previous, &loaded.snapshot)?;
  }
  store_cached_list(tls, &loaded.snapshot, &loaded.json, &loaded.signature, now)?;
  Ok(LoadedList {
    cache_present: true,
    fetched_at: Some(now),
    ..loaded
  })
}

async fn fetch_list(
  tls: &TlsConfig,
  client: &ControlHttpClient,
  now: u64,
) -> anyhow::Result<LoadedList> {
  let timeout = Duration::from_millis(tls.ct.log_list.request_timeout_ms);
  let json = fetch_bytes(
    client,
    LOG_LIST_URL,
    timeout,
    tls.ct.log_list.max_download_bytes,
    "application/json",
  )
  .await?;
  let signature = fetch_bytes(
    client,
    LOG_LIST_SIGNATURE_URL,
    timeout,
    MAX_SIGNATURE_BYTES,
    "application/octet-stream",
  )
  .await?;
  let snapshot = parse_and_verify_log_list(&json, &signature, now)?;
  Ok(LoadedList {
    snapshot,
    cache_present: false,
    fetched_at: None,
    json,
    signature,
  })
}

async fn fetch_bytes(
  client: &ControlHttpClient,
  raw_url: &str,
  timeout: Duration,
  max_body_bytes: usize,
  accept: &str,
) -> anyhow::Result<Vec<u8>> {
  let url = Url::parse(raw_url).context("ct_log_list_url")?;
  if url.scheme() != "https"
    || url.username() != ""
    || url.password().is_some()
    || url.fragment().is_some()
  {
    bail!("ct_log_list_url");
  }
  let request = http::Request::builder()
    .method(http::Method::GET)
    .uri(uri_from_url(&url)?)
    .header(ACCEPT, accept)
    .body(empty_body())
    .context("ct_log_list_request")?;
  let response = client
    .request(request, timeout, max_body_bytes)
    .await
    .context("ct_log_list_fetch")?;
  if response.status != http::StatusCode::OK {
    bail!("ct_log_list_http_status");
  }
  Ok(response.body.to_vec())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheBundle {
  schema: String,
  fetched_at: u64,
  json_base64: String,
  signature_base64: String,
}

fn load_cached_list(tls: &TlsConfig, now: u64) -> anyhow::Result<LoadedList> {
  let path = tls.ct.log_list.cache_dir.join(CACHE_FILE);
  let max = tls
    .ct
    .log_list
    .max_download_bytes
    .saturating_mul(2)
    .saturating_add(65_536);
  let encoded = read_bounded(&path, max, "ct_log_list_cache_read")?;
  let bundle: CacheBundle = serde_json::from_slice(&encoded).context("ct_log_list_cache_parse")?;
  if bundle.schema != "oxibelt.ct-log-list-lkg/v1" {
    bail!("ct_log_list_cache_schema");
  }
  if bundle.fetched_at > now.saturating_add(CACHE_FUTURE_SKEW_SECONDS) {
    bail!("ct_log_list_cache_timestamp");
  }
  let json = decode_cache_base64(&bundle.json_base64, tls.ct.log_list.max_download_bytes)?;
  let signature = decode_cache_base64(&bundle.signature_base64, MAX_SIGNATURE_BYTES)?;
  let snapshot = parse_and_verify_log_list(&json, &signature, now)?;
  Ok(LoadedList {
    snapshot,
    cache_present: true,
    fetched_at: Some(bundle.fetched_at),
    json,
    signature,
  })
}

fn store_cached_list(
  tls: &TlsConfig,
  snapshot: &CtLogListSnapshot,
  json: &[u8],
  signature: &[u8],
  fetched_at: u64,
) -> anyhow::Result<()> {
  let dir = &tls.ct.log_list.cache_dir;
  fs::create_dir_all(dir).context("ct_log_list_cache_create_dir")?;
  let metadata = fs::symlink_metadata(dir).context("ct_log_list_cache_metadata")?;
  if !metadata.is_dir()
    || metadata.file_type().is_symlink()
    || metadata.permissions().mode() & 0o002 != 0
  {
    bail!("ct_log_list_cache_permissions");
  }
  if let Err(error) = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
    let access = nix::unistd::AccessFlags::W_OK | nix::unistd::AccessFlags::X_OK;
    if error.kind() != std::io::ErrorKind::PermissionDenied
      || nix::unistd::eaccess(dir, access).is_err()
    {
      return Err(error).context("ct_log_list_cache_permissions");
    }
  }
  let lock_path = dir.join(CACHE_LOCK_FILE);
  let lock_file = OpenOptions::new()
    .read(true)
    .write(true)
    .create(true)
    .mode(0o600)
    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
    .open(&lock_path)
    .context("ct_log_list_cache_lock_open")?;
  let _lock = nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusive)
    .map_err(|(_, error)| anyhow!("ct_log_list_cache_lock: {error}"))?;
  if let Ok(previous) = load_cached_list(tls, fetched_at) {
    reject_rollback(&previous.snapshot, snapshot)?;
  }
  let bundle = CacheBundle {
    schema: "oxibelt.ct-log-list-lkg/v1".to_string(),
    fetched_at,
    json_base64: base64::engine::general_purpose::STANDARD.encode(json),
    signature_base64: base64::engine::general_purpose::STANDARD.encode(signature),
  };
  let encoded = serde_json::to_vec(&bundle).context("ct_log_list_cache_encode")?;
  let path = dir.join(CACHE_FILE);
  let mut nonce = [0_u8; 16];
  crate::crypto::random_fill(&mut nonce).context("ct_log_list_cache_nonce")?;
  let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
  let temp = dir.join(format!("{CACHE_FILE}.{}.{}.tmp", std::process::id(), nonce));
  let mut file = OpenOptions::new()
    .create_new(true)
    .write(true)
    .mode(0o600)
    .open(&temp)
    .context("ct_log_list_cache_temp_open")?;
  let write_result = (|| {
    file.write_all(&encoded)?;
    file.sync_all()?;
    fs::rename(&temp, &path)?;
    File::open(dir)?.sync_all()?;
    Ok::<(), std::io::Error>(())
  })();
  if write_result.is_err() {
    let _ = fs::remove_file(&temp);
  }
  write_result.context("ct_log_list_cache_write")
}

fn read_bounded(path: &Path, max: usize, code: &'static str) -> anyhow::Result<Vec<u8>> {
  let mut file = File::open(path).with_context(|| code)?;
  let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
  let mut bytes = Vec::with_capacity(max.min(64 * 1024));
  (&mut file)
    .take(limit)
    .read_to_end(&mut bytes)
    .with_context(|| code)?;
  if bytes.len() > max {
    bail!("ct_log_list_too_large");
  }
  Ok(bytes)
}

fn decode_cache_base64(value: &str, max: usize) -> anyhow::Result<Vec<u8>> {
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(value)
    .context("ct_log_list_cache_base64")?;
  if decoded.len() > max || base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
    bail!("ct_log_list_cache_base64");
  }
  Ok(decoded)
}

fn reject_rollback(old: &CtLogListSnapshot, new: &CtLogListSnapshot) -> anyhow::Result<()> {
  if new.timestamp < old.timestamp {
    bail!("ct_log_list_rollback");
  }
  let old_version = parse_version(&old.version)?;
  let new_version = parse_version(&new.version)?;
  if new_version < old_version || (new.timestamp == old.timestamp && new_version != old_version) {
    bail!("ct_log_list_rollback");
  }
  Ok(())
}

fn unix_now() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}

#[cfg(test)]
mod tests;
