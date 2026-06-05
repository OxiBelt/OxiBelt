use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, anyhow, bail};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE};
use rustls::pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use sha1::Digest;
use url::Url;
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
use x509_cert::ext::pkix::name::GeneralName;
use x509_ocsp::builder::OcspRequestBuilder;
use x509_ocsp::{
  BasicOcspResponse, CertId, CertStatus, OcspResponse, OcspResponseStatus, Request, ResponderId,
  Version,
};

use crate::config::{OcspMode, TlsConfig};
use crate::control_http::{ControlHttpClient, full_body, uri_from_url};
use crate::metrics::Metrics;

mod cert_id;
mod status;
use cert_id::{build_sha1_cert_id, cert_ids_match};
pub use status::OcspRuntimeStatus;
use status::{OcspStatusState, system_time_to_unix};

const OCSP_REQUEST_CONTENT_TYPE: &str = "application/ocsp-request";
const OCSP_RESPONSE_CONTENT_TYPE: &str = "application/ocsp-response";
const ID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";
const ID_PKIX_OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";
const ID_KP_OCSP_SIGNING_DER: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
const FAILURE_RETRY_SECONDS: u64 = 300;

#[derive(Clone)]
pub(crate) struct OcspStapleRuntime {
  inner: Arc<OcspStapleRuntimeInner>,
}

struct OcspStapleRuntimeInner {
  live: Option<Arc<LiveOcspResolver>>,
  status: Arc<Mutex<OcspStatusState>>,
  worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
  server_identity: Option<String>,
}

impl Drop for OcspStapleRuntimeInner {
  fn drop(&mut self) {
    if let Ok(mut worker) = self.worker.lock()
      && let Some(worker) = worker.take()
    {
      worker.abort();
    }
  }
}

impl OcspStapleRuntime {
  pub(crate) async fn new(
    tls: &TlsConfig,
    control_http: &ControlHttpClient,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    match tls.ocsp.mode {
      OcspMode::Disabled => Ok(Self::inactive(OcspStatusState::disabled())),
      OcspMode::StaticFile => Ok(Self::inactive(OcspStatusState::static_file(
        tls.ocsp.response_file.is_some(),
      ))),
      OcspMode::LiveFetch => Self::live_fetch(tls, control_http.clone(), metrics).await,
    }
  }

  fn inactive(status: OcspStatusState) -> Self {
    Self {
      inner: Arc::new(OcspStapleRuntimeInner {
        live: None,
        status: Arc::new(Mutex::new(status)),
        worker: Mutex::new(None),
        server_identity: None,
      }),
    }
  }

  async fn live_fetch(
    tls: &TlsConfig,
    control_http: ControlHttpClient,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    let provider = Arc::new(super::downstream_crypto_provider(tls));
    let mut base_key = super::load_downstream_certified_key(tls, &provider)
      .context("failed to create rustls certified key for OCSP live fetch")?;
    base_key.ocsp = None;
    let server_identity = super::certificate_identity(&base_key.cert);
    let context = Arc::new(LiveOcspContext::new(
      tls,
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
    let worker = tokio::spawn(async move {
      refresh_worker(worker_context, worker_live, worker_status).await;
    });

    Ok(Self {
      inner: Arc::new(OcspStapleRuntimeInner {
        live: Some(live),
        status,
        worker: Mutex::new(Some(worker)),
        server_identity: Some(server_identity),
      }),
    })
  }

  pub(crate) fn live_resolver(&self) -> Option<Arc<dyn rustls::server::ResolvesServerCert>> {
    self
      .inner
      .live
      .as_ref()
      .map(|resolver| resolver.clone() as Arc<dyn rustls::server::ResolvesServerCert>)
  }

  pub(crate) fn server_identity(&self) -> Option<&str> {
    self.inner.server_identity.as_deref()
  }

  pub(crate) fn status(&self) -> OcspRuntimeStatus {
    self
      .inner
      .live
      .as_ref()
      .inspect(|resolver| resolver.drop_stale_if_needed())
      .map(|_| ())
      .unwrap_or(());
    self
      .inner
      .status
      .lock()
      .map(|status| status.to_public())
      .unwrap_or_else(|_| OcspStatusState::live_degraded(Some("status_lock")).to_public())
  }
}

pub(super) fn downstream_cert_resolver(
  tls: &TlsConfig,
  provider: &rustls::crypto::CryptoProvider,
  runtime: Option<&OcspStapleRuntime>,
) -> anyhow::Result<(String, Arc<dyn ResolvesServerCert>)> {
  if let Some(runtime) = runtime
    && let Some(resolver) = runtime.live_resolver()
  {
    return Ok((
      runtime
        .server_identity()
        .ok_or_else(|| anyhow!("OCSP live fetch runtime is missing TLS identity"))?
        .to_string(),
      resolver,
    ));
  }

  let mut certified_key = super::load_downstream_certified_key(tls, provider)
    .context("failed to create rustls certified key")?;
  let server_identity = super::certificate_identity(&certified_key.cert);
  certified_key.ocsp = super::load_ocsp_response(tls)?;
  Ok((
    server_identity,
    Arc::new(rustls::sign::SingleCertAndKey::from(certified_key)),
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
  expected_cert_id: CertId,
  issuer_der: Vec<u8>,
  base_key: Arc<CertifiedKey>,
  control_http: ControlHttpClient,
  metrics: Arc<Metrics>,
  timeout: Duration,
  max_response_bytes: usize,
  clock_skew: Duration,
  refresh_jitter_pct: u8,
}

impl LiveOcspContext {
  fn new(
    tls: &TlsConfig,
    base_key: CertifiedKey,
    control_http: ControlHttpClient,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    let leaf_der = base_key
      .cert
      .first()
      .ok_or_else(|| anyhow!("tls.cert_chain must include a leaf certificate"))?
      .as_ref()
      .to_vec();
    let issuer_der = base_key
      .cert
      .get(1)
      .ok_or_else(|| {
        anyhow!("tls.cert_chain must include an issuer certificate for OCSP live fetch")
      })?
      .as_ref()
      .to_vec();
    let leaf = Certificate::from_der(&leaf_der).context("failed to parse leaf certificate")?;
    let issuer =
      Certificate::from_der(&issuer_der).context("failed to parse issuer certificate")?;
    let expected_cert_id = build_sha1_cert_id(&issuer, &leaf)
      .map_err(|error| anyhow!("failed to build OCSP CertID: {error}"))?;
    let request = Request::new(expected_cert_id.clone());
    let request_der = OcspRequestBuilder::new(Version::V1)
      .with_request(request)
      .build()
      .to_der()
      .context("failed to encode OCSP request")?;
    let responder_url = match tls.ocsp.responder_url.as_deref() {
      Some(raw) => Url::parse(raw).context("invalid tls.ocsp.responder_url")?,
      None => first_ocsp_aia_url(&leaf)?,
    };
    validate_responder_url(&responder_url)?;
    Ok(Self {
      responder_url,
      request_der,
      expected_cert_id,
      issuer_der,
      base_key: Arc::new(base_key),
      control_http,
      metrics,
      timeout: Duration::from_millis(tls.ocsp.request_timeout_ms),
      max_response_bytes: tls.ocsp.max_response_bytes,
      clock_skew: Duration::from_secs(tls.ocsp.clock_skew_seconds),
      refresh_jitter_pct: tls.ocsp.refresh_jitter_pct,
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
  verify_ocsp_response(context, response.body.as_ref())
}

#[derive(Clone)]
struct VerifiedOcspResponse {
  response_der: Vec<u8>,
  this_update: SystemTime,
  next_update: SystemTime,
}

fn verify_ocsp_response(
  context: &LiveOcspContext,
  response_der: &[u8],
) -> anyhow::Result<VerifiedOcspResponse> {
  let outer = OcspResponse::from_der(response_der).context("ocsp_parse")?;
  if outer.response_status != OcspResponseStatus::Successful {
    bail!("ocsp_unsuccessful_status");
  }
  let response_bytes = outer
    .response_bytes
    .ok_or_else(|| anyhow!("ocsp_no_response_bytes"))?;
  if response_bytes.response_type.to_string() != ID_PKIX_OCSP_BASIC {
    bail!("ocsp_unsupported_response_type");
  }
  let basic =
    BasicOcspResponse::from_der(response_bytes.response.as_bytes()).context("ocsp_basic_parse")?;
  verify_ocsp_signature(context, &basic)?;
  let now = SystemTime::now();
  let produced_at = basic.tbs_response_data.produced_at.0.to_system_time();
  if produced_at > now + context.clock_skew {
    bail!("ocsp_produced_at_future");
  }
  if basic.tbs_response_data.responses.len() != 1 {
    bail!("ocsp_response_count");
  }
  let single = &basic.tbs_response_data.responses[0];
  if !cert_ids_match(&single.cert_id, &context.expected_cert_id) {
    bail!("ocsp_cert_id_mismatch");
  }
  if !matches!(single.cert_status, CertStatus::Good(_)) {
    bail!("ocsp_cert_status");
  }
  let this_update = single.this_update.0.to_system_time();
  if this_update > now + context.clock_skew {
    bail!("ocsp_this_update_future");
  }
  let next_update = single
    .next_update
    .as_ref()
    .ok_or_else(|| anyhow!("ocsp_missing_next_update"))?
    .0
    .to_system_time();
  if next_update <= this_update {
    bail!("ocsp_invalid_update_window");
  }
  if next_update <= now {
    bail!("ocsp_stale_response");
  }
  Ok(VerifiedOcspResponse {
    response_der: response_der.to_vec(),
    this_update,
    next_update,
  })
}

fn verify_ocsp_signature(
  context: &LiveOcspContext,
  basic: &BasicOcspResponse,
) -> anyhow::Result<()> {
  let tbs_der = basic
    .tbs_response_data
    .to_der()
    .context("failed to encode OCSP tbsResponseData")?;
  let signature = basic
    .signature
    .as_bytes()
    .ok_or_else(|| anyhow!("ocsp_signature_unused_bits"))?;
  let algorithm_der = basic
    .signature_algorithm
    .to_der()
    .context("failed to encode OCSP signature algorithm")?;

  let issuer = Certificate::from_der(&context.issuer_der).context("failed to parse issuer")?;
  if responder_id_matches_cert(&basic.tbs_response_data.responder_id, &issuer)?
    && verify_signature_with_cert(&context.issuer_der, &algorithm_der, &tbs_der, signature).is_ok()
  {
    return Ok(());
  }

  for responder in basic.certs.as_deref().unwrap_or(&[]) {
    if !responder_id_matches_cert(&basic.tbs_response_data.responder_id, responder)? {
      continue;
    }
    let responder_der = responder
      .to_der()
      .context("failed to encode delegated OCSP responder certificate")?;
    verify_delegated_responder_cert(&responder_der, &context.issuer_der)?;
    verify_signature_with_cert(&responder_der, &algorithm_der, &tbs_der, signature)
      .context("ocsp_signature")?;
    return Ok(());
  }
  bail!("ocsp_unauthorized_responder")
}

fn verify_signature_with_cert(
  cert_der: &[u8],
  algorithm_der: &[u8],
  message: &[u8],
  signature: &[u8],
) -> anyhow::Result<()> {
  let cert_der = CertificateDer::from(cert_der.to_vec());
  let cert = EndEntityCert::try_from(&cert_der).context("failed to parse OCSP signer cert")?;
  for algorithm in supported_signature_algorithms() {
    if algorithm.signature_alg_id().as_ref() != algorithm_der {
      continue;
    }
    cert
      .verify_signature(algorithm, message, signature)
      .context("signature verification failed")?;
    return Ok(());
  }
  bail!("ocsp_unsupported_signature_algorithm")
}

fn verify_delegated_responder_cert(responder_der: &[u8], issuer_der: &[u8]) -> anyhow::Result<()> {
  let responder_der = CertificateDer::from(responder_der.to_vec());
  let responder =
    EndEntityCert::try_from(&responder_der).context("failed to parse delegated OCSP responder")?;
  let issuer = CertificateDer::from(issuer_der.to_vec());
  let anchors = [anchor_from_trusted_cert(&issuer).context("failed to build issuer trust anchor")?];
  let intermediates: [CertificateDer<'_>; 0] = [];
  let supported = supported_signature_algorithms();
  responder
    .verify_for_usage(
      &supported,
      &anchors,
      &intermediates,
      UnixTime::now(),
      KeyUsage::required(ID_KP_OCSP_SIGNING_DER),
      None,
      None,
    )
    .context("ocsp_responder_cert")?;
  Ok(())
}

fn supported_signature_algorithms() -> [&'static dyn SignatureVerificationAlgorithm; 20] {
  [
    webpki::aws_lc_rs::ECDSA_P256_SHA256,
    webpki::aws_lc_rs::ECDSA_P256_SHA384,
    webpki::aws_lc_rs::ECDSA_P256_SHA512,
    webpki::aws_lc_rs::ECDSA_P384_SHA256,
    webpki::aws_lc_rs::ECDSA_P384_SHA384,
    webpki::aws_lc_rs::ECDSA_P384_SHA512,
    webpki::aws_lc_rs::ECDSA_P521_SHA256,
    webpki::aws_lc_rs::ECDSA_P521_SHA384,
    webpki::aws_lc_rs::ECDSA_P521_SHA512,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    webpki::aws_lc_rs::RSA_PKCS1_3072_8192_SHA384,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    webpki::aws_lc_rs::ED25519,
  ]
}

fn responder_id_matches_cert(
  responder_id: &ResponderId,
  cert: &Certificate,
) -> anyhow::Result<bool> {
  match responder_id {
    ResponderId::ByName(name) => Ok(name == &cert.tbs_certificate.subject),
    ResponderId::ByKey(hash) => {
      let actual = sha1::Sha1::digest(
        cert
          .tbs_certificate
          .subject_public_key_info
          .subject_public_key
          .raw_bytes(),
      );
      Ok(hash.as_bytes() == actual.as_slice())
    }
  }
}

fn first_ocsp_aia_url(leaf: &Certificate) -> anyhow::Result<Url> {
  let aia = leaf
    .tbs_certificate
    .get::<AuthorityInfoAccessSyntax>()
    .context("failed to parse authorityInfoAccess")?
    .map(|(_, aia)| aia)
    .ok_or_else(|| anyhow!("tls leaf certificate does not include an OCSP AIA responder"))?;
  for access in aia.0 {
    if access.access_method.to_string() != ID_AD_OCSP {
      continue;
    }
    let GeneralName::UniformResourceIdentifier(uri) = access.access_location else {
      continue;
    };
    let url = Url::parse(uri.as_ref()).context("invalid OCSP AIA responder URL")?;
    validate_responder_url(&url)?;
    return Ok(url);
  }
  bail!("tls leaf certificate does not include an HTTP OCSP AIA responder")
}

fn validate_responder_url(url: &Url) -> anyhow::Result<()> {
  if !matches!(url.scheme(), "http" | "https") {
    bail!("tls.ocsp.responder_url scheme must be http or https");
  }
  if url.host_str().is_none() {
    bail!("tls.ocsp.responder_url must include a host");
  }
  if !url.username().is_empty() || url.password().is_some() {
    bail!("tls.ocsp.responder_url must not include credentials");
  }
  if url.fragment().is_some() {
    bail!("tls.ocsp.responder_url must not include a fragment");
  }
  Ok(())
}

fn next_refresh_time(
  this_update: SystemTime,
  next_update: SystemTime,
  jitter_pct: u8,
) -> SystemTime {
  let lifetime = next_update
    .duration_since(this_update)
    .unwrap_or_else(|_| Duration::from_secs(FAILURE_RETRY_SECONDS));
  let refresh_after = lifetime.mul_f64(0.70);
  let jitter_window = lifetime.mul_f64(f64::from(jitter_pct) / 100.0);
  let jitter = Duration::from_secs(stable_jitter_seconds(&next_update, jitter_window.as_secs()));
  let candidate = this_update + refresh_after + jitter;
  let latest = next_update
    .checked_sub(Duration::from_secs(60))
    .unwrap_or(this_update);
  let refresh = if candidate < latest {
    candidate
  } else {
    latest
  };
  let now = SystemTime::now();
  let soonest = now + Duration::from_secs(1);
  if refresh > soonest || next_update <= soonest {
    refresh
  } else {
    soonest
  }
}

fn stable_jitter_seconds(next_update: &SystemTime, window: u64) -> u64 {
  if window == 0 {
    return 0;
  }
  system_time_to_unix(*next_update) % window.saturating_add(1)
}

fn failure_retry_time(current_next_update: Option<SystemTime>) -> SystemTime {
  let retry = SystemTime::now() + Duration::from_secs(FAILURE_RETRY_SECONDS);
  if let Some(next_update) = current_next_update
    && next_update < retry
  {
    return next_update;
  }
  retry
}

fn classify_ocsp_error(error: &anyhow::Error) -> &'static str {
  let message = format!("{error:#}");
  for code in [
    "ocsp_stale_response",
    "ocsp_missing_next_update",
    "ocsp_invalid_update_window",
    "ocsp_produced_at_future",
    "ocsp_this_update_future",
    "ocsp_cert_status",
    "ocsp_cert_id_mismatch",
    "ocsp_unauthorized_responder",
    "ocsp_unsupported_signature_algorithm",
    "ocsp_signature",
    "ocsp_http_status",
    "ocsp_fetch",
    "ocsp_parse",
  ] {
    if message.contains(code) {
      return code;
    }
  }
  "ocsp_error"
}

fn unix_now() -> u64 {
  system_time_to_unix(SystemTime::now())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::UNIX_EPOCH;

  #[test]
  fn responder_url_policy_rejects_ssrf_prone_shapes() {
    for raw in [
      "ftp://ocsp.example.test/status",
      "https://user:pass@ocsp.example.test/status",
      "https://ocsp.example.test/status#fragment",
    ] {
      let url = Url::parse(raw).expect("test URL should parse");
      assert!(
        validate_responder_url(&url).is_err(),
        "{raw} should be rejected"
      );
    }

    let url = Url::parse("https://ocsp.example.test/status").expect("test URL should parse");
    validate_responder_url(&url).expect("plain HTTPS OCSP URL should be accepted");
  }

  #[test]
  fn next_refresh_time_stays_before_expiry() {
    let this_update = UNIX_EPOCH + Duration::from_secs(1_000);
    let next_update = UNIX_EPOCH + Duration::from_secs(2_000);

    let refresh = next_refresh_time(this_update, next_update, 10);

    assert!(refresh > this_update);
    assert!(refresh < next_update);
  }
}
