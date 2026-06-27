//! Runtime store for dynamic policy records and signatures.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use http::{HeaderMap, Method, StatusCode};
use sqlx::{Pool, Postgres, Row};
use tracing::{info, warn};

use crate::config::{Config, DynamicPolicyConfig, DynamicPolicyFailPolicy};
use crate::identity::Cidr;
use crate::limits::LimitState;
use crate::limits::sybil_identity::{self, SybilIdentityContext};
use crate::metrics::Metrics;

pub mod admin;
pub mod signature;
pub mod store;
pub use admin::*;
mod action;
mod person_proof_scope;
mod subject;
mod sybil;
use action::DynamicPolicyAction;
use subject::{DynamicPolicySubjectType, parse_subject_type, validate_subject};
use sybil::sybil_spec;

pub const MAX_DYNAMIC_POLICY_NAME_BYTES: usize = 128;
pub const MAX_DYNAMIC_POLICY_SUBJECT_BYTES: usize = 512;
pub const MAX_DYNAMIC_POLICY_ROUTE_BYTES: usize = 128;
pub const MAX_DYNAMIC_POLICY_PATH_BYTES: usize = 1024;
pub const MAX_DYNAMIC_POLICY_RATE_BYTES: usize = 32;
pub const MAX_DYNAMIC_POLICY_REASON_BYTES: usize = 512;
pub const MAX_DYNAMIC_POLICY_BODY_BYTES: usize = 8192;

#[derive(Clone)]
pub struct DynamicPolicyRuntime {
  inner: Option<Arc<DynamicPolicyInner>>,
}

struct DynamicPolicyInner {
  config: DynamicPolicyConfig,
  namespace: Arc<str>,
  route_names: Arc<HashSet<String>>,
  pool: Pool<Postgres>,
  snapshot: RwLock<Arc<DynamicPolicySnapshot>>,
  metrics: Arc<Metrics>,
  signature_key: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct DynamicPolicySnapshot {
  generation: i64,
  fingerprint: u64,
  policies: Arc<[DynamicPolicy]>,
}

#[derive(Debug, Clone)]
struct DynamicPolicy {
  id: i64,
  priority: i32,
  name: String,
  source: String,
  action: DynamicPolicyAction,
  subject_type: DynamicPolicySubjectType,
  subject: String,
  cidr: Option<Cidr>,
  route_name: Option<String>,
  method: Option<Method>,
  path_prefix: Option<String>,
  rate: Option<String>,
  burst: Option<u32>,
  status: StatusCode,
  body: String,
  reason: Option<String>,
  code: Option<String>,
  mode: DynamicPolicyMode,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DynamicPolicyMode {
  Enforce,
  DryRun,
}

impl DynamicPolicyMode {
  fn as_str(self) -> &'static str {
    match self {
      Self::Enforce => "enforce",
      Self::DryRun => "dry_run",
    }
  }
}

#[derive(Debug, Clone, Default)]
pub struct DynamicPolicyContext {
  pub matched: bool,
  pub action: Option<String>,
  pub name: Option<String>,
  pub reason: Option<String>,
  pub code: Option<String>,
  pub mode: Option<String>,
  pub source: Option<String>,
}

#[derive(Debug, Clone)]
pub enum DynamicPolicyTerminal {
  Text { status: StatusCode, body: String },
  Challenge { status: StatusCode },
  SilentClose,
}

#[derive(Debug, Clone, Default)]
pub struct DynamicPolicyOutcome {
  pub context: DynamicPolicyContext,
  pub terminal: Option<DynamicPolicyTerminal>,
}

pub struct DynamicPolicyRequest<'a> {
  pub client_ip: IpAddr,
  pub route_name: &'a str,
  pub method: &'a Method,
  pub path: &'a str,
  pub headers: Option<&'a HeaderMap>,
  pub tls_fingerprint: Option<&'a str>,
  pub client_asn: Option<u32>,
  pub tcp_max_hop: Option<u8>,
  pub person_proof_clearance_hash: Option<&'a str>,
}

#[derive(Debug, Clone)]
struct PolicyRow {
  id: i64,
  enabled: bool,
  priority: i32,
  name: String,
  source: String,
  action: String,
  subject_type: String,
  subject: String,
  route_name: Option<String>,
  method: Option<String>,
  path_prefix: Option<String>,
  rate: Option<String>,
  burst: Option<i32>,
  status: Option<i32>,
  body: Option<String>,
  reason: Option<String>,
  code: Option<String>,
  mode: String,
  writer_identity: Option<String>,
  signature_version: Option<String>,
  row_signature: Option<String>,
  expires_at: Option<String>,
}

impl DynamicPolicyRuntime {
  pub async fn new(config: &Config, metrics: Arc<Metrics>) -> anyhow::Result<Self> {
    if !config.dynamic_policy.enabled {
      return Ok(Self::disabled());
    }

    let Some(backend_name) = config.dynamic_policy_backend_name() else {
      bail!("dynamic_policy backend is not configured");
    };
    let backend = config
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == backend_name)
      .ok_or_else(|| anyhow!("dynamic_policy backend {backend_name} was not found"))?;
    let namespace = Arc::from(config.shared_state.namespace.as_str());
    let signature_key = if config.dynamic_policy.automation_api.enabled {
      Some(signature::load_key(
        &config.dynamic_policy.automation_api.signature_key_env,
      )?)
    } else {
      None
    };
    let route_names = Arc::new(
      config
        .routes
        .iter()
        .map(|route| route.name.clone())
        .collect::<HashSet<_>>(),
    );

    let pool = match store::connect_postgres_pool(backend).await {
      Ok(pool) => pool,
      Err(error)
        if config.dynamic_policy.fail_policy == DynamicPolicyFailPolicy::DisabledOnError =>
      {
        warn!(error = %error, "dynamic policy PostgreSQL connection failed; starting with dynamic policy disabled");
        metrics.record_dynamic_policy_refresh_error();
        metrics.set_dynamic_policy_active_policies(0);
        return Ok(Self::disabled());
      }
      Err(error) => {
        return Err(error).context("failed to connect dynamic policy PostgreSQL backend");
      }
    };
    store::init_postgres(&pool)
      .await
      .context("failed to initialize dynamic policy PostgreSQL tables")?;

    let snapshot = match load_snapshot(
      &pool,
      &config.dynamic_policy,
      &namespace,
      &route_names,
      signature_key.as_ref(),
    )
    .await
    {
      Ok(snapshot) => snapshot,
      Err(error)
        if config.dynamic_policy.fail_policy == DynamicPolicyFailPolicy::DisabledOnError =>
      {
        warn!(error = %error, "dynamic policy startup load failed; starting with empty snapshot");
        metrics.record_dynamic_policy_refresh_error();
        DynamicPolicySnapshot::empty()
      }
      Err(error) => return Err(error).context("failed to load initial dynamic policy snapshot"),
    };
    metrics.set_dynamic_policy_active_policies(snapshot.policies.len() as u64);

    let inner = Arc::new(DynamicPolicyInner {
      config: config.dynamic_policy.clone(),
      namespace,
      route_names,
      pool,
      snapshot: RwLock::new(Arc::new(snapshot)),
      metrics,
      signature_key,
    });
    spawn_refresh_task(&inner);
    Ok(Self { inner: Some(inner) })
  }

  pub fn disabled() -> Self {
    Self { inner: None }
  }

  pub fn context(&self) -> DynamicPolicyContext {
    DynamicPolicyContext::default()
  }

  pub fn enabled(&self) -> bool {
    self.inner.is_some()
  }

  pub fn needs_person_proof_clearance_for_request(
    &self,
    request: DynamicPolicyRequest<'_>,
  ) -> bool {
    self.inner.as_ref().is_some_and(|inner| {
      inner
        .snapshot()
        .needs_person_proof_clearance_for_request(&inner.config, request)
    })
  }

  pub fn evaluate(
    &self,
    request: DynamicPolicyRequest<'_>,
    limits: &LimitState,
  ) -> DynamicPolicyOutcome {
    let Some(inner) = &self.inner else {
      return DynamicPolicyOutcome::default();
    };
    let snapshot = inner.snapshot();
    evaluate_snapshot(
      &inner.config,
      inner.metrics.as_ref(),
      snapshot.as_ref(),
      request,
      limits,
    )
  }
}

fn evaluate_snapshot(
  config: &DynamicPolicyConfig,
  metrics: &Metrics,
  snapshot: &DynamicPolicySnapshot,
  request: DynamicPolicyRequest<'_>,
  limits: &LimitState,
) -> DynamicPolicyOutcome {
  let request_path = if config.matching.normalize_path {
    crate::waf::normalization::normalize_path(request.path)
  } else {
    request.path.to_string()
  };

  let mut dry_run_context = None;
  let mut selected = None;
  for policy in snapshot.policies.iter() {
    if !policy.matches(config, &request, &request_path) {
      continue;
    }
    metrics.record_dynamic_policy_match();
    if policy.mode == DynamicPolicyMode::DryRun {
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = policy.action.as_str(),
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy dry-run matched request"
      );
      dry_run_context.get_or_insert_with(|| policy.context());
      continue;
    }
    if selected.is_none_or(|current| policy.precedes(current)) {
      selected = Some(policy);
    }
  }

  let Some(policy) = selected else {
    return dry_run_context
      .map(|context| DynamicPolicyOutcome {
        context,
        terminal: None,
      })
      .unwrap_or_default();
  };
  let context = policy.context();
  match policy.action {
    DynamicPolicyAction::Allow => {
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = "allow",
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy allowed request"
      );
      DynamicPolicyOutcome {
        context,
        terminal: None,
      }
    }
    DynamicPolicyAction::Challenge => {
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = "challenge",
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy challenged request"
      );
      DynamicPolicyOutcome {
        context,
        terminal: Some(DynamicPolicyTerminal::Challenge {
          status: policy.status,
        }),
      }
    }
    DynamicPolicyAction::Reject => {
      metrics.record_dynamic_policy_reject();
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = "reject",
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy rejected request"
      );
      DynamicPolicyOutcome {
        context,
        terminal: Some(DynamicPolicyTerminal::Text {
          status: policy.status,
          body: policy.body.clone(),
        }),
      }
    }
    DynamicPolicyAction::SilentClose => {
      metrics.record_dynamic_policy_reject();
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = "silent_close",
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy silently closed request"
      );
      DynamicPolicyOutcome {
        context,
        terminal: Some(DynamicPolicyTerminal::SilentClose),
      }
    }
    DynamicPolicyAction::RateLimit => {
      let bucket = policy.bucket_name(request.route_name);
      let status = limits.check_direct_rate_limit(
        &bucket,
        policy.rate.as_deref().unwrap_or("1r/s"),
        policy.burst.unwrap_or(1),
        policy.status.as_u16(),
      );
      if let Some(status) = status {
        metrics.record_dynamic_policy_rate_limit_denied();
        info!(
          policy_id = policy.id,
          policy_name = %policy.name,
          action = "rate_limit",
          route = request.route_name,
          client_ip = %request.client_ip,
          "dynamic policy rate limit denied request"
        );
        return DynamicPolicyOutcome {
          context,
          terminal: Some(DynamicPolicyTerminal::Text {
            status,
            body: policy.body.clone(),
          }),
        };
      }
      DynamicPolicyOutcome {
        context,
        terminal: None,
      }
    }
  }
}

impl DynamicPolicyInner {
  fn snapshot(&self) -> Arc<DynamicPolicySnapshot> {
    self
      .snapshot
      .read()
      .expect("dynamic policy snapshot lock poisoned")
      .clone()
  }

  fn replace_snapshot(&self, snapshot: DynamicPolicySnapshot) {
    self
      .metrics
      .set_dynamic_policy_active_policies(snapshot.policies.len() as u64);
    *self
      .snapshot
      .write()
      .expect("dynamic policy snapshot lock poisoned") = Arc::new(snapshot);
  }
}

impl DynamicPolicySnapshot {
  fn empty() -> Self {
    Self {
      generation: 0,
      fingerprint: 0,
      policies: Arc::from([]),
    }
  }
}

impl DynamicPolicy {
  fn matches(
    &self,
    config: &DynamicPolicyConfig,
    request: &DynamicPolicyRequest<'_>,
    request_path: &str,
  ) -> bool {
    if !self.matches_request_scope(config, request, request_path) {
      return false;
    }

    match self.subject_type {
      DynamicPolicySubjectType::Ip => self.subject == request.client_ip.to_string(),
      DynamicPolicySubjectType::IpCidr => self
        .cidr
        .as_ref()
        .is_some_and(|cidr| cidr.contains(request.client_ip)),
      DynamicPolicySubjectType::IpPrefix => self
        .cidr
        .as_ref()
        .is_some_and(|cidr| cidr.contains(request.client_ip)),
      DynamicPolicySubjectType::IpRoute => {
        self.subject == format!("{}|{}", request.client_ip, request.route_name)
      }
      DynamicPolicySubjectType::IpPrefixRoute => {
        let Some(cidr) = self.cidr.as_ref() else {
          return false;
        };
        cidr.contains(request.client_ip)
          && self.subject == format!("{}|{}", cidr.canonical(), request.route_name)
      }
      DynamicPolicySubjectType::IpPath => self
        .path_prefix
        .as_deref()
        .is_some_and(|path| self.subject == format!("{}|{path}", request.client_ip)),
      DynamicPolicySubjectType::TlsFingerprint => {
        sybil_identity::tls_fingerprint_identity(self.sybil_context(request))
          .is_some_and(|identity| self.subject == identity)
      }
      DynamicPolicySubjectType::TlsFingerprintRoute => {
        sybil_identity::tls_fingerprint_identity(self.sybil_context(request))
          .is_some_and(|identity| self.subject == format!("{identity}|{}", request.route_name))
      }
      DynamicPolicySubjectType::TokenBindingHash => {
        sybil_identity::token_binding_hash_identity(self.sybil_context(request), sybil_spec(config))
          .is_some_and(|identity| self.subject == identity)
      }
      DynamicPolicySubjectType::PersonProofClearance => {
        sybil_identity::person_proof_clearance_identity(self.sybil_context(request))
          .is_some_and(|identity| self.subject == identity)
      }
      DynamicPolicySubjectType::Asn => sybil_identity::asn_identity(self.sybil_context(request))
        .is_some_and(|identity| self.subject == identity),
      DynamicPolicySubjectType::AsnRoute => {
        sybil_identity::asn_identity(self.sybil_context(request))
          .is_some_and(|identity| self.subject == format!("{identity}|{}", request.route_name))
      }
      DynamicPolicySubjectType::CompositeClient => {
        sybil_identity::composite_client_identity(self.sybil_context(request), sybil_spec(config))
          .is_some_and(|identity| self.subject == identity)
      }
    }
  }

  fn sybil_context<'a>(&self, request: &'a DynamicPolicyRequest<'a>) -> SybilIdentityContext<'a> {
    SybilIdentityContext {
      ip: request.client_ip,
      route_name: Some(request.route_name),
      headers: request.headers,
      tls_fingerprint: request.tls_fingerprint,
      client_asn: request.client_asn,
      tcp_max_hop: request.tcp_max_hop,
      person_proof_clearance_hash: request.person_proof_clearance_hash,
    }
  }

  fn bucket_name(&self, route_name: &str) -> String {
    let route = self.route_name.as_deref().unwrap_or(route_name);
    let path = self.path_prefix.as_deref().unwrap_or("-");
    format!(
      "dynamic:{}:{}:{}:{}:{}",
      self.id,
      self.subject_type.as_str(),
      self.subject,
      route,
      path
    )
  }

  fn context(&self) -> DynamicPolicyContext {
    DynamicPolicyContext {
      matched: true,
      action: Some(self.action.as_str().to_string()),
      name: Some(self.name.clone()),
      reason: self.reason.clone(),
      code: self.code.clone(),
      mode: Some(self.mode.as_str().to_string()),
      source: Some(self.source.clone()),
    }
  }

  fn precedes(&self, other: &Self) -> bool {
    self.precedence_key() < other.precedence_key()
  }

  fn precedence_key(&self) -> (u8, usize, u16, i32, i64) {
    (
      if self.route_name.is_some() { 0 } else { 1 },
      usize::MAX - self.path_prefix.as_deref().map(str::len).unwrap_or(0),
      u16::MAX - self.ip_specificity(),
      self.priority,
      self.id,
    )
  }

  fn ip_specificity(&self) -> u16 {
    match self.subject_type {
      DynamicPolicySubjectType::Ip
      | DynamicPolicySubjectType::IpRoute
      | DynamicPolicySubjectType::IpPath
      | DynamicPolicySubjectType::TlsFingerprint
      | DynamicPolicySubjectType::TlsFingerprintRoute
      | DynamicPolicySubjectType::TokenBindingHash
      | DynamicPolicySubjectType::PersonProofClearance
      | DynamicPolicySubjectType::CompositeClient => 1_000,
      DynamicPolicySubjectType::IpCidr
      | DynamicPolicySubjectType::IpPrefix
      | DynamicPolicySubjectType::IpPrefixRoute => self
        .cidr
        .as_ref()
        .map(|cidr| u16::from(cidr.prefix()))
        .unwrap_or(0),
      DynamicPolicySubjectType::Asn | DynamicPolicySubjectType::AsnRoute => 900,
    }
  }
}

fn spawn_refresh_task(inner: &Arc<DynamicPolicyInner>) {
  let weak = Arc::downgrade(inner);
  let interval = Duration::from_millis(inner.config.refresh_interval_ms);
  tokio::spawn(async move {
    refresh_loop(weak, interval).await;
  });
}

async fn refresh_loop(inner: Weak<DynamicPolicyInner>, interval: Duration) {
  loop {
    tokio::time::sleep(interval).await;
    let Some(inner) = inner.upgrade() else {
      break;
    };
    match load_snapshot(
      &inner.pool,
      &inner.config,
      &inner.namespace,
      &inner.route_names,
      inner.signature_key.as_ref(),
    )
    .await
    {
      Ok(snapshot) => {
        let current = inner.snapshot();
        if snapshot.generation != current.generation || snapshot.fingerprint != current.fingerprint
        {
          inner.replace_snapshot(snapshot);
          inner.metrics.record_dynamic_policy_refresh_success();
          info!("dynamic policy snapshot refreshed");
        }
      }
      Err(error) => {
        warn!(error = %error, "failed to refresh dynamic policy snapshot");
        inner.metrics.record_dynamic_policy_refresh_error();
        if inner.config.fail_policy == DynamicPolicyFailPolicy::DisabledOnError {
          inner.replace_snapshot(DynamicPolicySnapshot::empty());
        }
      }
    }
  }
}

async fn load_snapshot(
  pool: &Pool<Postgres>,
  config: &DynamicPolicyConfig,
  namespace: &str,
  route_names: &HashSet<String>,
  signature_key: Option<&[u8; 32]>,
) -> anyhow::Result<DynamicPolicySnapshot> {
  let generation = load_generation(pool, namespace).await?;
  let limit = i64::try_from(config.max_policies.saturating_add(1))
    .context("dynamic_policy.max_policies does not fit in i64")?;
  let rows = sqlx::query(
    "SELECT id, enabled, priority, name, source, action, subject_type, subject, route_name, method,
            path_prefix, rate, burst, status, body, reason, code, mode, writer_identity,
            signature_version, row_signature, expires_at::text AS expires_at
       FROM oxibelt_dynamic_policies
      WHERE namespace = $1
        AND enabled = true
        AND (expires_at IS NULL OR expires_at > now())
      ORDER BY priority ASC, id ASC
      LIMIT $2",
  )
  .bind(namespace)
  .bind(limit)
  .fetch_all(pool)
  .await?;
  if rows.len() > config.max_policies {
    bail!(
      "dynamic policy active policy count exceeds max_policies ({})",
      config.max_policies
    );
  }

  let mut hasher = std::collections::hash_map::DefaultHasher::new();
  generation.hash(&mut hasher);
  let mut policies = Vec::with_capacity(rows.len());
  for row in rows {
    let row = policy_row_from_pg(&row)?;
    hash_policy_row(&row, &mut hasher);
    policies.push(validate_policy_row(
      row,
      config,
      namespace,
      route_names,
      signature_key,
    )?);
  }

  Ok(DynamicPolicySnapshot {
    generation,
    fingerprint: hasher.finish(),
    policies: Arc::from(policies),
  })
}

fn hash_policy_row(row: &PolicyRow, hasher: &mut impl Hasher) {
  row.id.hash(hasher);
  row.enabled.hash(hasher);
  row.priority.hash(hasher);
  row.name.hash(hasher);
  row.source.hash(hasher);
  row.action.hash(hasher);
  row.subject_type.hash(hasher);
  row.subject.hash(hasher);
  row.route_name.hash(hasher);
  row.method.hash(hasher);
  row.path_prefix.hash(hasher);
  row.rate.hash(hasher);
  row.burst.hash(hasher);
  row.status.hash(hasher);
  row.body.hash(hasher);
  row.reason.hash(hasher);
  row.code.hash(hasher);
  row.mode.hash(hasher);
  row.writer_identity.hash(hasher);
  row.signature_version.hash(hasher);
  row.row_signature.hash(hasher);
  row.expires_at.hash(hasher);
}

fn policy_row_from_pg(row: &sqlx::postgres::PgRow) -> anyhow::Result<PolicyRow> {
  Ok(PolicyRow {
    id: row.try_get("id")?,
    enabled: row.try_get("enabled")?,
    priority: row.try_get("priority")?,
    name: row.try_get("name")?,
    source: row.try_get("source")?,
    action: row.try_get("action")?,
    subject_type: row.try_get("subject_type")?,
    subject: row.try_get("subject")?,
    route_name: row.try_get("route_name")?,
    method: row.try_get("method")?,
    path_prefix: row.try_get("path_prefix")?,
    rate: row.try_get("rate")?,
    burst: row.try_get("burst")?,
    status: row.try_get("status")?,
    body: row.try_get("body")?,
    reason: row.try_get("reason")?,
    code: row.try_get("code")?,
    mode: row.try_get("mode")?,
    writer_identity: row.try_get("writer_identity")?,
    signature_version: row.try_get("signature_version")?,
    row_signature: row.try_get("row_signature")?,
    expires_at: row.try_get("expires_at")?,
  })
}

async fn load_generation(pool: &Pool<Postgres>, namespace: &str) -> anyhow::Result<i64> {
  let generation: Option<i64> = sqlx::query_scalar(
    "SELECT generation FROM oxibelt_dynamic_policy_generation WHERE namespace = $1",
  )
  .bind(namespace)
  .fetch_optional(pool)
  .await?;
  Ok(generation.unwrap_or(0))
}

fn validate_policy_row(
  row: PolicyRow,
  config: &DynamicPolicyConfig,
  namespace: &str,
  route_names: &HashSet<String>,
  signature_key: Option<&[u8; 32]>,
) -> anyhow::Result<DynamicPolicy> {
  let PolicyRow {
    id,
    enabled,
    priority,
    name,
    source,
    action,
    subject_type,
    subject,
    route_name,
    method,
    path_prefix,
    rate,
    burst,
    status,
    body,
    reason,
    code,
    mode,
    writer_identity,
    signature_version,
    row_signature,
    expires_at,
  } = row;

  if config.automation_api.enabled {
    if config.automation_api.require_ttl && expires_at.is_none() {
      bail!("dynamic policy {id} requires expires_at when automation API require_ttl is enabled");
    }
    let Some(signature_key) = signature_key else {
      bail!("dynamic policy automation API requires a signature key");
    };
    if signature_version.as_deref() != Some(signature::SIGNATURE_VERSION) {
      bail!("dynamic policy {id} has missing or unsupported signature_version");
    }
    let Some(row_signature) = row_signature.as_deref() else {
      bail!("dynamic policy {id} is missing row_signature");
    };
    signature::verify(
      signature_key,
      &signature::DynamicPolicySignatureFields {
        namespace,
        enabled,
        priority,
        name: &name,
        source: &source,
        action: &action,
        subject_type: &subject_type,
        subject: &subject,
        route_name: route_name.as_deref(),
        method: method.as_deref(),
        path_prefix: path_prefix.as_deref(),
        rate: rate.as_deref(),
        burst,
        status,
        body: body.as_deref(),
        reason: reason.as_deref(),
        code: code.as_deref(),
        mode: &mode,
        writer_identity: writer_identity.as_deref(),
        expires_at: expires_at.as_deref(),
      },
      row_signature,
    )
    .with_context(|| format!("dynamic policy {id} signature verification failed"))?;
  }

  validate_string_len("dynamic policy name", &name, MAX_DYNAMIC_POLICY_NAME_BYTES)?;
  validate_string_len(
    "dynamic policy source",
    &source,
    MAX_DYNAMIC_POLICY_NAME_BYTES,
  )?;
  validate_string_len(
    "dynamic policy subject",
    &subject,
    MAX_DYNAMIC_POLICY_SUBJECT_BYTES,
  )?;
  if name.trim().is_empty() {
    bail!("dynamic policy {id} name must not be empty");
  }

  let action = match action.as_str() {
    "allow" => DynamicPolicyAction::Allow,
    "challenge" => DynamicPolicyAction::Challenge,
    "reject" => DynamicPolicyAction::Reject,
    "rate_limit" => DynamicPolicyAction::RateLimit,
    "silent_close" => DynamicPolicyAction::SilentClose,
    _ => bail!("dynamic policy {id} has unsupported action {action}"),
  };
  let subject_type = parse_subject_type(&subject_type)
    .with_context(|| format!("dynamic policy {id} has unsupported subject_type {subject_type}"))?;
  let mode = match mode.as_str() {
    "enforce" => DynamicPolicyMode::Enforce,
    "dry_run" => DynamicPolicyMode::DryRun,
    _ => bail!("dynamic policy {id} has unsupported mode {mode}"),
  };

  let route_name = route_name
    .map(|route| validate_route_name(id, route, route_names))
    .transpose()?;
  let method = method
    .map(|method| validate_method(id, method))
    .transpose()?;
  let path_prefix = path_prefix
    .map(|path| validate_path_prefix(id, &path, config.matching.normalize_path))
    .transpose()?;
  let reason = reason
    .map(|reason| {
      validate_string_len(
        "dynamic policy reason",
        &reason,
        MAX_DYNAMIC_POLICY_REASON_BYTES,
      )?;
      Ok::<_, anyhow::Error>(reason)
    })
    .transpose()?;
  let code = code
    .map(|code| {
      validate_string_len("dynamic policy code", &code, MAX_DYNAMIC_POLICY_NAME_BYTES)?;
      if code
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
      {
        bail!("dynamic policy {id} code contains invalid characters");
      }
      Ok::<_, anyhow::Error>(code)
    })
    .transpose()?;
  let status_provided = status.is_some();
  let status = status
    .map(validate_status)
    .transpose()
    .with_context(|| format!("dynamic policy {id} has invalid status"))?
    .unwrap_or_else(|| {
      if action == DynamicPolicyAction::Challenge {
        StatusCode::FORBIDDEN
      } else {
        StatusCode::from_u16(config.default_status).expect("validated default status")
      }
    });
  if action == DynamicPolicyAction::SilentClose {
    if status_provided || body.is_some() {
      bail!("dynamic policy {id} silent_close action does not support status or body");
    }
    if rate.is_some() || burst.is_some() {
      bail!("dynamic policy {id} silent_close action does not support rate or burst");
    }
  }
  if action == DynamicPolicyAction::Challenge {
    if body.is_some() {
      bail!("dynamic policy {id} challenge action does not support body");
    }
    if rate.is_some() || burst.is_some() {
      bail!("dynamic policy {id} challenge action does not support rate or burst");
    }
  }
  let body = if action == DynamicPolicyAction::SilentClose {
    String::new()
  } else {
    body.unwrap_or_else(|| config.default_body.clone())
  };
  validate_string_len("dynamic policy body", &body, MAX_DYNAMIC_POLICY_BODY_BYTES)?;

  let (subject, cidr) = validate_subject(
    id,
    subject_type,
    &subject,
    route_name.as_deref(),
    path_prefix.as_deref(),
  )?;

  let burst = burst
    .map(|value| {
      if value <= 0 {
        bail!("dynamic policy {id} burst must be greater than 0");
      }
      u32::try_from(value).context("dynamic policy burst does not fit in u32")
    })
    .transpose()?;
  if action == DynamicPolicyAction::RateLimit {
    let Some(rate) = rate.as_deref() else {
      bail!("dynamic policy {id} rate_limit action requires rate");
    };
    validate_string_len("dynamic policy rate", rate, MAX_DYNAMIC_POLICY_RATE_BYTES)?;
    crate::limits::parse_rate(rate)
      .with_context(|| format!("dynamic policy {id} has invalid rate"))?;
    if burst.is_none() {
      bail!("dynamic policy {id} rate_limit action requires burst");
    }
  }

  Ok(DynamicPolicy {
    id,
    priority,
    name,
    source,
    action,
    subject_type,
    subject,
    cidr,
    route_name,
    method,
    path_prefix,
    rate,
    burst,
    status,
    body,
    reason,
    code,
    mode,
  })
}

fn validate_string_len(field: &str, value: &str, max: usize) -> anyhow::Result<()> {
  if value.len() > max {
    bail!("{field} must be at most {max} bytes");
  }
  Ok(())
}

fn validate_route_name(
  id: i64,
  route: String,
  route_names: &HashSet<String>,
) -> anyhow::Result<String> {
  validate_string_len(
    "dynamic policy route_name",
    &route,
    MAX_DYNAMIC_POLICY_ROUTE_BYTES,
  )?;
  if !route_names.contains(&route) {
    bail!("dynamic policy {id} references unknown route_name {route}");
  }
  Ok(route)
}

fn validate_method(id: i64, method: String) -> anyhow::Result<Method> {
  validate_string_len("dynamic policy method", &method, 32)?;
  if method != method.to_ascii_uppercase() {
    bail!("dynamic policy {id} method must be uppercase");
  }
  Method::from_bytes(method.as_bytes())
    .with_context(|| format!("dynamic policy {id} has invalid method {method}"))
}

fn validate_path_prefix(id: i64, path: &str, normalize: bool) -> anyhow::Result<String> {
  validate_string_len(
    "dynamic policy path_prefix",
    path,
    MAX_DYNAMIC_POLICY_PATH_BYTES,
  )?;
  let path = if normalize {
    crate::waf::normalization::normalize_path(path)
  } else {
    path.to_string()
  };
  if !path.starts_with('/') {
    bail!("dynamic policy {id} path_prefix must start with '/'");
  }
  if path
    .bytes()
    .any(|byte| byte.is_ascii_control() || byte == b'\\')
  {
    bail!("dynamic policy {id} path_prefix contains unsafe characters");
  }
  Ok(path)
}

fn validate_status(status: i32) -> anyhow::Result<StatusCode> {
  if status < 0 {
    bail!("status must be positive");
  }
  let status = u16::try_from(status).context("status does not fit in u16")?;
  StatusCode::from_u16(status).map_err(Into::into)
}

#[cfg(test)]
mod tests;
