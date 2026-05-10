use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use http::{Method, StatusCode};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{Pool, Postgres};
use tracing::{info, warn};

use crate::config::{
  Config, DatabaseTlsMode, DynamicPolicyConfig, DynamicPolicyFailPolicy, SharedStateBackendConfig,
};
use crate::limits::LimitState;
use crate::metrics::Metrics;

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
  name: String,
  action: DynamicPolicyAction,
  subject_type: DynamicPolicySubjectType,
  subject: String,
  route_name: Option<String>,
  method: Option<Method>,
  path_prefix: Option<String>,
  rate: Option<String>,
  burst: Option<u32>,
  status: StatusCode,
  body: String,
  reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DynamicPolicyAction {
  Reject,
  RateLimit,
}

impl DynamicPolicyAction {
  fn as_str(self) -> &'static str {
    match self {
      Self::Reject => "reject",
      Self::RateLimit => "rate_limit",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DynamicPolicySubjectType {
  Ip,
  IpRoute,
  IpPath,
}

impl DynamicPolicySubjectType {
  fn as_str(self) -> &'static str {
    match self {
      Self::Ip => "client_ip",
      Self::IpRoute => "client_ip_route",
      Self::IpPath => "client_ip_path",
    }
  }
}

#[derive(Debug, Clone, Default)]
pub struct DynamicPolicyContext {
  pub matched: bool,
  pub action: Option<String>,
  pub name: Option<String>,
  pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DynamicPolicyTerminal {
  pub status: StatusCode,
  pub body: String,
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
}

type PolicyRow = (
  i64,
  i32,
  String,
  String,
  String,
  String,
  String,
  Option<String>,
  Option<String>,
  Option<String>,
  Option<String>,
  Option<i32>,
  Option<i32>,
  Option<String>,
  Option<String>,
  String,
);

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
    let route_names = Arc::new(
      config
        .routes
        .iter()
        .map(|route| route.name.clone())
        .collect::<HashSet<_>>(),
    );

    let pool = match connect_postgres_pool(backend).await {
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
    init_postgres(&pool)
      .await
      .context("failed to initialize dynamic policy PostgreSQL tables")?;

    let snapshot =
      match load_snapshot(&pool, &config.dynamic_policy, &namespace, &route_names).await {
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

  for policy in snapshot.policies.iter() {
    if !policy.matches(config, &request, &request_path) {
      continue;
    }
    let context = DynamicPolicyContext {
      matched: true,
      action: Some(policy.action.as_str().to_string()),
      name: Some(policy.name.clone()),
      reason: policy.reason.clone(),
    };
    metrics.record_dynamic_policy_match();
    match policy.action {
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
        return DynamicPolicyOutcome {
          context,
          terminal: Some(DynamicPolicyTerminal {
            status: policy.status,
            body: policy.body.clone(),
          }),
        };
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
            terminal: Some(DynamicPolicyTerminal {
              status,
              body: policy.body.clone(),
            }),
          };
        }
        return DynamicPolicyOutcome {
          context,
          terminal: None,
        };
      }
    }
  }

  DynamicPolicyOutcome::default()
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
    if let Some(method) = &self.method
      && method != request.method
    {
      return false;
    }
    if config.matching.trust_route_name
      && let Some(route_name) = &self.route_name
      && route_name != request.route_name
    {
      return false;
    }
    if let Some(path_prefix) = &self.path_prefix
      && !crate::routes::path_prefix_matches(path_prefix, request_path)
    {
      return false;
    }

    match self.subject_type {
      DynamicPolicySubjectType::Ip => self.subject == request.client_ip.to_string(),
      DynamicPolicySubjectType::IpRoute => {
        self.subject == format!("{}|{}", request.client_ip, request.route_name)
      }
      DynamicPolicySubjectType::IpPath => self
        .path_prefix
        .as_deref()
        .is_some_and(|path| self.subject == format!("{}|{path}", request.client_ip)),
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
) -> anyhow::Result<DynamicPolicySnapshot> {
  let generation = load_generation(pool, namespace).await?;
  let limit = i64::try_from(config.max_policies.saturating_add(1))
    .context("dynamic_policy.max_policies does not fit in i64")?;
  let rows: Vec<PolicyRow> = sqlx::query_as(
    "SELECT id, priority, name, source, action, subject_type, subject, route_name, method,
            path_prefix, rate, burst, status, body, reason, updated_at::text
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
    hash_policy_row(&row, &mut hasher);
    policies.push(validate_policy_row(row, config, route_names)?);
  }

  Ok(DynamicPolicySnapshot {
    generation,
    fingerprint: hasher.finish(),
    policies: Arc::from(policies),
  })
}

fn hash_policy_row(row: &PolicyRow, hasher: &mut impl Hasher) {
  row.0.hash(hasher);
  row.1.hash(hasher);
  row.2.hash(hasher);
  row.3.hash(hasher);
  row.4.hash(hasher);
  row.5.hash(hasher);
  row.6.hash(hasher);
  row.7.hash(hasher);
  row.8.hash(hasher);
  row.9.hash(hasher);
  row.10.hash(hasher);
  row.11.hash(hasher);
  row.12.hash(hasher);
  row.13.hash(hasher);
  row.14.hash(hasher);
  row.15.hash(hasher);
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
  route_names: &HashSet<String>,
) -> anyhow::Result<DynamicPolicy> {
  let (
    id,
    _priority,
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
    _updated_at,
  ) = row;

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
    "reject" => DynamicPolicyAction::Reject,
    "rate_limit" => DynamicPolicyAction::RateLimit,
    _ => bail!("dynamic policy {id} has unsupported action {action}"),
  };
  let subject_type = match subject_type.as_str() {
    "client_ip" => DynamicPolicySubjectType::Ip,
    "client_ip_route" => DynamicPolicySubjectType::IpRoute,
    "client_ip_path" => DynamicPolicySubjectType::IpPath,
    _ => bail!("dynamic policy {id} has unsupported subject_type {subject_type}"),
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
  let status = status
    .map(validate_status)
    .transpose()
    .with_context(|| format!("dynamic policy {id} has invalid status"))?
    .unwrap_or(StatusCode::from_u16(config.default_status).expect("validated default status"));
  let body = body.unwrap_or_else(|| config.default_body.clone());
  validate_string_len("dynamic policy body", &body, MAX_DYNAMIC_POLICY_BODY_BYTES)?;

  let subject = validate_subject(
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
    name,
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

fn validate_subject(
  id: i64,
  subject_type: DynamicPolicySubjectType,
  subject: &str,
  route_name: Option<&str>,
  path_prefix: Option<&str>,
) -> anyhow::Result<String> {
  let subject = match subject_type {
    DynamicPolicySubjectType::Ip => {
      let ip = IpAddr::from_str(subject)
        .with_context(|| format!("dynamic policy {id} subject must be a valid IP address"))?;
      ip.to_string()
    }
    DynamicPolicySubjectType::IpRoute => {
      let (ip, route) = split_composite_subject(id, subject, "client_ip_route")?;
      let ip = IpAddr::from_str(ip).with_context(|| {
        format!("dynamic policy {id} client_ip_route subject must start with a valid IP address")
      })?;
      let Some(route_name) = route_name else {
        bail!("dynamic policy {id} client_ip_route requires route_name");
      };
      if route != route_name {
        bail!("dynamic policy {id} client_ip_route subject route does not match route_name");
      }
      format!("{ip}|{route_name}")
    }
    DynamicPolicySubjectType::IpPath => {
      let (ip, path) = split_composite_subject(id, subject, "client_ip_path")?;
      let ip = IpAddr::from_str(ip).with_context(|| {
        format!("dynamic policy {id} client_ip_path subject must start with a valid IP address")
      })?;
      let Some(path_prefix) = path_prefix else {
        bail!("dynamic policy {id} client_ip_path requires path_prefix");
      };
      if path != path_prefix {
        bail!("dynamic policy {id} client_ip_path subject path does not match path_prefix");
      }
      format!("{ip}|{path_prefix}")
    }
  };
  Ok(subject)
}

fn split_composite_subject<'a>(
  id: i64,
  subject: &'a str,
  subject_type: &str,
) -> anyhow::Result<(&'a str, &'a str)> {
  let Some((ip, value)) = subject.split_once('|') else {
    bail!("dynamic policy {id} {subject_type} subject must use '<ip>|<value>' format");
  };
  if ip.is_empty() || value.is_empty() {
    bail!("dynamic policy {id} {subject_type} subject must not contain empty parts");
  }
  Ok((ip, value))
}

async fn connect_postgres_pool(
  config: &SharedStateBackendConfig,
) -> anyhow::Result<Pool<Postgres>> {
  let connection_url =
    config.connection_url_with_prefix(&format!("shared_state.backends.{}", config.name))?;
  let mut options = PgConnectOptions::from_str(&connection_url)?
    .application_name("oxibelt-dynamic-policy")
    .ssl_mode(match config.tls.mode {
      DatabaseTlsMode::Off => PgSslMode::Disable,
      DatabaseTlsMode::VerifyFull => PgSslMode::VerifyFull,
    });
  if let Some(ca_cert) = &config.tls.ca_cert {
    options = options.ssl_root_cert(ca_cert);
  }
  if let (Some(client_cert), Some(client_key)) = (&config.tls.client_cert, &config.tls.client_key) {
    options = options
      .ssl_client_cert(client_cert)
      .ssl_client_key(client_key);
  }
  PgPoolOptions::new()
    .max_connections(config.max_connections)
    .acquire_timeout(Duration::from_millis(config.connect_timeout_ms))
    .connect_with(options)
    .await
    .map_err(Into::into)
}

async fn init_postgres(pool: &Pool<Postgres>) -> anyhow::Result<()> {
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_dynamic_policies (
       id bigserial PRIMARY KEY,
       namespace text NOT NULL,
       enabled boolean NOT NULL DEFAULT true,
       priority integer NOT NULL DEFAULT 100,
       name text NOT NULL,
       source text NOT NULL DEFAULT 'external',
       action text NOT NULL,
       subject_type text NOT NULL,
       subject text NOT NULL,
       route_name text NULL,
       method text NULL,
       path_prefix text NULL,
       rate text NULL,
       burst integer NULL,
       status integer NULL,
       body text NULL,
       reason text NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       updated_at timestamptz NOT NULL DEFAULT now(),
       expires_at timestamptz NULL
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE INDEX IF NOT EXISTS oxibelt_dynamic_policies_active_idx
       ON oxibelt_dynamic_policies (namespace, enabled, expires_at, priority)",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE INDEX IF NOT EXISTS oxibelt_dynamic_policies_subject_idx
       ON oxibelt_dynamic_policies (namespace, subject_type, subject)",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_dynamic_policy_generation (
       namespace text PRIMARY KEY,
       generation bigint NOT NULL DEFAULT 0,
       updated_at timestamptz NOT NULL DEFAULT now()
     )",
  )
  .execute(pool)
  .await?;
  Ok(())
}

#[cfg(test)]
mod tests;
