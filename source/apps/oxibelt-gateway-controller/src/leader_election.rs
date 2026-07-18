//! Lease-based single-writer authority for the Gateway API controller.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use oxibelt_control_http::{empty_body, full_body, uri_from_url};
use serde_json::{Value, json};
use tracing::{info, warn};

use super::cli::RunArgs;
use super::health::ControllerHealth;
use super::kubernetes_time::rfc3339_now;
use super::watch::{KUBERNETES_MAX_BODY_BYTES, KubernetesPoller};

const LEASE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_WATCH_EVENT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LeaderElectionConfig {
  pub namespace: String,
  pub lease_name: String,
  pub lease_duration: Duration,
  pub renew_deadline: Duration,
  pub retry_period: Duration,
}

impl LeaderElectionConfig {
  pub fn from_args(args: &RunArgs) -> anyhow::Result<Self> {
    super::rollout::validate_kubernetes_dns_label(
      "leader-election namespace",
      &args.leader_election_namespace,
    )?;
    super::rollout::validate_kubernetes_dns_label(
      "leader-election Lease name",
      &args.leader_election_lease_name,
    )?;
    let lease = args.leader_election_lease_duration_seconds;
    let renew = args.leader_election_renew_deadline_seconds;
    let retry = args.leader_election_retry_period_seconds;
    if !(10..=300).contains(&lease) {
      bail!("leader-election lease duration must be between 10 and 300 seconds");
    }
    if !(5..=120).contains(&renew) {
      bail!("leader-election renew deadline must be between 5 and 120 seconds");
    }
    if !(1..=30).contains(&retry) {
      bail!("leader-election retry period must be between 1 and 30 seconds");
    }
    if retry >= renew || renew >= lease {
      bail!("leader-election timings must satisfy retry period < renew deadline < lease duration");
    }
    if retry.saturating_mul(2) > renew || renew.saturating_add(retry) > lease {
      bail!(
        "leader-election timings must satisfy 2 * retry period <= renew deadline and renew deadline + retry period <= lease duration"
      );
    }
    Ok(Self {
      namespace: args.leader_election_namespace.clone(),
      lease_name: args.leader_election_lease_name.clone(),
      lease_duration: Duration::from_secs(lease),
      renew_deadline: Duration::from_secs(renew),
      retry_period: Duration::from_secs(retry),
    })
  }

  fn lease_path(&self) -> String {
    format!(
      "/apis/coordination.k8s.io/v1/namespaces/{}/leases/{}",
      self.namespace, self.lease_name
    )
  }

  fn lease_collection_path(&self) -> String {
    format!(
      "/apis/coordination.k8s.io/v1/namespaces/{}/leases",
      self.namespace
    )
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LeadershipTerm {
  pub lease_uid: String,
  pub leader_epoch: u64,
  pub holder_identity: String,
}

#[derive(Debug)]
struct AuthorityState {
  term: Option<LeadershipTerm>,
  confirmed_at: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct Leadership {
  config: LeaderElectionConfig,
  state: Arc<RwLock<AuthorityState>>,
}

impl Leadership {
  pub fn new(config: LeaderElectionConfig) -> Self {
    Self {
      config,
      state: Arc::new(RwLock::new(AuthorityState {
        term: None,
        confirmed_at: None,
      })),
    }
  }

  fn confirm(&self, term: LeadershipTerm) {
    if let Ok(mut state) = self.state.write() {
      state.term = Some(term);
      state.confirmed_at = Some(Instant::now());
    }
  }

  pub fn revoke(&self) {
    if let Ok(mut state) = self.state.write() {
      state.term = None;
      state.confirmed_at = None;
    }
  }

  pub fn is_leader(&self) -> bool {
    self.write_permit().is_ok()
  }

  pub fn write_permit(&self) -> anyhow::Result<WritePermit> {
    let state = self
      .state
      .read()
      .map_err(|_| anyhow::anyhow!("leader authority lock is poisoned"))?;
    let term = state
      .term
      .clone()
      .context("this controller replica is not the active leader")?;
    let confirmed_at = state
      .confirmed_at
      .context("leader authority has no renewal proof")?;
    if confirmed_at.elapsed() >= self.config.renew_deadline {
      bail!("leader authority expired before the renew deadline");
    }
    Ok(WritePermit { term })
  }

  pub fn validate(&self, permit: &WritePermit) -> anyhow::Result<()> {
    let current = self.write_permit()?;
    if current.term != permit.term {
      bail!("leadership changed before the Kubernetes write");
    }
    Ok(())
  }
}

#[derive(Debug)]
pub struct WritePermit {
  term: LeadershipTerm,
}

impl WritePermit {
  pub fn term(&self) -> &LeadershipTerm {
    &self.term
  }
}

#[derive(Debug)]
struct ObservedLease {
  resource_version: String,
  holder_identity: Option<String>,
  leader_epoch: u64,
  observed_at: Instant,
}

pub fn process_identity() -> anyhow::Result<String> {
  let pod_name = std::env::var("POD_NAME").unwrap_or_else(|_| "controller".to_string());
  let pod_uid = std::env::var("POD_UID").unwrap_or_else(|_| "unknown".to_string());
  let mut nonce = [0_u8; 16];
  getrandom::fill(&mut nonce).context("failed to generate a unique leader-election identity")?;
  let nonce = nonce
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect::<String>();
  let mut identity = format!("{pod_name}.{}.{nonce}", &pod_uid[..pod_uid.len().min(24)]);
  identity.truncate(128);
  Ok(identity)
}

pub async fn run_leader_election(
  kubernetes: KubernetesPoller,
  config: LeaderElectionConfig,
  identity: String,
  leadership: Leadership,
  health: ControllerHealth,
  mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
  let mut observed: Option<ObservedLease> = None;
  loop {
    if *shutdown.borrow() {
      break;
    }
    let was_leader = leadership.is_leader();
    match election_step(&kubernetes, &config, &identity, &leadership, &mut observed).await {
      Ok(leader) => {
        health.mark_election(true, leader, None);
        if leader && !was_leader {
          info!(lease = %config.lease_name, identity, "acquired Gateway controller leadership");
        } else if !leader && was_leader {
          warn!(lease = %config.lease_name, identity, "lost Gateway controller leadership");
        }
      }
      Err(error) => {
        leadership.revoke();
        health.mark_election(false, false, Some(error.to_string()));
        warn!(error = %error, lease = %config.lease_name, "leader-election step failed closed");
      }
    }

    let wait = if leadership.is_leader() {
      wait_for_shutdown(config.retry_period, &mut shutdown).await
    } else {
      tokio::select! {
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
        result = watch_lease_once(&kubernetes, &config) => {
          if let Err(error) = result {
            warn!(error = %error, lease = %config.lease_name, "Lease watch ended; reconnecting from a fresh GET");
          }
          false
        }
      }
    };
    if wait {
      break;
    }
  }

  if let Ok(permit) = leadership.write_permit()
    && let Err(error) = release_lease(&kubernetes, &config, &leadership, &permit).await
  {
    warn!(error = %error, lease = %config.lease_name, "failed to release Lease; expiry will fence the old term");
  }
  leadership.revoke();
  health.mark_election(false, false, None);
  Ok(())
}

async fn wait_for_shutdown(
  duration: Duration,
  shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
  tokio::select! {
    changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
    _ = tokio::time::sleep(duration) => false,
  }
}

async fn election_step(
  kubernetes: &KubernetesPoller,
  config: &LeaderElectionConfig,
  identity: &str,
  leadership: &Leadership,
  observed: &mut Option<ObservedLease>,
) -> anyhow::Result<bool> {
  let lease = get_lease(kubernetes, config).await?;
  let resource_version = required_string(&lease, "/metadata/resourceVersion")?;
  let lease_uid = required_string(&lease, "/metadata/uid")?;
  let holder_identity = lease
    .pointer("/spec/holderIdentity")
    .and_then(Value::as_str)
    .filter(|holder| !holder.is_empty())
    .map(str::to_string);
  let leader_epoch = lease
    .pointer("/spec/leaseTransitions")
    .and_then(Value::as_u64)
    .unwrap_or_default();
  let same_observation = observed.as_ref().is_some_and(|prior| {
    prior.resource_version == resource_version
      && prior.holder_identity == holder_identity
      && prior.leader_epoch == leader_epoch
  });
  if !same_observation {
    *observed = Some(ObservedLease {
      resource_version: resource_version.to_string(),
      holder_identity: holder_identity.clone(),
      leader_epoch,
      observed_at: Instant::now(),
    });
  }

  let renewing = holder_identity.as_deref() == Some(identity);
  let available = holder_identity.is_none()
    || observed
      .as_ref()
      .is_some_and(|lease| lease.observed_at.elapsed() >= config.lease_duration);
  if !renewing && !available {
    leadership.revoke();
    return Ok(false);
  }

  let next_epoch = if renewing {
    leader_epoch
  } else {
    leader_epoch
      .checked_add(1)
      .context("Lease transition counter overflowed")?
  };
  let patch = build_lease_patch(&lease, identity, config, next_epoch, !renewing)?;
  let updated = patch_lease(kubernetes, config, patch).await?;
  let term = LeadershipTerm {
    lease_uid: required_string(&updated, "/metadata/uid")?.to_string(),
    leader_epoch: updated
      .pointer("/spec/leaseTransitions")
      .and_then(Value::as_u64)
      .context("updated Lease has no valid spec.leaseTransitions")?,
    holder_identity: required_string(&updated, "/spec/holderIdentity")?.to_string(),
  };
  if term.lease_uid != lease_uid || term.holder_identity != identity {
    leadership.revoke();
    bail!("Kubernetes returned a Lease that does not prove the requested leadership term");
  }
  *observed = Some(ObservedLease {
    resource_version: required_string(&updated, "/metadata/resourceVersion")?.to_string(),
    holder_identity: Some(identity.to_string()),
    leader_epoch: term.leader_epoch,
    observed_at: Instant::now(),
  });
  leadership.confirm(term);
  Ok(true)
}

fn build_lease_patch(
  lease: &Value,
  identity: &str,
  config: &LeaderElectionConfig,
  epoch: u64,
  acquiring: bool,
) -> anyhow::Result<Value> {
  let resource_version = required_string(lease, "/metadata/resourceVersion")?;
  let uid = required_string(lease, "/metadata/uid")?;
  let now = rfc3339_now();
  let mut operations = vec![
    json!({"op":"test", "path":"/metadata/resourceVersion", "value":resource_version}),
    json!({"op":"test", "path":"/metadata/uid", "value":uid}),
  ];
  if let Some(holder) = lease.pointer("/spec/holderIdentity") {
    operations.push(json!({"op":"test", "path":"/spec/holderIdentity", "value":holder}));
  }
  let mut spec = json!({
    "holderIdentity": identity,
    "leaseDurationSeconds": config.lease_duration.as_secs(),
    "renewTime": now,
    "leaseTransitions": epoch,
  });
  if acquiring {
    spec["acquireTime"] = Value::String(rfc3339_now());
  } else if let Some(acquire_time) = lease.pointer("/spec/acquireTime") {
    spec["acquireTime"] = acquire_time.clone();
  }
  operations.push(json!({"op":"add", "path":"/spec", "value":spec}));
  Ok(Value::Array(operations))
}

async fn get_lease(
  kubernetes: &KubernetesPoller,
  config: &LeaderElectionConfig,
) -> anyhow::Result<Value> {
  let (status, body) =
    lease_request(kubernetes, Method::GET, &config.lease_path(), None, None).await?;
  if status == StatusCode::NOT_FOUND {
    bail!(
      "leader-election Lease {}/{} is missing; restore the Helm-owned Lease before writes can resume",
      config.namespace,
      config.lease_name
    );
  }
  if !status.is_success() {
    bail!(
      "Kubernetes Lease GET returned {status}: {}",
      String::from_utf8_lossy(&body)
    );
  }
  serde_json::from_slice(&body).context("failed to parse Kubernetes Lease")
}

async fn patch_lease(
  kubernetes: &KubernetesPoller,
  config: &LeaderElectionConfig,
  patch: Value,
) -> anyhow::Result<Value> {
  let body = serde_json::to_vec(&patch).context("failed to serialize Lease JSON Patch")?;
  let (status, body) = lease_request(
    kubernetes,
    Method::PATCH,
    &config.lease_path(),
    Some("application/json-patch+json"),
    Some(body),
  )
  .await?;
  if status == StatusCode::CONFLICT || status == StatusCode::UNPROCESSABLE_ENTITY {
    bail!("Lease changed while acquiring or renewing leadership");
  }
  if !status.is_success() {
    bail!(
      "Kubernetes Lease PATCH returned {status}: {}",
      String::from_utf8_lossy(&body)
    );
  }
  serde_json::from_slice(&body).context("failed to parse patched Kubernetes Lease")
}

async fn release_lease(
  kubernetes: &KubernetesPoller,
  config: &LeaderElectionConfig,
  leadership: &Leadership,
  permit: &WritePermit,
) -> anyhow::Result<()> {
  leadership.validate(permit)?;
  validate_write_permit(kubernetes, leadership, permit).await?;
  let lease = get_lease(kubernetes, config).await?;
  let patch = json!([
    {"op":"test", "path":"/metadata/resourceVersion", "value":required_string(&lease, "/metadata/resourceVersion")?},
    {"op":"test", "path":"/metadata/uid", "value":permit.term.lease_uid},
    {"op":"test", "path":"/spec/holderIdentity", "value":permit.term.holder_identity},
    {"op":"test", "path":"/spec/leaseTransitions", "value":permit.term.leader_epoch},
    {"op":"replace", "path":"/spec/holderIdentity", "value":null}
  ]);
  let _ = patch_lease(kubernetes, config, patch).await?;
  Ok(())
}

pub async fn validate_write_permit(
  kubernetes: &KubernetesPoller,
  leadership: &Leadership,
  permit: &WritePermit,
) -> anyhow::Result<()> {
  leadership.validate(permit)?;
  let lease = get_lease(kubernetes, &leadership.config).await?;
  if required_string(&lease, "/metadata/uid")? != permit.term.lease_uid
    || required_string(&lease, "/spec/holderIdentity")? != permit.term.holder_identity
    || lease
      .pointer("/spec/leaseTransitions")
      .and_then(Value::as_u64)
      != Some(permit.term.leader_epoch)
  {
    leadership.revoke();
    bail!("fresh Lease read no longer proves this process's leadership term");
  }
  leadership.validate(permit)
}

async fn lease_request(
  kubernetes: &KubernetesPoller,
  method: Method,
  path: &str,
  content_type: Option<&str>,
  body: Option<Vec<u8>>,
) -> anyhow::Result<(StatusCode, Bytes)> {
  let mut url = kubernetes.base_url.clone();
  url.set_path(path);
  url.set_query(None);
  let mut builder = Request::builder()
    .method(method)
    .uri(uri_from_url(&url)?)
    .header(http::header::ACCEPT, "application/json")
    .header(http::header::AUTHORIZATION, kubernetes.bearer()?);
  if let Some(content_type) = content_type {
    builder = builder.header(http::header::CONTENT_TYPE, content_type);
  }
  let response = kubernetes
    .client
    .request(
      builder.body(full_body(Bytes::from(body.unwrap_or_default())))?,
      LEASE_REQUEST_TIMEOUT,
      KUBERNETES_MAX_BODY_BYTES,
    )
    .await?;
  Ok((response.status, response.body))
}

async fn watch_lease_once(
  kubernetes: &KubernetesPoller,
  config: &LeaderElectionConfig,
) -> anyhow::Result<()> {
  let mut url = kubernetes.base_url.clone();
  url.set_path(&config.lease_collection_path());
  url.set_query(None);
  {
    let mut query = url.query_pairs_mut();
    query.append_pair(
      "fieldSelector",
      &format!("metadata.name={}", config.lease_name),
    );
    query.append_pair("watch", "true");
    query.append_pair("allowWatchBookmarks", "true");
    query.append_pair(
      "timeoutSeconds",
      &config.retry_period.as_secs().max(1).to_string(),
    );
  }
  let request = Request::builder()
    .method(Method::GET)
    .uri(uri_from_url(&url)?)
    .header(http::header::ACCEPT, "application/json")
    .header(http::header::AUTHORIZATION, kubernetes.bearer()?)
    .body(empty_body())?;
  let response = kubernetes
    .client
    .request_stream(request, LEASE_REQUEST_TIMEOUT)
    .await?;
  if response.status == StatusCode::GONE {
    return Ok(());
  }
  if !response.status.is_success() {
    bail!("Kubernetes Lease watch returned {}", response.status);
  }
  let mut body = response.body;
  let mut buffer = Vec::new();
  let timeout = config.retry_period.saturating_add(Duration::from_secs(1));
  tokio::time::timeout(timeout, async {
    while let Some(frame) = body.frame().await {
      let frame = frame.context("Kubernetes Lease watch body failed")?;
      let Some(data) = frame.data_ref() else {
        continue;
      };
      if buffer.len().saturating_add(data.len()) > MAX_WATCH_EVENT_BYTES {
        bail!("Kubernetes Lease watch event exceeded {MAX_WATCH_EVENT_BYTES} bytes");
      }
      buffer.extend_from_slice(data);
      if buffer.contains(&b'\n') {
        break;
      }
    }
    Ok::<(), anyhow::Error>(())
  })
  .await
  .context("Kubernetes Lease watch timed out")??;
  Ok(())
}

fn required_string<'a>(value: &'a Value, pointer: &str) -> anyhow::Result<&'a str> {
  value
    .pointer(pointer)
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
    .with_context(|| format!("Kubernetes Lease field {pointer} is required"))
}

#[cfg(test)]
#[path = "leader_election/tests.rs"]
mod tests;
