use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use http::Request;
use oxibelt_control_http::{
  ControlHttpClient, ControlHttpResponseBodyLimitError, empty_body, full_body, uri_from_url,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};
use url::Url;

use super::cli::{RunArgs, SharedArgs};
use super::compatibility::CompatibilityPolicy;
use super::health::ControllerHealth;
use super::leader_election::{Leadership, WritePermit, validate_write_permit};
use super::model::KubernetesObject;
use super::rollout;
use super::rollout_status::RolloutStatus;
use super::status;
use super::translate;

const DEFAULT_SERVICE_ACCOUNT_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const DEFAULT_SERVICE_ACCOUNT_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
pub(super) const KUBERNETES_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const REFERENCED_CONFIG_MAP_MAX_BODY_BYTES: usize = 320 * 1024;
const MAX_REFERENCED_CONFIG_MAPS: usize = 64;

#[derive(Clone)]
pub struct KubernetesPoller {
  pub(super) client: ControlHttpClient,
  pub(super) base_url: Url,
  pub(super) service_account_token_path: PathBuf,
  pub(super) namespace: Option<String>,
  pub(super) leadership: Option<Leadership>,
}

impl KubernetesPoller {
  pub fn from_environment(args: &SharedArgs) -> anyhow::Result<Self> {
    validate_watch_namespace(args.watch_namespace.as_deref())?;
    let host = std::env::var("KUBERNETES_SERVICE_HOST")
      .context("KUBERNETES_SERVICE_HOST is not set; run inside a Kubernetes pod")?;
    let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
      .or_else(|_| std::env::var("KUBERNETES_SERVICE_PORT"))
      .unwrap_or_else(|_| "443".to_string());
    let base_url = Url::parse(&format!("https://{host}:{port}"))
      .context("failed to build Kubernetes API URL")?;
    let token_path = Path::new(DEFAULT_SERVICE_ACCOUNT_TOKEN);
    read_bearer_token(token_path)?;
    let ca_path = PathBuf::from(DEFAULT_SERVICE_ACCOUNT_CA);
    let ca_certs = ca_path
      .exists()
      .then_some(ca_path)
      .into_iter()
      .collect::<Vec<_>>();
    Ok(Self {
      client: ControlHttpClient::new(&ca_certs)?,
      base_url,
      service_account_token_path: token_path.to_path_buf(),
      namespace: args.watch_namespace.clone(),
      leadership: None,
    })
  }

  pub fn with_leadership(mut self, leadership: Leadership) -> Self {
    self.leadership = Some(leadership);
    self
  }

  pub(super) async fn authorize_write(&self) -> anyhow::Result<WritePermit> {
    let leadership = self
      .leadership
      .as_ref()
      .context("Kubernetes mutation attempted without leader-election authority")?;
    let permit = leadership.write_permit()?;
    validate_write_permit(self, leadership, &permit).await?;
    Ok(permit)
  }

  pub(super) fn bearer(&self) -> anyhow::Result<String> {
    read_bearer_token(&self.service_account_token_path)
  }

  async fn snapshot(&self) -> anyhow::Result<Vec<KubernetesObject>> {
    let mut objects = Vec::new();
    objects.extend(
      self
        .list_objects("/apis/gateway.networking.k8s.io/v1/gatewayclasses")
        .await?,
    );
    objects.extend(
      self
        .list_namespaced("/apis/gateway.networking.k8s.io/v1", "gateways")
        .await?,
    );
    objects.extend(
      self
        .list_namespaced("/apis/gateway.networking.k8s.io/v1", "httproutes")
        .await?,
    );
    objects.extend(
      self
        .list_namespaced("/apis/gateway.networking.k8s.io/v1", "grpcroutes")
        .await?,
    );
    objects.extend(
      self
        .list_namespaced("/apis/gateway.networking.k8s.io/v1", "tlsroutes")
        .await?,
    );
    objects.extend(
      self
        .list_namespaced("/apis/gateway.networking.k8s.io/v1", "referencegrants")
        .await?,
    );
    objects.extend(
      self
        .list_namespaced("/apis/gateway.networking.k8s.io/v1", "tcproutes")
        .await?,
    );
    objects.extend(
      self
        .list_namespaced("/apis/gateway.networking.k8s.io/v1", "udproutes")
        .await?,
    );
    objects.extend(
      self
        .list_namespaced("/apis/gateway.networking.k8s.io/v1", "backendtlspolicies")
        .await?,
    );
    objects.extend(
      self
        .list_objects(&namespace_snapshot_path(self.namespace.as_deref()))
        .await?,
    );
    objects.extend(self.list_namespaced("/api/v1", "services").await?);
    let config_maps = backend_tls_config_map_refs(&objects)?;
    for (namespace, name) in config_maps {
      if let Some(config_map) = self.get_config_map(&namespace, &name).await? {
        objects.push(config_map);
      }
    }
    Ok(objects)
  }

  async fn get_config_map(
    &self,
    namespace: &str,
    name: &str,
  ) -> anyhow::Result<Option<KubernetesObject>> {
    validate_kubernetes_path_segment("ConfigMap namespace", namespace)?;
    validate_kubernetes_path_segment("ConfigMap name", name)?;
    let path = format!("/api/v1/namespaces/{namespace}/configmaps/{name}");
    let mut url = self.base_url.clone();
    url.set_path(&path);
    url.set_query(None);
    let request = Request::builder()
      .method(http::Method::GET)
      .uri(uri_from_url(&url)?)
      .header(http::header::ACCEPT, "application/json")
      .header(http::header::AUTHORIZATION, self.bearer()?)
      .body(empty_body())?;
    let response = match self
      .client
      .request(
        request,
        Duration::from_secs(10),
        REFERENCED_CONFIG_MAP_MAX_BODY_BYTES,
      )
      .await
    {
      Ok(response) => response,
      Err(error) => {
        if let Some(limit_error) = error.downcast_ref::<ControlHttpResponseBodyLimitError>()
          && (limit_error.status().is_success()
            || limit_error.status() == http::StatusCode::NOT_FOUND)
        {
          warn!(
            namespace,
            name,
            status = %limit_error.status(),
            max_body_bytes = limit_error.max_body_bytes(),
            "referenced BackendTLSPolicy ConfigMap response exceeded the bounded body limit"
          );
          return Ok(None);
        }
        return Err(error);
      }
    };
    if response.status == http::StatusCode::NOT_FOUND {
      return Ok(None);
    }
    if !response.status.is_success() {
      bail!("Kubernetes API {path} returned {}", response.status);
    }
    let mut parsed = parse_list(response.body)
      .with_context(|| format!("failed to parse Kubernetes ConfigMap from {path}"))?;
    if parsed.len() != 1 || parsed[0].kind != "ConfigMap" {
      bail!("Kubernetes API {path} did not return exactly one ConfigMap");
    }
    Ok(parsed.pop())
  }

  async fn list_namespaced(
    &self,
    api_prefix: &str,
    resource: &str,
  ) -> anyhow::Result<Vec<KubernetesObject>> {
    let path = match &self.namespace {
      Some(namespace) if api_prefix == "/api/v1" => {
        format!("{api_prefix}/namespaces/{namespace}/{resource}")
      }
      Some(namespace) => format!("{api_prefix}/namespaces/{namespace}/{resource}"),
      None => format!("{api_prefix}/{resource}"),
    };
    self.list_objects(&path).await
  }

  async fn list_objects(&self, path: &str) -> anyhow::Result<Vec<KubernetesObject>> {
    let mut url = self.base_url.clone();
    url.set_path(path);
    url.set_query(None);
    let bearer = self.bearer()?;
    let request = Request::builder()
      .method(http::Method::GET)
      .uri(uri_from_url(&url)?)
      .header(http::header::ACCEPT, "application/json")
      .header(http::header::AUTHORIZATION, bearer)
      .body(empty_body())?;
    let response = self
      .client
      .request(request, Duration::from_secs(10), KUBERNETES_MAX_BODY_BYTES)
      .await?;
    if response.status == http::StatusCode::NOT_FOUND {
      bail!(
        "required Kubernetes API list endpoint {path} was not found; verify the watched namespace and serve the required v1 Gateway API resources"
      );
    }
    if !response.status.is_success() {
      bail!("Kubernetes API {path} returned {}", response.status);
    }
    parse_list(response.body).map_err(|error| {
      anyhow::anyhow!("failed to parse Kubernetes API list from {path}: {error:#}")
    })
  }

  pub async fn apply_status_patches(&self, patches: &[status::StatusPatch]) -> anyhow::Result<()> {
    for patch in patches {
      let _permit = self.authorize_write().await?;
      self.patch_status(patch).await.with_context(|| {
        format!(
          "failed to patch status for {}/{}/{}",
          patch.resource,
          patch.namespace.as_deref().unwrap_or("_cluster"),
          patch.name
        )
      })?;
    }
    Ok(())
  }

  async fn patch_status(&self, patch: &status::StatusPatch) -> anyhow::Result<()> {
    let path = match &patch.namespace {
      Some(namespace) => format!(
        "{}/namespaces/{}/{}/{}/status",
        patch.api_prefix, namespace, patch.resource, patch.name
      ),
      None => format!(
        "{}/{}/{}/status",
        patch.api_prefix, patch.resource, patch.name
      ),
    };
    let mut url = self.base_url.clone();
    url.set_path(&path);
    url.set_query(None);
    let resource_version = patch
      .resource_version
      .as_deref()
      .context("status mutation requires the observed metadata.resourceVersion")?;
    let body = serde_json::to_vec(&json!([
      {"op":"test", "path":"/metadata/resourceVersion", "value":resource_version},
      {"op":"add", "path":"/status", "value":patch.status.clone()}
    ]))
    .context("failed to serialize Kubernetes status patch")?;
    let bearer = self.bearer()?;
    let request = Request::builder()
      .method(http::Method::PATCH)
      .uri(uri_from_url(&url)?)
      .header(http::header::ACCEPT, "application/json")
      .header(http::header::AUTHORIZATION, bearer)
      .header(http::header::CONTENT_TYPE, "application/json-patch+json")
      .body(full_body(Bytes::from(body)))?;
    let response = self
      .client
      .request(request, Duration::from_secs(10), KUBERNETES_MAX_BODY_BYTES)
      .await?;
    if response.status == http::StatusCode::NOT_FOUND {
      bail!("Kubernetes status subresource {path} disappeared before the guarded patch");
    }
    if !response.status.is_success() {
      let body = String::from_utf8_lossy(&response.body);
      bail!(
        "Kubernetes API status patch {path} returned {}: {}",
        response.status,
        body
      );
    }
    Ok(())
  }
}

fn namespace_snapshot_path(namespace: Option<&str>) -> String {
  match namespace {
    Some(namespace) => format!("/api/v1/namespaces/{namespace}"),
    None => "/api/v1/namespaces".to_string(),
  }
}

fn validate_watch_namespace(namespace: Option<&str>) -> anyhow::Result<()> {
  if let Some(namespace) = namespace {
    rollout::validate_kubernetes_dns_label("watch namespace", namespace)?;
  }
  Ok(())
}

fn backend_tls_config_map_refs(
  objects: &[KubernetesObject],
) -> anyhow::Result<BTreeSet<(String, String)>> {
  let mut refs = BTreeSet::new();
  for policy in objects
    .iter()
    .filter(|object| object.kind == "BackendTLSPolicy")
  {
    let Some(ca_refs) = policy
      .spec
      .pointer("/validation/caCertificateRefs")
      .and_then(Value::as_array)
    else {
      continue;
    };
    for ca_ref in ca_refs {
      let group = ca_ref.get("group").and_then(Value::as_str).unwrap_or("");
      let kind = ca_ref
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("ConfigMap");
      let Some(name) = ca_ref.get("name").and_then(Value::as_str) else {
        continue;
      };
      if group.is_empty() && kind == "ConfigMap" {
        let namespace = policy.namespace();
        if validate_kubernetes_path_segment("ConfigMap namespace", namespace).is_ok()
          && validate_kubernetes_path_segment("ConfigMap name", name).is_ok()
        {
          refs.insert((namespace.to_string(), name.to_string()));
        }
      }
    }
  }
  if refs.len() > MAX_REFERENCED_CONFIG_MAPS {
    bail!(
      "BackendTLSPolicy snapshot references {} ConfigMaps; maximum is {}",
      refs.len(),
      MAX_REFERENCED_CONFIG_MAPS
    );
  }
  Ok(refs)
}

fn validate_kubernetes_path_segment(label: &str, value: &str) -> anyhow::Result<()> {
  let valid = !value.is_empty()
    && value.len() <= 253
    && value != "."
    && value != ".."
    && value.bytes().all(|byte| {
      byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
    })
    && value
      .as_bytes()
      .first()
      .is_some_and(u8::is_ascii_alphanumeric)
    && value
      .as_bytes()
      .last()
      .is_some_and(u8::is_ascii_alphanumeric);
  if !valid {
    bail!("{label} is not a valid Kubernetes DNS path segment");
  }
  Ok(())
}

pub async fn run_poll_loop(
  kubernetes: KubernetesPoller,
  shared: &SharedArgs,
  args: &RunArgs,
  compatibility: &CompatibilityPolicy,
  health: ControllerHealth,
  leadership: Leadership,
  mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
  let interval = Duration::from_millis(args.poll_interval_ms.max(250));
  loop {
    if *shutdown.borrow() {
      return Ok(());
    }
    if leadership.is_leader() {
      match reconcile_once(&kubernetes, shared, args, compatibility).await {
        Ok(rollout_status) => health.mark_reconciled(rollout_status),
        Err(error) => {
          health.mark_failed(error.to_string());
          error!(error = %error, "Gateway API reconcile failed");
        }
      }
    }
    tokio::select! {
      changed = shutdown.changed() => {
        if changed.is_err() || *shutdown.borrow() {
          return Ok(());
        }
      }
      _ = tokio::time::sleep(interval) => {}
    }
  }
}

async fn reconcile_once(
  kubernetes: &KubernetesPoller,
  shared: &SharedArgs,
  args: &RunArgs,
  compatibility: &CompatibilityPolicy,
) -> anyhow::Result<RolloutStatus> {
  kubernetes
    .preflight_target_compatibility(args, compatibility)
    .await?;
  let objects = rollout::canonicalize_objects(&kubernetes.snapshot().await?);
  let rendered = translate::translate_objects(&objects, shared)?;
  status::print_diagnostics(&rendered.diagnostics);
  let rollout_status = if shared.dry_run {
    info!("dry-run enabled; immutable ConfigMap rollout was not applied");
    RolloutStatus::pending("DryRun")
  } else {
    apply_status_patches(
      kubernetes,
      &objects,
      shared,
      &rendered.diagnostics,
      &RolloutStatus::pending("RolloutInProgress"),
    )
    .await?;
    match kubernetes
      .reconcile_immutable_rollout(
        shared,
        args,
        compatibility,
        &rendered.toml,
        &rendered.assets,
      )
      .await
    {
      Ok(status) => status,
      Err(error) => {
        let rollout_status = RolloutStatus::failed("RolloutFailed");
        let failed_objects = rollout::canonicalize_objects(&kubernetes.snapshot().await?);
        apply_status_patches(
          kubernetes,
          &failed_objects,
          shared,
          &rendered.diagnostics,
          &rollout_status,
        )
        .await?;
        return Err(error);
      }
    }
  };
  let (status_objects, status_diagnostics, source_snapshot_digest) = if shared.dry_run {
    (
      objects.clone(),
      rendered.diagnostics.clone(),
      source_snapshot_digest(&objects),
    )
  } else {
    let fresh_objects = rollout::canonicalize_objects(&kubernetes.snapshot().await?);
    let fresh_rendered = translate::translate_objects(&fresh_objects, shared)?;
    if rollout_status.phase.is_committed()
      && (fresh_rendered.toml != rendered.toml || fresh_rendered.assets != rendered.assets)
    {
      bail!("Gateway API resources changed before status commit; refusing stale Programmed=True");
    }
    let digest = source_snapshot_digest(&fresh_objects);
    (fresh_objects, fresh_rendered.diagnostics, digest)
  };
  let mut rollout_status = rollout_status;
  if rollout_status.phase.is_committed() && !shared.dry_run {
    rollout_status.proof = Some(
      kubernetes
        .prove_committed_rollout(args, &rollout_status, source_snapshot_digest)
        .await?,
    );
  }
  apply_status_patches(
    kubernetes,
    &status_objects,
    shared,
    &status_diagnostics,
    &rollout_status,
  )
  .await?;
  Ok(rollout_status)
}

async fn apply_status_patches(
  kubernetes: &KubernetesPoller,
  objects: &[KubernetesObject],
  shared: &SharedArgs,
  diagnostics: &[super::model::Diagnostic],
  rollout_status: &RolloutStatus,
) -> anyhow::Result<()> {
  let status_patches = status::build_status_patches(objects, shared, diagnostics, rollout_status);
  if shared.dry_run {
    info!(
      patches = status_patches.len(),
      "dry-run enabled; Kubernetes status patches were not applied"
    );
  } else {
    kubernetes.apply_status_patches(&status_patches).await?;
  }
  Ok(())
}

fn source_snapshot_digest(objects: &[KubernetesObject]) -> String {
  let mut proof = objects
    .iter()
    .map(|object| {
      let data_digest = if object.data.is_empty() {
        String::new()
      } else {
        let encoded = serde_json::to_vec(&object.data).unwrap_or_default();
        let digest = Sha256::digest(encoded);
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
      };
      format!(
        "{}/{}/{}/{}/{}/{}/{}/{}",
        object.api_version,
        object.kind,
        object.namespace(),
        object.name(),
        object.metadata.uid.as_deref().unwrap_or(""),
        object.metadata.generation.unwrap_or_default(),
        object.metadata.resource_version.as_deref().unwrap_or(""),
        data_digest,
      )
    })
    .collect::<Vec<_>>();
  proof.sort();
  let digest = Sha256::digest(proof.join("\n").as_bytes());
  digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_list(body: Bytes) -> anyhow::Result<Vec<KubernetesObject>> {
  let value: Value =
    serde_json::from_slice(&body).context("failed to parse Kubernetes list JSON")?;
  KubernetesObject::from_value(value)
}

fn read_bearer_token(path: &Path) -> anyhow::Result<String> {
  let token =
    std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
  let token = token.trim();
  if token.is_empty() {
    bail!("Kubernetes service account token is empty");
  }
  Ok(format!("Bearer {token}"))
}

#[cfg(test)]
#[path = "watch/tests.rs"]
mod tests;
