use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use http::Request;
use oxibelt::control_http::{ControlHttpClient, empty_body, full_body, uri_from_url};
use serde_json::{Value, json};
use tracing::{error, info, warn};
use url::Url;

use super::cli::{RunArgs, SharedArgs};
use super::health::ControllerHealth;
use super::model::KubernetesObject;
use super::rollout;
use super::rollout_status::RolloutStatus;
use super::status;
use super::translate;

const DEFAULT_SERVICE_ACCOUNT_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const DEFAULT_SERVICE_ACCOUNT_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
pub(super) const KUBERNETES_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

pub struct KubernetesPoller {
  pub(super) client: ControlHttpClient,
  pub(super) base_url: Url,
  pub(super) service_account_token_path: PathBuf,
  pub(super) namespace: Option<String>,
}

impl KubernetesPoller {
  pub fn from_environment(args: &SharedArgs) -> anyhow::Result<Self> {
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
    })
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
    match self
      .list_namespaced("/apis/gateway.networking.k8s.io/v1", "referencegrants")
      .await
    {
      Ok(grants) => objects.extend(grants),
      Err(error) => {
        warn!(error = %error, "Gateway API v1 ReferenceGrant list failed; trying v1beta1");
        objects.extend(
          self
            .list_namespaced("/apis/gateway.networking.k8s.io/v1beta1", "referencegrants")
            .await
            .unwrap_or_default(),
        );
      }
    }
    objects.extend(
      self
        .list_namespaced("/apis/gateway.networking.k8s.io/v1alpha2", "tcproutes")
        .await
        .unwrap_or_default(),
    );
    objects.extend(self.list_objects("/api/v1/namespaces").await?);
    objects.extend(self.list_namespaced("/api/v1", "services").await?);
    Ok(objects)
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
      return Ok(Vec::new());
    }
    if !response.status.is_success() {
      bail!("Kubernetes API {path} returned {}", response.status);
    }
    parse_list(response.body)
  }

  pub async fn apply_status_patches(&self, patches: &[status::StatusPatch]) -> anyhow::Result<()> {
    for patch in patches {
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
    let body = serde_json::to_vec(&json!({ "status": patch.status.clone() }))
      .context("failed to serialize Kubernetes status patch")?;
    let bearer = self.bearer()?;
    let request = Request::builder()
      .method(http::Method::PATCH)
      .uri(uri_from_url(&url)?)
      .header(http::header::ACCEPT, "application/json")
      .header(http::header::AUTHORIZATION, bearer)
      .header(http::header::CONTENT_TYPE, "application/merge-patch+json")
      .body(full_body(Bytes::from(body)))?;
    let response = self
      .client
      .request(request, Duration::from_secs(10), KUBERNETES_MAX_BODY_BYTES)
      .await?;
    if response.status == http::StatusCode::NOT_FOUND {
      warn!(
        path,
        "Kubernetes status subresource was not found; skipping status patch"
      );
      return Ok(());
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

pub async fn run_poll_loop(
  kubernetes: KubernetesPoller,
  shared: &SharedArgs,
  args: &RunArgs,
  health: ControllerHealth,
) -> anyhow::Result<()> {
  let interval = Duration::from_millis(args.poll_interval_ms.max(250));
  loop {
    match reconcile_once(&kubernetes, shared, args).await {
      Ok(rollout_status) => health.mark_reconciled(rollout_status),
      Err(error) => {
        health.mark_failed(error.to_string());
        error!(error = %error, "Gateway API reconcile failed");
      }
    }
    tokio::time::sleep(interval).await;
  }
}

async fn reconcile_once(
  kubernetes: &KubernetesPoller,
  shared: &SharedArgs,
  args: &RunArgs,
) -> anyhow::Result<RolloutStatus> {
  let objects = rollout::canonicalize_objects(&kubernetes.snapshot().await?);
  let rendered = translate::translate_objects(&objects, shared)?;
  status::print_diagnostics(&rendered.diagnostics);
  let has_errors = rendered
    .diagnostics
    .iter()
    .any(|diagnostic| matches!(diagnostic.severity, super::model::DiagnosticSeverity::Error));
  if has_errors {
    let rollout_status = RolloutStatus::failed("TranslationFailed");
    apply_status_patches(
      kubernetes,
      &objects,
      shared,
      &rendered.diagnostics,
      &rollout_status,
    )
    .await;
    bail!("translation produced blocking diagnostics; refusing to apply generated config");
  }
  let rollout_status = if shared.dry_run {
    info!("dry-run enabled; immutable ConfigMap rollout was not applied");
    RolloutStatus::pending("DryRun")
  } else {
    match kubernetes
      .reconcile_immutable_rollout(shared, args, &rendered.toml)
      .await
    {
      Ok(status) => status,
      Err(error) => {
        let rollout_status = RolloutStatus::failed("RolloutFailed");
        apply_status_patches(
          kubernetes,
          &objects,
          shared,
          &rendered.diagnostics,
          &rollout_status,
        )
        .await;
        return Err(error);
      }
    }
  };
  apply_status_patches(
    kubernetes,
    &objects,
    shared,
    &rendered.diagnostics,
    &rollout_status,
  )
  .await;
  Ok(rollout_status)
}

async fn apply_status_patches(
  kubernetes: &KubernetesPoller,
  objects: &[KubernetesObject],
  shared: &SharedArgs,
  diagnostics: &[super::model::Diagnostic],
  rollout_status: &RolloutStatus,
) {
  let status_patches = status::build_status_patches(objects, shared, diagnostics, rollout_status);
  if shared.dry_run {
    info!(
      patches = status_patches.len(),
      "dry-run enabled; Kubernetes status patches were not applied"
    );
  } else if let Err(error) = kubernetes.apply_status_patches(&status_patches).await {
    warn!(error = %error, "Gateway API status patching failed");
  }
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
