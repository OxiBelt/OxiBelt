use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use http::Request;
use oxibelt::control_http::{ControlHttpClient, empty_body, full_body, uri_from_url};
use serde_json::{Value, json};
use tracing::{error, info, warn};
use url::Url;

use super::admin_sync::AdminSync;
use super::cli::{RunArgs, SharedArgs};
use super::model::KubernetesObject;
use super::status;
use super::translate;

const DEFAULT_SERVICE_ACCOUNT_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const DEFAULT_SERVICE_ACCOUNT_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const KUBERNETES_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

pub struct KubernetesPoller {
  client: ControlHttpClient,
  base_url: Url,
  bearer: String,
  namespace: Option<String>,
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
    let token = std::fs::read_to_string(token_path)
      .with_context(|| format!("failed to read {}", token_path.display()))?;
    let token = token.trim();
    if token.is_empty() {
      bail!("Kubernetes service account token is empty");
    }
    let ca_path = PathBuf::from(DEFAULT_SERVICE_ACCOUNT_CA);
    let ca_certs = ca_path
      .exists()
      .then_some(ca_path)
      .into_iter()
      .collect::<Vec<_>>();
    Ok(Self {
      client: ControlHttpClient::new(&ca_certs)?,
      base_url,
      bearer: format!("Bearer {token}"),
      namespace: args.watch_namespace.clone(),
    })
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
    let request = Request::builder()
      .method(http::Method::GET)
      .uri(uri_from_url(&url)?)
      .header(http::header::ACCEPT, "application/json")
      .header(http::header::AUTHORIZATION, self.bearer.as_str())
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
    let request = Request::builder()
      .method(http::Method::PATCH)
      .uri(uri_from_url(&url)?)
      .header(http::header::ACCEPT, "application/json")
      .header(http::header::AUTHORIZATION, self.bearer.as_str())
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
  admin: AdminSync,
  shared: &SharedArgs,
  args: &RunArgs,
) -> anyhow::Result<()> {
  let interval = Duration::from_millis(args.poll_interval_ms.max(250));
  loop {
    match reconcile_once(&kubernetes, &admin, shared).await {
      Ok(()) => {}
      Err(error) => error!(error = %error, "Gateway API reconcile failed"),
    }
    tokio::time::sleep(interval).await;
  }
}

async fn reconcile_once(
  kubernetes: &KubernetesPoller,
  admin: &AdminSync,
  shared: &SharedArgs,
) -> anyhow::Result<()> {
  let objects = kubernetes.snapshot().await?;
  let rendered = translate::translate_objects(&objects, shared)?;
  status::print_diagnostics(&rendered.diagnostics);
  let status_patches = status::build_status_patches(&objects, shared, &rendered.diagnostics);
  if shared.dry_run {
    info!(
      patches = status_patches.len(),
      "dry-run enabled; Kubernetes status patches were not applied"
    );
  } else if let Err(error) = kubernetes.apply_status_patches(&status_patches).await {
    warn!(error = %error, "Gateway API status patching failed");
  }
  let has_errors = rendered
    .diagnostics
    .iter()
    .any(|diagnostic| matches!(diagnostic.severity, super::model::DiagnosticSeverity::Error));
  if has_errors {
    bail!("translation produced blocking diagnostics; refusing to apply generated config");
  }
  if shared.dry_run {
    info!("dry-run enabled; generated OxiBelt config was not applied");
    return Ok(());
  }
  let response = admin
    .sync_managed_config(&shared.managed_config_path, &rendered.toml)
    .await?;
  info!(response = %response, "applied Gateway API generated OxiBelt config");
  Ok(())
}

fn parse_list(body: Bytes) -> anyhow::Result<Vec<KubernetesObject>> {
  let value: Value =
    serde_json::from_slice(&body).context("failed to parse Kubernetes list JSON")?;
  KubernetesObject::from_value(value)
}
