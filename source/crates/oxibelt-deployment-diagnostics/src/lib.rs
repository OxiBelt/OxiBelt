//! Read-only deployment diagnostics for rendered manifests, Helm, and Kubernetes.

mod checks;
mod kubernetes;
mod manifest;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, bail};
use k8s_openapi::api::{
  apps::v1::{DaemonSet, Deployment},
  autoscaling::v2::HorizontalPodAutoscaler,
};
use kube::{Api, Client, api::ListParams, discovery::Discovery};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use oxibelt::diagnostics::{DiagnosticReport, DiagnosticSeverity};

pub(crate) const MAX_MANIFEST_FILES: usize = 1_024;
pub(crate) const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_MANIFEST_DOCUMENTS: usize = 4_096;
const MAX_HELM_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_HELM_STDERR_BYTES: usize = 64 * 1024;
const HELM_TIMEOUT: Duration = Duration::from_secs(30);
const SUPPORTED_KUBERNETES_MIN_MINOR: u32 = 34;
const SUPPORTED_KUBERNETES_MAX_MINOR: u32 = 36;
const REQUIRED_GATEWAY_API_V1_RESOURCES: &[&str] = &[
  "backendtlspolicies",
  "gatewayclasses",
  "gateways",
  "grpcroutes",
  "httproutes",
  "referencegrants",
  "tcproutes",
  "tlsroutes",
  "udproutes",
];

fn helm_template_command(
  chart: &Path,
  values: &[PathBuf],
  release: &str,
  namespace: &str,
) -> Command {
  let mut command = Command::new("helm");
  command
    .arg("template")
    .arg("--namespace")
    .arg(namespace)
    .arg("--dry-run=client")
    .arg("--no-hooks")
    .arg("--disable-openapi-validation");
  for value_file in values {
    command.arg("--values").arg(value_file);
  }
  command
    .arg("--")
    .arg(release)
    .arg(chart)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);
  command
}

/// Options for read-only live Kubernetes inspection.
#[derive(Debug, Clone, Default)]
pub struct KubernetesDoctorOptions {
  pub context: Option<String>,
  pub namespace: Option<String>,
  pub all_namespaces: bool,
  pub selector: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Manifest {
  pub(crate) source: String,
  pub(crate) document: usize,
  pub(crate) default_namespace: String,
  pub(crate) value: Value,
}

/// Inspect a directory of rendered Kubernetes YAML. The directory may contain
/// multi-document YAML and `kind: List` envelopes, but no symlinks.
pub fn diagnose_rendered_directory(path: &Path) -> anyhow::Result<DiagnosticReport> {
  let files = manifest::collect_manifest_files(path)?;
  let mut manifests = Vec::new();
  let mut total_bytes = 0_usize;
  for file in files {
    let raw = manifest::read_bounded_file(&file, &mut total_bytes)?;
    manifest::append_yaml_manifests(
      &mut manifests,
      &manifest::safe_path_label(&file),
      "default",
      &raw,
    )?;
  }
  Ok(checks::diagnose_manifests(manifests))
}

/// Render a local Helm chart with client-only, non-hooked rendering and inspect
/// the resulting YAML. No repository or remote chart references are accepted.
pub async fn diagnose_helm_chart(
  chart: &Path,
  values: &[PathBuf],
  release: &str,
  namespace: &str,
) -> anyhow::Result<DiagnosticReport> {
  manifest::validate_helm_identifier("release", release)?;
  manifest::validate_helm_identifier("namespace", namespace)?;
  manifest::validate_chart_tree(chart)?;
  for value_file in values {
    manifest::ensure_regular_file(value_file, "Helm values file")?;
  }

  let mut command = helm_template_command(chart, values, release, namespace);

  let mut child = command
    .spawn()
    .context("failed to start Helm for local client-side rendering")?;
  let stdout = child
    .stdout
    .take()
    .ok_or_else(|| anyhow::anyhow!("Helm stdout pipe was unavailable"))?;
  let stderr = child
    .stderr
    .take()
    .ok_or_else(|| anyhow::anyhow!("Helm stderr pipe was unavailable"))?;
  let rendered = tokio::time::timeout(HELM_TIMEOUT, async {
    let (stdout, stderr, status) = tokio::join!(
      read_limited(stdout, MAX_HELM_OUTPUT_BYTES),
      drain_limited(stderr, MAX_HELM_STDERR_BYTES),
      child.wait(),
    );
    Ok::<_, anyhow::Error>((stdout?, stderr?, status?))
  })
  .await;
  let (stdout, _stderr_bytes, status) = match rendered {
    Ok(result) => result?,
    Err(_) => {
      let _ = child.kill().await;
      let _ = child.wait().await;
      bail!(
        "helm template exceeded the {} second safety timeout",
        HELM_TIMEOUT.as_secs()
      );
    }
  };
  if !status.success() {
    bail!(
      "helm template failed with status {}; stderr is intentionally not included in doctor output",
      status
    );
  }
  let raw = std::str::from_utf8(&stdout).context("helm template produced non-UTF-8 YAML output")?;
  let mut manifests = Vec::new();
  manifest::append_yaml_manifests(
    &mut manifests,
    &format!("helm://{release}/{namespace}"),
    namespace,
    raw,
  )?;
  Ok(checks::diagnose_manifests(manifests))
}

/// List only workload and autoscaler resources from Kubernetes, then inspect
/// their serialized manifests. This function never reads Secrets or writes.
pub async fn diagnose_kubernetes(
  options: &KubernetesDoctorOptions,
) -> anyhow::Result<DiagnosticReport> {
  let config = manifest::load_safe_kubernetes_config(options).await?;
  let config = kubernetes::DirectKubernetesConfig::try_from(config)?;
  let namespace = options
    .namespace
    .clone()
    .unwrap_or_else(|| config.default_namespace().to_owned());
  let client = config.into_client()?;
  let mut live_report = DiagnosticReport::new();
  diagnose_kubernetes_server(&client, &mut live_report).await;
  diagnose_gateway_api(&client, &mut live_report).await;
  let list_params = options
    .selector
    .as_deref()
    .map_or_else(ListParams::default, |selector| {
      ListParams::default().labels(selector)
    });

  let deployments = list_resources::<Deployment>(client.clone(), &namespace, options, &list_params)
    .await
    .context("failed to list Kubernetes Deployments")?;
  let daemon_sets = list_resources::<DaemonSet>(client.clone(), &namespace, options, &list_params)
    .await
    .context("failed to list Kubernetes DaemonSets")?;
  let autoscalers =
    list_resources::<HorizontalPodAutoscaler>(client, &namespace, options, &list_params)
      .await
      .context("failed to list Kubernetes HorizontalPodAutoscalers")?;

  let mut manifests = Vec::new();
  for deployment in deployments {
    push_kubernetes_manifest(&mut manifests, "Deployment", deployment)?;
  }
  for daemon_set in daemon_sets {
    push_kubernetes_manifest(&mut manifests, "DaemonSet", daemon_set)?;
  }
  for autoscaler in autoscalers {
    push_kubernetes_manifest(&mut manifests, "HorizontalPodAutoscaler", autoscaler)?;
  }
  let mut report = checks::diagnose_manifests(manifests);
  for finding in live_report.findings {
    report.push(
      finding.severity,
      &finding.id,
      &finding.category,
      finding.target,
      finding.message,
      finding.remediation,
    );
  }
  Ok(report.finish())
}

async fn diagnose_kubernetes_server(client: &Client, report: &mut DiagnosticReport) {
  match client.apiserver_version().await {
    Ok(version) => diagnose_server_version(
      report,
      &version.git_version,
      &version.major,
      &version.minor,
    ),
    Err(_) => report.push(
      DiagnosticSeverity::Error,
      "kubernetes.unsupported_server_version",
      "kubernetes",
      "kubernetes://version",
      "Kubernetes API server version could not be read",
      "Grant read-only access to the non-resource /version endpoint and verify Kubernetes 1.34 through 1.36.",
    ),
  }
}

fn diagnose_server_version(
  report: &mut DiagnosticReport,
  git_version: &str,
  major: &str,
  minor: &str,
) {
  let parsed = minor
    .bytes()
    .take_while(u8::is_ascii_digit)
    .try_fold(0_u32, |value, digit| {
      value.checked_mul(10)?.checked_add(u32::from(digit - b'0'))
    });
  if major != "1"
    || parsed.is_none_or(|minor| {
      !(SUPPORTED_KUBERNETES_MIN_MINOR..=SUPPORTED_KUBERNETES_MAX_MINOR).contains(&minor)
    })
  {
    report.push(
      DiagnosticSeverity::Error,
      "kubernetes.unsupported_server_version",
      "kubernetes",
      "kubernetes://version",
      format!(
        "Kubernetes API server {git_version} is outside the qualified 1.{SUPPORTED_KUBERNETES_MIN_MINOR} through 1.{SUPPORTED_KUBERNETES_MAX_MINOR} range"
      ),
      "Use a qualified Kubernetes minor or keep the Kubernetes feature state experimental.",
    );
  }
}

async fn diagnose_gateway_api(client: &Client, report: &mut DiagnosticReport) {
  let discovery = Discovery::new(client.clone())
    .filter(&["gateway.networking.k8s.io"])
    .run()
    .await;
  let served = match discovery {
    Ok(discovery) => discovery
      .groups()
      .find(|group| group.name() == "gateway.networking.k8s.io")
      .map(|group| {
        group
          .versioned_resources("v1")
          .into_iter()
          .map(|(resource, _)| resource.plural)
          .collect::<BTreeSet<_>>()
      })
      .unwrap_or_default(),
    Err(_) => {
      report.push(
        DiagnosticSeverity::Error,
        "kubernetes.required_gateway_api_missing",
        "kubernetes",
        "kubernetes://apis/gateway.networking.k8s.io/v1",
        "Gateway API discovery failed; required served v1 resources could not be verified",
        "Install the pinned standard Gateway API CRD bundle and permit read-only API discovery.",
      );
      return;
    }
  };
  diagnose_gateway_resources(report, &served);
}

fn diagnose_gateway_resources(report: &mut DiagnosticReport, served: &BTreeSet<String>) {
  let missing = REQUIRED_GATEWAY_API_V1_RESOURCES
    .iter()
    .copied()
    .filter(|resource| !served.contains(*resource))
    .collect::<Vec<_>>();
  if !missing.is_empty() {
    report.push(
      DiagnosticSeverity::Error,
      "kubernetes.required_gateway_api_missing",
      "kubernetes",
      "kubernetes://apis/gateway.networking.k8s.io/v1",
      format!(
        "required Gateway API v1 resources are not served: {}",
        missing.join(", ")
      ),
      "Install the pinned standard Gateway API CRD bundle before starting the Gateway Controller.",
    );
  }
}

async fn list_resources<T>(
  client: Client,
  namespace: &str,
  options: &KubernetesDoctorOptions,
  list_params: &ListParams,
) -> anyhow::Result<Vec<T>>
where
  T: kube::Resource<DynamicType = (), Scope = kube::core::NamespaceResourceScope>
    + Clone
    + serde::de::DeserializeOwned
    + std::fmt::Debug,
{
  let api = if options.all_namespaces {
    Api::<T>::all(client)
  } else {
    Api::<T>::namespaced(client, namespace)
  };
  Ok(api.list(list_params).await?.items)
}

fn push_kubernetes_manifest<T>(
  manifests: &mut Vec<Manifest>,
  kind: &str,
  resource: T,
) -> anyhow::Result<()>
where
  T: serde::Serialize,
{
  let value = serde_json::to_value(resource).context("failed to serialize Kubernetes resource")?;
  let name = value
    .pointer("/metadata/name")
    .and_then(Value::as_str)
    .unwrap_or("unnamed");
  let namespace = value
    .pointer("/metadata/namespace")
    .and_then(Value::as_str)
    .unwrap_or("default");
  manifests.push(Manifest {
    source: format!("kubernetes://{kind}/{namespace}/{name}"),
    document: 1,
    default_namespace: namespace.to_string(),
    value,
  });
  Ok(())
}

async fn read_limited<R>(mut reader: R, maximum: usize) -> io::Result<Vec<u8>>
where
  R: AsyncRead + Unpin,
{
  let mut output = Vec::new();
  let mut buffer = [0_u8; 8_192];
  loop {
    let count = reader.read(&mut buffer).await?;
    if count == 0 {
      return Ok(output);
    }
    if output.len().saturating_add(count) > maximum {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Helm stdout exceeds the doctor inspection limit",
      ));
    }
    output.extend_from_slice(&buffer[..count]);
  }
}

async fn drain_limited<R>(mut reader: R, maximum: usize) -> io::Result<usize>
where
  R: AsyncRead + Unpin,
{
  let mut total = 0_usize;
  let mut buffer = [0_u8; 4_096];
  loop {
    let count = reader.read(&mut buffer).await?;
    if count == 0 {
      return Ok(total);
    }
    total = total.saturating_add(count);
    if total > maximum {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Helm stderr exceeds the doctor inspection limit",
      ));
    }
  }
}
