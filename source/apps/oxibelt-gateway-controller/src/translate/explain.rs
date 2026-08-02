//! Bounded, deterministic and redacted translation evidence.

use serde::Serialize;

use super::super::cli::SharedArgs;
use super::super::model::{DiagnosticSeverity, KubernetesObject, object_ref};
use super::super::rollout::{ConfigArtifactAsset, digest_artifact_bundle, digest_content};
use super::{RenderedAsset, TranslationState};

const EXPLAIN_SCHEMA_VERSION: &str = "gateway.oxibelt.dev/explain-v1alpha1";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TranslationExplanation {
  schema_version: &'static str,
  experimental: bool,
  qualification: &'static str,
  source_snapshot_digest: String,
  artifact_digest: String,
  content_digest: String,
  validation: ExplainValidation,
  sources: Vec<ExplainSource>,
  fragments: Vec<ExplainFragment>,
  policies: Vec<ExplainPolicy>,
  target_assignments: Vec<String>,
  diagnostics: Vec<ExplainDiagnostic>,
  rollout_receipts: Vec<ExplainRolloutReceipt>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExplainValidation {
  valid: bool,
  requires_exact_data_plane: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExplainSource {
  object: String,
  uid: Option<String>,
  resource_version: Option<String>,
  generation: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExplainFragment {
  kind: &'static str,
  name: String,
  source: String,
  policy: Option<String>,
  backends: Vec<ExplainBackend>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExplainBackend {
  identity: String,
  service: Option<String>,
  normalized_weight: u32,
  discovery: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExplainPolicy {
  route: String,
  source: String,
  waf_request_rule_groups: Vec<String>,
  max_request_body_bytes: Option<u64>,
  upstream_request_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExplainDiagnostic {
  severity: &'static str,
  code: &'static str,
  object: String,
  message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExplainRolloutReceipt {
  target: String,
  active_generation: Option<i64>,
  artifact_digest: Option<String>,
  state: &'static str,
}

pub(super) fn build_explanation(
  objects: &[KubernetesObject],
  state: &TranslationState,
  args: &SharedArgs,
  toml: &str,
  assets: &[RenderedAsset],
) -> anyhow::Result<TranslationExplanation> {
  let artifact_assets = assets
    .iter()
    .map(|asset| ConfigArtifactAsset {
      data_key: asset.data_key.clone(),
      managed_path: asset.managed_path.clone(),
      content: asset.content.clone(),
    })
    .collect::<Vec<_>>();
  let artifact_digest =
    digest_artifact_bundle(&args.managed_config_path, toml.as_bytes(), &artifact_assets);
  let requires_exact_data_plane = state.pools.values().any(|pool| pool.discoveries.len() > 1);
  let sources = objects
    .iter()
    .filter(|object| object.kind != "Secret")
    .map(|object| ExplainSource {
      object: object_ref(object),
      uid: object.metadata.uid.clone(),
      resource_version: object.metadata.resource_version.clone(),
      generation: object.metadata.generation,
    })
    .collect();
  let mut fragments = Vec::new();
  for auth in state.external_auth.values() {
    fragments.push(ExplainFragment {
      kind: "external_auth",
      name: auth.name.clone(),
      source: auth.source.clone(),
      policy: None,
      backends: Vec::new(),
    });
  }
  for pool in state.pools.values() {
    let mut backends = pool
      .servers
      .iter()
      .map(|server| ExplainBackend {
        identity: server.id.clone(),
        service: None,
        normalized_weight: server.weight,
        discovery: false,
      })
      .collect::<Vec<_>>();
    backends.extend(pool.discoveries.iter().map(|discovery| ExplainBackend {
      identity: discovery.id.clone(),
      service: Some(format!("{}/{}", discovery.namespace, discovery.service)),
      normalized_weight: discovery.weight_multiplier,
      discovery: true,
    }));
    fragments.push(ExplainFragment {
      kind: "upstream_pool",
      name: pool.name.clone(),
      source: pool.source.clone(),
      policy: None,
      backends,
    });
  }
  for route in &state.routes {
    fragments.push(ExplainFragment {
      kind: "route",
      name: route.name.clone(),
      source: route.source.clone(),
      policy: route.policy_source.clone(),
      backends: Vec::new(),
    });
  }
  for rule in &state.sni_rules {
    fragments.push(ExplainFragment {
      kind: "sni_rule",
      name: rule.name.clone(),
      source: rule.source.clone(),
      policy: None,
      backends: Vec::new(),
    });
  }
  for listener in state.stream_listeners.values() {
    fragments.push(ExplainFragment {
      kind: "stream_listener",
      name: listener.name.clone(),
      source: listener.source.clone(),
      policy: None,
      backends: Vec::new(),
    });
  }
  fragments.sort_by(|left, right| {
    (left.kind, left.name.as_str(), left.source.as_str()).cmp(&(
      right.kind,
      right.name.as_str(),
      right.source.as_str(),
    ))
  });
  let mut policies = state
    .routes
    .iter()
    .filter_map(|route| {
      route.policy_source.as_ref().map(|source| ExplainPolicy {
        route: route.name.clone(),
        source: source.clone(),
        waf_request_rule_groups: route.waf_request_rule_groups.clone(),
        max_request_body_bytes: route.max_request_body_bytes,
        upstream_request_timeout_ms: route.upstream_request_timeout_ms,
      })
    })
    .collect::<Vec<_>>();
  policies.sort_by(|left, right| {
    (left.route.as_str(), left.source.as_str()).cmp(&(right.route.as_str(), right.source.as_str()))
  });
  let target_assignments = objects
    .iter()
    .filter(|object| object.kind == "OxiBeltDataPlaneTarget")
    .map(object_ref)
    .collect::<Vec<_>>();
  let diagnostics = state
    .diagnostics
    .iter()
    .map(|diagnostic| ExplainDiagnostic {
      severity: match diagnostic.severity {
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Error => "error",
      },
      code: diagnostic.code.as_str(),
      object: diagnostic.object.clone(),
      message: diagnostic.message.clone(),
    })
    .collect::<Vec<_>>();
  let valid = !state
    .diagnostics
    .iter()
    .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error);
  Ok(TranslationExplanation {
    schema_version: EXPLAIN_SCHEMA_VERSION,
    experimental: true,
    qualification: "experimental-unqualified",
    source_snapshot_digest: super::super::watch::redacted_source_snapshot_digest(objects),
    artifact_digest: format!("sha256:{artifact_digest}"),
    content_digest: format!("sha256:{}", digest_content(toml.as_bytes())),
    validation: ExplainValidation {
      valid,
      requires_exact_data_plane,
    },
    sources,
    fragments,
    policies,
    target_assignments,
    diagnostics,
    rollout_receipts: Vec::new(),
  })
}

impl TranslationExplanation {
  pub fn select(mut self, gateway: Option<&str>, route: Option<&str>) -> anyhow::Result<Self> {
    let gateway = gateway.map(parse_selector).transpose()?;
    let route = route.map(parse_selector).transpose()?;
    let gateway_object = gateway.map(|(namespace, name)| format!("Gateway/{namespace}/{name}"));
    let route_suffix = route.map(|(namespace, name)| format!("/{namespace}/{name}"));
    if gateway_object.is_some() || route_suffix.is_some() {
      self.sources.retain(|source| {
        gateway_object
          .as_ref()
          .is_some_and(|object| source.object == *object)
          || route_suffix
            .as_ref()
            .is_some_and(|suffix| source.object.ends_with(suffix))
      });
    }
    if let Some(route_suffix) = route_suffix {
      self.fragments.retain(|fragment| {
        let source_prefix = fragment.source.split_whitespace().next().unwrap_or("");
        source_prefix.ends_with(&route_suffix)
      });
      self
        .diagnostics
        .retain(|diagnostic| diagnostic.object.ends_with(&route_suffix));
    }
    Ok(self)
  }
}

fn parse_selector(value: &str) -> anyhow::Result<(&str, &str)> {
  let Some((namespace, name)) = value.split_once('/') else {
    anyhow::bail!("explain selectors must use namespace/name");
  };
  if namespace.is_empty()
    || name.is_empty()
    || name.contains('/')
    || !namespace
      .bytes()
      .chain(name.bytes())
      .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
  {
    anyhow::bail!("explain selectors must use lowercase Kubernetes namespace/name values");
  }
  Ok((namespace, name))
}
