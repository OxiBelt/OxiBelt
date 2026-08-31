use std::collections::{BTreeSet, HashSet};
use std::time::Duration;

use anyhow::{Context, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::cli::RunArgs;
use super::model::{KubernetesObject, ObjectKey};
use super::rollout::{RolloutPhase, RolloutTarget, WorkloadKind};
use super::rollout_status::RolloutStatus;
use super::status::StatusPatch;

pub const API_VERSION: &str = "gateway.oxibelt.dev/v1alpha1";
pub const KIND: &str = "OxiBeltDataPlaneTarget";
pub const POLICY_VERSION: &str = "v1alpha1";
pub const MAX_TARGETS: usize = 32;
const MAX_ALLOWED_NAMESPACES: usize = 64;
const MAX_CAPABILITIES: usize = 32;
const MAX_TIMEOUT_SECONDS: u64 = 3_600;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PlannedTarget {
  pub resource: ObjectKey,
  pub resource_version: Option<String>,
  pub observed_generation: i64,
  pub gateway_class_name: String,
  pub allowed_namespaces: BTreeSet<String>,
  pub capabilities: Vec<String>,
  pub policy_version: String,
  pub rollout: RolloutTarget,
}

impl PlannedTarget {
  pub fn identity(&self) -> String {
    format!("{}/{}", self.resource.namespace, self.resource.name)
  }

  pub fn bound_toml(&self, source_snapshot_digest: &str, generated_toml: &str) -> String {
    let capabilities = self.capabilities.join(",");
    let allowed_namespaces = self
      .allowed_namespaces
      .iter()
      .cloned()
      .collect::<Vec<_>>()
      .join(",");
    format!(
      "# oxibelt-data-plane-target-artifact-v1\n\
       # target = {}\n\
       # target_context = {}\n\
       # workload = {}/{}/{}\n\
       # gateway_class = {}\n\
       # allowed_namespaces = {}\n\
       # policy_version = {}\n\
       # capabilities = {}\n\
       # source_snapshot_digest = {}\n{}",
      self.identity(),
      self
        .rollout
        .artifact_context
        .as_deref()
        .expect("typed targets always have an artifact context"),
      self.rollout.namespace,
      self.rollout.kind.label_value(),
      self.rollout.name,
      self.gateway_class_name,
      allowed_namespaces,
      self.policy_version,
      capabilities,
      source_snapshot_digest,
      generated_toml,
    )
  }

  pub fn selects_gateway(&self, gateway: &KubernetesObject) -> bool {
    gateway.kind == "Gateway"
      && self.allowed_namespaces.contains(gateway.namespace())
      && gateway.spec.get("gatewayClassName").and_then(Value::as_str)
        == Some(self.gateway_class_name.as_str())
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TargetSet {
  Legacy(RolloutTarget),
  StaticReplicated(Vec<PlannedTarget>),
}

impl TargetSet {
  pub fn from_objects(
    objects: &[KubernetesObject],
    args: &RunArgs,
    controller_name: &str,
  ) -> anyhow::Result<Self> {
    let resources = objects
      .iter()
      .filter(|object| object.kind == KIND)
      .collect::<Vec<_>>();
    if resources.is_empty() {
      return Ok(Self::Legacy(RolloutTarget::from_args(args)?));
    }
    if resources.len() > MAX_TARGETS {
      bail!(
        "OxiBeltDataPlaneTarget snapshot contains {} targets; maximum is {MAX_TARGETS}",
        resources.len()
      );
    }
    if let Some(resource) = resources
      .iter()
      .find(|resource| resource.api_version != API_VERSION)
    {
      bail!(
        "OxiBeltDataPlaneTarget {}/{} uses unsupported apiVersion `{}`; expected `{API_VERSION}`",
        resource.namespace(),
        resource.name(),
        resource.api_version,
      );
    }

    let owned_classes = objects
      .iter()
      .filter(|object| object.kind == "GatewayClass")
      .filter(|object| {
        object.spec.get("controllerName").and_then(Value::as_str) == Some(controller_name)
      })
      .map(KubernetesObject::name)
      .collect::<HashSet<_>>();
    let mut targets = resources
      .into_iter()
      .map(parse_target)
      .collect::<anyhow::Result<Vec<_>>>()?;
    targets.sort_by(|left, right| left.resource.cmp(&right.resource));

    let mut workloads = HashSet::new();
    let target_classes = targets
      .iter()
      .map(|target| target.gateway_class_name.as_str())
      .collect::<HashSet<_>>();
    if target_classes.len() != 1 || owned_classes.len() != 1 {
      bail!(
        "OxiBeltDataPlaneTarget v1alpha1 requires one static replicated target set for the controller's one owned GatewayClass"
      );
    }
    for target in &targets {
      if !owned_classes.contains(target.gateway_class_name.as_str()) {
        bail!(
          "OxiBeltDataPlaneTarget {} selects GatewayClass `{}` that is absent or not owned by controller `{controller_name}`",
          target.identity(),
          target.gateway_class_name,
        );
      }
      let workload = (
        target.rollout.namespace.clone(),
        target.rollout.kind,
        target.rollout.name.clone(),
      );
      if !workloads.insert(workload) {
        bail!(
          "OxiBeltDataPlaneTarget {} conflicts with another target selecting the same workload",
          target.identity()
        );
      }
    }
    for gateway in objects.iter().filter(|object| {
      object.kind == "Gateway"
        && object
          .spec
          .get("gatewayClassName")
          .and_then(Value::as_str)
          .is_some_and(|name| target_classes.contains(name))
    }) {
      if !targets.iter().any(|target| target.selects_gateway(gateway)) {
        bail!(
          "Gateway {}/{} has no allowed OxiBeltDataPlaneTarget assignment",
          gateway.namespace(),
          gateway.name()
        );
      }
    }
    Ok(Self::StaticReplicated(targets))
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TargetOutcome {
  pub target: PlannedTarget,
  pub source_snapshot_digest: String,
  pub translation_succeeded: bool,
  pub rollout: Option<RolloutStatus>,
  pub failure_reason: Option<&'static str>,
}

impl TargetOutcome {
  pub fn status_patch(&self) -> StatusPatch {
    let generation = self.target.observed_generation;
    let programmed = self
      .rollout
      .as_ref()
      .is_some_and(RolloutStatus::is_committed)
      && self.failure_reason.is_none();
    let state = match self.rollout.as_ref().map(|status| status.phase) {
      Some(RolloutPhase::RollbackRequested) => "RollingBack",
      Some(RolloutPhase::RolledBack | RolloutPhase::Failed) => "Degraded",
      _ if self.failure_reason.is_some() => "Blocked",
      None | Some(RolloutPhase::Generated) => "Pending",
      Some(RolloutPhase::Validated) => "Validating",
      Some(
        RolloutPhase::CanaryApplying
        | RolloutPhase::CanaryHealthy
        | RolloutPhase::Expanding
        | RolloutPhase::FullyApplied,
      ) => "Applying",
      Some(RolloutPhase::Committed) => "Active",
    };
    let reason = self.failure_reason.unwrap_or(if programmed {
      "TargetActive"
    } else {
      "RolloutPending"
    });
    let message = if programmed {
      "The assigned target proves its independent immutable artifact is active"
    } else if self.failure_reason.is_some() {
      "The assigned target failed independently; other target rollouts were not changed"
    } else {
      "The assigned target is waiting for independent immutable rollout convergence"
    };
    let now = super::kubernetes_time::rfc3339_now();
    let mut status = serde_json::json!({
      "observedGeneration": generation,
      "state": state,
      "sourceSnapshotDigest": format!("sha256:{}", self.source_snapshot_digest),
      "conditions": [
        {
          "type": "Assigned",
          "status": "True",
          "reason": "StaticReplicated",
          "message": format!(
            "GatewayClass {} is assigned by operator-owned target policy {}",
            self.target.gateway_class_name,
            self.target.policy_version,
          ),
          "observedGeneration": generation,
          "lastTransitionTime": now,
        },
        {
          "type": "Translated",
          "status": if self.translation_succeeded { "True" } else { "False" },
          "reason": if self.translation_succeeded { "TranslationSucceeded" } else { "TranslationFailed" },
          "message": if self.translation_succeeded {
            "The assigned Gateway snapshot translated without blocking diagnostics"
          } else {
            "The assigned Gateway snapshot has blocking translation diagnostics"
          },
          "observedGeneration": generation,
          "lastTransitionTime": now,
        },
        {
          "type": "Programmed",
          "status": if programmed { "True" } else { "False" },
          "reason": reason,
          "message": message,
          "observedGeneration": generation,
          "lastTransitionTime": now,
        }
      ],
    });
    if let Some(revision) = self
      .rollout
      .as_ref()
      .and_then(|rollout| rollout.desired_revision.as_deref())
    {
      if let Some(digest) = revision.rsplit('-').next().filter(|digest| {
        digest.len() == 64
          && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
      }) {
        status["artifactDigest"] = Value::String(format!("sha256:{digest}"));
      }
      if programmed
        || self
          .rollout
          .as_ref()
          .is_some_and(|rollout| rollout.phase == RolloutPhase::Committed)
      {
        status["activeRevision"] = Value::String(revision.to_string());
      } else if self
        .rollout
        .as_ref()
        .is_some_and(|rollout| rollout.phase == RolloutPhase::RollbackRequested)
      {
        status["rollbackRevision"] = Value::String(revision.to_string());
      }
    }
    StatusPatch {
      api_prefix: "/apis/gateway.oxibelt.dev/v1alpha1",
      resource: "oxibeltdataplanetargets",
      namespace: Some(self.target.resource.namespace.clone()),
      name: self.target.resource.name.clone(),
      resource_version: self.target.resource_version.clone(),
      status,
    }
  }
}

pub fn objects_for_target(
  objects: &[KubernetesObject],
  target: &PlannedTarget,
  status_service: Option<&str>,
) -> Vec<KubernetesObject> {
  let gateways = objects
    .iter()
    .filter(|object| target.selects_gateway(object))
    .map(KubernetesObject::key)
    .collect::<BTreeSet<_>>();
  let selected_routes = objects
    .iter()
    .filter(|object| is_route_kind(&object.kind))
    .filter(|route| route_attaches_to_gateway(route, &gateways))
    .map(|route| (route.kind.clone(), route.key()))
    .collect::<BTreeSet<_>>();
  let selected_route_objects = objects
    .iter()
    .filter(|route| selected_routes.contains(&(route.kind.clone(), route.key())))
    .collect::<Vec<_>>();
  let mut service_keys = selected_route_objects
    .iter()
    .flat_map(|route| service_refs_for_route(route))
    .collect::<BTreeSet<_>>();
  if let Some((namespace, name)) = status_service.and_then(|value| value.split_once('/'))
    && !namespace.is_empty()
    && !name.is_empty()
    && !name.contains('/')
  {
    service_keys.insert(ObjectKey {
      namespace: namespace.to_string(),
      name: name.to_string(),
    });
  }
  let backend_tls_policies = objects
    .iter()
    .filter(|object| object.kind == "BackendTLSPolicy")
    .filter(|policy| backend_tls_target(policy).is_some_and(|key| service_keys.contains(&key)))
    .map(KubernetesObject::key)
    .collect::<BTreeSet<_>>();
  let config_map_keys = objects
    .iter()
    .filter(|object| {
      object.kind == "BackendTLSPolicy" && backend_tls_policies.contains(&object.key())
    })
    .flat_map(backend_tls_config_map_refs)
    .collect::<BTreeSet<_>>();
  let client_secret_keys = objects
    .iter()
    .filter(|object| object.kind == "Gateway" && gateways.contains(&object.key()))
    .filter_map(|gateway| {
      super::upstream_client_tls::gateway_secret_reference(gateway)
        .ok()
        .flatten()
    })
    .collect::<BTreeSet<_>>();
  let selected_namespaces = gateways
    .iter()
    .map(|key| key.namespace.clone())
    .chain(selected_routes.iter().map(|(_, key)| key.namespace.clone()))
    .collect::<BTreeSet<_>>();

  let mut selected = objects
    .iter()
    .filter(|object| match object.kind.as_str() {
      "GatewayClass" => object.name() == target.gateway_class_name,
      "Gateway" => gateways.contains(&object.key()),
      kind if is_route_kind(kind) => selected_routes.contains(&(kind.to_string(), object.key())),
      "OxiBeltRoutePolicy" => {
        route_policy_targets_selected_route(object, &selected_routes, &selected_route_objects)
      }
      "Service" => service_keys.contains(&object.key()),
      "BackendTLSPolicy" => backend_tls_policies.contains(&object.key()),
      "ConfigMap" => config_map_keys.contains(&object.key()),
      "Secret" => client_secret_keys.contains(&object.key()),
      "ReferenceGrant" => {
        reference_grant_supports_selected_backend(object, &selected_routes, &service_keys)
          || reference_grant_supports_selected_gateway_secret(
            object,
            &gateways,
            &client_secret_keys,
          )
      }
      "Namespace" => selected_namespaces.contains(object.name()),
      KIND => false,
      _ => false,
    })
    .cloned()
    .collect::<Vec<_>>();
  selected.sort_by(|left, right| {
    (
      left.api_version.as_str(),
      left.kind.as_str(),
      left.namespace(),
      left.name(),
    )
      .cmp(&(
        right.api_version.as_str(),
        right.kind.as_str(),
        right.namespace(),
        right.name(),
      ))
  });
  selected
}

fn reference_grant_supports_selected_gateway_secret(
  grant: &KubernetesObject,
  gateways: &BTreeSet<ObjectKey>,
  secrets: &BTreeSet<ObjectKey>,
) -> bool {
  let from_matches = grant
    .spec
    .get("from")
    .and_then(Value::as_array)
    .is_some_and(|entries| {
      entries.iter().any(|entry| {
        entry.get("group").and_then(Value::as_str) == Some(super::gateway_policy::GATEWAY_GROUP)
          && entry.get("kind").and_then(Value::as_str) == Some("Gateway")
          && entry
            .get("namespace")
            .and_then(Value::as_str)
            .is_some_and(|namespace| gateways.iter().any(|key| key.namespace == namespace))
      })
    });
  from_matches
    && grant
      .spec
      .get("to")
      .and_then(Value::as_array)
      .is_some_and(|entries| {
        entries.iter().any(|entry| {
          entry
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
            && entry.get("kind").and_then(Value::as_str) == Some("Secret")
            && secrets.iter().any(|secret| {
              secret.namespace == grant.namespace()
                && entry
                  .get("name")
                  .and_then(Value::as_str)
                  .is_none_or(|name| secret.name == name)
            })
        })
      })
}

fn service_refs_for_route(route: &KubernetesObject) -> Vec<ObjectKey> {
  fn insert_ref(route: &KubernetesObject, reference: &Value, services: &mut BTreeSet<ObjectKey>) {
    let group = reference.get("group").and_then(Value::as_str).unwrap_or("");
    let kind = reference
      .get("kind")
      .and_then(Value::as_str)
      .unwrap_or("Service");
    let Some(name) = reference.get("name").and_then(Value::as_str) else {
      return;
    };
    if group.is_empty() && kind == "Service" {
      services.insert(ObjectKey {
        namespace: reference
          .get("namespace")
          .and_then(Value::as_str)
          .unwrap_or_else(|| route.namespace())
          .to_string(),
        name: name.to_string(),
      });
    }
  }

  let mut services = BTreeSet::new();
  for rule in route
    .spec
    .get("rules")
    .and_then(Value::as_array)
    .into_iter()
    .flatten()
  {
    for backend in rule
      .get("backendRefs")
      .and_then(Value::as_array)
      .into_iter()
      .flatten()
    {
      insert_ref(route, backend, &mut services);
    }
    for filter in rule
      .get("filters")
      .and_then(Value::as_array)
      .into_iter()
      .flatten()
    {
      for pointer in ["/requestMirror/backendRef", "/externalAuth/backendRef"] {
        if let Some(reference) = filter.pointer(pointer) {
          insert_ref(route, reference, &mut services);
        }
      }
    }
  }
  services.into_iter().collect()
}

fn backend_tls_target(policy: &KubernetesObject) -> Option<ObjectKey> {
  let target = policy.spec.get("targetRefs")?.as_array()?.first()?;
  let group = target.get("group").and_then(Value::as_str).unwrap_or("");
  let kind = target
    .get("kind")
    .and_then(Value::as_str)
    .unwrap_or("Service");
  if !group.is_empty() || kind != "Service" {
    return None;
  }
  Some(ObjectKey {
    namespace: policy.namespace().to_string(),
    name: target.get("name").and_then(Value::as_str)?.to_string(),
  })
}

fn backend_tls_config_map_refs(policy: &KubernetesObject) -> Vec<ObjectKey> {
  policy
    .spec
    .pointer("/validation/caCertificateRefs")
    .and_then(Value::as_array)
    .into_iter()
    .flatten()
    .filter_map(|reference| {
      let group = reference.get("group").and_then(Value::as_str).unwrap_or("");
      let kind = reference
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("ConfigMap");
      if !group.is_empty() || kind != "ConfigMap" {
        return None;
      }
      Some(ObjectKey {
        namespace: policy.namespace().to_string(),
        name: reference.get("name").and_then(Value::as_str)?.to_string(),
      })
    })
    .collect()
}

fn reference_grant_supports_selected_backend(
  grant: &KubernetesObject,
  routes: &BTreeSet<(String, ObjectKey)>,
  services: &BTreeSet<ObjectKey>,
) -> bool {
  let from_matches = grant
    .spec
    .get("from")
    .and_then(Value::as_array)
    .is_some_and(|from_entries| {
      from_entries.iter().any(|from| {
        from.get("group").and_then(Value::as_str) == Some(super::gateway_policy::GATEWAY_GROUP)
          && from
            .get("kind")
            .and_then(Value::as_str)
            .zip(from.get("namespace").and_then(Value::as_str))
            .is_some_and(|(kind, namespace)| {
              routes
                .iter()
                .any(|(route_kind, key)| route_kind == kind && key.namespace == namespace)
            })
      })
    });
  from_matches
    && grant
      .spec
      .get("to")
      .and_then(Value::as_array)
      .is_some_and(|to_entries| {
        to_entries.iter().any(|to| {
          to.get("group")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
            && to.get("kind").and_then(Value::as_str) == Some("Service")
            && services.iter().any(|service| {
              service.namespace == grant.namespace()
                && to
                  .get("name")
                  .and_then(Value::as_str)
                  .is_none_or(|name| service.name == name)
            })
        })
      })
}

fn parse_target(object: &KubernetesObject) -> anyhow::Result<PlannedTarget> {
  let prefix = format!(
    "OxiBeltDataPlaneTarget {}/{}",
    object.namespace(),
    object.name()
  );
  reject_unknown_fields(
    &object.spec,
    &[
      "gatewayClassName",
      "assignment",
      "workloadRef",
      "capabilities",
      "policyVersion",
      "rollout",
    ],
    &format!("{prefix} spec"),
  )?;
  let gateway_class_name = required_string(&object.spec, "gatewayClassName", &prefix)?;
  validate_dns_subdomain("spec.gatewayClassName", gateway_class_name)?;
  let policy_version = required_string(&object.spec, "policyVersion", &prefix)?;
  if policy_version != POLICY_VERSION {
    bail!("{prefix} spec.policyVersion must be `{POLICY_VERSION}`");
  }

  let assignment = required_object(&object.spec, "assignment", &prefix)?;
  reject_unknown_fields(
    assignment,
    &["mode", "allowedNamespaces"],
    "spec.assignment",
  )?;
  if required_string(assignment, "mode", &prefix)? != "Replicated" {
    bail!("{prefix} spec.assignment.mode must be `Replicated` in v1alpha1");
  }
  let allowed_namespaces = required_string_array(
    assignment,
    "allowedNamespaces",
    1,
    MAX_ALLOWED_NAMESPACES,
    &prefix,
  )?
  .into_iter()
  .collect::<BTreeSet<_>>();
  for namespace in &allowed_namespaces {
    super::rollout::validate_kubernetes_dns_label("target allowed namespace", namespace)?;
  }

  let workload = required_object(&object.spec, "workloadRef", &prefix)?;
  reject_unknown_fields(
    workload,
    &[
      "group",
      "kind",
      "namespace",
      "name",
      "containerName",
      "volumeName",
    ],
    "spec.workloadRef",
  )?;
  if required_string(workload, "group", &prefix)? != "apps" {
    bail!("{prefix} spec.workloadRef.group must be `apps`");
  }
  let kind = match required_string(workload, "kind", &prefix)? {
    "Deployment" => WorkloadKind::Deployment,
    "DaemonSet" => WorkloadKind::DaemonSet,
    _ => bail!("{prefix} spec.workloadRef.kind must be `Deployment` or `DaemonSet`"),
  };
  let namespace = required_string(workload, "namespace", &prefix)?;
  let name = required_string(workload, "name", &prefix)?;
  let container_name = required_string(workload, "containerName", &prefix)?;
  let volume_name = required_string(workload, "volumeName", &prefix)?;
  super::rollout::validate_kubernetes_dns_label("target workload namespace", namespace)?;
  super::rollout::validate_kubernetes_dns_label("target workload name", name)?;
  super::rollout::validate_kubernetes_dns_label("target workload container name", container_name)?;
  super::rollout::validate_kubernetes_dns_label("target workload volume name", volume_name)?;

  let capabilities =
    required_string_array(&object.spec, "capabilities", 1, MAX_CAPABILITIES, &prefix)?;
  for capability in &capabilities {
    validate_capability(capability)?;
  }
  if capabilities
    .binary_search_by(|capability| capability.as_str().cmp("gateway-api"))
    .is_err()
  {
    bail!("{prefix} spec.capabilities must include `gateway-api`");
  }

  let rollout = required_object(&object.spec, "rollout", &prefix)?;
  reject_unknown_fields(
    rollout,
    &[
      "timeoutSeconds",
      "configMapPrefix",
      "concurrency",
      "failurePolicy",
    ],
    "spec.rollout",
  )?;
  let timeout_seconds = required_u64(rollout, "timeoutSeconds", &prefix)?;
  if !(1..=MAX_TIMEOUT_SECONDS).contains(&timeout_seconds) {
    bail!("{prefix} spec.rollout.timeoutSeconds must be between 1 and {MAX_TIMEOUT_SECONDS}");
  }
  if required_u64(rollout, "concurrency", &prefix)? != 1 {
    bail!("{prefix} spec.rollout.concurrency must be 1 in v1alpha1");
  }
  if required_string(rollout, "failurePolicy", &prefix)? != "Rollback" {
    bail!("{prefix} spec.rollout.failurePolicy must be `Rollback` in v1alpha1");
  }
  let config_map_prefix = required_string(rollout, "configMapPrefix", &prefix)?;
  super::rollout::validate_kubernetes_dns_label("target ConfigMap prefix", config_map_prefix)?;
  let resource = object.key();
  let mut rollout_target = RolloutTarget {
    namespace: namespace.to_string(),
    kind,
    name: name.to_string(),
    container_name: container_name.to_string(),
    volume_name: volume_name.to_string(),
    timeout: Duration::from_secs(timeout_seconds),
    config_map_prefix: config_map_prefix.to_string(),
    artifact_context: None,
  };
  let artifact_context = target_artifact_context(
    &resource,
    gateway_class_name,
    &allowed_namespaces,
    &rollout_target,
    &capabilities,
    policy_version,
  );
  rollout_target.artifact_context = Some(artifact_context);

  Ok(PlannedTarget {
    resource,
    resource_version: object.metadata.resource_version.clone(),
    observed_generation: object.metadata.generation.unwrap_or_default(),
    gateway_class_name: gateway_class_name.to_string(),
    allowed_namespaces,
    capabilities,
    policy_version: policy_version.to_string(),
    rollout: rollout_target,
  })
}

fn target_artifact_context(
  resource: &ObjectKey,
  gateway_class_name: &str,
  allowed_namespaces: &BTreeSet<String>,
  rollout: &RolloutTarget,
  capabilities: &[String],
  policy_version: &str,
) -> String {
  let mut digest = Sha256::new();
  digest.update(b"oxibelt-data-plane-target-context-v1\0");
  for value in [
    resource.namespace.as_str(),
    resource.name.as_str(),
    gateway_class_name,
    rollout.kind.label_value(),
    rollout.namespace.as_str(),
    rollout.name.as_str(),
    rollout.container_name.as_str(),
    rollout.volume_name.as_str(),
    policy_version,
    rollout.config_map_prefix.as_str(),
  ] {
    digest.update(value.as_bytes());
    digest.update(b"\0");
  }
  digest.update(rollout.timeout.as_secs().to_be_bytes());
  digest.update(b"\0allowed-namespaces\0");
  for namespace in allowed_namespaces {
    digest.update(namespace.as_bytes());
    digest.update(b"\0");
  }
  digest.update(b"capabilities\0");
  for capability in capabilities {
    digest.update(capability.as_bytes());
    digest.update(b"\0");
  }
  digest
    .finalize()
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}

fn is_route_kind(kind: &str) -> bool {
  matches!(
    kind,
    "HTTPRoute" | "GRPCRoute" | "TLSRoute" | "TCPRoute" | "UDPRoute"
  )
}

fn route_attaches_to_gateway(route: &KubernetesObject, gateways: &BTreeSet<ObjectKey>) -> bool {
  route
    .spec
    .get("parentRefs")
    .and_then(Value::as_array)
    .is_some_and(|parents| {
      parents.iter().any(|parent| {
        parent
          .get("group")
          .and_then(Value::as_str)
          .unwrap_or("gateway.networking.k8s.io")
          == "gateway.networking.k8s.io"
          && parent
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("Gateway")
            == "Gateway"
          && parent
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| {
              let namespace = parent
                .get("namespace")
                .and_then(Value::as_str)
                .unwrap_or_else(|| route.namespace());
              gateways.contains(&ObjectKey {
                namespace: namespace.to_string(),
                name: name.to_string(),
              })
            })
      })
    })
}

fn route_policy_targets_selected_route(
  policy: &KubernetesObject,
  routes: &BTreeSet<(String, ObjectKey)>,
  route_objects: &[&KubernetesObject],
) -> bool {
  let kind = policy
    .spec
    .pointer("/targetRef/kind")
    .and_then(Value::as_str);
  let name = policy
    .spec
    .pointer("/targetRef/name")
    .and_then(Value::as_str);
  kind.zip(name).is_some_and(|(kind, name)| {
    let key = ObjectKey {
      namespace: policy.namespace().to_string(),
      name: name.to_string(),
    };
    routes.contains(&(kind.to_string(), key.clone()))
      && route_objects.iter().any(|route| {
        route.kind == kind && route.key() == key && route_references_policy(route, policy.name())
      })
  })
}

fn route_references_policy(route: &KubernetesObject, policy_name: &str) -> bool {
  route
    .spec
    .get("rules")
    .and_then(Value::as_array)
    .into_iter()
    .flatten()
    .flat_map(|rule| {
      rule
        .get("filters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    })
    .any(|filter| {
      filter.get("type").and_then(Value::as_str) == Some("ExtensionRef")
        && filter
          .pointer("/extensionRef/group")
          .and_then(Value::as_str)
          == Some("gateway.oxibelt.dev")
        && filter.pointer("/extensionRef/kind").and_then(Value::as_str)
          == Some("OxiBeltRoutePolicy")
        && filter.pointer("/extensionRef/name").and_then(Value::as_str) == Some(policy_name)
    })
}

fn required_object<'a>(value: &'a Value, field: &str, prefix: &str) -> anyhow::Result<&'a Value> {
  value
    .get(field)
    .filter(|value| value.is_object())
    .with_context(|| format!("{prefix} spec.{field} must be an object"))
}

fn required_string<'a>(value: &'a Value, field: &str, prefix: &str) -> anyhow::Result<&'a str> {
  value
    .get(field)
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
    .with_context(|| format!("{prefix} spec.{field} must be a non-empty string"))
}

fn required_u64(value: &Value, field: &str, prefix: &str) -> anyhow::Result<u64> {
  value
    .get(field)
    .and_then(Value::as_u64)
    .with_context(|| format!("{prefix} spec.{field} must be an unsigned integer"))
}

fn required_string_array(
  value: &Value,
  field: &str,
  min: usize,
  max: usize,
  prefix: &str,
) -> anyhow::Result<Vec<String>> {
  let array = value
    .get(field)
    .and_then(Value::as_array)
    .with_context(|| format!("{prefix} spec.{field} must be an array"))?;
  if !(min..=max).contains(&array.len()) {
    bail!("{prefix} spec.{field} must contain {min}..={max} values");
  }
  let mut values = array
    .iter()
    .map(|value| {
      value
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .with_context(|| format!("{prefix} spec.{field} values must be non-empty strings"))
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
  values.sort();
  if values.windows(2).any(|values| values[0] == values[1]) {
    bail!("{prefix} spec.{field} values must be unique");
  }
  Ok(values)
}

fn reject_unknown_fields(value: &Value, allowed: &[&str], prefix: &str) -> anyhow::Result<()> {
  let object = value
    .as_object()
    .with_context(|| format!("{prefix} must be an object"))?;
  if let Some(field) = object
    .keys()
    .find(|field| !allowed.contains(&field.as_str()))
  {
    bail!("{prefix}.{field} is unsupported");
  }
  Ok(())
}

fn validate_dns_subdomain(label: &str, value: &str) -> anyhow::Result<()> {
  let valid = !value.is_empty()
    && value.len() <= 253
    && value.split('.').all(|part| {
      !part.is_empty()
        && part.len() <= 63
        && part
          .as_bytes()
          .first()
          .is_some_and(u8::is_ascii_alphanumeric)
        && part
          .as_bytes()
          .last()
          .is_some_and(u8::is_ascii_alphanumeric)
        && part
          .bytes()
          .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    });
  if !valid {
    bail!("{label} must be a lowercase Kubernetes DNS subdomain");
  }
  Ok(())
}

fn validate_capability(value: &str) -> anyhow::Result<()> {
  if value.len() > 63
    || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
    || !value
      .as_bytes()
      .last()
      .is_some_and(u8::is_ascii_alphanumeric)
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
  {
    bail!("spec.capabilities values must be lowercase capability identifiers");
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cli::{CompatibilityMode, RolloutTargetKind};

  fn args() -> RunArgs {
    RunArgs {
      poll_interval_ms: 5_000,
      rollout_target_namespace: "legacy".to_string(),
      rollout_target_kind: RolloutTargetKind::Deployment,
      rollout_target_name: "legacy".to_string(),
      rollout_target_container_name: "oxibelt".to_string(),
      rollout_volume_name: "gateway-config".to_string(),
      rollout_timeout_seconds: 300,
      rollout_config_map_prefix: "legacy-config".to_string(),
      leader_election_namespace: "controller".to_string(),
      leader_election_lease_name: "controller".to_string(),
      leader_election_lease_duration_seconds: 15,
      leader_election_renew_deadline_seconds: 10,
      leader_election_retry_period_seconds: 2,
      compatibility_mode: CompatibilityMode::Exact,
      compatibility_previous_version: None,
      compatibility_deadline: None,
    }
  }

  fn objects(yaml: &str) -> Vec<KubernetesObject> {
    serde_saphyr::from_multiple::<Value>(yaml)
      .expect("yaml")
      .into_iter()
      .flat_map(|value| KubernetesObject::from_value(value).expect("objects"))
      .collect()
  }

  fn fixture() -> Vec<KubernetesObject> {
    objects(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: edge}
spec: {controllerName: oxibelt.dev/gateway-controller}
---
apiVersion: gateway.oxibelt.dev/v1alpha1
kind: OxiBeltDataPlaneTarget
metadata: {name: west, namespace: control, resourceVersion: "7"}
spec:
  gatewayClassName: edge
  assignment:
    mode: Replicated
    allowedNamespaces: [tenant-b, tenant-a]
  workloadRef:
    group: apps
    kind: Deployment
    namespace: data-plane
    name: oxibelt-west
    containerName: oxibelt
    volumeName: gateway-config
  capabilities: [http3, gateway-api]
  policyVersion: v1alpha1
  rollout:
    timeoutSeconds: 300
    configMapPrefix: oxibelt-west-config
    concurrency: 1
    failurePolicy: Rollback
"#,
    )
  }

  #[test]
  fn typed_targets_are_sorted_bounded_and_bind_artifact_identity() {
    let set = TargetSet::from_objects(&fixture(), &args(), "oxibelt.dev/gateway-controller")
      .expect("target set");
    let TargetSet::StaticReplicated(targets) = set else {
      panic!("typed targets")
    };
    assert_eq!(targets.len(), 1);
    assert_eq!(
      targets[0]
        .allowed_namespaces
        .iter()
        .cloned()
        .collect::<Vec<_>>(),
      ["tenant-a", "tenant-b"]
    );
    assert_eq!(targets[0].capabilities, ["gateway-api", "http3"]);
    let bound = targets[0].bound_toml("aabb", "[[routes]]\nname = \"app\"\n");
    assert!(bound.contains("# target = control/west"));
    assert!(bound.contains("# capabilities = gateway-api,http3"));
    assert!(bound.contains("# source_snapshot_digest = aabb"));
    assert!(!bound.contains("Secret"));
  }

  #[test]
  fn replicated_targets_receive_distinct_deterministic_artifact_identities() {
    let mut resources = fixture();
    let mut east = resources.last().expect("west target").clone();
    east.metadata.name = "east".to_string();
    east.spec["workloadRef"]["name"] = Value::String("oxibelt-east".to_string());
    resources.push(east);
    let TargetSet::StaticReplicated(targets) =
      TargetSet::from_objects(&resources, &args(), "oxibelt.dev/gateway-controller")
        .expect("target set")
    else {
      panic!("typed targets")
    };
    assert_eq!(targets[0].resource.name, "east");
    assert_eq!(targets[1].resource.name, "west");
    let artifact = |target: &PlannedTarget| {
      let bound = target.bound_toml("11aa", "[[routes]]\nname = \"app\"\n");
      crate::rollout::ConfigArtifact::new(&target.rollout, "conf.d/generated.toml", bound)
        .expect("artifact")
    };
    let east = artifact(&targets[0]);
    let west = artifact(&targets[1]);
    assert_ne!(east.artifact_digest, west.artifact_digest);
    assert_ne!(east.name, west.name);
    assert_eq!(east, artifact(&targets[0]));
  }

  #[test]
  fn capability_change_cannot_load_an_artifact_from_the_previous_target_context() {
    let TargetSet::StaticReplicated(original) =
      TargetSet::from_objects(&fixture(), &args(), "oxibelt.dev/gateway-controller")
        .expect("original target")
    else {
      panic!("typed")
    };
    let artifact = crate::rollout::ConfigArtifact::new(
      &original[0].rollout,
      "conf.d/generated.toml",
      original[0].bound_toml("11aa", "[[routes]]\nname = \"app\"\n"),
    )
    .expect("artifact");
    let manifest = artifact.manifest(&original[0].rollout);

    let mut changed_objects = fixture();
    changed_objects.last_mut().expect("target").spec["capabilities"] =
      serde_json::json!(["gateway-api", "http3", "websocket"]);
    let TargetSet::StaticReplicated(changed) =
      TargetSet::from_objects(&changed_objects, &args(), "oxibelt.dev/gateway-controller")
        .expect("changed target")
    else {
      panic!("typed")
    };
    assert_ne!(
      original[0].rollout.artifact_context,
      changed[0].rollout.artifact_context
    );
    assert!(
      crate::rollout::ConfigArtifact::from_existing(&changed[0].rollout, &manifest)
        .expect_err("cross-context artifact")
        .to_string()
        .contains("deterministic rollout identity")
    );
  }

  #[test]
  fn legacy_target_remains_when_no_typed_resources_exist() {
    let set = TargetSet::from_objects(&[], &args(), "oxibelt.dev/gateway-controller")
      .expect("legacy target");
    let TargetSet::Legacy(target) = set else {
      panic!("legacy")
    };
    assert_eq!(target.name, "legacy");
  }

  #[test]
  fn invalid_fields_caps_and_duplicate_workloads_fail_closed() {
    let mut resources = fixture();
    resources.last_mut().expect("target").api_version = "gateway.oxibelt.dev/v1beta1".to_string();
    assert!(
      TargetSet::from_objects(&resources, &args(), "oxibelt.dev/gateway-controller")
        .expect_err("unsupported target apiVersion")
        .to_string()
        .contains("unsupported apiVersion")
    );

    let mut resources = fixture();
    resources.last_mut().expect("target").spec["rawAdminUrl"] =
      Value::String("https://attacker.invalid".to_string());
    assert!(
      TargetSet::from_objects(&resources, &args(), "oxibelt.dev/gateway-controller")
        .expect_err("unknown field")
        .to_string()
        .contains("rawAdminUrl")
    );

    let mut resources = fixture();
    let mut duplicate = resources.last().expect("target").clone();
    duplicate.metadata.name = "east".to_string();
    resources.push(duplicate);
    assert!(
      TargetSet::from_objects(&resources, &args(), "oxibelt.dev/gateway-controller")
        .expect_err("duplicate workload")
        .to_string()
        .contains("same workload")
    );

    let mut resources = fixture();
    resources.extend(objects(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: unassigned, namespace: tenant-c}
spec: {gatewayClassName: edge, listeners: []}
"#,
    ));
    assert!(
      TargetSet::from_objects(&resources, &args(), "oxibelt.dev/gateway-controller")
        .expect_err("unassigned Gateway")
        .to_string()
        .contains("no allowed")
    );
  }

  #[test]
  fn target_snapshot_contains_only_assigned_gateways_and_routes() {
    let mut resources = fixture();
    resources.extend(objects(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: selected, namespace: tenant-a}
spec: {gatewayClassName: edge, listeners: []}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: other, namespace: tenant-c}
spec: {gatewayClassName: foreign, listeners: []}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: selected, namespace: tenant-a}
spec:
  parentRefs: [{name: selected}]
  rules:
  - backendRefs: [{name: shared, port: 80}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: other, namespace: tenant-c}
spec:
  parentRefs: [{name: other}]
  rules: []
---
apiVersion: v1
kind: Service
metadata: {name: shared, namespace: tenant-a}
spec: {ports: [{port: 80}]}
---
apiVersion: v1
kind: Service
metadata:
  name: unrelated-invalid
  namespace: tenant-c
  annotations: {oxibelt.dev/upstream-scheme: ftp}
spec: {ports: [{port: 80}]}
---
apiVersion: gateway.oxibelt.dev/v1alpha1
kind: OxiBeltRoutePolicy
metadata: {name: unreferenced-invalid, namespace: tenant-a}
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: selected}
  unknown: poison
"#,
    ));
    let TargetSet::StaticReplicated(targets) =
      TargetSet::from_objects(&resources, &args(), "oxibelt.dev/gateway-controller")
        .expect("target set")
    else {
      panic!("typed")
    };
    let selected = objects_for_target(&resources, &targets[0], None);
    assert!(
      selected
        .iter()
        .any(|object| object.kind == "Gateway" && object.name() == "selected")
    );
    assert!(
      !selected
        .iter()
        .any(|object| object.kind == "Gateway" && object.name() == "other")
    );
    assert!(
      selected
        .iter()
        .any(|object| object.kind == "HTTPRoute" && object.name() == "selected")
    );
    assert!(
      !selected
        .iter()
        .any(|object| object.kind == "HTTPRoute" && object.name() == "other")
    );
    assert!(
      selected
        .iter()
        .any(|object| object.kind == "Service" && object.name() == "shared")
    );
    assert!(
      !selected
        .iter()
        .any(|object| object.kind == "Service" && object.name() == "unrelated-invalid"),
      "an unrelated target namespace must not inject a blocking supporting object"
    );
    assert!(
      !selected
        .iter()
        .any(|object| object.kind == "OxiBeltRoutePolicy"),
      "an unreferenced policy must not poison the target merely by naming its route"
    );
  }

  #[test]
  fn target_snapshot_retains_only_reference_reachable_backend_support() {
    let mut resources = fixture();
    resources.extend(objects(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: selected, namespace: tenant-a}
spec: {gatewayClassName: edge, listeners: []}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: selected, namespace: tenant-a}
spec:
  parentRefs: [{name: selected}]
  rules:
  - backendRefs: [{name: app, namespace: backend, port: 443}]
---
apiVersion: v1
kind: Service
metadata: {name: app, namespace: backend}
spec: {ports: [{port: 443}]}
---
apiVersion: v1
kind: Service
metadata: {name: unrelated, namespace: backend}
spec: {ports: [{port: 443}]}
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata: {name: app, namespace: backend}
spec:
  from: [{group: gateway.networking.k8s.io, kind: HTTPRoute, namespace: tenant-a}]
  to: [{group: "", kind: Service, name: app}]
---
apiVersion: gateway.networking.k8s.io/v1alpha3
kind: BackendTLSPolicy
metadata: {name: app, namespace: backend}
spec:
  targetRefs: [{group: "", kind: Service, name: app}]
  validation:
    hostname: app.backend.svc.cluster.local
    caCertificateRefs: [{group: "", kind: ConfigMap, name: app-ca}]
---
apiVersion: v1
kind: ConfigMap
metadata: {name: app-ca, namespace: backend}
data: {ca.crt: certificate}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: unrelated, namespace: backend}
data: {ca.crt: unrelated}
"#,
    ));
    let TargetSet::StaticReplicated(targets) =
      TargetSet::from_objects(&resources, &args(), "oxibelt.dev/gateway-controller")
        .expect("target set")
    else {
      panic!("typed")
    };
    let selected = objects_for_target(&resources, &targets[0], None);
    assert!(
      ["Service", "ReferenceGrant", "BackendTLSPolicy", "ConfigMap"]
        .iter()
        .all(|kind| selected.iter().any(|object| object.kind == *kind)),
      "an explicit cross-namespace backend must retain its grant and TLS trust chain"
    );
    assert!(
      !selected.iter().any(|object| object.name() == "unrelated"),
      "same-namespace objects outside the selected dependency closure must be excluded"
    );
  }

  #[test]
  fn target_status_is_bounded_and_contains_no_workload_endpoint_or_credentials() {
    let TargetSet::StaticReplicated(targets) =
      TargetSet::from_objects(&fixture(), &args(), "oxibelt.dev/gateway-controller")
        .expect("target set")
    else {
      panic!("typed")
    };
    let digest = "a".repeat(64);
    let outcome = TargetOutcome {
      target: targets[0].clone(),
      source_snapshot_digest: "b".repeat(64),
      translation_succeeded: true,
      rollout: Some(RolloutStatus {
        phase: RolloutPhase::Committed,
        desired_revision: Some(format!("oxibelt-west-{digest}")),
        desired_content_digest: Some("content".to_string()),
        reason: None,
        proof: Some(crate::rollout_status::CommitProof::test()),
        target_summary: None,
      }),
      failure_reason: None,
    };
    let patch = outcome.status_patch();
    assert_eq!(patch.status["state"], "Active");
    assert_eq!(patch.status["artifactDigest"], format!("sha256:{digest}"));
    let encoded = patch.status.to_string();
    assert!(encoded.len() < 4096);
    assert!(!encoded.contains("workloadRef"));
    assert!(!encoded.to_ascii_lowercase().contains("secret"));
    assert!(!encoded.contains("https://"));
  }
}
