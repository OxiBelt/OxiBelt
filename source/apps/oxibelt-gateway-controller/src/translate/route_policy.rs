//! Bounded OxiBeltRoutePolicy v1alpha1 parsing and route-local merge rules.

use std::collections::BTreeMap;

use anyhow::{Context, bail};
use serde_json::Value;

use super::super::model::{Diagnostic, KubernetesObject, ObjectKey, object_ref};
use super::{GeneratedRoute, SharedArgs, string_array_at, string_at, u64_at, unsupported_field};

pub(super) const ROUTE_POLICY_API_VERSION: &str = "gateway.oxibelt.dev/v1alpha1";
pub(super) const ROUTE_POLICY_KIND: &str = "OxiBeltRoutePolicy";
const MAX_POLICY_WAF_GROUPS: usize = 16;

#[derive(Debug, Clone)]
pub(super) struct ParsedRoutePolicyRef {
  pub(super) name: String,
}

#[derive(Debug, Clone)]
pub(super) struct RoutePolicy {
  object: KubernetesObject,
  target_kind: String,
  target_name: String,
  request_rule_groups: Vec<String>,
  max_request_body_bytes: Option<u64>,
  upstream_request_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub(super) enum RoutePolicyDecision {
  Valid(Box<RoutePolicy>),
  InvalidTargetKnown {
    target_kind: String,
    target_name: String,
    diagnostic_indices: Vec<usize>,
  },
  InvalidTargetUnknown,
}

pub(super) struct RoutePolicyApplyError {
  pub(super) message: String,
  pub(super) covered_diagnostics: Option<Vec<usize>>,
}

pub(super) fn index_route_policies(
  objects: &[KubernetesObject],
  args: &SharedArgs,
  diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<ObjectKey, RoutePolicyDecision> {
  let mut policies = BTreeMap::new();
  for object in objects
    .iter()
    .filter(|object| object.kind == ROUTE_POLICY_KIND)
  {
    let decision = match parse_route_policy(object, args) {
      Ok(policy) => RoutePolicyDecision::Valid(Box::new(policy)),
      Err(error) => {
        let diagnostic = diagnostics.len();
        diagnostics.push(Diagnostic::error(
          object_ref(object),
          format!("invalid OxiBeltRoutePolicy: {error:#}"),
        ));
        match exact_route_policy_target(object) {
          Some((target_kind, target_name)) => RoutePolicyDecision::InvalidTargetKnown {
            target_kind,
            target_name,
            diagnostic_indices: vec![diagnostic],
          },
          None => RoutePolicyDecision::InvalidTargetUnknown,
        }
      }
    };
    let key = object.key();
    if policies.insert(key.clone(), decision).is_some() {
      diagnostics.push(Diagnostic::error(
        object_ref(object),
        "duplicate OxiBeltRoutePolicy identity in input snapshot",
      ));
      policies.insert(key, RoutePolicyDecision::InvalidTargetUnknown);
    }
  }
  policies
}

pub(super) fn parse_route_policy_ref(filter: &Value) -> anyhow::Result<ParsedRoutePolicyRef> {
  let reference = filter
    .get("extensionRef")
    .context("ExtensionRef filter requires extensionRef")?;
  if let Some(field) = unsupported_field(reference, &["group", "kind", "name"]) {
    bail!("OxiBeltRoutePolicy ExtensionRef field {field} is unsupported");
  }
  if string_at(reference, &["group"]) != Some("gateway.oxibelt.dev")
    || string_at(reference, &["kind"]) != Some(ROUTE_POLICY_KIND)
  {
    bail!("ExtensionRef supports only gateway.oxibelt.dev/{ROUTE_POLICY_KIND}");
  }
  let name =
    string_at(reference, &["name"]).context("OxiBeltRoutePolicy ExtensionRef name is required")?;
  validate_dns_subdomain("OxiBeltRoutePolicy ExtensionRef name", name)?;
  Ok(ParsedRoutePolicyRef {
    name: name.to_string(),
  })
}

pub(super) fn apply_route_policy(
  policies: &BTreeMap<ObjectKey, RoutePolicyDecision>,
  reference: &ParsedRoutePolicyRef,
  source_route: &KubernetesObject,
  generated: &mut GeneratedRoute,
) -> Result<(), RoutePolicyApplyError> {
  let key = ObjectKey {
    namespace: source_route.namespace().to_string(),
    name: reference.name.clone(),
  };
  let Some(decision) = policies.get(&key) else {
    return Err(RoutePolicyApplyError {
      message: format!(
        "OxiBeltRoutePolicy {}/{} was not found in the input snapshot",
        key.namespace, key.name
      ),
      covered_diagnostics: Some(Vec::new()),
    });
  };
  let policy = match decision {
    RoutePolicyDecision::Valid(policy) => policy,
    RoutePolicyDecision::InvalidTargetKnown {
      target_kind,
      target_name,
      diagnostic_indices,
    } if target_kind == &source_route.kind && target_name == source_route.name() => {
      return Err(RoutePolicyApplyError {
        message: format!(
          "OxiBeltRoutePolicy {}/{} is invalid for {}/{}",
          key.namespace,
          key.name,
          source_route.kind,
          source_route.name()
        ),
        covered_diagnostics: Some(diagnostic_indices.clone()),
      });
    }
    RoutePolicyDecision::InvalidTargetKnown { .. } | RoutePolicyDecision::InvalidTargetUnknown => {
      return Err(RoutePolicyApplyError {
        message: format!(
          "OxiBeltRoutePolicy {}/{} is invalid with an ambiguous target",
          key.namespace, key.name
        ),
        covered_diagnostics: None,
      });
    }
  };
  if policy.object.api_version != ROUTE_POLICY_API_VERSION {
    return Err(RoutePolicyApplyError {
      message: format!(
        "OxiBeltRoutePolicy {}/{} must use {ROUTE_POLICY_API_VERSION}",
        key.namespace, key.name
      ),
      covered_diagnostics: Some(Vec::new()),
    });
  }
  if policy.target_kind != source_route.kind || policy.target_name != source_route.name() {
    return Err(RoutePolicyApplyError {
      message: format!(
        "OxiBeltRoutePolicy {}/{} targetRef does not select {}/{}",
        key.namespace,
        key.name,
        source_route.kind,
        source_route.name()
      ),
      covered_diagnostics: Some(Vec::new()),
    });
  }

  generated.policy_source = Some(format!(
    "{ROUTE_POLICY_KIND}/{}/{}",
    policy.object.namespace(),
    policy.object.name()
  ));
  generated.waf_request_rule_groups = policy.request_rule_groups.clone();
  generated.max_request_body_bytes = policy.max_request_body_bytes;
  generated.upstream_request_timeout_ms = policy.upstream_request_timeout_ms;
  Ok(())
}

fn exact_route_policy_target(object: &KubernetesObject) -> Option<(String, String)> {
  let target = object.spec.get("targetRef")?;
  if unsupported_field(target, &["group", "kind", "name", "sectionName"]).is_some()
    || string_at(target, &["group"]) != Some("gateway.networking.k8s.io")
    || target
      .get("sectionName")
      .is_some_and(|value| !value.is_null())
  {
    return None;
  }
  let kind = string_at(target, &["kind"])?;
  if !matches!(kind, "HTTPRoute" | "GRPCRoute") {
    return None;
  }
  let name = string_at(target, &["name"])?;
  validate_dns_subdomain("spec.targetRef.name", name).ok()?;
  Some((kind.to_string(), name.to_string()))
}

fn parse_route_policy(object: &KubernetesObject, args: &SharedArgs) -> anyhow::Result<RoutePolicy> {
  if object.api_version != ROUTE_POLICY_API_VERSION {
    bail!("apiVersion must be {ROUTE_POLICY_API_VERSION}");
  }
  if let Some(field) = unsupported_field(&object.spec, &["targetRef", "waf", "limits", "timeouts"])
  {
    bail!("spec.{field} is unsupported");
  }
  let target = object
    .spec
    .get("targetRef")
    .context("spec.targetRef is required")?;
  if let Some(field) = unsupported_field(target, &["group", "kind", "name", "sectionName"]) {
    bail!("spec.targetRef.{field} is unsupported");
  }
  if string_at(target, &["group"]) != Some("gateway.networking.k8s.io") {
    bail!("spec.targetRef.group must be gateway.networking.k8s.io");
  }
  let target_kind = string_at(target, &["kind"]).context("spec.targetRef.kind is required")?;
  if !matches!(target_kind, "HTTPRoute" | "GRPCRoute") {
    bail!("spec.targetRef.kind must be HTTPRoute or GRPCRoute");
  }
  let target_name = string_at(target, &["name"]).context("spec.targetRef.name is required")?;
  validate_dns_subdomain("spec.targetRef.name", target_name)?;
  if target
    .get("sectionName")
    .is_some_and(|value| !value.is_null())
  {
    bail!("spec.targetRef.sectionName is unsupported in v1alpha1");
  }

  let request_rule_groups = object
    .spec
    .get("waf")
    .map(|waf| {
      if let Some(field) = unsupported_field(waf, &["requestRuleGroups"]) {
        bail!("spec.waf.{field} is unsupported");
      }
      let groups = string_array_at(waf, &["requestRuleGroups"]);
      if groups.len() > MAX_POLICY_WAF_GROUPS {
        bail!("spec.waf.requestRuleGroups must contain at most {MAX_POLICY_WAF_GROUPS} entries");
      }
      let mut unique = std::collections::HashSet::new();
      for group in &groups {
        if group.is_empty()
          || group.len() > 32
          || !group
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
          bail!("spec.waf.requestRuleGroups entries must match [A-Za-z0-9-]{{1,32}}");
        }
        if !unique.insert(group.as_str()) {
          bail!("spec.waf.requestRuleGroups contains duplicate group {group}");
        }
      }
      Ok(groups)
    })
    .transpose()?
    .unwrap_or_default();

  let max_request_body_bytes = object
    .spec
    .get("limits")
    .map(|limits| {
      if let Some(field) = unsupported_field(limits, &["maxRequestBodyBytes"]) {
        bail!("spec.limits.{field} is unsupported");
      }
      let value = u64_at(limits, &["maxRequestBodyBytes"])
        .context("spec.limits.maxRequestBodyBytes is required when limits is present")?;
      if value == 0 || value > args.route_policy_max_request_body_bytes {
        bail!(
          "spec.limits.maxRequestBodyBytes exceeds the operator cap of {}",
          args.route_policy_max_request_body_bytes
        );
      }
      Ok(value)
    })
    .transpose()?;

  let upstream_request_timeout_ms = object
    .spec
    .get("timeouts")
    .map(|timeouts| {
      if let Some(field) = unsupported_field(timeouts, &["upstreamRequestMilliseconds"]) {
        bail!("spec.timeouts.{field} is unsupported");
      }
      let value = u64_at(timeouts, &["upstreamRequestMilliseconds"]).context(
        "spec.timeouts.upstreamRequestMilliseconds is required when timeouts is present",
      )?;
      if value == 0 || value > args.route_policy_max_timeout_ms {
        bail!(
          "spec.timeouts.upstreamRequestMilliseconds exceeds the operator cap of {}",
          args.route_policy_max_timeout_ms
        );
      }
      Ok(value)
    })
    .transpose()?;

  if request_rule_groups.is_empty()
    && max_request_body_bytes.is_none()
    && upstream_request_timeout_ms.is_none()
  {
    bail!("at least one bounded policy field is required");
  }

  Ok(RoutePolicy {
    object: object.clone(),
    target_kind: target_kind.to_string(),
    target_name: target_name.to_string(),
    request_rule_groups,
    max_request_body_bytes,
    upstream_request_timeout_ms,
  })
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
    bail!("{label} must be a Kubernetes DNS subdomain");
  }
  Ok(())
}
