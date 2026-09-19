//! Bounded OxiBeltRoutePolicy v1alpha1 parsing and route-local merge rules.

use std::collections::{BTreeMap, HashSet};

use anyhow::{Context, bail};
use serde_json::Value;

use super::super::model::{Diagnostic, KubernetesObject, ObjectKey, object_ref};
use super::{
  ClientCertificateForwardFormat, ClientCertificateForwarding, GeneratedHttpVersion,
  GeneratedRoute, SharedArgs, string_array_at, string_at, u64_at, unsupported_field,
};

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
  client_certificate_forwarding: Option<ClientCertificateForwarding>,
  webtransport_upstream_http_version: Option<GeneratedHttpVersion>,
  resumable_upload_profile: Option<String>,
  compression_dictionary_profile: Option<String>,
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

pub(super) fn forwarding_headers(
  policies: &BTreeMap<ObjectKey, RoutePolicyDecision>,
) -> oxibelt_control_protocol::HyphenUnderscoreHeaderNameSet {
  let mut headers = policies
    .values()
    .filter_map(|decision| match decision {
      RoutePolicyDecision::Valid(policy) => policy.client_certificate_forwarding.as_ref(),
      RoutePolicyDecision::InvalidTargetKnown { .. }
      | RoutePolicyDecision::InvalidTargetUnknown => None,
    })
    .map(|forwarding| forwarding.header.clone())
    .collect::<HashSet<_>>();
  if !headers.is_empty() {
    headers.insert("client-cert".to_string());
    headers.insert("client-cert-chain".to_string());
  }
  oxibelt_control_protocol::HyphenUnderscoreHeaderNameSet::new(headers.iter().map(String::as_str))
}

pub(super) fn apply_route_policy(
  policies: &BTreeMap<ObjectKey, RoutePolicyDecision>,
  reference: &ParsedRoutePolicyRef,
  source_route: &KubernetesObject,
  generated: &mut GeneratedRoute,
  allowed_client_certificate_forward_headers: &HashSet<String>,
  allowed_resumable_upload_profiles: &[crate::cli::ResumableUploadProfileAllowlistEntry],
  allowed_compression_dictionary_profiles: &[crate::cli::CompressionDictionaryProfileAllowlistEntry],
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
  generated.webtransport_upstream_http_version = policy.webtransport_upstream_http_version;
  if let Some(forwarding) = &policy.client_certificate_forwarding {
    if !allowed_client_certificate_forward_headers.contains(&forwarding.header) {
      return Err(RoutePolicyApplyError {
        message: format!(
          "OxiBeltRoutePolicy clientCertificateForwarding header {} is not admitted by operator policy",
          forwarding.header
        ),
        covered_diagnostics: Some(Vec::new()),
      });
    }
    generated.client_certificate_forwarding = Some(forwarding.clone());
  }
  if let Some(profile) = &policy.resumable_upload_profile {
    if generated.path_exact.is_some()
      || !generated.methods.is_empty()
      || !generated.headers.is_empty()
      || !generated.queries.is_empty()
      || generated.redirect.is_some()
      || generated.direct_response_status.is_some()
    {
      return Err(RoutePolicyApplyError {
        message: "OxiBeltRoutePolicy resumableUpload requires an unconditional prefix route"
          .to_owned(),
        covered_diagnostics: Some(Vec::new()),
      });
    }
    if !allowed_resumable_upload_profiles.iter().any(|admission| {
      admission.namespace == source_route.namespace() && admission.profile == *profile
    }) {
      return Err(RoutePolicyApplyError {
        message: format!(
          "OxiBeltRoutePolicy resumableUpload.profileRef {profile} is not admitted for namespace {} by operator policy",
          source_route.namespace()
        ),
        covered_diagnostics: Some(Vec::new()),
      });
    }
    generated.resumable_upload = Some(profile.clone());
  }
  if let Some(profile) = &policy.compression_dictionary_profile {
    if policy.target_kind != "HTTPRoute" || source_route.kind != "HTTPRoute" {
      return Err(RoutePolicyApplyError {
        message: "OxiBeltRoutePolicy compressionDictionary is supported only for HTTPRoute targets"
          .to_owned(),
        covered_diagnostics: Some(Vec::new()),
      });
    }
    if !allowed_compression_dictionary_profiles
      .iter()
      .any(|admission| {
        admission.namespace == source_route.namespace() && admission.profile == *profile
      })
    {
      return Err(RoutePolicyApplyError {
        message: format!(
          "OxiBeltRoutePolicy compressionDictionary.profileRef {profile} is not admitted for namespace {} by operator policy",
          source_route.namespace()
        ),
        covered_diagnostics: Some(Vec::new()),
      });
    }
    generated.compression_dictionary_profile = Some(profile.clone());
  }
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
  if let Some(field) = unsupported_field(
    &object.spec,
    &[
      "targetRef",
      "waf",
      "limits",
      "timeouts",
      "clientCertificateForwarding",
      "webTransport",
      "resumableUpload",
      "compressionDictionary",
    ],
  ) {
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

  let client_certificate_forwarding = object
    .spec
    .get("clientCertificateForwarding")
    .map(parse_client_certificate_forwarding)
    .transpose()?;
  if let Some(forwarding) = &client_certificate_forwarding
    && !args
      .client_certificate_forward_allowed_headers
      .iter()
      .filter_map(|header| {
        oxibelt_control_protocol::normalize_route_action_header_name(header).ok()
      })
      .any(|header| header == forwarding.header)
  {
    bail!(
      "spec.clientCertificateForwarding.header {} is not admitted by operator policy",
      forwarding.header
    );
  }

  let webtransport_upstream_http_version = object
    .spec
    .get("webTransport")
    .map(parse_webtransport)
    .transpose()?;
  if webtransport_upstream_http_version.is_some() && target_kind != "HTTPRoute" {
    bail!("spec.webTransport is supported only for HTTPRoute targets");
  }

  let resumable_upload_profile = object
    .spec
    .get("resumableUpload")
    .map(parse_resumable_upload)
    .transpose()?;
  let compression_dictionary_profile = object
    .spec
    .get("compressionDictionary")
    .map(parse_compression_dictionary)
    .transpose()?;
  if compression_dictionary_profile.is_some() && target_kind != "HTTPRoute" {
    bail!("spec.compressionDictionary is supported only for HTTPRoute targets");
  }
  if let Some(profile) = &compression_dictionary_profile
    && !args
      .compression_dictionary_profiles
      .iter()
      .any(|admission| admission.namespace == object.namespace() && admission.profile == *profile)
  {
    bail!(
      "spec.compressionDictionary.profileRef {profile} is not admitted for namespace {} by operator policy",
      object.namespace()
    );
  }
  if let Some(profile) = &resumable_upload_profile
    && !args
      .resumable_upload_profiles
      .iter()
      .any(|admission| admission.namespace == object.namespace() && admission.profile == *profile)
  {
    bail!(
      "spec.resumableUpload.profileRef {profile} is not admitted for namespace {} by operator policy",
      object.namespace()
    );
  }
  if resumable_upload_profile.is_some() && args.resumable_upload_target.is_none() {
    bail!(
      "spec.resumableUpload.profileRef requires an operator-configured resumable-upload target"
    );
  }

  if request_rule_groups.is_empty()
    && max_request_body_bytes.is_none()
    && upstream_request_timeout_ms.is_none()
    && client_certificate_forwarding.is_none()
    && webtransport_upstream_http_version.is_none()
    && resumable_upload_profile.is_none()
    && compression_dictionary_profile.is_none()
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
    client_certificate_forwarding,
    webtransport_upstream_http_version,
    resumable_upload_profile,
    compression_dictionary_profile,
  })
}

fn parse_webtransport(value: &Value) -> anyhow::Result<GeneratedHttpVersion> {
  if let Some(field) = unsupported_field(value, &["upstreamHttpVersion"]) {
    bail!("spec.webTransport.{field} is unsupported");
  }
  match string_at(value, &["upstreamHttpVersion"])
    .context("spec.webTransport.upstreamHttpVersion is required")?
  {
    "h2" => Ok(GeneratedHttpVersion::H2),
    "h3" => Ok(GeneratedHttpVersion::H3),
    _ => bail!("spec.webTransport.upstreamHttpVersion must be h2 or h3"),
  }
}

fn parse_resumable_upload(value: &Value) -> anyhow::Result<String> {
  if let Some(field) = unsupported_field(value, &["profileRef"]) {
    bail!("spec.resumableUpload.{field} is unsupported");
  }
  let profile =
    string_at(value, &["profileRef"]).context("spec.resumableUpload.profileRef is required")?;
  validate_dns_subdomain("spec.resumableUpload.profileRef", profile)?;
  Ok(profile.to_string())
}

fn parse_compression_dictionary(value: &Value) -> anyhow::Result<String> {
  if let Some(field) = unsupported_field(value, &["profileRef"]) {
    bail!("spec.compressionDictionary.{field} is unsupported");
  }
  let profile = string_at(value, &["profileRef"])
    .context("spec.compressionDictionary.profileRef is required")?;
  validate_dns_subdomain("spec.compressionDictionary.profileRef", profile)?;
  Ok(profile.to_string())
}

fn parse_client_certificate_forwarding(
  value: &Value,
) -> anyhow::Result<ClientCertificateForwarding> {
  if let Some(field) = unsupported_field(value, &["header", "format"]) {
    bail!("spec.clientCertificateForwarding.{field} is unsupported");
  }
  let header =
    string_at(value, &["header"]).context("spec.clientCertificateForwarding.header is required")?;
  let header = oxibelt_control_protocol::normalize_route_action_header_name(header)
    .context("spec.clientCertificateForwarding.header is invalid")?;
  if oxibelt_control_protocol::is_reserved_client_certificate_forwarding_header(&header) {
    bail!("spec.clientCertificateForwarding.header {header} is reserved");
  }
  if oxibelt_control_protocol::hyphen_underscore_header_names_equivalent(
    &header,
    "client-cert-chain",
  ) {
    bail!("spec.clientCertificateForwarding.header client-cert-chain is forbidden");
  }
  let format = match value.get("format") {
    None => "url_encoded_pem",
    Some(value) => value
      .as_str()
      .context("spec.clientCertificateForwarding.format must be a string")?,
  };
  let format = match format {
    "url_encoded_pem" => ClientCertificateForwardFormat::UrlEncodedPem,
    "rfc9440" => ClientCertificateForwardFormat::Rfc9440,
    _ => bail!("spec.clientCertificateForwarding.format must be url_encoded_pem or rfc9440"),
  };
  if oxibelt_control_protocol::hyphen_underscore_header_names_equivalent(&header, "client-cert")
    && format != ClientCertificateForwardFormat::Rfc9440
  {
    bail!("spec.clientCertificateForwarding.header client-cert requires format rfc9440");
  }
  Ok(ClientCertificateForwarding { header, format })
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
