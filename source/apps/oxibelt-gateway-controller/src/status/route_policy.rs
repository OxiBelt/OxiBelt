use std::collections::HashMap;

use serde_json::{Value, json};

use super::super::model::{
  Diagnostic, DiagnosticSeverity, KubernetesObject, object_ref as model_object_ref,
};
use super::super::rollout_status::RolloutStatus;
use super::{CONDITION_FALSE, CONDITION_TRUE, StatusPatch, bool_status, condition, string_at};

const API_PREFIX: &str = "/apis/gateway.oxibelt.dev/v1alpha1";

pub(super) fn patch(
  policy: &KubernetesObject,
  objects: &[KubernetesObject],
  diagnostics: &HashMap<String, Vec<&Diagnostic>>,
  rollout_status: &RolloutStatus,
  target_was_translated: bool,
  now: &str,
) -> StatusPatch {
  let errors = diagnostics
    .get(&model_object_ref(policy))
    .cloned()
    .unwrap_or_default()
    .into_iter()
    .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    .collect::<Vec<_>>();
  let target_kind = string_at(&policy.spec, &["targetRef", "kind"]);
  let target_name = string_at(&policy.spec, &["targetRef", "name"]);
  let target = target_kind.zip(target_name).and_then(|(kind, name)| {
    objects.iter().find(|object| {
      object.kind == kind && object.namespace() == policy.namespace() && object.name() == name
    })
  });
  let references = target
    .map(|route| policy_refs(route, policy.name()))
    .unwrap_or_default();
  let referenced = references > 0;
  let conflicted = references > 1;
  let accepted = errors.is_empty() && !conflicted;
  let resolved = target.is_some() && referenced;
  let programmed = rollout_status.programmed(accepted && resolved && target_was_translated);
  let accepted_reason = errors.first().map_or(
    if conflicted { "Conflicted" } else { "Accepted" },
    |error| error.code.as_str(),
  );
  let mut status = json!({
    "observedGeneration": policy.metadata.generation.unwrap_or_default(),
    "conditions": [
      condition(
        "Accepted",
        bool_status(accepted),
        accepted_reason,
        if accepted {
          "OxiBeltRoutePolicy is within operator bounds"
        } else if conflicted {
          "The target rule references the policy more than once"
        } else {
          "OxiBeltRoutePolicy contains an invalid, unsupported, or over-cap field"
        },
        policy.metadata.generation,
        now,
      ),
      condition(
        "ResolvedRefs",
        bool_status(resolved),
        if resolved { "ResolvedRefs" } else if target.is_none() { "TargetNotFound" } else { "NotReferenced" },
        if resolved {
          "The target route references this policy through ExtensionRef"
        } else if target.is_none() {
          "The target route was not found in the input snapshot"
        } else {
          "The target route does not reference this policy through ExtensionRef"
        },
        policy.metadata.generation,
        now,
      ),
      condition(
        "Conflicted",
        if conflicted { CONDITION_TRUE } else { CONDITION_FALSE },
        if conflicted { "Conflicted" } else { "NoConflicts" },
        if conflicted {
          "Multiple references would make policy precedence ambiguous"
        } else {
          "No route-policy reference conflict was detected"
        },
        policy.metadata.generation,
        now,
      ),
      condition(
        "Programmed",
        bool_status(programmed.programmed),
        if accepted && resolved && !target_was_translated {
          "TranslationOmitted"
        } else {
          programmed.reason
        },
        if accepted && resolved && !target_was_translated {
          "The target route and policy controls are absent from the committed translation"
        } else {
          &programmed.message
        },
        policy.metadata.generation,
        now,
      )
    ]
  });
  if let Some(digest) = rollout_status
    .proof
    .as_ref()
    .and_then(|proof| proof.revision.rsplit('-').next())
    .filter(|digest| {
      digest.len() == 64
        && digest
          .bytes()
          .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
  {
    status["artifactDigest"] = Value::String(format!("sha256:{digest}"));
  }
  StatusPatch {
    api_prefix: API_PREFIX,
    resource: "oxibeltroutepolicies",
    namespace: Some(policy.namespace().to_string()),
    name: policy.name().to_string(),
    resource_version: policy.metadata.resource_version.clone(),
    status,
  }
}

fn policy_refs(route: &KubernetesObject, policy_name: &str) -> usize {
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
    .filter(|filter| {
      string_at(filter, &["type"]) == Some("ExtensionRef")
        && string_at(filter, &["extensionRef", "group"]) == Some("gateway.oxibelt.dev")
        && string_at(filter, &["extensionRef", "kind"]) == Some("OxiBeltRoutePolicy")
        && string_at(filter, &["extensionRef", "name"]) == Some(policy_name)
    })
    .count()
}
