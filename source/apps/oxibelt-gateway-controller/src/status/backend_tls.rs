use super::*;

pub(super) fn patch(
  object: &KubernetesObject,
  args: &SharedArgs,
  diagnostics: &HashMap<String, Vec<&Diagnostic>>,
  now: &str,
) -> StatusPatch {
  let object_errors = diagnostics
    .get(&model_object_ref(object))
    .cloned()
    .unwrap_or_default()
    .into_iter()
    .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    .collect::<Vec<_>>();
  let accepted = object_errors.is_empty();
  let reason = if accepted {
    "Accepted"
  } else if object_errors
    .iter()
    .any(|diagnostic| diagnostic.message.contains("Conflicted"))
  {
    "Conflicted"
  } else if object_errors
    .iter()
    .any(|diagnostic| diagnostic.message.contains("target Service"))
  {
    "TargetNotFound"
  } else if object_errors
    .iter()
    .any(|diagnostic| diagnostic.message.contains("ConfigMap"))
  {
    "InvalidCACertificateRef"
  } else {
    "Invalid"
  };
  let target_ref = object
    .spec
    .get("targetRefs")
    .and_then(Value::as_array)
    .and_then(|target_refs| target_refs.first())
    .map(normalized_target_ref)
    .unwrap_or_else(|| json!({ "group": "", "kind": "Service", "name": "invalid" }));
  let mut ancestors = object
    .status
    .get("ancestors")
    .and_then(Value::as_array)
    .cloned()
    .unwrap_or_default()
    .into_iter()
    .filter(|ancestor| {
      string_at(ancestor, &["controllerName"]) != Some(args.controller_name.as_str())
    })
    .collect::<Vec<_>>();
  ancestors.push(json!({
    "ancestorRef": target_ref,
    "controllerName": args.controller_name,
    "conditions": [condition(
      "Accepted",
      bool_status(accepted),
      reason,
      if accepted {
        "BackendTLSPolicy is accepted by OxiBelt"
      } else {
        "BackendTLSPolicy is invalid, unresolved, or conflicted"
      },
      object.metadata.generation,
      now,
    )],
  }));
  StatusPatch {
    api_prefix: "/apis/gateway.networking.k8s.io/v1",
    resource: "backendtlspolicies",
    namespace: Some(object.namespace().to_string()),
    name: object.name().to_string(),
    resource_version: object.metadata.resource_version.clone(),
    status: json!({ "ancestors": ancestors }),
  }
}

fn normalized_target_ref(target: &Value) -> Value {
  let mut out = Map::new();
  out.insert(
    "group".to_string(),
    Value::String(string_at(target, &["group"]).unwrap_or("").to_string()),
  );
  out.insert(
    "kind".to_string(),
    Value::String(
      string_at(target, &["kind"])
        .unwrap_or("Service")
        .to_string(),
    ),
  );
  if let Some(name) = string_at(target, &["name"]) {
    out.insert("name".to_string(), Value::String(name.to_string()));
  }
  if let Some(section_name) = string_at(target, &["sectionName"]) {
    out.insert(
      "sectionName".to_string(),
      Value::String(section_name.to_string()),
    );
  }
  Value::Object(out)
}
