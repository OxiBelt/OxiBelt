//! Side-effect-free entry points for fuzzing Gateway API translation.
//!
//! This module is available only through the non-default `fuzzing` feature.

use std::net::{IpAddr, Ipv4Addr};

use serde_json::{Value, json};

use super::cli::{
  BackendResolution, DEFAULT_CONTROLLER_NAME, DEFAULT_MANAGED_CONFIG_PATH, SharedArgs,
  UdpBatchMode, UdpFlowState,
};
use super::model::KubernetesObject;
use super::rollout::RolloutState;

pub const MAX_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_OBJECTS: usize = 16;
const MAX_VALUE_DEPTH: usize = 32;
const MAX_VALUE_NODES: usize = 4_096;

/// Exercises bounded, in-memory Gateway API translation.
///
/// The input may be one JSON value or a stream of YAML documents. Malformed,
/// oversized, or over-populated inputs are rejected as unsupported fuzz cases.
/// The function never constructs a Kubernetes client and performs no network
/// or filesystem access.
pub fn exercise_gateway_api_translation(input: &[u8]) {
  let _ = exercise(input);
}

#[derive(Debug, Default, Eq, PartialEq)]
struct ExerciseReport {
  documents: usize,
  objects: usize,
  translated: bool,
}

fn exercise(input: &[u8]) -> ExerciseReport {
  if input.len() > MAX_INPUT_BYTES {
    return ExerciseReport::default();
  }
  let Some(values) = parse_values(input) else {
    return ExerciseReport::default();
  };
  if values.len() > MAX_OBJECTS || !values.iter().all(value_within_budget) {
    return ExerciseReport::default();
  }

  let documents = values.len();
  let mut objects = Vec::new();
  for value in values {
    exercise_rollout_annotations(&value);
    let Ok(mut parsed) = KubernetesObject::from_value(value) else {
      return ExerciseReport {
        documents,
        objects: objects.len(),
        translated: false,
      };
    };
    if objects.len().saturating_add(parsed.len()) > MAX_OBJECTS {
      return ExerciseReport {
        documents,
        objects: objects.len(),
        translated: false,
      };
    }
    objects.append(&mut parsed);
  }

  let object_count = objects.len();
  let args = translation_args(input.len().is_multiple_of(2));
  let Ok(rendered) = super::translate::translate_objects(&objects, &args) else {
    return ExerciseReport {
      documents,
      objects: object_count,
      translated: false,
    };
  };

  // Reparse the generated document before comparing it.  Formatting and
  // comments are implementation details; the fuzz invariant is that the
  // generated configuration has the same TOML meaning when translation is
  // repeated or the input snapshot is presented in another order.
  let parsed_toml = toml::from_str::<toml::Value>(&rendered.toml)
    .expect("Gateway translation produced invalid TOML");
  let repeated = super::translate::translate_objects(&objects, &args)
    .expect("repeating Gateway translation should preserve its result");
  let repeated_toml = toml::from_str::<toml::Value>(&repeated.toml)
    .expect("repeated Gateway translation produced invalid TOML");

  let mut reordered_objects = objects.clone();
  reordered_objects.reverse();
  let reordered = super::translate::translate_objects(&reordered_objects, &args)
    .expect("reordering a Gateway snapshot should preserve its result");
  let reordered_toml = toml::from_str::<toml::Value>(&reordered.toml)
    .expect("reordered Gateway translation produced invalid TOML");

  assert_eq!(
    parsed_toml, repeated_toml,
    "repeated Gateway translation changed the semantic TOML"
  );
  assert_eq!(
    rendered.diagnostics, repeated.diagnostics,
    "repeated Gateway translation changed diagnostics"
  );
  assert_eq!(
    parsed_toml, reordered_toml,
    "reordered Gateway snapshot changed the semantic TOML"
  );
  assert_eq!(
    rendered.diagnostics, reordered.diagnostics,
    "reordered Gateway snapshot changed diagnostics"
  );
  ExerciseReport {
    documents,
    objects: object_count,
    translated: true,
  }
}

fn parse_values(input: &[u8]) -> Option<Vec<Value>> {
  if let Ok(value) = serde_json::from_slice(input) {
    return Some(vec![value]);
  }
  let input = std::str::from_utf8(input).ok()?;
  let options = serde_saphyr::options! {
    budget: serde_saphyr::budget! {
      max_events: 8_192,
      max_aliases: 64,
      max_anchors: 64,
      max_depth: MAX_VALUE_DEPTH,
      max_inclusion_depth: 0,
      max_documents: MAX_OBJECTS,
      max_nodes: MAX_VALUE_NODES,
      max_total_scalar_bytes: MAX_INPUT_BYTES,
      max_total_comment_bytes: MAX_INPUT_BYTES,
      max_merge_keys: 64,
    },
  };
  serde_saphyr::from_multiple_with_options::<Value>(input, options).ok()
}

fn value_within_budget(value: &Value) -> bool {
  let mut remaining_nodes = MAX_VALUE_NODES;
  let mut pending = vec![(value, 0_usize)];
  while let Some((value, depth)) = pending.pop() {
    if depth > MAX_VALUE_DEPTH || remaining_nodes == 0 {
      return false;
    }
    remaining_nodes -= 1;
    match value {
      Value::Array(values) => {
        pending.extend(values.iter().map(|value| (value, depth + 1)));
      }
      Value::Object(values) => {
        pending.extend(values.values().map(|value| (value, depth + 1)));
      }
      _ => {}
    }
  }
  true
}

fn exercise_rollout_annotations(value: &Value) {
  let mut remaining = MAX_OBJECTS;
  let mut pending = vec![value];
  while let Some(value) = pending.pop() {
    if remaining == 0 {
      return;
    }
    remaining -= 1;
    let state = RolloutState::from_workload(value);
    let round_trip = json!({"metadata": {"annotations": state.annotations()}});
    assert_eq!(
      state,
      RolloutState::from_workload(&round_trip),
      "rollout annotation decoding did not round-trip"
    );
    if let Some(items) = value.get("items").and_then(Value::as_array) {
      pending.extend(items.iter().take(remaining).rev());
    }
  }
}

fn translation_args(endpoint_slice_watch: bool) -> SharedArgs {
  SharedArgs {
    controller_name: DEFAULT_CONTROLLER_NAME.to_string(),
    managed_config_path: DEFAULT_MANAGED_CONFIG_PATH.to_string(),
    watch_namespace: None,
    status_address: Vec::new(),
    status_service: None,
    l4_bind_address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    l4_connect_timeout_ms: 3_000,
    l4_idle_timeout_ms: 75_000,
    udp_flow_state: UdpFlowState::SharedRequired,
    udp_max_flows: 8_192,
    udp_new_flow_rate: "200r/s".to_string(),
    udp_new_flow_burst: 400,
    udp_datagram_rate: "200r/s".to_string(),
    udp_datagram_burst: 400,
    udp_batch: UdpBatchMode::Auto,
    udp_batch_size: 16,
    backend_resolution: if endpoint_slice_watch {
      BackendResolution::EndpointSliceWatch
    } else {
      BackendResolution::ClusterDns
    },
    request_mirror_max_body_bytes: 0,
    external_auth_max_body_bytes: 0,
    external_auth_allowed_content_types: Vec::new(),
    external_auth_allowed_request_headers: Vec::new(),
    external_auth_allowed_identity_headers: Vec::new(),
    external_auth_allowed_terminal_headers: Vec::new(),
    external_auth_allow_credentials: false,
    route_policy_max_request_body_bytes: 10_485_760,
    route_policy_max_timeout_ms: 30_000,
    dry_run: true,
    health_bind: None,
  }
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::{MAX_INPUT_BYTES, MAX_OBJECTS, exercise};

  #[test]
  fn valid_json_exercises_translation_and_rollout_annotations() {
    let input = serde_json::to_vec(&json!({
      "apiVersion": "v1",
      "kind": "Service",
      "metadata": {
        "name": "backend",
        "annotations": {
          "oxibelt.dev/gateway-config-phase": "Committed",
          "oxibelt.dev/gateway-config-started-at-unix": "42"
        }
      },
      "spec": {"ports": [{"port": 8080}]}
    }))
    .expect("serialize fuzz fixture");

    let report = exercise(&input);
    assert_eq!(report.documents, 1);
    assert_eq!(report.objects, 1);
    assert!(report.translated);
  }

  #[test]
  fn yaml_documents_exercise_object_conversion() {
    let input = b"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: first\n---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: second\n";

    let report = exercise(input);
    assert_eq!(report.documents, 2);
    assert_eq!(report.objects, 2);
    assert!(report.translated);
  }

  #[test]
  fn malformed_and_oversized_inputs_are_bounded_noops() {
    assert_eq!(exercise(&[0xff, 0xfe]), Default::default());
    assert_eq!(
      exercise(&vec![b'x'; MAX_INPUT_BYTES + 1]),
      Default::default()
    );
  }

  #[test]
  fn overpopulated_lists_do_not_reach_translation() {
    let items = (0..=MAX_OBJECTS)
      .map(|index| {
        json!({
          "apiVersion": "v1",
          "kind": "Namespace",
          "metadata": {"name": format!("namespace-{index}")}
        })
      })
      .collect::<Vec<_>>();
    let input = serde_json::to_vec(&json!({
      "apiVersion": "v1",
      "kind": "List",
      "items": items
    }))
    .expect("serialize list fixture");

    let report = exercise(&input);
    assert_eq!(report.documents, 1);
    assert_eq!(report.objects, 0);
    assert!(!report.translated);
  }
}
