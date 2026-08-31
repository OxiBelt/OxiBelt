use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::rollout_patch::WorkloadPatch;

fn target() -> RolloutTarget {
  RolloutTarget {
    namespace: "default".to_string(),
    kind: WorkloadKind::Deployment,
    name: "edge".to_string(),
    container_name: "oxibelt".to_string(),
    volume_name: "gateway-config".to_string(),
    timeout: Duration::from_secs(300),
    config_map_prefix: "oxibelt-gateway-config".to_string(),
    artifact_context: None,
  }
}

fn workload() -> Value {
  json!({
    "metadata": {
      "resourceVersion": "7",
      "uid": "target-deployment-uid",
      "generation": 2,
      "annotations": { IMMUTABLE_ROLLOUT_ANNOTATION: "true" },
    },
    "spec": {
      "replicas": 3,
      "selector": { "matchLabels": { "app": "edge" } },
      "template": {
        "metadata": { "annotations": {} },
        "spec": {
          "containers": [{
            "name": "oxibelt",
            "args": ["--config", "/etc/oxibelt/config/oxibelt.toml"],
            "volumeMounts": [{
              "name": "config",
              "mountPath": "/etc/oxibelt/config",
              "readOnly": true,
            }],
          }],
          "volumes": [{
            "name": "config",
            "configMap": {
              "name": "base-config",
              "items": [
                {"key": "oxibelt.toml", "path": "oxibelt.toml"},
                {
                  "key": "gateway-config-directory",
                  "path": "conf.d/.keep",
                  "mode": 288,
                },
                {
                  "key": "gateway-config-directory",
                  "path": "conf.d/gateway-api.generated.toml",
                },
              ],
              "defaultMode": 416,
              "optional": false,
            },
          }],
        },
      },
    },
    "status": {
      "observedGeneration": 2,
      "updatedReplicas": 3,
      "readyReplicas": 3,
      "availableReplicas": 3,
    },
  })
}

fn projected_workload(artifact: &ConfigArtifact) -> Value {
  let mut workload = workload();
  workload["metadata"]["annotations"][DESIRED_REVISION_ANNOTATION] = json!(artifact.name);
  workload["metadata"]["annotations"][ARTIFACT_DIGEST_ANNOTATION] = json!(artifact.artifact_digest);
  workload["metadata"]["annotations"][CONFIG_DIGEST_ANNOTATION] = json!(artifact.content_digest);
  workload["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][0]["name"] =
    json!("gateway-config");
  workload["spec"]["template"]["spec"]["volumes"]
    .as_array_mut()
    .expect("volumes")
    .push(json!({
      "name": "gateway-config",
      "projected": {
        "defaultMode": 416,
        "sources": [
          {"configMap": {
            "name": "base-config",
            "items": [
              {"key": "oxibelt.toml", "path": "oxibelt.toml"},
              {
                "key": "gateway-config-directory",
                "path": "conf.d/.keep",
                "mode": 288,
              },
            ],
            "optional": false,
          }},
          {"configMap": {
            "name": artifact.name,
            "items": [{
              "key": artifact.data_key,
              "path": artifact.managed_path,
            }],
          }},
        ],
      },
    }));
  workload
}

fn legacy_workload(artifact: &ConfigArtifact) -> Value {
  let mut workload = workload();
  workload["metadata"]["annotations"][DESIRED_REVISION_ANNOTATION] = json!(artifact.name);
  workload["metadata"]["annotations"][ARTIFACT_DIGEST_ANNOTATION] = json!(artifact.artifact_digest);
  workload["metadata"]["annotations"][CONFIG_DIGEST_ANNOTATION] = json!(artifact.content_digest);
  workload["spec"]["template"]["spec"]["volumes"]
    .as_array_mut()
    .expect("volumes")
    .push(json!({
      "name": "gateway-config",
      "configMap": {
        "name": artifact.name,
        "items": [{"key": artifact.data_key, "path": artifact.data_key}],
        "defaultMode": 420,
      },
    }));
  workload["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
    .as_array_mut()
    .expect("volume mounts")
    .push(json!({
      "name": "gateway-config",
      "mountPath": "/etc/oxibelt/config/conf.d/gateway-api.generated.toml",
      "subPath": artifact.data_key,
      "readOnly": true,
    }));
  workload
}

fn generated_source_replacement(patch: &WorkloadPatch) -> &Value {
  patch
    .operations
    .iter()
    .find(|operation| {
      operation["path"] == "/spec/template/spec/volumes/1/projected/sources/1/configMap"
    })
    .map(|operation| &operation["value"])
    .expect("generated projected source replacement")
}

#[test]
fn artifact_digest_is_stable_and_separates_path_from_content_digest() {
  let target = target();
  let first = ConfigArtifact::new(
    &target,
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n".to_string(),
  )
  .expect("artifact");
  let second = ConfigArtifact::new(
    &target,
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n".to_string(),
  )
  .expect("artifact");
  assert_eq!(first.artifact_digest, second.artifact_digest);
  assert_eq!(first.content_digest, digest_content(b"[[routes]]\n"));
  assert_ne!(first.artifact_digest, first.content_digest);
  assert_eq!(
    first.name,
    format!(
      "oxibelt-gateway-config-deployment-edge-{}",
      first.artifact_digest
    )
  );
}

#[test]
fn ca_assets_are_digest_bound_and_projected_into_the_certificate_root() {
  let content = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";
  let digest = digest_content(content.as_bytes());
  let asset = ConfigArtifactAsset {
    data_key: format!("gateway-api-ca-{digest}.pem"),
    managed_path: format!("gateway-api-ca/{digest}.pem"),
    content: content.to_string(),
  };
  let artifact = ConfigArtifact::new_with_assets(
    &target(),
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n".to_string(),
    vec![asset.clone()],
  )
  .expect("asset bundle");
  let manifest = artifact.manifest(&target());
  assert_eq!(manifest["data"][&asset.data_key], content);

  let prior = RolloutState::from_workload(&workload());
  let state = RolloutState::new_attempt(&artifact, &prior, 1);
  let patch = build_workload_patch(&workload(), &target(), &artifact, &state)
    .expect("asset-aware workload patch");
  assert!(patch.operations.iter().any(|operation| {
    operation["value"]["projected"]["sources"][1]["configMap"]["items"]
      .as_array()
      .is_some_and(|items| {
        items
          .iter()
          .any(|item| item["key"] == asset.data_key && item["path"] == asset.managed_path)
      })
  }));
  assert!(patch.operations.iter().any(|operation| {
    operation["value"]["mountPath"] == "/etc/oxibelt/cert/gateway-api-ca"
      && operation["value"]["subPath"] == "gateway-api-ca"
      && operation["value"]["readOnly"] == true
  }));
}

#[test]
fn client_identity_revisions_are_artifact_bound_and_separately_projected() {
  let first_secret = "oxibelt-upstream-client-11111111111111111111111111111111";
  let rotated_secret = "oxibelt-upstream-client-22222222222222222222222222222222";
  let artifact = ConfigArtifact::new_with_assets_and_client_identities(
    &target(),
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n".to_string(),
    Vec::new(),
    vec![first_secret.to_string()],
  )
  .expect("client identity artifact");
  let rotated = ConfigArtifact::new_with_assets_and_client_identities(
    &target(),
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n".to_string(),
    Vec::new(),
    vec![rotated_secret.to_string()],
  )
  .expect("rotated client identity artifact");
  assert_ne!(artifact.artifact_digest, rotated.artifact_digest);
  assert_ne!(artifact.name, rotated.name);
  assert_eq!(
    artifact.manifest(&target())["metadata"]["annotations"][CLIENT_IDENTITY_SECRETS_ANNOTATION],
    first_secret
  );

  let state = RolloutState::new_attempt(&artifact, &RolloutState::from_workload(&workload()), 1);
  let patch = build_workload_patch(&workload(), &target(), &artifact, &state)
    .expect("client identity workload patch");
  let volumes = patch
    .operations
    .iter()
    .find(|operation| operation["path"] == "/spec/template/spec/volumes")
    .and_then(|operation| operation["value"].as_array())
    .expect("combined volume replacement");
  assert!(volumes.iter().any(|volume| {
    volume["name"] == "gateway-config"
      && volume["projected"]["sources"][1]["configMap"]["name"] == artifact.name
  }));
  assert!(volumes.iter().any(|volume| {
    volume["secret"]["secretName"] == first_secret && volume["secret"]["defaultMode"] == 0o440
  }));
  let mounts = patch
    .operations
    .iter()
    .find(|operation| operation["path"] == "/spec/template/spec/containers/0/volumeMounts")
    .and_then(|operation| operation["value"].as_array())
    .expect("client identity mount replacement");
  assert!(mounts.iter().any(|mount| {
    mount["mountPath"] == format!("/etc/oxibelt/cert/upstream-client/{first_secret}")
      && mount["readOnly"] == true
  }));
}

#[test]
fn client_identity_mounts_are_removed_for_tombstones_and_restored_on_recovery() {
  let secret = "oxibelt-upstream-client-11111111111111111111111111111111";
  let identity_artifact = ConfigArtifact::new_with_assets_and_client_identities(
    &target(),
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n".to_string(),
    Vec::new(),
    vec![secret.to_string()],
  )
  .expect("identity artifact");
  let tombstone_artifact = ConfigArtifact::new(
    &target(),
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n[routes.actions.direct_response]\nstatus = 503\n".to_string(),
  )
  .expect("tombstone artifact");

  let mut mounted = projected_workload(&identity_artifact);
  let mount_state = RolloutState::new_attempt(
    &identity_artifact,
    &RolloutState::from_workload(&mounted),
    1,
  );
  let mount_patch = build_workload_patch(&mounted, &target(), &identity_artifact, &mount_state)
    .expect("identity mount patch");
  for (path, pointer) in [
    ("/spec/template/spec/volumes", "/spec/template/spec/volumes"),
    (
      "/spec/template/spec/containers/0/volumeMounts",
      "/spec/template/spec/containers/0/volumeMounts",
    ),
  ] {
    let value = mount_patch
      .operations
      .iter()
      .find(|operation| operation["path"] == path)
      .map(|operation| operation["value"].clone())
      .expect("identity projection replacement");
    *mounted
      .pointer_mut(pointer)
      .expect("workload projection path") = value;
  }

  let tombstone_state = RolloutState::new_attempt(
    &tombstone_artifact,
    &RolloutState::from_workload(&mounted),
    2,
  );
  let removal = build_workload_patch(&mounted, &target(), &tombstone_artifact, &tombstone_state)
    .expect("tombstone removal patch");
  let removed_volumes = removal
    .operations
    .iter()
    .find(|operation| operation["path"] == "/spec/template/spec/volumes")
    .map(|operation| operation["value"].clone())
    .expect("managed identity volume removal");
  let removed_mounts = removal
    .operations
    .iter()
    .find(|operation| operation["path"] == "/spec/template/spec/containers/0/volumeMounts")
    .map(|operation| operation["value"].clone())
    .expect("managed identity mount removal");
  assert!(!removed_volumes.to_string().contains(secret));
  assert!(!removed_mounts.to_string().contains(secret));

  let recovered_from = projected_workload(&tombstone_artifact);
  let recovery_state = RolloutState::new_attempt(
    &identity_artifact,
    &RolloutState::from_workload(&recovered_from),
    3,
  );
  let recovery = build_workload_patch(
    &recovered_from,
    &target(),
    &identity_artifact,
    &recovery_state,
  )
  .expect("identity recovery patch");
  assert!(recovery.operations.iter().any(|operation| {
    operation["path"] == "/spec/template/spec/volumes"
      && operation["value"].to_string().contains(secret)
  }));
  assert!(recovery.operations.iter().any(|operation| {
    operation["path"] == "/spec/template/spec/containers/0/volumeMounts"
      && operation["value"].to_string().contains(secret)
  }));
}

#[test]
fn artifact_names_and_ownership_labels_are_scoped_to_the_target_kind() {
  let deployment = target();
  let mut daemon_set = deployment.clone();
  daemon_set.kind = WorkloadKind::DaemonSet;
  let content = "[[routes]]\n".to_string();
  let deployment_artifact = ConfigArtifact::new(
    &deployment,
    "conf.d/gateway-api.generated.toml",
    content.clone(),
  )
  .expect("deployment artifact");
  let daemon_set_artifact =
    ConfigArtifact::new(&daemon_set, "conf.d/gateway-api.generated.toml", content)
      .expect("DaemonSet artifact");
  assert_eq!(
    deployment_artifact.artifact_digest,
    daemon_set_artifact.artifact_digest
  );
  assert_ne!(deployment_artifact.name, daemon_set_artifact.name);
  let manifest = daemon_set_artifact.manifest(&daemon_set);
  assert_eq!(
    manifest["metadata"]["labels"][ROLLOUT_TARGET_KIND_LABEL],
    "daemonset"
  );
  assert!(!deployment_artifact.matches_existing(&deployment, &manifest));
}

#[test]
fn artifact_rejects_unsafe_path_and_unowned_toml_sections() {
  let mut target = target();
  assert!(ConfigArtifact::new(&target, "../gateway.toml", String::new()).is_err());
  assert!(ConfigArtifact::new(&target, "gateway.toml", String::new()).is_err());
  assert!(ConfigArtifact::new(&target, "conf.d/gateway.toml", "[admin]\n".to_string()).is_err());
  target.artifact_context = Some("not-a-digest".to_string());
  assert!(ConfigArtifact::new(&target, "conf.d/gateway.toml", "[[routes]]\n".to_string()).is_err());
}

#[test]
fn initial_patch_builds_a_projected_root_without_a_nested_subpath_mount() {
  let target = target();
  let artifact = ConfigArtifact::new(
    &target,
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n".to_string(),
  )
  .expect("artifact");
  let state = RolloutState::new_attempt(&artifact, &RolloutState::from_workload(&workload()), 10);
  let patch = build_workload_patch(&workload(), &target, &artifact, &state).expect("patch");
  assert_eq!(patch.operations[0]["op"], "test");
  assert_eq!(patch.operations[0]["path"], "/metadata/resourceVersion");
  let volume = patch
    .operations
    .iter()
    .find(|operation| operation["path"] == "/spec/template/spec/volumes/-")
    .map(|operation| &operation["value"])
    .expect("projected rollout volume should be added");
  assert_eq!(volume["name"], "gateway-config");
  assert_eq!(volume["projected"]["defaultMode"], 416);
  assert_eq!(
    volume["projected"]["sources"][0]["configMap"],
    json!({
      "name": "base-config",
      "items": [
        {"key": "oxibelt.toml", "path": "oxibelt.toml"},
        {"key": "gateway-config-directory", "path": "conf.d/.keep", "mode": 288},
      ],
      "optional": false,
    })
  );
  assert_eq!(
    volume["projected"]["sources"][1]["configMap"],
    json!({
      "name": artifact.name,
      "items": [{
        "key": "gateway-api.generated.toml",
        "path": "conf.d/gateway-api.generated.toml",
      }],
    })
  );
  assert!(patch.operations.iter().any(|operation| {
    operation["op"] == "replace"
      && operation["path"] == "/spec/template/spec/containers/0/volumeMounts/0/name"
      && operation["value"] == "gateway-config"
  }));
  assert!(!patch.json().to_string().contains("subPath"));
}

#[test]
fn projected_updates_and_rollbacks_replace_only_the_generated_source() {
  let target = target();
  let first = ConfigArtifact::new(
    &target,
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\nid = \"first\"\n".to_string(),
  )
  .expect("first artifact");
  let second = ConfigArtifact::new(
    &target,
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\nid = \"second\"\n".to_string(),
  )
  .expect("second artifact");

  let current = projected_workload(&first);
  let update_state = RolloutState::new_attempt(&second, &RolloutState::from_workload(&current), 20);
  let update = build_workload_patch(&current, &target, &second, &update_state).expect("update");
  assert_eq!(
    generated_source_replacement(&update),
    &json!({
      "name": second.name,
      "items": [{
        "key": second.data_key,
        "path": second.managed_path,
      }],
    })
  );
  assert_eq!(
    update
      .operations
      .iter()
      .filter(|operation| operation["path"]
        .as_str()
        .is_some_and(|path| { path.starts_with("/spec/template/spec/volumes/") }))
      .count(),
    1
  );
  assert!(!update.operations.iter().any(|operation| {
    operation["path"]
      .as_str()
      .is_some_and(|path| path.contains("/volumeMounts"))
  }));

  let failed = projected_workload(&second);
  let rollback_state = RolloutState::new_attempt(&first, &RolloutState::from_workload(&failed), 30);
  let rollback = build_workload_patch(&failed, &target, &first, &rollback_state).expect("rollback");
  assert_eq!(generated_source_replacement(&rollback)["name"], first.name);
  assert_eq!(
    rollback
      .operations
      .iter()
      .filter(|operation| operation["path"]
        .as_str()
        .is_some_and(|path| { path.starts_with("/spec/template/spec/volumes/") }))
      .count(),
    1
  );
}

#[test]
fn exact_legacy_subpath_rollout_is_migrated_to_the_projected_root() {
  let target = target();
  let artifact = ConfigArtifact::new(
    &target,
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n".to_string(),
  )
  .expect("artifact");
  let legacy = legacy_workload(&artifact);
  let state = RolloutState::from_workload(&legacy);
  let patch = build_workload_patch(&legacy, &target, &artifact, &state).expect("migration");

  let volume = patch
    .operations
    .iter()
    .find(|operation| operation["path"] == "/spec/template/spec/volumes/1")
    .map(|operation| &operation["value"])
    .expect("legacy volume replacement");
  assert!(volume.get("configMap").is_none());
  assert_eq!(
    volume["projected"]["sources"][1]["configMap"]["name"],
    artifact.name
  );
  assert!(patch.operations.iter().any(|operation| {
    operation["path"] == "/spec/template/spec/containers/0/volumeMounts/0/name"
      && operation["value"] == "gateway-config"
  }));
  assert!(patch.operations.iter().any(|operation| {
    operation["op"] == "remove"
      && operation["path"] == "/spec/template/spec/containers/0/volumeMounts/1"
  }));
  assert!(!volume.to_string().contains("subPath"));

  let mut nondefault_legacy = legacy_workload(&artifact);
  nondefault_legacy["spec"]["template"]["spec"]["volumes"][1]["configMap"]["defaultMode"] =
    json!(384);
  assert!(
    build_workload_patch(&nondefault_legacy, &target, &artifact, &state).is_err(),
    "legacy migration must accept only the API server's default ConfigMap mode"
  );
}

#[test]
fn projected_rollout_rejects_unknown_sources_revision_drift_and_overlapping_mounts() {
  let target = target();
  let artifact = ConfigArtifact::new(
    &target,
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n".to_string(),
  )
  .expect("artifact");
  let state = RolloutState::from_workload(&projected_workload(&artifact));

  let mut extra_source = projected_workload(&artifact);
  extra_source["spec"]["template"]["spec"]["volumes"][1]["projected"]["sources"]
    .as_array_mut()
    .expect("sources")
    .push(json!({"secret": {"name": "operator-secret"}}));
  assert!(build_workload_patch(&extra_source, &target, &artifact, &state).is_err());

  let mut revision_drift = projected_workload(&artifact);
  revision_drift["spec"]["template"]["spec"]["volumes"][1]["projected"]["sources"][1]["configMap"]
    ["name"] = json!("operator-revision");
  assert!(build_workload_patch(&revision_drift, &target, &artifact, &state).is_err());

  let mut overlap = projected_workload(&artifact);
  overlap["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
    .as_array_mut()
    .expect("volume mounts")
    .push(json!({
      "name": "operator-config",
      "mountPath": "/etc/oxibelt/config/conf.d/operator.toml",
      "readOnly": true,
    }));
  assert!(build_workload_patch(&overlap, &target, &artifact, &state).is_err());

  let mut sidecar_collision = projected_workload(&artifact);
  sidecar_collision["spec"]["template"]["spec"]["containers"]
    .as_array_mut()
    .expect("containers")
    .push(json!({
      "name": "sidecar",
      "volumeMounts": [{
        "name": "gateway-config",
        "mountPath": "/sidecar/config",
        "readOnly": true,
      }],
    }));
  assert!(build_workload_patch(&sidecar_collision, &target, &artifact, &state).is_err());
}

#[test]
fn initial_rollout_refuses_to_adopt_an_operator_volume_name_collision() {
  let target = target();
  let artifact = ConfigArtifact::new(
    &target,
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n".to_string(),
  )
  .expect("artifact");
  let mut conflicting = workload();
  conflicting["spec"]["template"]["spec"]["volumes"]
    .as_array_mut()
    .expect("volumes")
    .push(json!({
      "name": "gateway-config",
      "configMap": { "name": "operator-config" },
    }));
  let state = RolloutState::new_attempt(&artifact, &RolloutState::from_workload(&conflicting), 10);
  assert!(build_workload_patch(&conflicting, &target, &artifact, &state).is_err());
}

#[test]
fn rollout_requires_workload_level_opt_in() {
  let target = target();
  let artifact = ConfigArtifact::new(
    &target,
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n".to_string(),
  )
  .expect("artifact");
  let mut template_only = workload();
  template_only["metadata"]["annotations"] = json!({});
  template_only["spec"]["template"]["metadata"]["annotations"] = json!({
    IMMUTABLE_ROLLOUT_ANNOTATION: "true"
  });
  let state =
    RolloutState::new_attempt(&artifact, &RolloutState::from_workload(&template_only), 10);
  assert!(build_workload_patch(&template_only, &target, &artifact, &state).is_err());
}

#[test]
fn first_attempt_round_trip_keeps_missing_commit_metadata_absent() {
  let target = target();
  let artifact = ConfigArtifact::new(
    &target,
    "conf.d/gateway-api.generated.toml",
    "[[routes]]\n".to_string(),
  )
  .expect("artifact");
  let initial = RolloutState::from_workload(&json!({ "metadata": { "annotations": {} }}));
  let attempt = RolloutState::new_attempt(&artifact, &initial, 10);
  let round_trip = RolloutState::from_workload(&json!({
    "metadata": { "annotations": attempt.annotations() }
  }));
  assert_eq!(round_trip.committed_revision, None);
  assert_eq!(round_trip.committed_content_digest, None);
  assert_eq!(round_trip.failed_revision, None);
}

fn replica_set(uid: &str, deployment_uid: &str) -> Value {
  json!({
    "metadata": {
      "uid": uid,
      "ownerReferences": [{
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "uid": deployment_uid,
        "controller": true,
      }],
    },
  })
}

fn ready_pod(owner_kind: &str, owner_uid: &str, revision: &str, digest: &str) -> Value {
  json!({
    "metadata": {
      "labels": { "app": "edge" },
      "annotations": {
        CONFIG_REVISION_ANNOTATION: revision,
        CONFIG_DIGEST_ANNOTATION: digest,
      },
      "ownerReferences": [{
        "apiVersion": "apps/v1",
        "kind": owner_kind,
        "uid": owner_uid,
        "controller": true,
      }],
    },
    "status": { "conditions": [{ "type": "Ready", "status": "True" }] },
  })
}

#[test]
fn pod_convergence_requires_every_ready_target_owned_pod_to_match() {
  let target = target();
  let workload = workload();
  let ownership = WorkloadPodOwnership::from_workload(
    &target,
    &workload,
    &[replica_set(
      "target-replica-set-uid",
      "target-deployment-uid",
    )],
  )
  .expect("target ownership");
  let pods = vec![
    ready_pod("ReplicaSet", "target-replica-set-uid", "revision", "digest"),
    ready_pod("ReplicaSet", "target-replica-set-uid", "old", "old"),
  ];
  let convergence =
    evaluate_convergence(&target, &workload, &ownership, &pods, "revision", "digest");
  assert_eq!(convergence.pods.desired_ready, 1);
  assert_eq!(convergence.pods.stale_ready, 1);
  assert!(!convergence.all_replicas_converged());
}

#[test]
fn deployment_convergence_excludes_selector_colliding_non_target_replica_set_pods() {
  let target = target();
  let mut workload = workload();
  workload["spec"]["replicas"] = json!(1);
  workload["status"]["updatedReplicas"] = json!(1);
  workload["status"]["readyReplicas"] = json!(1);
  workload["status"]["availableReplicas"] = json!(1);
  let ownership = WorkloadPodOwnership::from_workload(
    &target,
    &workload,
    &[
      replica_set("target-replica-set-uid", "target-deployment-uid"),
      replica_set("tenant-replica-set-uid", "tenant-deployment-uid"),
    ],
  )
  .expect("target ownership");
  let target_pod = ready_pod("ReplicaSet", "target-replica-set-uid", "revision", "digest");
  let colliding_pod = ready_pod("ReplicaSet", "tenant-replica-set-uid", "old", "old");
  let convergence = evaluate_convergence(
    &target,
    &workload,
    &ownership,
    &[target_pod, colliding_pod],
    "revision",
    "digest",
  );
  assert_eq!(convergence.pods.selected, 1);
  assert_eq!(convergence.pods.desired_ready, 1);
  assert_eq!(convergence.pods.stale_ready, 0);
  assert!(convergence.all_replicas_converged());
}

#[test]
fn daemonset_ownership_requires_the_exact_direct_controller_uid() {
  let mut target = target();
  target.kind = WorkloadKind::DaemonSet;
  let mut workload = workload();
  workload["metadata"]["uid"] = json!("target-daemonset-uid");
  let ownership =
    WorkloadPodOwnership::from_workload(&target, &workload, &[]).expect("DaemonSet ownership");
  assert!(pod_is_selected(
    &workload,
    &ownership,
    &ready_pod("DaemonSet", "target-daemonset-uid", "revision", "digest")
  ));
  assert!(!pod_is_selected(
    &workload,
    &ownership,
    &ready_pod("DaemonSet", "tenant-daemonset-uid", "revision", "digest")
  ));
}

#[test]
fn ownership_verification_fails_closed_for_missing_or_malformed_uids() {
  let target = target();
  let mut missing_target_uid = workload();
  missing_target_uid["metadata"]
    .as_object_mut()
    .expect("metadata")
    .remove("uid");
  assert!(WorkloadPodOwnership::from_workload(&target, &missing_target_uid, &[]).is_err());

  let workload = workload();
  let missing_replica_set_uid = json!({
    "metadata": {
      "ownerReferences": [{
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "uid": "target-deployment-uid",
        "controller": true,
      }],
    },
  });
  let malformed_owner_uid = json!({
    "metadata": {
      "uid": "target-replica-set-uid",
      "ownerReferences": [{
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "controller": true,
      }],
    },
  });
  let ownership = WorkloadPodOwnership::from_workload(
    &target,
    &workload,
    &[missing_replica_set_uid, malformed_owner_uid],
  )
  .expect("ownership calculation is safe with missing or malformed ReplicaSet UIDs");
  assert!(!pod_is_selected(
    &workload,
    &ownership,
    &ready_pod("ReplicaSet", "target-replica-set-uid", "revision", "digest")
  ));
}
