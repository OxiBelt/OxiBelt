use std::time::Duration;

use serde_json::{Value, json};

use super::*;

fn target() -> RolloutTarget {
  RolloutTarget {
    namespace: "default".to_string(),
    kind: WorkloadKind::Deployment,
    name: "edge".to_string(),
    container_name: "oxibelt".to_string(),
    volume_name: "gateway-config".to_string(),
    timeout: Duration::from_secs(300),
    config_map_prefix: "oxibelt-gateway-config".to_string(),
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
            "volumeMounts": [],
          }],
          "volumes": [],
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
  let target = target();
  assert!(ConfigArtifact::new(&target, "../gateway.toml", String::new()).is_err());
  assert!(ConfigArtifact::new(&target, "gateway.toml", String::new()).is_err());
  assert!(ConfigArtifact::new(&target, "conf.d/gateway.toml", "[admin]\n".to_string()).is_err());
}

#[test]
fn patch_is_resource_version_guarded_and_keeps_mount_read_only() {
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
  assert!(patch.operations.iter().any(|operation| {
    operation["path"] == "/spec/template/spec/containers/0/volumeMounts/-"
      && operation["value"]["readOnly"] == true
      && operation["value"]["mountPath"] == "/etc/oxibelt/config/conf.d/gateway-api.generated.toml"
  }));
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
  conflicting["spec"]["template"]["spec"]["volumes"] = json!([{
    "name": "gateway-config",
    "configMap": { "name": "operator-config" },
  }]);
  conflicting["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] = json!([{
    "name": "gateway-config",
    "mountPath": "/etc/oxibelt/config/conf.d/gateway-api.generated.toml",
    "subPath": "gateway-api.generated.toml",
    "readOnly": true,
  }]);
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
