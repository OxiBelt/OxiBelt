use super::*;

#[test]
fn disabled_runtime_exposes_no_cluster_artifact_capability() {
  let runtime = AdminMutationRuntime::disabled("default");
  assert!(!runtime.cluster_mode());
  assert!(runtime.artifact_cipher().is_err());
  assert!(ensure_cluster_member(&runtime, "edge-a").is_err());
  assert!(runtime.installed_cluster_controller().is_none());
  assert!(runtime.cluster_rollout_ready());
}
