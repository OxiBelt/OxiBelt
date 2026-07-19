//! Compile-time contracts for compatibility and strict data-plane package boundaries.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source manifest must have a repository parent")
    .to_path_buf()
}

#[test]
fn compatibility_runtime_retains_admin_and_person_proof_surfaces() {
  assert!(
    !oxibelt::server::ADMIN_CAPABILITY_FEATURE_KEYS.is_empty(),
    "the data-plane library must retain its integrated Admin capability surface"
  );
  assert_eq!(oxibelt::waf::PERSON_PROOF_API_VERSION, "1.0.0");
  let _ = std::any::TypeId::of::<oxibelt::waf::WafPersonProofConfig>();
}

#[test]
fn strict_package_is_isolated_from_compatibility_defaults() {
  let root_manifest =
    fs::read_to_string(repo_root().join("Cargo.toml")).expect("workspace manifest should read");
  assert!(root_manifest.contains("\"source/apps/oxibelt-dataplane-strict\""));
  let default_members = root_manifest
    .split("default-members = [")
    .nth(1)
    .and_then(|tail| tail.split(']').next())
    .expect("workspace must declare default-members");
  assert!(
    !default_members.contains("oxibelt-dataplane-strict"),
    "strict package must be built alone so feature unification cannot restore Admin"
  );

  let strict_manifest =
    fs::read_to_string(repo_root().join("source/apps/oxibelt-dataplane-strict/Cargo.toml"))
      .expect("strict package manifest should read");
  assert!(strict_manifest.contains("name = \"oxibelt-dataplane-strict\""));
  assert!(strict_manifest.contains("autobins = false"));
  assert!(strict_manifest.contains("oxibelt = { path = \"../..\", default-features = false }"));
  assert_eq!(strict_manifest.matches("[[bin]]").count(), 1);
  assert!(strict_manifest.contains("name = \"oxibelt-dataplane-strict\""));
}

#[test]
fn strict_build_keeps_person_proof_and_conditionally_excludes_admin_openapi() {
  let build_script =
    fs::read_to_string(repo_root().join("source/build.rs")).expect("build script should read");
  assert!(build_script.contains("OXIBELT_PERSON_PROOF_ASSET_SHA256"));
  assert!(build_script.contains("cfg(feature = \"admin-runtime\")"));
  assert!(build_script.contains("OXIBELT_ADMIN_OPENAPI_SHA256"));
}
