//! Compile-time contracts for compatibility and strict data-plane package boundaries.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source manifest must have a repository parent")
    .to_path_buf()
}

fn manifest(relative_path: &str) -> toml::Value {
  let path = repo_root().join(relative_path);
  let source = fs::read_to_string(&path)
    .unwrap_or_else(|error| panic!("{} should read: {error}", path.display()));
  toml::from_str(&source)
    .unwrap_or_else(|error| panic!("{} should parse as TOML: {error}", path.display()))
}

fn table<'a>(
  value: &'a toml::Value,
  key: &str,
  context: &str,
) -> &'a toml::map::Map<String, toml::Value> {
  value
    .get(key)
    .and_then(toml::Value::as_table)
    .unwrap_or_else(|| panic!("{context} must contain a `{key}` table"))
}

fn string_set(value: &toml::Value, context: &str) -> BTreeSet<String> {
  value
    .as_array()
    .unwrap_or_else(|| panic!("{context} must be an array"))
    .iter()
    .map(|entry| {
      entry
        .as_str()
        .unwrap_or_else(|| panic!("{context} entries must be strings"))
        .to_owned()
    })
    .collect()
}

fn dependency<'a>(
  manifest: &'a toml::Value,
  package: &str,
  context: &str,
) -> &'a toml::map::Map<String, toml::Value> {
  table(manifest, "dependencies", context)
    .get(package)
    .and_then(toml::Value::as_table)
    .unwrap_or_else(|| panic!("{context} must declare `{package}` as a dependency table"))
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
fn workspace_dependencies_disable_oxibelt_default_features() {
  let root_manifest = manifest("Cargo.toml");
  let workspace = table(&root_manifest, "workspace", "workspace manifest");
  let members = string_set(
    workspace
      .get("members")
      .expect("workspace must declare members"),
    "workspace members",
  );
  let default_members = string_set(
    workspace
      .get("default-members")
      .expect("workspace must declare default-members"),
    "workspace default-members",
  );

  assert!(members.contains("source/apps/oxibelt-dataplane-strict"));
  assert!(
    !default_members.contains("source/apps/oxibelt-dataplane-strict"),
    "strict package must be built alone so feature unification cannot restore Admin"
  );

  let workspace_dependencies = workspace
    .get("dependencies")
    .and_then(toml::Value::as_table)
    .expect("workspace must declare dependency policy");
  let oxibelt = workspace_dependencies
    .get("oxibelt")
    .and_then(toml::Value::as_table)
    .expect("workspace must declare `oxibelt` as a dependency table");
  assert_eq!(
    oxibelt.get("path").and_then(toml::Value::as_str),
    Some("source")
  );
  assert_eq!(
    oxibelt
      .get("default-features")
      .and_then(toml::Value::as_bool),
    Some(false),
    "workspace consumers must opt into role-owned `oxibelt` features"
  );
}

#[test]
fn strict_package_is_isolated_from_compatibility_defaults() {
  let strict_manifest = manifest("source/apps/oxibelt-dataplane-strict/Cargo.toml");
  let package = table(&strict_manifest, "package", "strict package manifest");
  assert_eq!(
    package.get("name").and_then(toml::Value::as_str),
    Some("oxibelt-dataplane-strict")
  );
  assert_eq!(
    package.get("autobins").and_then(toml::Value::as_bool),
    Some(false)
  );

  let oxibelt = dependency(&strict_manifest, "oxibelt", "strict package manifest");
  assert_eq!(
    oxibelt.get("path").and_then(toml::Value::as_str),
    Some("../..")
  );
  assert_eq!(
    oxibelt
      .get("default-features")
      .and_then(toml::Value::as_bool),
    Some(false)
  );

  let binaries = strict_manifest
    .get("bin")
    .and_then(toml::Value::as_array)
    .expect("strict package must declare explicit binaries");
  assert_eq!(
    binaries.len(),
    1,
    "strict package must expose exactly one production binary"
  );
  let binary = binaries[0]
    .as_table()
    .expect("strict package binary must be a table");
  assert_eq!(
    binary.get("name").and_then(toml::Value::as_str),
    Some("oxibelt-dataplane-strict")
  );
  assert_eq!(
    binary.get("path").and_then(toml::Value::as_str),
    Some("../../src/main.rs")
  );
}

#[test]
fn workspace_consumers_enable_only_role_owned_oxibelt_features() {
  let tools_manifest = manifest("source/apps/oxibeltctl/Cargo.toml");
  let tools_features = table(
    &tools_manifest,
    "features",
    "operator-tools package manifest",
  );
  assert_eq!(
    string_set(
      tools_features
        .get("default")
        .expect("operator tools must declare default features"),
      "operator-tools default features",
    ),
    BTreeSet::from(["cli".to_owned()]),
    "operator tools must retain the CLI in default builds"
  );
  assert_eq!(
    string_set(
      tools_features
        .get("cli")
        .expect("operator tools must declare the `cli` feature"),
      "operator-tools `cli` feature",
    ),
    BTreeSet::from(["dep:sequoia-openpgp".to_owned()]),
    "the CLI feature must own only its optional OpenPGP dependency"
  );
  assert!(
    string_set(
      tools_features
        .get("fuzzing")
        .expect("operator tools must retain the `fuzzing` feature"),
      "operator-tools `fuzzing` feature",
    )
    .is_empty(),
    "the library-only fuzzing feature must remain separate from CLI dependencies"
  );

  let sequoia = dependency(
    &tools_manifest,
    "sequoia-openpgp",
    "operator-tools package manifest",
  );
  assert_eq!(
    sequoia.get("workspace").and_then(toml::Value::as_bool),
    Some(true)
  );
  assert_eq!(
    sequoia.get("optional").and_then(toml::Value::as_bool),
    Some(true),
    "OpenPGP must remain optional for library-only builds"
  );

  let tools_binaries = tools_manifest
    .get("bin")
    .and_then(toml::Value::as_array)
    .expect("operator tools must declare explicit binaries");
  assert_eq!(
    tools_binaries.len(),
    1,
    "operator tools must expose exactly one production binary"
  );
  let tools_binary = tools_binaries[0]
    .as_table()
    .expect("operator-tools binary must be a table");
  assert_eq!(
    tools_binary.get("name").and_then(toml::Value::as_str),
    Some("oxibeltctl")
  );
  assert_eq!(
    string_set(
      tools_binary
        .get("required-features")
        .expect("operator-tools binary must declare required features"),
      "operator-tools binary required features",
    ),
    BTreeSet::from(["cli".to_owned()]),
    "the operator-tools binary must require only the CLI feature"
  );

  let tools_oxibelt = dependency(
    &tools_manifest,
    "oxibelt",
    "operator-tools package manifest",
  );
  assert_eq!(
    tools_oxibelt
      .get("workspace")
      .and_then(toml::Value::as_bool),
    Some(true)
  );
  assert_eq!(
    string_set(
      tools_oxibelt
        .get("features")
        .expect("operator tools must declare `oxibelt` features"),
      "operator-tools `oxibelt` features",
    ),
    BTreeSet::from(["admin-runtime".to_owned(), "config-tooling".to_owned()])
  );

  for (role, relative_path) in [
    ("key signer", "source/apps/oxibelt-keysigner/Cargo.toml"),
    (
      "netport switcher",
      "source/apps/oxibelt-netport-switcher/Cargo.toml",
    ),
  ] {
    let role_manifest = manifest(relative_path);
    let role_features = table(&role_manifest, "features", role);
    assert_eq!(
      role_features
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>(),
      BTreeSet::from(["crypto-ring", "default"]),
      "{role} must not expose unrelated runtime feature forwarding"
    );
    assert!(
      string_set(
        role_features
          .get("default")
          .unwrap_or_else(|| panic!("{role} must declare default features")),
        &format!("{role} default features"),
      )
      .is_empty(),
      "{role} defaults must remain empty"
    );
    assert_eq!(
      string_set(
        role_features
          .get("crypto-ring")
          .unwrap_or_else(|| panic!("{role} must declare crypto-ring forwarding")),
        &format!("{role} crypto-ring forwarding"),
      ),
      BTreeSet::from(["oxibelt/crypto-ring".to_owned()]),
      "{role} crypto-ring must enable only the matching runtime backend"
    );

    let role_oxibelt = dependency(&role_manifest, "oxibelt", role);
    assert_eq!(
      role_oxibelt.get("workspace").and_then(toml::Value::as_bool),
      Some(true)
    );
    assert!(
      role_oxibelt.get("features").is_none(),
      "{role} must not enable `oxibelt` features outside its feature table"
    );
  }
}

#[test]
fn strict_build_keeps_person_proof_and_conditionally_excludes_admin_openapi() {
  let build_script =
    fs::read_to_string(repo_root().join("source/build.rs")).expect("build script should read");
  assert!(build_script.contains("OXIBELT_PERSON_PROOF_ASSET_SHA256"));
  assert!(build_script.contains("cfg(feature = \"admin-runtime\")"));
  assert!(build_script.contains("OXIBELT_ADMIN_OPENAPI_SHA256"));
}
