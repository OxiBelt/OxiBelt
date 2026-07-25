use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const CARGO_VET_BOOTSTRAP_EXEMPTIONS_PATH: &str = "supply-chain/cargo-vet-bootstrap-exemptions.txt";
const CARGO_VET_BOOTSTRAP_EXEMPTIONS_SHA256: &str =
  "8edb58ae7bd40fa0f256d0687171cbdcec443b1c511327eaccffdad9c74c53cd";

fn repo_root() -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source crate must have a repository parent")
    .to_path_buf()
}

fn read(path: &str) -> String {
  fs::read_to_string(repo_root().join(path))
    .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn json_policy() -> serde_json::Value {
  serde_json::from_str(&read("supply-chain/dependency-policy.json"))
    .expect("dependency policy must be valid JSON")
}

fn toml_document(path: &str) -> toml::Value {
  toml::from_str(&read(path)).unwrap_or_else(|error| panic!("failed to parse {path}: {error}"))
}

fn sha256_hex(contents: &[u8]) -> String {
  let digest = Sha256::digest(contents);
  digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn exact_cargo_vet_subject(package: &str, version: &str, criteria: &str) -> String {
  assert!(
    !package.is_empty() && !package.contains('@') && !package.contains(':'),
    "cargo-vet subject has invalid package: {package}"
  );
  assert!(
    !version.is_empty() && !version.contains('@') && !version.contains(':'),
    "cargo-vet subject has invalid version: {version}"
  );
  assert!(
    matches!(criteria, "safe-to-deploy" | "safe-to-run"),
    "cargo-vet subject has invalid criteria: {criteria}"
  );
  format!("{package}@{version}:{criteria}")
}

fn cargo_vet_exemption_subjects(vet_config: &toml::Value) -> BTreeSet<String> {
  let mut subjects = BTreeSet::new();
  for (package, entries) in vet_config["exemptions"]
    .as_table()
    .expect("cargo-vet exemptions must be a table")
  {
    for entry in entries
      .as_array()
      .expect("cargo-vet exemption entries must be arrays")
    {
      let version = entry["version"]
        .as_str()
        .unwrap_or_else(|| panic!("cargo-vet exemption {package} requires a version"));
      let criteria = entry["criteria"]
        .as_str()
        .unwrap_or_else(|| panic!("cargo-vet exemption {package}@{version} requires criteria"));
      let subject = exact_cargo_vet_subject(package, version, criteria);
      assert!(
        subjects.insert(subject.clone()),
        "duplicate cargo-vet exemption subject: {subject}"
      );
    }
  }
  subjects
}

fn cargo_vet_bootstrap_exemption_subjects() -> BTreeSet<String> {
  let inventory = read(CARGO_VET_BOOTSTRAP_EXEMPTIONS_PATH);
  assert_eq!(
    sha256_hex(inventory.as_bytes()),
    CARGO_VET_BOOTSTRAP_EXEMPTIONS_SHA256,
    "cargo-vet bootstrap exemption inventory changed"
  );

  let mut subjects = BTreeSet::new();
  let mut previous = None;
  for (index, subject) in inventory.lines().enumerate() {
    assert_eq!(
      subject.trim(),
      subject,
      "cargo-vet bootstrap exemption line {} has surrounding whitespace",
      index + 1
    );
    let (package_version, criteria) = subject.rsplit_once(':').unwrap_or_else(|| {
      panic!(
        "cargo-vet bootstrap exemption line {} needs criteria",
        index + 1
      )
    });
    let (package, version) = package_version.rsplit_once('@').unwrap_or_else(|| {
      panic!(
        "cargo-vet bootstrap exemption line {} needs package@version",
        index + 1
      )
    });
    assert_eq!(
      exact_cargo_vet_subject(package, version, criteria),
      subject,
      "cargo-vet bootstrap exemption line {} is not exact",
      index + 1
    );
    if let Some(previous) = previous {
      assert!(
        previous < subject,
        "cargo-vet bootstrap exemption inventory must be strictly sorted"
      );
    }
    assert!(
      subjects.insert(subject.to_owned()),
      "duplicate cargo-vet bootstrap exemption subject: {subject}"
    );
    previous = Some(subject);
  }
  assert_eq!(
    subjects.len(),
    424,
    "cargo-vet bootstrap exemption inventory must remain independently frozen"
  );
  subjects
}

fn current_unix_day() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("system time must be after Unix epoch")
    .as_secs() as i64
    / 86_400
}

fn active_non_bootstrap_cargo_vet_exception_subjects(
  policy: &serde_json::Value,
) -> BTreeSet<String> {
  let today = current_unix_day();
  let mut subjects = BTreeSet::new();
  for exception in policy["exceptions"]
    .as_array()
    .expect("exceptions must be an array")
    .iter()
    .filter(|exception| {
      exception["ecosystem"] == "rust"
        && exception["control"] == "cargo-vet"
        && exception["bootstrap"].as_bool() != Some(true)
    })
  {
    let id = exception["id"]
      .as_str()
      .expect("cargo-vet exception requires an id");
    let subject = exception["subject"]
      .as_str()
      .expect("cargo-vet exception requires an exact subject");
    let (package_version, criteria) = subject
      .rsplit_once(':')
      .expect("cargo-vet exception subject must end in criteria");
    let (package, version) = package_version
      .rsplit_once('@')
      .expect("cargo-vet exception subject must identify package@version");
    assert_eq!(
      exact_cargo_vet_subject(package, version, criteria),
      subject,
      "cargo-vet exception {id} must use an exact subject"
    );
    let expires = parse_date(
      exception["expiresOn"]
        .as_str()
        .expect("cargo-vet exception requires expiresOn"),
    );
    assert!(expires >= today, "cargo-vet exception {id} is expired");
    assert!(
      subjects.insert(subject.to_owned()),
      "duplicate active cargo-vet exception subject: {subject}"
    );
  }
  subjects
}

fn cargo_vet_subject_mapping_errors(
  current_exemptions: &BTreeSet<String>,
  bootstrap_exemptions: &BTreeSet<String>,
  active_exceptions: &BTreeSet<String>,
) -> Vec<String> {
  let mut errors = current_exemptions
    .difference(bootstrap_exemptions)
    .filter(|subject| !active_exceptions.contains(*subject))
    .map(|subject| {
      format!(
        "cargo-vet exemption {subject} is outside the frozen bootstrap inventory and requires exactly one active non-bootstrap exception"
      )
    })
    .collect::<Vec<_>>();
  errors.extend(
    active_exceptions
      .difference(current_exemptions)
      .map(|subject| {
        format!("cargo-vet exception {subject} must match an exact config.toml exemption")
      }),
  );
  errors
}

fn compatibility_line(version: &str) -> String {
  let mut components = version
    .split(['-', '+'])
    .next()
    .expect("version must have a core")
    .split('.');
  let major = components.next().expect("version must have a major");
  if major == "0" {
    let minor = components.next().expect("0.x version must have a minor");
    if minor == "0" {
      format!(
        "0.0.{}",
        components.next().expect("0.0.x version must have a patch")
      )
    } else {
      format!("0.{minor}")
    }
  } else {
    major.to_owned()
  }
}

#[test]
fn compatibility_lines_follow_cargo_zero_major_semantics() {
  assert_eq!(compatibility_line("1.2.3"), "1");
  assert_eq!(compatibility_line("0.2.3"), "0.2");
  assert_eq!(compatibility_line("0.0.3"), "0.0.3");
  assert_eq!(compatibility_line("0.0.7-alpha.1+metadata"), "0.0.7");
}

fn parse_date(value: &str) -> i64 {
  assert_eq!(value.len(), 10, "date must use YYYY-MM-DD: {value}");
  assert_eq!(&value[4..5], "-", "date must use YYYY-MM-DD: {value}");
  assert_eq!(&value[7..8], "-", "date must use YYYY-MM-DD: {value}");

  let year = value[..4]
    .parse::<i64>()
    .unwrap_or_else(|_| panic!("invalid year in {value}"));
  let month = value[5..7]
    .parse::<i64>()
    .unwrap_or_else(|_| panic!("invalid month in {value}"));
  let day = value[8..]
    .parse::<i64>()
    .unwrap_or_else(|_| panic!("invalid day in {value}"));

  assert!((1..=12).contains(&month), "invalid month in {value}");
  let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
  let month_days = [
    31,
    if leap { 29 } else { 28 },
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  assert!(
    day >= 1 && day <= month_days[(month - 1) as usize],
    "invalid day in {value}"
  );

  let adjusted_year = year - i64::from(month <= 2);
  let era = if adjusted_year >= 0 {
    adjusted_year
  } else {
    adjusted_year - 399
  } / 400;
  let year_of_era = adjusted_year - era * 400;
  let adjusted_month = month + if month > 2 { -3 } else { 9 };
  let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
  let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
  era * 146_097 + day_of_era - 719_468
}

#[test]
fn dependency_exceptions_are_owned_bounded_and_current() {
  let policy = json_policy();
  assert_eq!(policy["schemaVersion"], 1);
  assert_eq!(policy["policyOwner"], "OxiBelt maintainers");

  let maximum_days = policy["maxExceptionDays"]
    .as_i64()
    .expect("maxExceptionDays must be an integer");
  assert!((1..=90).contains(&maximum_days));

  let today = current_unix_day();
  let mut ids = BTreeSet::new();
  let mut subjects = BTreeSet::new();
  let exceptions = policy["exceptions"]
    .as_array()
    .expect("exceptions must be an array");
  assert!(!exceptions.is_empty());

  for exception in exceptions {
    let id = exception["id"].as_str().expect("exception needs an id");
    assert!(ids.insert(id), "duplicate exception id: {id}");
    let subject = exception["subject"]
      .as_str()
      .expect("exception needs a subject");
    assert!(
      subjects.insert((exception["control"].to_string(), subject)),
      "duplicate exception subject: {subject}"
    );
    for field in ["ecosystem", "control", "rationale", "owner"] {
      assert!(
        exception[field]
          .as_str()
          .is_some_and(|value| !value.trim().is_empty()),
        "{id} requires non-empty {field}"
      );
    }

    let reviewed = parse_date(
      exception["reviewedOn"]
        .as_str()
        .expect("exception requires reviewedOn"),
    );
    let expires = parse_date(
      exception["expiresOn"]
        .as_str()
        .expect("exception requires expiresOn"),
    );
    assert!(expires >= reviewed, "{id} expires before review");
    assert!(
      expires - reviewed <= maximum_days,
      "{id} exceeds the {maximum_days}-day exception limit"
    );
    assert!(expires >= today, "dependency exception {id} is expired");

    if exception["bootstrap"].as_bool() == Some(true) {
      assert_eq!(
        exception["trackingReference"].as_str(),
        Some(
          ".agents/temp/OxiBelt_Medium_Scale_Security_Edge_P0-P2_Improvement_Plan.md#phase-12-strengthen-dependency-admission-and-independent-verification"
        )
      );
    } else {
      assert!(
        exception["trackingIssue"]
          .as_str()
          .is_some_and(|url| url.starts_with("https://github.com/OxiBelt/OxiBelt/issues/")),
        "non-bootstrap exception {id} requires an OxiBelt GitHub issue"
      );
    }
  }
}

#[test]
fn rust_policy_classifies_and_pins_critical_dependency_lines() {
  let policy = json_policy();
  let rust = &policy["rust"];
  assert_eq!(
    rust["allowedRegistries"],
    serde_json::json!(["https://github.com/rust-lang/crates.io-index"])
  );
  assert_eq!(rust["approvedGitSources"], serde_json::json!([]));

  let triggers = rust["reviewTriggers"]
    .as_array()
    .expect("Rust review triggers must be an array");
  for required in [
    "new direct dependency",
    "new or changed dependency source",
    "new critical dependency version or feature",
    "new transitive critical major version",
    "new build script or proc-macro capability",
    "new or extended dependency-policy exception",
  ] {
    assert!(triggers.iter().any(|trigger| trigger == required));
  }

  let cargo_lock = toml_document("Cargo.lock");
  let locked_packages = cargo_lock["package"]
    .as_array()
    .expect("Cargo.lock package list must be an array");
  let locked_registry_packages = locked_packages
    .iter()
    .filter(|package| {
      package.get("source").and_then(toml::Value::as_str)
        == Some("registry+https://github.com/rust-lang/crates.io-index")
    })
    .filter_map(|package| {
      Some((
        package["name"].as_str()?.to_owned(),
        package["version"].as_str()?.to_owned(),
      ))
    })
    .collect::<BTreeSet<_>>();

  let mut compatibility_lines = BTreeMap::<String, BTreeSet<String>>::new();
  for (name, version) in &locked_registry_packages {
    compatibility_lines
      .entry(name.clone())
      .or_default()
      .insert(compatibility_line(version));
  }
  compatibility_lines.retain(|_, lines| lines.len() > 1);
  let baseline = rust["duplicateCompatibilityBaseline"]
    .as_object()
    .expect("duplicate compatibility baseline must be an object");
  assert_eq!(
    compatibility_lines.keys().collect::<BTreeSet<_>>(),
    baseline.keys().collect::<BTreeSet<_>>(),
    "duplicate compatibility-line package set changed"
  );
  for (name, lines) in compatibility_lines {
    let recorded = baseline[&name]
      .as_array()
      .expect("duplicate compatibility lines must be an array")
      .iter()
      .map(|line| line.as_str().expect("compatibility line must be a string"))
      .collect::<BTreeSet<_>>();
    assert_eq!(
      lines.iter().map(String::as_str).collect::<BTreeSet<_>>(),
      recorded,
      "duplicate compatibility lines changed for {name}"
    );
  }

  let categories = rust["criticalDependencies"]
    .as_array()
    .expect("criticalDependencies must be an array");
  let category_names = categories
    .iter()
    .map(|entry| entry["category"].as_str().expect("category needs a name"))
    .collect::<BTreeSet<_>>();
  assert_eq!(
    category_names,
    BTreeSet::from([
      "compression",
      "cryptography",
      "database",
      "kubernetes",
      "parsing-serialization",
      "tls-quic-http",
    ])
  );

  let mut classified = BTreeSet::new();
  for category in categories {
    assert!(
      category["reviewBoundary"]
        .as_str()
        .is_some_and(|boundary| !boundary.is_empty())
    );
    let packages = category["packages"]
      .as_object()
      .expect("critical category packages must be an object");
    for (name, versions) in packages {
      assert!(classified.insert(name), "{name} has multiple categories");
      for version in versions
        .as_array()
        .expect("critical dependency versions must be an array")
      {
        let version = version.as_str().expect("version must be a string");
        assert!(
          locked_registry_packages.contains(&(name.clone(), version.to_owned())),
          "critical dependency {name}@{version} is not in Cargo.lock"
        );
      }
    }
  }
  assert!(
    classified.len() >= 40,
    "critical coverage unexpectedly shrank"
  );
}

#[test]
fn kubernetes_client_features_exclude_proxy_transports() {
  let root = toml_document("Cargo.toml");
  let kube = &root["workspace"]["dependencies"]["kube"];
  assert_eq!(kube["default-features"].as_bool(), Some(false));
  let features = kube["features"]
    .as_array()
    .expect("workspace kube features must be an array")
    .iter()
    .map(|feature| feature.as_str().expect("kube feature must be a string"))
    .collect::<BTreeSet<_>>();
  assert_eq!(
    features,
    BTreeSet::from(["aws-lc-rs", "client", "runtime", "rustls-tls"])
  );
  assert!(!features.contains("http-proxy"));
  assert!(!features.contains("socks5"));
}

#[test]
fn cargo_vet_imports_and_bootstrap_inventory_are_locked() {
  let policy = json_policy();
  let vet_policy = &policy["rust"]["cargoVet"];
  assert_eq!(vet_policy["version"], "0.10.2");
  assert_eq!(vet_policy["deploymentCriteria"], "safe-to-deploy");
  assert_eq!(vet_policy["developmentCriteria"], "safe-to-run");

  let vet_config_text = read("supply-chain/config.toml");
  let vet_config = toml_document("supply-chain/config.toml");
  assert_eq!(vet_config["cargo-vet"]["version"].as_str(), Some("0.10"));
  for peer in ["google", "mozilla"] {
    assert_eq!(
      vet_config["imports"][peer]["url"].as_str(),
      vet_policy["imports"][peer].as_str()
    );
  }

  let current_exemptions = cargo_vet_exemption_subjects(&vet_config);
  assert_eq!(
    current_exemptions.len() as u64,
    vet_policy["exemptedPackageVersions"]
      .as_u64()
      .expect("exemptedPackageVersions must be an integer")
  );
  assert_eq!(
    sha256_hex(read("Cargo.lock").as_bytes()),
    vet_policy["lockfileSha256"]
  );
  assert_eq!(
    sha256_hex(vet_config_text.as_bytes()),
    vet_policy["exemptionInventorySha256"]
  );

  let bootstrap_id = vet_policy["bootstrapException"]
    .as_str()
    .expect("cargo-vet needs a bootstrap exception id");
  assert!(policy["exceptions"].as_array().is_some_and(|exceptions| {
    exceptions.iter().any(|exception| {
      exception["id"] == bootstrap_id
        && exception["ecosystem"] == "rust"
        && exception["control"] == "cargo-vet"
        && exception["subject"]
          == format!(
            "Cargo.lock@sha256:{}",
            vet_policy["lockfileSha256"].as_str().unwrap_or_default()
          )
    })
  }));

  let bootstrap_exemptions = cargo_vet_bootstrap_exemption_subjects();
  let active_exceptions = active_non_bootstrap_cargo_vet_exception_subjects(&policy);
  let mapping_errors = cargo_vet_subject_mapping_errors(
    &current_exemptions,
    &bootstrap_exemptions,
    &active_exceptions,
  );
  assert!(
    mapping_errors.is_empty(),
    "cargo-vet exemption/exception mapping violations:\n{}",
    mapping_errors.join("\n")
  );

  let imports_lock = read("supply-chain/imports.lock");
  assert!(imports_lock.contains("[[audits.google."));
  assert!(imports_lock.contains("[[audits.mozilla."));
}

#[test]
fn cargo_vet_rejects_unmapped_subjects_in_both_directions() {
  // The integration boundary calls this helper only after accepting the synchronized
  // exemption count and config hash, so exercise the remaining subject-mapping control.
  let bootstrap_exemptions = BTreeSet::from(["existing@1.0.0:safe-to-deploy".to_owned()]);
  let mut current_exemptions = BTreeSet::from([
    "existing@1.0.0:safe-to-deploy".to_owned(),
    "new-package@2.0.0:safe-to-deploy".to_owned(),
  ]);
  let mut active_exceptions = BTreeSet::new();

  assert_eq!(
    cargo_vet_subject_mapping_errors(
      &current_exemptions,
      &bootstrap_exemptions,
      &active_exceptions,
    ),
    vec![
      "cargo-vet exemption new-package@2.0.0:safe-to-deploy is outside the frozen bootstrap inventory and requires exactly one active non-bootstrap exception"
        .to_owned()
    ]
  );

  active_exceptions.insert("new-package@2.0.0:safe-to-deploy".to_owned());
  assert!(
    cargo_vet_subject_mapping_errors(
      &current_exemptions,
      &bootstrap_exemptions,
      &active_exceptions,
    )
    .is_empty(),
    "the exact active exception must preserve a legitimate post-bootstrap exemption"
  );

  current_exemptions.remove("new-package@2.0.0:safe-to-deploy");
  assert_eq!(
    cargo_vet_subject_mapping_errors(
      &current_exemptions,
      &bootstrap_exemptions,
      &active_exceptions,
    ),
    vec![
      "cargo-vet exception new-package@2.0.0:safe-to-deploy must match an exact config.toml exemption"
        .to_owned()
    ],
    "a stale active exception must not outlive its exact Cargo-vet exemption"
  );
}

#[test]
fn cargo_deny_enforces_full_graph_license_ban_and_source_policy() {
  let policy = json_policy();
  let deny = toml_document("deny.toml");
  assert_eq!(deny["graph"]["all-features"].as_bool(), Some(true));
  assert_eq!(deny["graph"]["targets"].as_array().map(Vec::len), Some(6));
  assert_eq!(deny["advisories"]["yanked"].as_str(), Some("deny"));
  assert_eq!(deny["advisories"]["unmaintained"].as_str(), Some("all"));
  assert_eq!(
    deny["advisories"]["ignore"].as_array().map(Vec::len),
    Some(0)
  );
  assert_eq!(deny["bans"]["multiple-versions"].as_str(), Some("warn"));
  assert_eq!(deny["bans"]["wildcards"].as_str(), Some("deny"));

  let denied = deny["bans"]["deny"]
    .as_array()
    .expect("bans.deny must be an array");
  for banned in ["native-tls", "openssl"] {
    assert!(
      denied
        .iter()
        .any(|entry| entry["crate"].as_str() == Some(banned)),
      "missing ban for {banned}"
    );
  }
  for singular in [
    "aws-lc-rs",
    "http",
    "hyper",
    "jsonschema",
    "k8s-openapi",
    "kube",
    "openssl-sys",
    "quinn",
    "rustls",
    "sequoia-openpgp",
    "serde",
    "serde_json",
    "sqlx",
    "toml",
    "zstd",
  ] {
    assert!(denied.iter().any(|entry| {
      entry["crate"].as_str() == Some(singular)
        && entry["deny-multiple-versions"].as_bool() == Some(true)
    }));
  }

  assert_eq!(deny["sources"]["unknown-registry"].as_str(), Some("deny"));
  assert_eq!(deny["sources"]["unknown-git"].as_str(), Some("deny"));
  assert_eq!(deny["sources"]["required-git-spec"].as_str(), Some("rev"));
  let registries = deny["sources"]["allow-registry"]
    .as_array()
    .expect("allow-registry must be an array")
    .iter()
    .map(|value| value.as_str().expect("registry must be a string"))
    .collect::<Vec<_>>();
  let policy_registries = policy["rust"]["allowedRegistries"]
    .as_array()
    .unwrap()
    .iter()
    .map(|value| value.as_str().expect("policy registry must be a string"))
    .collect::<Vec<_>>();
  assert_eq!(registries, policy_registries);
  assert_eq!(
    deny["sources"]["allow-git"].as_array().unwrap().len(),
    policy["rust"]["approvedGitSources"]
      .as_array()
      .unwrap()
      .len()
  );

  let allowed_licenses = deny["licenses"]["allow"]
    .as_array()
    .expect("license allow list must be an array");
  for required in ["Apache-2.0", "BSD-3-Clause", "ISC", "MIT", "OpenSSL"] {
    assert!(
      allowed_licenses
        .iter()
        .any(|license| license.as_str() == Some(required))
    );
  }

  let exceptions = policy["exceptions"]
    .as_array()
    .expect("policy exceptions must be an array");
  for exception in deny["licenses"]["exceptions"]
    .as_array()
    .expect("license exceptions must be an array")
  {
    let package = exception["crate"]
      .as_str()
      .expect("license crate is required");
    for license in exception["allow"]
      .as_array()
      .expect("exception licenses must be an array")
    {
      let subject = format!(
        "{package}:{}",
        license.as_str().expect("license must be a string")
      );
      assert!(exceptions.iter().any(|entry| {
        entry["ecosystem"] == "rust" && entry["control"] == "license" && entry["subject"] == subject
      }));
    }
  }
}

#[test]
fn cargo_lock_uses_only_the_approved_registry() {
  let lock = toml_document("Cargo.lock");
  for package in lock["package"]
    .as_array()
    .expect("Cargo.lock packages must be an array")
  {
    if let Some(source) = package.get("source").and_then(toml::Value::as_str) {
      assert_eq!(
        source, "registry+https://github.com/rust-lang/crates.io-index",
        "{}@{} has an unapproved source",
        package["name"], package["version"]
      );
    }
  }
}
