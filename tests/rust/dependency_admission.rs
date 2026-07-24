use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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

  let today = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("system time must be after Unix epoch")
    .as_secs() as i64
    / 86_400;
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

  let exemption_count = vet_config["exemptions"]
    .as_table()
    .expect("cargo-vet exemptions must be a table")
    .values()
    .map(|entries| {
      entries
        .as_array()
        .expect("cargo-vet exemption entries must be arrays")
        .len()
    })
    .sum::<usize>();
  assert_eq!(
    exemption_count as u64,
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

  let imports_lock = read("supply-chain/imports.lock");
  assert!(imports_lock.contains("[[audits.google."));
  assert!(imports_lock.contains("[[audits.mozilla."));
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
