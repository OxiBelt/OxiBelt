use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const CARGO_VET_BOOTSTRAP_EXEMPTIONS_PATH: &str = "supply-chain/cargo-vet-bootstrap-exemptions.txt";
const CARGO_VET_BOOTSTRAP_EXEMPTIONS_SHA256: &str =
  "ead1d1105d6a4c791bcd7c0893466a6329ec29d7757c6226648158354d45b033";

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

fn string_array<'a>(value: &'a toml::Value, description: &str) -> Vec<&'a str> {
  value
    .as_array()
    .unwrap_or_else(|| panic!("{description} must be an array"))
    .iter()
    .map(|entry| {
      entry
        .as_str()
        .unwrap_or_else(|| panic!("{description} entries must be strings"))
    })
    .collect()
}

fn sha256_hex(contents: &[u8]) -> String {
  let digest = Sha256::digest(contents);
  digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn checksum_manifest(path: &str) -> BTreeMap<String, String> {
  let mut entries = BTreeMap::new();
  let mut previous = None;
  for (index, line) in read(path).lines().enumerate() {
    let (checksum, relative) = line.split_once("  ").unwrap_or_else(|| {
      panic!(
        "{path} line {} must use sha256sum's two-space separator",
        index + 1
      )
    });
    assert_eq!(
      checksum.len(),
      64,
      "{path} line {} must contain a SHA-256 digest",
      index + 1
    );
    assert!(
      checksum
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
      "{path} line {} must contain a lowercase SHA-256 digest",
      index + 1
    );
    assert!(
      Path::new(relative)
        .components()
        .all(|component| matches!(component, Component::Normal(_))),
      "{path} line {} must contain a normalized relative path",
      index + 1
    );
    if let Some(previous) = previous {
      assert!(previous < relative, "{path} paths must be strictly sorted");
    }
    assert!(
      entries
        .insert(relative.to_owned(), checksum.to_owned())
        .is_none(),
      "{path} contains duplicate path {relative}"
    );
    previous = Some(relative);
  }
  entries
}

fn hash_regular_tree(root: &Path) -> BTreeMap<String, String> {
  fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<String, String>) {
    for entry in fs::read_dir(directory)
      .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
    {
      let entry = entry.expect("directory entry must be readable");
      let path = entry.path();
      let file_type = entry
        .file_type()
        .unwrap_or_else(|error| panic!("failed to inspect {}: {error}", path.display()));
      assert!(
        !file_type.is_symlink(),
        "vendored dependency contains symlink {}",
        path.display()
      );
      if file_type.is_dir() {
        visit(root, &path, files);
        continue;
      }
      assert!(
        file_type.is_file(),
        "vendored dependency contains non-regular file {}",
        path.display()
      );
      let relative = path
        .strip_prefix(root)
        .expect("vendored file must remain below root")
        .components()
        .map(|component| {
          component
            .as_os_str()
            .to_str()
            .expect("vendored paths must be UTF-8")
        })
        .collect::<Vec<_>>()
        .join("/");
      let contents = fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
      assert!(
        files
          .insert(relative.clone(), sha256_hex(&contents))
          .is_none(),
        "duplicate vendored path {relative}"
      );
    }
  }

  let mut files = BTreeMap::new();
  visit(root, root, &mut files);
  files
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
    443,
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

#[test]
fn aws_lc_stable_signature_evidence_matches_first_party_features() {
  let core = toml_document("source/Cargo.toml");
  assert_eq!(
    string_array(
      &core["features"]["mutation-pqc"],
      "source mutation-pqc feature",
    ),
    ["admin-runtime"]
  );

  let quic_parser = &core["dependencies"]["quic-parser"];
  assert_eq!(quic_parser["version"].as_str(), Some("0.1.5"));
  assert_eq!(quic_parser["default-features"].as_bool(), Some(false));
  assert_eq!(
    string_array(
      &quic_parser["features"],
      "source quic-parser dependency features",
    ),
    ["aws-lc-rs"]
  );
  let cargo_lock = toml_document("Cargo.lock");
  let locked_quic_parser_versions = cargo_lock["package"]
    .as_array()
    .expect("Cargo.lock package list must be an array")
    .iter()
    .filter(|package| package["name"].as_str() == Some("quic-parser"))
    .map(|package| {
      package["version"]
        .as_str()
        .expect("locked quic-parser version must be a string")
    })
    .collect::<Vec<_>>();
  assert_eq!(locked_quic_parser_versions, ["0.1.5"]);

  let cli = toml_document("source/apps/oxibeltctl/Cargo.toml");
  assert_eq!(
    string_array(
      &cli["features"]["mutation-pqc"],
      "oxibeltctl mutation-pqc feature",
    ),
    ["oxibelt/mutation-pqc"]
  );

  for path in [
    "source/apps/oxibeltctl/src/mutation_signer.rs",
    "source/src/admin_mutation/verifier.rs",
  ] {
    assert!(
      !read(path).contains("aws_lc_rs::unstable"),
      "{path} must use stable AWS-LC signature APIs"
    );
  }

  let audits = toml_document("supply-chain/audits.toml");
  let matching_audits = audits["audits"]["aws-lc-rs"]
    .as_array()
    .expect("aws-lc-rs audits must be an array")
    .iter()
    .filter(|audit| audit["delta"].as_str() == Some("1.17.3 -> 1.18.0"))
    .collect::<Vec<_>>();
  assert_eq!(
    matching_audits.len(),
    1,
    "the AWS-LC 1.18.0 delta needs one unambiguous audit record"
  );
  let audit = matching_audits[0];
  assert_eq!(audit["criteria"].as_str(), Some("safe-to-deploy"));
  let notes = audit["notes"]
    .as_str()
    .expect("the AWS-LC 1.18.0 audit needs review notes");
  assert!(notes.contains(
    "first-party mutation-pqc features use the stable signature API and no longer request aws-lc-rs/unstable"
  ));
  assert!(
    notes.contains("locked quic-parser 0.1.5 dependency still requests that feature independently")
  );
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
      "credential-internationalization",
      "cryptography",
      "database",
      "kubernetes",
      "memory-allocation",
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
          "critical dependency {name}@{version} is not a crates.io package"
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
  assert_eq!(bootstrap_id, "rust-cargo-vet-bootstrap");
  let lockfile_subject = format!(
    "Cargo.lock@sha256:{}",
    vet_policy["lockfileSha256"]
      .as_str()
      .expect("cargo-vet needs a lockfile digest")
  );
  let exceptions = policy["exceptions"]
    .as_array()
    .expect("dependency policy needs an exception inventory");
  for (id, control) in [
    (
      "rust-duplicate-compatibility-bootstrap",
      "duplicate-compatibility-lines",
    ),
    (bootstrap_id, "cargo-vet"),
  ] {
    assert!(
      exceptions.iter().any(|exception| {
        exception["id"] == id
          && exception["ecosystem"] == "rust"
          && exception["control"] == control
          && exception["subject"].as_str() == Some(lockfile_subject.as_str())
      }),
      "{id} must bind {control} to the current Cargo.lock digest"
    );
  }

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

#[test]
fn allocator_binding_defaults_to_secure_mimalloc_only_on_supported_targets() {
  let runtime = toml_document("source/Cargo.toml");
  let features = runtime["features"].as_table().expect("runtime features");
  assert_eq!(
    string_array(
      &features["allocator-mimalloc-experiment"],
      "allocator feature"
    ),
    vec!["dep:oxibelt-allocator"]
  );
  for (name, value) in features {
    if name != "allocator-mimalloc-experiment" && name != "default" {
      assert!(
        string_array(value, "runtime feature").iter().all(|entry| {
          *entry != "allocator-mimalloc-experiment"
            && *entry != "dep:oxibelt-allocator"
            && *entry != "oxibelt-allocator/native-mimalloc"
        }),
        "unreviewed feature can change allocator selection: {name}"
      );
    }
  }
  assert_eq!(
    string_array(&features["default"], "runtime default features"),
    vec!["admin-runtime", "allocator-mimalloc-experiment"],
    "default integrated builds must select the architecture-gated allocator"
  );

  let allocator = toml_document("source/crates/oxibelt-allocator/Cargo.toml");
  assert!(
    string_array(
      &allocator["features"]["default"],
      "allocator default features"
    )
    .is_empty()
  );
  assert_eq!(
    string_array(
      &allocator["features"]["native-mimalloc"],
      "allocator native feature"
    ),
    vec!["dep:cc"]
  );
  let cc = &allocator["build-dependencies"]["cc"];
  assert_eq!(cc["version"].as_str(), Some("=1.4.5"));
  assert_eq!(cc["optional"].as_bool(), Some(true));
  assert!(
    runtime["dependencies"].get("oxibelt-allocator").is_none(),
    "the native allocator must not be an unconditional dependency"
  );
  let allocator_target = "cfg(all(target_os = \"linux\", target_arch = \"x86_64\", target_pointer_width = \"64\", any(target_env = \"gnu\", target_env = \"musl\")))";
  let targets = runtime["target"]
    .as_table()
    .expect("runtime target dependencies");
  let allocator_targets = targets
    .iter()
    .filter(|(_, target)| {
      target
        .get("dependencies")
        .and_then(|deps| deps.get("oxibelt-allocator"))
        .is_some()
    })
    .map(|(name, _)| name.as_str())
    .collect::<Vec<_>>();
  assert_eq!(allocator_targets, vec![allocator_target]);
  let source_allocator = &targets[allocator_target]["dependencies"]["oxibelt-allocator"];
  assert_eq!(source_allocator["workspace"].as_bool(), Some(true));
  assert_eq!(source_allocator["optional"].as_bool(), Some(true));
  assert_eq!(
    string_array(&source_allocator["features"], "native target feature"),
    vec!["native-mimalloc"]
  );

  for manifest in ["Cargo.toml", "source/Cargo.toml"] {
    let text = read(manifest);
    assert!(
      !text.contains("libmimalloc-sys") && !text.contains("mimalloc ="),
      "{manifest} must not restore the removed mimalloc Rust packages"
    );
  }
  let root = toml_document("Cargo.toml");
  let workspace_allocator = &root["workspace"]["dependencies"]["oxibelt-allocator"];
  assert_eq!(
    workspace_allocator["path"].as_str(),
    Some("source/crates/oxibelt-allocator")
  );
  assert_eq!(
    workspace_allocator["default-features"].as_bool(),
    Some(false)
  );
  assert_eq!(
    workspace_allocator
      .as_table()
      .expect("workspace allocator dependency")
      .len(),
    2,
    "workspace allocator dependency gained an unreviewed setting"
  );
  assert!(
    root.get("patch").is_none(),
    "the removed allocator package must not remain patched"
  );
  assert!(
    root["workspace"]
      .as_table()
      .expect("workspace table")
      .get("exclude")
      .is_none(),
    "the native source is not a Cargo package or workspace exclusion"
  );
  assert!(
    string_array(&root["workspace"]["members"], "workspace members")
      .contains(&"source/crates/oxibelt-allocator")
  );
  assert!(
    !string_array(
      &root["workspace"]["default-members"],
      "workspace default members"
    )
    .contains(&"source/crates/oxibelt-allocator"),
    "the optional allocator crate must stay outside the default build set"
  );

  let lock = toml_document("Cargo.lock");
  let packages = lock["package"].as_array().expect("lock packages");
  assert!(
    packages.iter().all(|package| !matches!(
      package["name"].as_str(),
      Some("mimalloc" | "libmimalloc-sys")
    )),
    "Cargo.lock must not contain the removed allocator packages"
  );
  let owned = packages
    .iter()
    .filter(|package| package["name"].as_str() == Some("oxibelt-allocator"))
    .collect::<Vec<_>>();
  assert_eq!(owned.len(), 1, "owned allocator crate inventory changed");
  assert!(
    owned[0].get("source").is_none() && owned[0].get("checksum").is_none(),
    "owned allocator crate must resolve from the workspace"
  );

  let binding = read("source/crates/oxibelt-allocator/src/lib.rs");
  for symbol in [
    "mi_malloc_aligned",
    "mi_zalloc_aligned",
    "mi_realloc_aligned",
    "mi_free",
  ] {
    assert_eq!(
      binding.matches(&format!("fn {symbol}(")).count(),
      1,
      "private binding must declare {symbol} exactly once"
    );
  }
  assert!(
    !binding.contains("pub fn mi_") && !binding.contains("pub unsafe fn"),
    "the allocator bridge must not expose a raw native API"
  );
  assert!(
    binding.contains("pub struct Mimalloc")
      && binding.contains("unsafe impl GlobalAlloc for Mimalloc"),
    "the owned crate must expose only its safe GlobalAlloc adapter"
  );
  assert!(
    read("source/src/main.rs").contains("oxibelt_allocator::Mimalloc")
      && !read("source/src/lib.rs").contains("oxibelt_allocator::Mimalloc"),
    "only the integrated binary may install the allocator bridge"
  );
  assert!(
    read("tests/rust/allocator-experiment-check.rs").contains("oxibelt_allocator::Mimalloc"),
    "the allocator checker must exercise the same owned binding"
  );

  let build = read("source/crates/oxibelt-allocator/build.rs");
  for required in [
    "CARGO_CFG_TARGET_OS",
    "CARGO_CFG_TARGET_ARCH",
    "CARGO_CFG_TARGET_POINTER_WIDTH",
    "CARGO_CFG_TARGET_ENV",
    "target_os == \"linux\"",
    "target_arch == \"x86_64\"",
    "target_pointer_width == \"64\"",
    "matches!(target_env.as_str(), \"gnu\" | \"musl\")",
    "third_party/mimalloc-3.5.1",
    "src/static.c",
    "build.define(\"MI_SECURE\", \"4\")",
    "build.define(\"MI_DEBUG\", \"0\")",
    "build.flag(\"-ftls-model=initial-exec\")",
    "format!(\"{build_kind}_CFLAGS\")",
    "CC_SHELL_ESCAPED_FLAGS",
    "changes_preprocessor_input",
    "\"--CONFIG\"",
    "\"-SPECS\"",
    "normalized.contains(\"TLS-MODEL\")",
    "OXIBELT_MIMALLOC_TRANSLATION_UNIT",
    "#if !defined(MI_SECURE) || MI_SECURE != 4",
    "#if !defined(MI_DEBUG) || MI_DEBUG != 0",
    "build.file(write_guarded_translation_unit())",
    "build.compile(\"oxibelt_mimalloc\")",
    "audit_native_archive()",
    "Command::new(\"nm\")",
    "REQUIRED_PRIVATE_ALLOCATOR_SYMBOLS",
    "FORBIDDEN_PROCESS_ALLOCATOR_SYMBOLS",
    "normalized.contains(\"MI_\")",
  ] {
    assert!(build.contains(required), "build script lost {required}");
  }
  let translation_unit_include = build
    .find("#include \"src/static.c\"")
    .expect("the guarded translation unit must include the reviewed native source");
  let override_guards = build
    .match_indices("#if defined(MI_MALLOC_OVERRIDE)")
    .map(|(index, _)| index)
    .collect::<Vec<_>>();
  assert_eq!(
    override_guards.len(),
    2,
    "the guarded translation unit must check allocator override state before and after the native source"
  );
  assert!(
    override_guards[0] < translation_unit_include && translation_unit_include < override_guards[1],
    "the native source must remain enclosed by allocator override guards"
  );
  assert!(
    !build.contains("build.define(\"MI_MALLOC_OVERRIDE\"")
      && !build.contains("build.define(\"MI_OVERRIDE\""),
    "the native build must not override the process C allocator"
  );
}

#[cfg(all(
  target_os = "linux",
  target_arch = "x86_64",
  any(target_env = "gnu", target_env = "musl")
))]
#[test]
fn allocator_native_archive_rejects_transient_override_injection() {
  let temporary = tempfile::tempdir().expect("temporary allocator build root");
  let shadow_source = temporary.path().join("shadow/src");
  fs::create_dir_all(&shadow_source).expect("create shadow source directory");
  let native_source = repo_root()
    .join("source/third_party/mimalloc-3.5.1/src/static.c")
    .canonicalize()
    .expect("canonical native translation unit");
  let native_source = native_source
    .to_str()
    .expect("native source path must be valid UTF-8")
    .replace('"', "\\\"");
  fs::write(
    shadow_source.join("static.c"),
    format!(
      "#define MI_MALLOC_OVERRIDE\n#include \"{native_source}\"\n#undef MI_MALLOC_OVERRIDE\n"
    ),
  )
  .expect("write shadow translation unit");

  let output = std::process::Command::new(env!("CARGO"))
    .current_dir(repo_root())
    .env("CARGO_TARGET_DIR", temporary.path().join("target"))
    .env(
      "CC",
      format!("cc -I{}", temporary.path().join("shadow").display()),
    )
    .args([
      "check",
      "--locked",
      "--offline",
      "-p",
      "oxibelt-allocator",
      "--features",
      "native-mimalloc",
    ])
    .output()
    .expect("run adversarial allocator build");
  let diagnostics = format!(
    "{}\n{}",
    String::from_utf8_lossy(&output.stdout),
    String::from_utf8_lossy(&output.stderr)
  );
  assert!(
    !output.status.success(),
    "transient allocator override injection unexpectedly built successfully"
  );
  assert!(
    diagnostics
      .contains("native allocator archive must not define process allocator symbol `malloc`"),
    "adversarial build failed without the archive-symbol rejection: {diagnostics}"
  );
}

#[test]
fn allocator_native_source_is_byte_locked_and_governed() {
  const NATIVE_PATH: &str = "source/third_party/mimalloc-3.5.1";
  const UPSTREAM_MANIFEST: &str = "source/third_party/mimalloc-3.5.1/UPSTREAM-MANIFEST.sha256";
  const NATIVE_MANIFEST: &str = "source/third_party/mimalloc-3.5.1/NATIVE-MANIFEST.sha256";
  const PROVENANCE: &str = "source/third_party/mimalloc-3.5.1/SOURCE-PROVENANCE.json";
  const README: &str = "source/third_party/mimalloc-3.5.1/README.OXIBELT.md";
  const BINDING: &str = "source/crates/oxibelt-allocator/src/lib.rs";

  assert_eq!(
    read(".gitattributes"),
    "source/third_party/mimalloc-3.5.1/** -whitespace\n",
    "vendored upstream whitespace policy changed"
  );

  let policy = json_policy();
  let native_sources = policy["rust"]["nativeSources"]
    .as_array()
    .expect("nativeSources must be an array");
  assert_eq!(native_sources.len(), 1, "native source inventory changed");
  let native = &native_sources[0];
  assert_eq!(native["id"], "mimalloc");
  assert_eq!(native["version"], "3.5.1");
  assert_eq!(native["path"], NATIVE_PATH);
  assert_eq!(
    native["upstreamRepository"],
    "https://github.com/microsoft/mimalloc"
  );
  assert_eq!(native["upstreamVersion"], "3.5.1");
  assert_eq!(
    native["upstreamRevision"],
    "34fbd7e7cd4627424490afe19b20f8066bfc537d"
  );
  assert_eq!(
    native["acquisition"]["method"],
    "git archive from the exact upstream annotated tag"
  );
  assert_eq!(native["acquisition"]["tag"], "v3.5.1");
  assert_eq!(
    native["acquisition"]["tagObject"],
    "8e05dab9b9e38aa92ab6a6e137baefeaa9e45e40"
  );
  assert_eq!(native["acquisition"]["tagSignature"], "absent");
  assert_eq!(native["acquisition"]["dependency"], false);
  assert_eq!(
    native["sourceScope"],
    "67 upstream source files plus 4 OxiBelt metadata files (71 total); exact unsigned tag and no patches; independent safety review and performance qualification deferred"
  );
  assert_eq!(native["patches"], serde_json::json!([]));
  assert_eq!(native["provenanceReviewedOn"], "2026-09-12");
  assert_eq!(native["independentNativeSafetyReview"], "deferred");
  assert_eq!(native["performanceQualification"], "deferred");
  assert!(native.get("reviewedOn").is_none());
  assert_eq!(native["license"], "MIT");
  assert_eq!(native["secureLevel"], 4);
  assert_eq!(native["allocatorOverride"], false);
  assert_eq!(
    native["targets"],
    serde_json::json!(["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"])
  );
  assert_eq!(native["maintenanceReviewIntervalDays"], 90);
  assert_eq!(native["owner"], "@piquark6046");
  assert_eq!(native["reviewedOn"], "2026-09-10");
  assert_eq!(
    native["trackingIssue"],
    "https://github.com/OxiBelt/OxiBelt/issues/183"
  );

  let critical = policy["rust"]["criticalDependencies"]
    .as_array()
    .expect("criticalDependencies must be an array")
    .iter()
    .find(|entry| entry["category"] == "memory-allocation")
    .expect("memory-allocation critical category");
  assert_eq!(
    critical["packages"],
    serde_json::json!({}),
    "native allocator must not be represented as a Cargo package"
  );
  assert_eq!(critical["nativeSources"], serde_json::json!(["mimalloc"]));

  let vendor_root = repo_root().join(NATIVE_PATH);
  let files = hash_regular_tree(&vendor_root);
  assert_eq!(files.len(), 71, "governed native source file set changed");
  assert_eq!(
    sha256_hex(&fs::read(repo_root().join(UPSTREAM_MANIFEST)).unwrap()),
    native["upstreamManifestSha256"]
  );
  assert_eq!(
    sha256_hex(&fs::read(repo_root().join(NATIVE_MANIFEST)).unwrap()),
    native["nativeManifestSha256"]
  );
  assert_eq!(
    sha256_hex(&fs::read(repo_root().join(PROVENANCE)).unwrap()),
    native["sourceProvenanceSha256"]
  );
  assert_eq!(
    sha256_hex(&fs::read(repo_root().join(README)).unwrap()),
    native["readmeSha256"]
  );
  assert_eq!(
    sha256_hex(&fs::read(repo_root().join(BINDING)).unwrap()),
    native["rustBinding"]["sha256"]
  );

  let upstream = checksum_manifest(UPSTREAM_MANIFEST);
  let selected = checksum_manifest(NATIVE_MANIFEST);
  assert_eq!(upstream.len(), 67, "upstream native manifest changed");
  assert_eq!(selected.len(), 67, "selected native manifest changed");
  assert_eq!(
    upstream.keys().collect::<Vec<_>>(),
    selected.keys().collect::<Vec<_>>(),
    "selected native source must retain the reviewed upstream file set"
  );

  let mut source_files = files.clone();
  for excluded in [
    "NATIVE-MANIFEST.sha256",
    "README.OXIBELT.md",
    "SOURCE-PROVENANCE.json",
    "UPSTREAM-MANIFEST.sha256",
  ] {
    assert!(
      source_files.remove(excluded).is_some(),
      "missing governed metadata file {excluded}"
    );
  }
  assert_eq!(
    source_files, selected,
    "native source differs from its selected content manifest"
  );

  let changed = upstream
    .iter()
    .filter(|(path, checksum)| selected.get(*path) != Some(*checksum))
    .map(|(path, _)| path.as_str())
    .collect::<BTreeSet<_>>();
  assert!(
    changed.is_empty(),
    "native source must match the upstream tag exactly"
  );

  let provenance: serde_json::Value =
    serde_json::from_str(&read(PROVENANCE)).expect("source provenance must be valid JSON");
  assert_eq!(provenance["schemaVersion"], 1);
  assert_eq!(provenance["component"]["path"], NATIVE_PATH);
  assert_eq!(provenance["component"]["version"], native["version"]);
  assert_eq!(
    provenance["upstream"]["repository"],
    native["upstreamRepository"]
  );
  assert_eq!(provenance["upstream"]["tag"], native["acquisition"]["tag"]);
  assert_eq!(
    provenance["upstream"]["tagObject"],
    native["acquisition"]["tagObject"]
  );
  assert_eq!(
    provenance["upstream"]["tagSignature"],
    native["acquisition"]["tagSignature"]
  );
  assert_eq!(
    provenance["upstream"]["revision"],
    native["upstreamRevision"]
  );
  assert_eq!(
    provenance["acquisition"]["method"],
    native["acquisition"]["method"]
  );
  assert_eq!(provenance["acquisition"]["dependency"], false);
  assert_eq!(native["patches"], serde_json::json!([]));
  assert!(
    provenance["patches"]
      .as_array()
      .expect("source provenance patches must be an array")
      .is_empty(),
    "unreviewed native patches must not be introduced"
  );
  assert_eq!(
    provenance["manifests"]["upstream"]["sha256"],
    native["upstreamManifestSha256"]
  );
  assert_eq!(
    provenance["manifests"]["native"]["sha256"],
    native["nativeManifestSha256"]
  );
  assert_eq!(
    provenance["rustBinding"]["path"],
    native["rustBinding"]["path"]
  );
  for (path, checksum) in native["licenseFiles"]
    .as_object()
    .expect("native license files must be an object")
  {
    assert_eq!(
      files.get(path).map(String::as_str),
      checksum.as_str(),
      "native license digest is stale for {path}"
    );
  }

  assert_eq!(native["rustBinding"]["path"], BINDING);
  assert_eq!(
    native["rustBinding"]["derivedFrom"],
    "https://github.com/purpleprotocol/mimalloc_rust"
  );
  assert_eq!(native["rustBinding"]["license"], "MIT");
  assert_eq!(
    native["rustBinding"]["visibility"],
    "safe allocator type; private raw FFI"
  );
  assert_eq!(
    native["buildIntegration"]["path"],
    "source/crates/oxibelt-allocator/build.rs"
  );
  assert_eq!(
    sha256_hex(&fs::read(repo_root().join("source/crates/oxibelt-allocator/build.rs")).unwrap()),
    native["buildIntegration"]["sha256"]
  );
  assert_eq!(
    provenance["buildIntegration"]["path"],
    native["buildIntegration"]["path"]
  );
  assert_eq!(
    provenance["buildIntegration"]["sha256"],
    native["buildIntegration"]["sha256"]
  );
  assert_eq!(provenance["rustBinding"]["rawVisibility"], "private");
  assert_eq!(
    provenance["rustBinding"]["adapterVisibility"],
    "public-safe-type"
  );
  let binding = read(BINDING);
  assert!(
    binding.contains("Copyright 2019 Octavian Oncescu")
      && binding.contains("Permission is hereby granted, free of charge"),
    "the adapted Rust binding must retain its complete MIT notice"
  );
  let notices = read("THIRD-PARTY-NOTICES.md");
  assert!(
    notices.contains("Microsoft mimalloc")
      && notices.contains("purpleprotocol/mimalloc_rust")
      && notices.contains("Copyright 2019 Octavian Oncescu"),
    "repository notices must preserve native and Rust-binding attribution"
  );

  let vet = read("supply-chain/config.toml");
  let audits = read("supply-chain/audits.toml");
  assert!(
    !vet.contains("[policy.libmimalloc-sys]") && !audits.contains("[[audits.mimalloc]]"),
    "removed Cargo packages must not retain Cargo-vet policy or audits"
  );
}
