use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const CARGO_VET_BOOTSTRAP_EXEMPTIONS_PATH: &str = "supply-chain/cargo-vet-bootstrap-exemptions.txt";
const CARGO_VET_BOOTSTRAP_EXEMPTIONS_SHA256: &str =
  "30c96c7d993f1b7eb7db9a7815e2e91a579e83d10928a3a39fc8365889a38f14";

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

#[test]
fn bindgen_and_prettyplease_share_the_same_syn_ast() {
  let lock = toml_document("Cargo.lock");
  let packages = lock["package"].as_array().expect("Cargo packages");
  let dependency = |package: &toml::Value, prefix: &str| {
    package["dependencies"]
      .as_array()
      .expect("package dependencies")
      .iter()
      .filter_map(toml::Value::as_str)
      .find(|edge| edge.starts_with(prefix))
      .expect("version-qualified dependency edge")
      .to_owned()
  };

  for generator in packages
    .iter()
    .filter(|package| package["name"].as_str() == Some("bindgen"))
  {
    let formatter_edge = dependency(generator, "prettyplease ");
    let (_, formatter_version) = formatter_edge.split_once(' ').unwrap();
    let formatter = packages
      .iter()
      .find(|package| {
        package["name"].as_str() == Some("prettyplease")
          && package["version"].as_str() == Some(formatter_version)
      })
      .expect("locked formatter");
    assert_eq!(
      dependency(generator, "syn "),
      dependency(formatter, "syn "),
      "Bindgen and its formatter must exchange the same Syn AST type",
    );
  }
}

#[test]
fn aws_lc_stable_signature_evidence_matches_first_party_features() {
  let core = toml_document("source/Cargo.toml");
  assert_eq!(
    string_array(
      &core["features"]["mutation-pqc"],
      "source mutation-pqc feature",
    ),
    ["admin-runtime", "oxibelt-admin-mutation-core/mutation-pqc"]
  );
  let mutation_core = toml_document("source/crates/oxibelt-admin-mutation-core/Cargo.toml");
  assert!(
    string_array(
      &mutation_core["features"]["mutation-pqc"],
      "mutation core mutation-pqc feature",
    )
    .is_empty(),
    "mutation-pqc must not enable an unstable AWS-LC feature"
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
    "source/crates/oxibelt-admin-mutation-core/src/admin_mutation/verifier.rs",
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
          locked_registry_packages.contains(&(name.clone(), version.to_owned()))
            || (name == "hyper" && version == "1.12.0" && {
              assert_hyper_vendor_admission();
              true
            })
            || (name == "h2" && version == "0.4.20" && {
              assert_h2_vendor_admission();
              true
            })
            || (name == "rustls" && version == "0.23.46" && {
              assert_rustls_vendor_admission();
              true
            })
            || matches!(
              (name.as_str(), version),
              ("quinn", "0.11.12")
                | ("quinn-proto", "0.11.19")
                | ("h3", "0.0.8")
                | ("web-transport-quinn", "0.13.4")
                | ("web-transport-proto", "0.6.2")
            ),
          "critical dependency {name}@{version} is not an approved registry or byte-locked vendored package"
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

fn assert_hyper_vendor_admission() {
  const VENDOR: &str = "source/third_party/hyper";
  let root = toml_document("Cargo.toml");
  let patches = root["patch"]["crates-io"]
    .as_table()
    .expect("reviewed Hyper patch");
  assert_eq!(root["patch"].as_table().expect("patch table").len(), 1);
  assert_eq!(patches.len(), 8, "unreviewed Cargo patch");
  assert_eq!(
    patches["h2"]["path"].as_str(),
    Some("source/third_party/h2")
  );
  assert_eq!(patches["h2"].as_table().expect("patch").len(), 1);
  assert_eq!(patches["hyper"]["path"].as_str(), Some(VENDOR));
  assert_eq!(patches["hyper"].as_table().expect("patch").len(), 1);
  assert_eq!(
    patches["rustls"]["path"].as_str(),
    Some("source/third_party/rustls")
  );
  assert_eq!(patches["rustls"].as_table().expect("patch").len(), 1);
  assert_eq!(
    string_array(&root["workspace"]["exclude"], "exclusions"),
    vec![
      VENDOR,
      "source/third_party/h2",
      "source/third_party/rustls",
      "source/third_party/quinn",
      "source/third_party/quinn-proto",
      "source/third_party/h3",
      "source/third_party/web-transport-quinn",
      "source/third_party/web-transport-proto",
    ]
  );
  let manifest = toml_document(&format!("{VENDOR}/Cargo.toml"));
  assert_eq!(manifest["package"]["name"].as_str(), Some("hyper"));
  assert_eq!(manifest["package"]["version"].as_str(), Some("1.12.0"));
  assert_eq!(manifest["package"]["license"].as_str(), Some("MIT"));
  assert_eq!(manifest["package"]["build"].as_bool(), Some(false));
  let lock = toml_document("Cargo.lock");
  let hyper = lock["package"]
    .as_array()
    .expect("packages")
    .iter()
    .filter(|package| package["name"].as_str() == Some("hyper"))
    .collect::<Vec<_>>();
  assert_eq!(hyper.len(), 1);
  assert_eq!(hyper[0]["version"].as_str(), Some("1.12.0"));
  assert!(hyper[0].get("source").is_none());
  assert!(hyper[0].get("checksum").is_none());
  let policy = json_policy();
  let sources = policy["rust"]["vendoredRustSources"]
    .as_array()
    .expect("vendor inventory");
  assert_eq!(sources.len(), 8);
  let source = sources
    .iter()
    .find(|source| source["name"] == "hyper")
    .expect("Hyper source inventory");
  assert_eq!(source["name"], "hyper");
  assert_eq!(source["version"], "1.12.0");
  assert_eq!(source["path"], VENDOR);
  assert_eq!(source["license"], "MIT");
  assert_eq!(source["owner"], "@piquark6046");
  assert_eq!(
    source["trackingIssue"],
    "https://github.com/OxiBelt/OxiBelt/issues/194"
  );
  assert_eq!(
    source["upstreamArchiveSha256"],
    "2c3e324da4c95177d6291d4c8730197c0d1822f8a9766814a4a44fa5ab797c9c"
  );
  assert_eq!(source["manifestPath"], "supply-chain/hyper-source.sha256");
  assert_eq!(
    sha256_hex(read("supply-chain/hyper-source.sha256").as_bytes()),
    source["manifestSha256"]
  );
  let expected = checksum_manifest("supply-chain/hyper-source.sha256");
  let mut actual = hash_regular_tree(&repo_root().join(VENDOR));
  // An independently run upstream unit suite creates this untracked lockfile;
  // the production dependency graph is exclusively the root Cargo.lock.
  actual.remove("Cargo.lock");
  assert_eq!(
    actual, expected,
    "vendored Hyper changed without source review"
  );
}

#[test]
fn hyper_transport_source_is_byte_locked_and_governed() {
  assert_hyper_vendor_admission();
}

fn assert_rustls_vendor_admission() {
  const VENDOR: &str = "source/third_party/rustls";
  let root = toml_document("Cargo.toml");
  let patches = root["patch"]["crates-io"]
    .as_table()
    .expect("reviewed Cargo patches");
  assert_eq!(patches["rustls"]["path"].as_str(), Some(VENDOR));
  assert_eq!(patches["rustls"].as_table().expect("patch").len(), 1);
  let manifest = toml_document(&format!("{VENDOR}/Cargo.toml"));
  assert_eq!(manifest["package"]["name"].as_str(), Some("rustls"));
  assert_eq!(manifest["package"]["version"].as_str(), Some("0.23.46"));
  assert_eq!(
    manifest["package"]["license"].as_str(),
    Some("Apache-2.0 OR ISC OR MIT")
  );
  assert_eq!(manifest["package"]["build"].as_str(), Some("build.rs"));

  let lock = toml_document("Cargo.lock");
  let rustls = lock["package"]
    .as_array()
    .expect("packages")
    .iter()
    .filter(|package| package["name"].as_str() == Some("rustls"))
    .collect::<Vec<_>>();
  assert_eq!(rustls.len(), 1);
  assert_eq!(rustls[0]["version"].as_str(), Some("0.23.46"));
  assert!(rustls[0].get("source").is_none());
  assert!(rustls[0].get("checksum").is_none());

  let policy = json_policy();
  let sources = policy["rust"]["vendoredRustSources"]
    .as_array()
    .expect("vendor inventory");
  assert_eq!(sources.len(), 8);
  let source = sources
    .iter()
    .find(|source| source["name"] == "rustls")
    .expect("rustls source inventory");
  assert_eq!(source["version"], "0.23.46");
  assert_eq!(source["path"], VENDOR);
  assert_eq!(source["license"], "Apache-2.0 OR ISC OR MIT");
  assert_eq!(source["owner"], "@piquark6046");
  assert_eq!(
    source["trackingIssue"],
    "https://github.com/OxiBelt/OxiBelt/issues/209"
  );
  assert_eq!(
    source["upstreamRepository"],
    "https://github.com/rustls/rustls"
  );
  assert_eq!(
    source["upstreamArchiveSha256"],
    "48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf"
  );
  assert_eq!(source["manifestPath"], "supply-chain/rustls-source.sha256");
  assert_eq!(
    source["manifestSha256"],
    "1bc3cc7c1656f5882b958c3f67d81c218cc6740292e2608b7da3388a3ccf11b1"
  );
  assert_eq!(
    sha256_hex(read("supply-chain/rustls-source.sha256").as_bytes()),
    source["manifestSha256"]
  );
  assert_eq!(
    hash_regular_tree(&repo_root().join(VENDOR)),
    checksum_manifest("supply-chain/rustls-source.sha256"),
    "vendored rustls changed without source review"
  );
}

#[test]
fn rustls_tls_source_is_byte_locked_and_governed() {
  assert_rustls_vendor_admission();
}

fn assert_h2_vendor_admission() {
  const VENDOR: &str = "source/third_party/h2";
  let policy = json_policy();
  let source = policy["rust"]["vendoredRustSources"]
    .as_array()
    .unwrap()
    .iter()
    .find(|source| source["name"] == "h2")
    .expect("h2 source inventory");
  assert_eq!(source["version"], "0.4.20");
  assert_eq!(source["path"], VENDOR);
  assert_eq!(source["license"], "MIT");
  assert_eq!(source["owner"], "@piquark6046");
  assert_eq!(
    source["trackingIssue"],
    "https://github.com/OxiBelt/OxiBelt/issues/195"
  );
  assert_eq!(
    source["upstreamArchiveSha256"],
    "7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118"
  );
  assert_eq!(source["manifestPath"], "supply-chain/h2-source.sha256");
  assert_eq!(
    sha256_hex(read("supply-chain/h2-source.sha256").as_bytes()),
    source["manifestSha256"]
  );
  let expected = checksum_manifest("supply-chain/h2-source.sha256");
  let mut actual = hash_regular_tree(&repo_root().join(VENDOR));
  actual.remove("Cargo.lock");
  assert_eq!(
    actual, expected,
    "vendored h2 changed without source review"
  );
  let manifest = toml_document(&format!("{VENDOR}/Cargo.toml"));
  assert_eq!(manifest["package"]["name"].as_str(), Some("h2"));
  assert_eq!(manifest["package"]["version"].as_str(), Some("0.4.20"));
  assert_eq!(manifest["package"]["license"].as_str(), Some("MIT"));
  assert_eq!(manifest["package"]["build"].as_bool(), Some(false));
  let lock = toml_document("Cargo.lock");
  let packages = lock["package"]
    .as_array()
    .unwrap()
    .iter()
    .filter(|package| package["name"].as_str() == Some("h2"))
    .collect::<Vec<_>>();
  assert_eq!(packages.len(), 1);
  assert_eq!(packages[0]["version"].as_str(), Some("0.4.20"));
  assert!(packages[0].get("source").is_none());
  assert!(packages[0].get("checksum").is_none());
}

#[test]
fn h2_transport_source_is_byte_locked_and_governed() {
  assert_h2_vendor_admission();
}

#[test]
fn webtransport_h3_transport_sources_are_byte_locked_and_governed() {
  let root = toml_document("Cargo.toml");
  let patches = root["patch"]["crates-io"]
    .as_table()
    .expect("Cargo patches");
  let lock = toml_document("Cargo.lock");
  let packages = lock["package"].as_array().expect("Cargo packages");
  let policy = json_policy();
  let sources = policy["rust"]["vendoredRustSources"]
    .as_array()
    .expect("vendor inventory");
  assert_eq!(sources.len(), 8);
  for (name, version) in [
    ("quinn", "0.11.12"),
    ("quinn-proto", "0.11.19"),
    ("h3", "0.0.8"),
    ("web-transport-quinn", "0.13.4"),
    ("web-transport-proto", "0.6.2"),
  ] {
    let vendor = format!("source/third_party/{name}");
    assert_eq!(patches[name]["path"].as_str(), Some(vendor.as_str()));
    assert_eq!(patches[name].as_table().expect("patch").len(), 1);
    let manifest = toml_document(&format!("{vendor}/Cargo.toml"));
    assert_eq!(manifest["package"]["name"].as_str(), Some(name));
    assert_eq!(manifest["package"]["version"].as_str(), Some(version));
    let locked = packages
      .iter()
      .filter(|package| package["name"].as_str() == Some(name))
      .collect::<Vec<_>>();
    assert_eq!(locked.len(), 1, "one locked {name} package");
    assert_eq!(locked[0]["version"].as_str(), Some(version));
    assert!(locked[0].get("source").is_none());
    assert!(locked[0].get("checksum").is_none());
    let source = sources
      .iter()
      .find(|source| source["name"] == name)
      .expect("vendor policy entry");
    assert_eq!(source["version"].as_str(), Some(version));
    assert_eq!(source["path"].as_str(), Some(vendor.as_str()));
    assert_eq!(
      source["license"].as_str(),
      manifest["package"]["license"].as_str()
    );
    assert_eq!(source["owner"], "@piquark6046");
    assert_eq!(
      source["trackingIssue"],
      "https://github.com/OxiBelt/OxiBelt/issues/220"
    );
    let upstream_hash = source["upstreamArchiveSha256"]
      .as_str()
      .expect("upstream archive SHA-256");
    assert_eq!(upstream_hash.len(), 64);
    assert!(
      upstream_hash
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    let manifest_path = source["manifestPath"]
      .as_str()
      .expect("vendor manifest path");
    assert_eq!(
      sha256_hex(read(manifest_path).as_bytes()),
      source["manifestSha256"]
    );
    let expected = checksum_manifest(manifest_path);
    let mut actual = hash_regular_tree(&repo_root().join(&vendor));
    if !expected.contains_key("Cargo.lock") {
      actual.remove("Cargo.lock");
    }
    assert_eq!(
      actual, expected,
      "vendored {name} changed without source review"
    );
  }
}

#[test]
fn allocator_integration_is_removed_from_current_build_and_admission() {
  let root = toml_document("Cargo.toml");
  let runtime = toml_document("source/Cargo.toml");
  let runtime_features = runtime["features"].as_table().expect("runtime features");
  assert!(
    !runtime_features.contains_key("allocator-mimalloc-experiment"),
    "the removed allocator feature must not return"
  );
  assert_eq!(
    string_array(&runtime_features["default"], "runtime default features"),
    vec!["admin-runtime"]
  );
  assert!(
    runtime["dependencies"].get("oxibelt-allocator").is_none(),
    "the runtime must not depend on the removed allocator crate"
  );
  assert!(
    root["workspace"]["dependencies"]
      .get("oxibelt-allocator")
      .is_none(),
    "the workspace must not declare the removed allocator crate"
  );
  assert!(
    !string_array(&root["workspace"]["members"], "workspace members")
      .contains(&"source/crates/oxibelt-allocator"),
    "the allocator crate must not remain a workspace member"
  );

  let root_path = repo_root();
  for removed_path in [
    "source/crates/oxibelt-allocator",
    "source/third_party/mimalloc-3.5.2",
    "tests/rust/allocator-experiment-check.rs",
    "tests/scripts/run-allocator-sanitizers.sh",
  ] {
    assert!(
      !root_path.join(removed_path).exists(),
      "removed allocator path still exists: {removed_path}"
    );
  }

  let lock = toml_document("Cargo.lock");
  let packages = lock["package"].as_array().expect("lock packages");
  assert!(
    packages.iter().all(|package| !matches!(
      package["name"].as_str(),
      Some("oxibelt-allocator" | "mimalloc" | "libmimalloc-sys")
    )),
    "Cargo.lock must not contain removed allocator packages"
  );

  let policy = json_policy();
  let rust = &policy["rust"];
  assert!(
    rust["nativeSources"]
      .as_array()
      .expect("native source inventory")
      .is_empty(),
    "allocator native source admission must be removed"
  );
  assert!(
    rust["criticalDependencies"]
      .as_array()
      .expect("critical dependency inventory")
      .iter()
      .all(|entry| entry["category"] != "memory-allocation"),
    "the removed allocator must not remain a critical dependency"
  );
  assert!(
    !read("source/src/lib.rs").contains("mark_binary_allocator_mimalloc_experiment")
      && !read("source/src/process_globals.rs")
        .contains("mark_binary_allocator_mimalloc_experiment"),
    "the allocator selection marker must be removed from the library API"
  );
  assert!(
    !read("source/apps/oxibelt-dataplane-strict/build.rs")
      .contains("allocator-mimalloc-experiment"),
    "strict builds must not register the removed Cargo feature"
  );
  assert!(
    !read("tests/rust/unsafe_code_policy.rs").contains("source/crates/oxibelt-allocator"),
    "the removed allocator bridge must not remain in the unsafe-code allowlist"
  );
}
