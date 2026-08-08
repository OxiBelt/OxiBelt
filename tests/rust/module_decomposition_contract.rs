use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};

const SOURCE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
const FIXTURE_ROOT: &str = concat!(
  env!("CARGO_MANIFEST_DIR"),
  "/../tests/fixtures/rust-dependency-boundaries"
);
const PURE_WAF_MODULES: &[&str] = &[
  "waf/expression.rs",
  "waf/compiler.rs",
  "waf/plan.rs",
  "waf/evaluator_core.rs",
  "waf/evaluator_values.rs",
  "waf/evaluator_member.rs",
  "waf/evaluator_calls.rs",
  "waf/evaluator_helpers.rs",
  "waf/object_model.rs",
];
const WEBTRANSPORT_ADMIN_BRIDGES: &[&str] = &[
  "proxy/http3/webtransport_bridge/session.rs",
  "proxy/http3/webtransport_bridge/session/state.rs",
  "proxy/http3/webtransport_bridge/session/admin_commands.rs",
];

#[derive(Debug, Default)]
struct ModuleFacts {
  paths: BTreeSet<String>,
  trait_objects: usize,
  wildcard_public_reexport: bool,
}

#[derive(Default)]
struct RawFacts {
  paths: Vec<Vec<String>>,
  aliases: BTreeMap<String, Vec<String>>,
  trait_objects: usize,
  wildcard_public_reexport: bool,
}

impl<'ast> Visit<'ast> for RawFacts {
  fn visit_path(&mut self, path: &'ast syn::Path) {
    self.paths.push(
      path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect(),
    );
    visit::visit_path(self, path);
  }

  fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
    collect_use_tree(
      &item.tree,
      &[],
      &mut self.paths,
      &mut self.aliases,
      matches!(item.vis, syn::Visibility::Public(_)),
      &mut self.wildcard_public_reexport,
    );
  }

  fn visit_type_trait_object(&mut self, node: &'ast syn::TypeTraitObject) {
    self.trait_objects += 1;
    visit::visit_type_trait_object(self, node);
  }
}

fn collect_use_tree(
  tree: &syn::UseTree,
  prefix: &[String],
  paths: &mut Vec<Vec<String>>,
  aliases: &mut BTreeMap<String, Vec<String>>,
  public: bool,
  wildcard_public_reexport: &mut bool,
) {
  match tree {
    syn::UseTree::Path(path) => {
      let mut next = prefix.to_vec();
      next.push(path.ident.to_string());
      collect_use_tree(
        &path.tree,
        &next,
        paths,
        aliases,
        public,
        wildcard_public_reexport,
      );
    }
    syn::UseTree::Name(name) => {
      let mut full = prefix.to_vec();
      if name.ident == "self" {
        paths.push(full.clone());
        if let Some(alias) = full.last().cloned() {
          aliases.insert(alias, full);
        }
      } else {
        full.push(name.ident.to_string());
        paths.push(full.clone());
        aliases.insert(name.ident.to_string(), full);
      }
    }
    syn::UseTree::Rename(rename) => {
      let mut full = prefix.to_vec();
      full.push(rename.ident.to_string());
      paths.push(full.clone());
      aliases.insert(rename.rename.to_string(), full);
    }
    syn::UseTree::Glob(_) => {
      paths.push(prefix.to_vec());
      if public {
        *wildcard_public_reexport = true;
      }
    }
    syn::UseTree::Group(group) => {
      for item in &group.items {
        collect_use_tree(
          item,
          prefix,
          paths,
          aliases,
          public,
          wildcard_public_reexport,
        );
      }
    }
  }
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
  assert!(
    root.exists(),
    "dependency-boundary source root {} must exist",
    root.display()
  );
  let mut pending = vec![root.to_path_buf()];
  let mut sources = Vec::new();
  while let Some(directory) = pending.pop() {
    let mut entries = fs::read_dir(&directory)
      .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
      .map(|entry| {
        entry
          .expect("source directory entry should be readable")
          .path()
      })
      .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
      if path.is_dir() {
        pending.push(path);
      } else if path.extension().is_some_and(|extension| extension == "rs") {
        sources.push(path);
      }
    }
  }
  sources.sort();
  sources
}

fn relative(path: &Path) -> String {
  path
    .strip_prefix(SOURCE_ROOT)
    .expect("Rust source should be below source/src")
    .to_string_lossy()
    .replace('\\', "/")
}

fn is_test_source(path: &str) -> bool {
  path
    .split('/')
    .any(|part| part == "tests" || part.ends_with("_tests.rs") || part.ends_with("tests.rs"))
}

fn module_segments(relative_path: &str) -> Vec<String> {
  let mut segments = relative_path
    .trim_end_matches(".rs")
    .split('/')
    .map(str::to_string)
    .collect::<Vec<_>>();
  if segments
    .last()
    .is_some_and(|name| name == "lib" || name == "mod")
  {
    segments.pop();
  }
  segments
}

fn canonicalize_path(
  raw: &[String],
  aliases: &BTreeMap<String, Vec<String>>,
  relative_path: &str,
) -> String {
  if raw.is_empty() {
    return String::new();
  }
  let mut expanded = if let Some(alias) = aliases.get(&raw[0]) {
    alias
      .iter()
      .cloned()
      .chain(raw[1..].iter().cloned())
      .collect()
  } else {
    raw.to_vec()
  };
  let mut canonical = Vec::new();
  match expanded.first().map(String::as_str) {
    Some("crate") => canonical.append(&mut expanded),
    Some("self") | Some("super") => {
      let mut module = module_segments(relative_path);
      while expanded.first().is_some_and(|segment| segment == "super") {
        module.pop();
        expanded.remove(0);
      }
      if expanded.first().is_some_and(|segment| segment == "self") {
        expanded.remove(0);
      }
      canonical.push("crate".to_string());
      canonical.extend(module);
      canonical.append(&mut expanded);
    }
    _ => canonical.append(&mut expanded),
  }
  canonical.join("::")
}

fn facts_from_source(relative_path: &str, source: &str) -> Result<ModuleFacts, syn::Error> {
  let syntax = syn::parse_file(source)?;
  let mut raw = RawFacts::default();
  raw.visit_file(&syntax);
  let paths = raw
    .paths
    .iter()
    .map(|path| canonicalize_path(path, &raw.aliases, relative_path))
    .filter(|path| !path.is_empty())
    .collect();
  Ok(ModuleFacts {
    paths,
    trait_objects: raw.trait_objects,
    wildcard_public_reexport: raw.wildcard_public_reexport,
  })
}

fn facts(path: &Path) -> ModuleFacts {
  let source = fs::read_to_string(path)
    .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
  facts_from_source(&relative(path), &source)
    .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn sources_at(relative_path: &str) -> Vec<PathBuf> {
  let path = Path::new(SOURCE_ROOT).join(relative_path);
  assert!(
    path.exists(),
    "decomposition contract target {relative_path} must exist"
  );
  if path.is_dir() {
    rust_sources(&path)
  } else {
    vec![path]
  }
}

fn path_matches(path: &str, prefix: &str) -> bool {
  path == prefix
    || path
      .strip_prefix(prefix)
      .is_some_and(|remainder| remainder.starts_with("::"))
}

#[derive(Debug, Eq, PartialEq)]
struct Violation {
  boundary: &'static str,
  source: String,
  dependency: String,
}

fn push_forbidden(
  violations: &mut Vec<Violation>,
  boundary: &'static str,
  source: &str,
  facts: &ModuleFacts,
  forbidden: &[&str],
  allowed: &[&str],
) {
  for dependency in &facts.paths {
    if forbidden
      .iter()
      .any(|prefix| path_matches(dependency, prefix))
      && !allowed
        .iter()
        .any(|prefix| path_matches(dependency, prefix))
    {
      violations.push(Violation {
        boundary,
        source: source.to_string(),
        dependency: dependency.clone(),
      });
    }
  }
}

fn dependency_violations(source: &str, facts: &ModuleFacts) -> Vec<Violation> {
  if is_test_source(source) {
    return Vec::new();
  }
  let mut violations = Vec::new();

  if source == "proxy/mod.rs" || source.starts_with("proxy/") {
    let webtransport_admin_bridge = WEBTRANSPORT_ADMIN_BRIDGES.contains(&source);
    let allowed = if webtransport_admin_bridge {
      &["crate::webtransport_admin"][..]
    } else {
      &[][..]
    };
    push_forbidden(
      &mut violations,
      "protocol/data-plane runtime",
      source,
      facts,
      &["crate::server", "crate::admin", "crate::webtransport_admin"],
      allowed,
    );
  }

  if source == "config.rs" || source.starts_with("config/") {
    push_forbidden(
      &mut violations,
      "configuration model and compiler",
      source,
      facts,
      &[
        "crate::proxy",
        "crate::server",
        "crate::state",
        "crate::runtime",
      ],
      &[],
    );
  }

  if source == "activation_plan.rs" || source.starts_with("activation_plan/") {
    let allowed = if source == "activation_plan/file_adapter.rs" {
      &["std::fs", "std::path", "crate::config::Config"][..]
    } else {
      &[][..]
    };
    push_forbidden(
      &mut violations,
      "activation-plan policy",
      source,
      facts,
      &[
        "std::fs",
        "std::path",
        "std::net",
        "std::process",
        "tokio",
        "sqlx",
        "kube",
        "k8s_openapi",
        "crate::application",
        "crate::listener_socket",
        "crate::reload",
        "crate::server",
        "crate::state",
        "crate::runtime",
        "crate::admin_mutation",
        "crate::config::Config",
      ],
      allowed,
    );
  }

  if PURE_WAF_MODULES.contains(&source) {
    push_forbidden(
      &mut violations,
      "WAF compiler and evaluator",
      source,
      facts,
      &[
        "std::fs",
        "tokio::fs",
        "sqlx",
        "redis",
        "crate::config",
        "crate::server",
        "crate::proxy",
        "crate::shared_state",
        "crate::state",
        "crate::runtime",
      ],
      &[],
    );
  }

  if source == "remote_signer.rs" || source.starts_with("remote_signer/") {
    push_forbidden(
      &mut violations,
      "TLS/key isolation remote signer",
      source,
      facts,
      &[
        "crate::server",
        "crate::proxy",
        "crate::shared_state",
        "crate::waf",
        "crate::admin",
        "crate::webtransport_admin",
      ],
      &[],
    );
  }

  if source == "tls.rs" || source.starts_with("tls/") {
    push_forbidden(
      &mut violations,
      "TLS/key isolation",
      source,
      facts,
      &[
        "crate::server",
        "crate::proxy",
        "crate::shared_state",
        "crate::admin",
        "crate::webtransport_admin",
        "crate::waf",
      ],
      &["crate::waf::metadata::WafClientCertificateMetadata"],
    );
  }

  if source == "diagnostics.rs" || source.starts_with("diagnostics/") {
    push_forbidden(
      &mut violations,
      "deployment diagnostics and support tooling",
      source,
      facts,
      &[
        "crate::kubernetes",
        "crate::kube",
        "crate::controller",
        "crate::gateway_controller",
        "kube",
        "k8s_openapi",
      ],
      &[],
    );
  }

  violations
}

fn public_module_names(source: &str) -> Result<BTreeSet<String>, syn::Error> {
  let syntax = syn::parse_file(source)?;
  Ok(
    syntax
      .items
      .iter()
      .filter_map(|item| match item {
        syn::Item::Mod(module) if matches!(module.vis, syn::Visibility::Public(_)) => {
          Some(module.ident.to_string())
        }
        _ => None,
      })
      .collect(),
  )
}

#[test]
fn every_runtime_source_is_valid_rust_syntax() {
  let sources = rust_sources(Path::new(SOURCE_ROOT));
  assert!(
    !sources.is_empty(),
    "source/src should contain Rust modules"
  );
  for source in sources {
    let _ = facts(&source);
  }
}

#[test]
fn configured_boundary_targets_exist() {
  for target in PURE_WAF_MODULES
    .iter()
    .chain(WEBTRANSPORT_ADMIN_BRIDGES)
    .copied()
    .chain([
      "config.rs",
      "config",
      "activation_plan",
      "proxy",
      "remote_signer.rs",
      "remote_signer",
      "tls.rs",
      "tls",
      "diagnostics.rs",
      "diagnostics",
    ])
  {
    let path = Path::new(SOURCE_ROOT).join(target);
    assert!(
      path.exists(),
      "configured dependency-boundary target {target} must exist"
    );
  }
}

#[test]
fn dependency_boundaries_hold_for_all_runtime_sources() {
  let mut violations = Vec::new();
  for source in rust_sources(Path::new(SOURCE_ROOT)) {
    let relative = relative(&source);
    violations.extend(dependency_violations(&relative, &facts(&source)));
  }
  assert!(
    violations.is_empty(),
    "forbidden module dependencies:\n{}",
    violations
      .iter()
      .map(|violation| format!(
        "{}: {} imports {}",
        violation.boundary, violation.source, violation.dependency
      ))
      .collect::<Vec<_>>()
      .join("\n")
  );
}

#[test]
fn activation_plan_file_io_is_confined_to_the_exact_tooling_adapter() {
  let adapter_path = Path::new(SOURCE_ROOT).join("activation_plan/file_adapter.rs");
  let adapter = facts(&adapter_path);
  assert!(
    adapter
      .paths
      .iter()
      .any(|path| path_matches(path, "std::fs")),
    "the positive adapter control must exercise its narrow filesystem allowance"
  );
  assert!(
    adapter
      .paths
      .iter()
      .any(|path| path_matches(path, "std::path")),
    "the positive adapter control must exercise its narrow path allowance"
  );
  assert!(
    adapter
      .paths
      .iter()
      .any(|path| path_matches(path, "crate::config::Config")),
    "the positive adapter control must exercise its narrow Config loader allowance"
  );
  assert!(
    dependency_violations("activation_plan/file_adapter.rs", &adapter).is_empty(),
    "the current file adapter must remain accepted"
  );

  for source in rust_sources(&Path::new(SOURCE_ROOT).join("activation_plan")) {
    let relative = relative(&source);
    if relative == "activation_plan/file_adapter.rs" || is_test_source(&relative) {
      continue;
    }
    let facts = facts(&source);
    for forbidden in ["std::fs", "std::path", "crate::config::Config"] {
      assert!(
        !facts.paths.iter().any(|path| path_matches(path, forbidden)),
        "activation-plan adapter-only dependency {forbidden} escaped into {relative}"
      );
    }
  }

  for (fixture, forbidden) in [
    ("activation-plan-diff-to-fs.txt", "std::fs"),
    ("activation-plan-diff-to-path.txt", "std::path"),
    (
      "activation-plan-diff-to-config-loader.txt",
      "crate::config::Config",
    ),
  ] {
    let path = Path::new(FIXTURE_ROOT).join(fixture);
    let source = fs::read_to_string(&path)
      .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let fixture_facts = facts_from_source("activation_plan/diff.rs", &source)
      .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
    assert!(
      dependency_violations("activation_plan/diff.rs", &fixture_facts)
        .iter()
        .any(|violation| path_matches(&violation.dependency, forbidden)),
      "fixture {fixture} must exercise adapter-only dependency {forbidden}"
    );
  }
}

#[test]
fn forbidden_dependency_fixtures_are_rejected() {
  for (fixture, source_path, boundary) in [
    (
      "config-to-proxy.txt",
      "config/injected.rs",
      "configuration model and compiler",
    ),
    (
      "proxy-to-admin.txt",
      "proxy/http/injected.rs",
      "protocol/data-plane runtime",
    ),
    (
      "activation-plan-to-server.txt",
      "activation_plan/injected.rs",
      "activation-plan policy",
    ),
    (
      "activation-plan-diff-to-fs.txt",
      "activation_plan/diff.rs",
      "activation-plan policy",
    ),
    (
      "activation-plan-diff-to-path.txt",
      "activation_plan/diff.rs",
      "activation-plan policy",
    ),
    (
      "activation-plan-diff-to-config-loader.txt",
      "activation_plan/diff.rs",
      "activation-plan policy",
    ),
    (
      "activation-plan-file-adapter-to-runtime.txt",
      "activation_plan/file_adapter.rs",
      "activation-plan policy",
    ),
    (
      "waf-to-config.txt",
      "waf/compiler.rs",
      "WAF compiler and evaluator",
    ),
  ] {
    let path = Path::new(FIXTURE_ROOT).join(fixture);
    assert!(
      path.is_file(),
      "dependency-boundary fixture {fixture} must exist"
    );
    let source = fs::read_to_string(&path)
      .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let facts = facts_from_source(source_path, &source)
      .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
    let violations = dependency_violations(source_path, &facts);
    assert!(
      violations
        .iter()
        .any(|violation| violation.boundary == boundary),
      "fixture {fixture} must violate {boundary}; got {violations:?}"
    );
  }
}

#[test]
fn root_public_modules_match_the_reviewed_compatibility_surface() {
  let source = fs::read_to_string(Path::new(SOURCE_ROOT).join("lib.rs"))
    .expect("source/src/lib.rs should be readable");
  let actual = public_module_names(&source).expect("source/src/lib.rs should parse");
  let expected = [
    "access_log",
    "activation_plan",
    "admin_audit",
    "admin_client",
    "admin_mutation",
    "cache",
    "circuit_breakers",
    "client_identity",
    "config",
    "control_http",
    "diagnostics",
    "dynamic_policy",
    "external_auth",
    "filesystem_access",
    "fuzzing",
    "hardening",
    "identity",
    "ipm",
    "lifecycle",
    "limits",
    "metrics",
    "mitigation",
    "netport_switcher",
    "overload",
    "pools",
    "proxy",
    "proxy_protocol",
    "proxy_protocol_egress",
    "quic",
    "reload",
    "remote_signer",
    "routes",
    "runtime",
    "runtime_introspection",
    "server",
    "shared_state",
    "state",
    "stream",
    "telemetry",
    "tls",
    "turn",
    "upstream_control",
    "upstream_discovery",
    "waf",
    "webtransport_admin",
  ]
  .into_iter()
  .map(str::to_string)
  .collect::<BTreeSet<_>>();
  assert_eq!(
    actual, expected,
    "new root `pub mod` declarations require dependency-boundary policy review"
  );

  let fixture = fs::read_to_string(Path::new(FIXTURE_ROOT).join("accidental-public-module.txt"))
    .expect("accidental public-module fixture should be readable");
  let fixture_modules = public_module_names(&fixture).expect("public-module fixture should parse");
  assert!(
    !fixture_modules.is_subset(&expected),
    "public-module fixture must exercise the compatibility-surface detector"
  );
}

#[test]
fn wildcard_public_reexports_stay_in_reviewed_facades() {
  let allowed = [
    "config.rs",
    "config/tls.rs",
    "config/upstream_pool.rs",
    "dynamic_policy.rs",
    "ipm/mod.rs",
    "waf.rs",
    "waf/devtools.rs",
  ]
  .into_iter()
  .map(str::to_string)
  .collect::<BTreeSet<_>>();
  let actual = rust_sources(Path::new(SOURCE_ROOT))
    .into_iter()
    .filter_map(|source| {
      let relative = relative(&source);
      facts(&source).wildcard_public_reexport.then_some(relative)
    })
    .collect::<BTreeSet<_>>();
  assert_eq!(
    actual, allowed,
    "new wildcard public re-exports require facade and compatibility review"
  );
}

#[test]
fn extracted_hot_path_orchestration_stays_concrete() {
  let hot_roots = [
    "proxy/http/pipeline",
    "waf/evaluator_core.rs",
    "waf/evaluator_values.rs",
    "waf/evaluator_member.rs",
    "waf/evaluator_calls.rs",
    "waf/evaluator_helpers.rs",
    "cache/policy.rs",
  ];
  for root in hot_roots {
    for source in sources_at(root) {
      let path = relative(&source);
      if is_test_source(&path) {
        continue;
      }
      let facts = facts(&source);
      assert_eq!(
        facts.trait_objects, 0,
        "hot-path decomposition module {path} must not add trait-object dispatch"
      );
      assert!(
        !facts.paths.iter().any(|path| {
          [
            "std::sync::Mutex",
            "std::sync::RwLock",
            "tokio::sync::Mutex",
            "tokio::sync::RwLock",
            "tokio::sync::mpsc",
            "tokio::spawn",
          ]
          .iter()
          .any(|prefix| path_matches(path, prefix))
        }),
        "hot-path decomposition module {path} must not add locks, channels, or tasks"
      );
    }
  }
}

#[test]
fn storage_adapters_do_not_own_policy() {
  let storage_roots = [
    "cache/storage.rs",
    "shared_state/backend_memory.rs",
    "shared_state/backend_redis.rs",
    "shared_state/backend_postgres.rs",
  ];
  for root in storage_roots {
    for source in sources_at(root) {
      let path = relative(&source);
      if is_test_source(&path) {
        continue;
      }
      let facts = facts(&source);
      assert!(
        !facts.paths.iter().any(|path| {
          [
            "crate::cache::policy",
            "crate::config::CachePolicy",
            "crate::config::RateLimit",
            "crate::shared_state::failure_policy",
          ]
          .iter()
          .any(|prefix| path_matches(path, prefix))
        }),
        "storage adapter {path} must not own policy decisions"
      );
    }
  }
}
