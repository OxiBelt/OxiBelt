use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};

const SOURCE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");

#[derive(Default)]
struct ModuleFacts {
  paths: Vec<String>,
  trait_objects: usize,
}

impl<'ast> Visit<'ast> for ModuleFacts {
  fn visit_path(&mut self, path: &'ast syn::Path) {
    self.paths.push(
      path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::"),
    );
    visit::visit_path(self, path);
  }

  fn visit_type_trait_object(&mut self, node: &'ast syn::TypeTraitObject) {
    self.trait_objects += 1;
    visit::visit_type_trait_object(self, node);
  }
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
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

fn facts(path: &Path) -> ModuleFacts {
  let source = fs::read_to_string(path)
    .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
  let syntax = syn::parse_file(&source)
    .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
  let mut facts = ModuleFacts::default();
  facts.visit_file(&syntax);
  facts
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

fn has_path(facts: &ModuleFacts, prefixes: &[&str]) -> Option<String> {
  facts
    .paths
    .iter()
    .find(|path| prefixes.iter().any(|prefix| path.starts_with(prefix)))
    .cloned()
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
fn request_path_modules_do_not_depend_on_admin_routing() {
  for target in ["proxy/http.rs", "proxy/http"] {
    for source in sources_at(target) {
      let path = relative(&source);
      if is_test_source(&path) {
        continue;
      }
      let facts = facts(&source);
      assert!(
        has_path(&facts, &["crate::server", "crate::admin"]).is_none(),
        "request-path module {path} must not depend on Admin routing"
      );
    }
  }
}

#[test]
fn pure_waf_representation_modules_have_no_side_effect_dependencies() {
  let pure_modules = [
    "waf/expression.rs",
    "waf/expression/parser.rs",
    "waf/expression/analysis.rs",
    "waf/evaluator_values.rs",
  ];
  for module in pure_modules {
    let source = Path::new(SOURCE_ROOT).join(module);
    if !source.exists() {
      continue;
    }
    let facts = facts(&source);
    let forbidden = [
      "std::fs",
      "tokio::fs",
      "sqlx",
      "redis",
      "crate::server",
      "crate::shared_state",
      "crate::config",
    ];
    assert!(
      has_path(&facts, &forbidden).is_none(),
      "side-effect-free WAF module {module} crossed a dependency boundary"
    );
  }
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
        has_path(
          &facts,
          &[
            "std::sync::Mutex",
            "std::sync::RwLock",
            "tokio::sync::Mutex",
            "tokio::sync::RwLock",
            "tokio::sync::mpsc",
            "tokio::spawn",
          ],
        )
        .is_none(),
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
        has_path(
          &facts,
          &[
            "crate::cache::policy",
            "crate::config::CachePolicy",
            "crate::config::RateLimit",
            "crate::shared_state::failure_policy",
          ],
        )
        .is_none(),
        "storage adapter {path} must not own policy decisions"
      );
    }
  }
}
