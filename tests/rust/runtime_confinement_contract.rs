use std::fs;
use std::path::{Path, PathBuf};

fn source_root() -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(root: &Path, files: &mut Vec<PathBuf>) {
  for entry in fs::read_dir(root).expect("source directory should be readable") {
    let entry = entry.expect("source entry should be readable");
    let path = entry.path();
    if path.is_dir() {
      rust_sources(&path, files);
    } else if path.extension().is_some_and(|extension| extension == "rs") {
      files.push(path);
    }
  }
}

#[test]
fn post_confinement_resolution_does_not_use_libc_nss() {
  let mut files = Vec::new();
  rust_sources(&source_root(), &mut files);
  let forbidden = ["tokio::net::lookup_host", ".to_socket_addrs()"];
  let mut violations = Vec::new();
  for path in files {
    let source = fs::read_to_string(&path).expect("Rust source should be readable");
    for token in forbidden {
      if source.contains(token) {
        violations.push(format!("{} contains {token}", path.display()));
      }
    }
  }
  assert!(
    violations.is_empty(),
    "runtime hostname resolution must use the bounded manifest-aware resolver:\n{}",
    violations.join("\n")
  );
}
