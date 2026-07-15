use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

const UNSAFE_ALLOWLIST: &[&str] = &[
  "source/src/hardening/syscalls.rs",
  "source/src/tcp_hop/syscalls.rs",
];
const GOVERNED_LINTS: &[&str] = &[
  "unsafe_code",
  "unsafe_op_in_unsafe_fn",
  "undocumented_unsafe_blocks",
  "multiple_unsafe_ops_per_block",
  "missing_safety_doc",
];
const LOWERING_ATTRIBUTES: &[&str] = &["allow", "warn", "expect"];

#[derive(Debug)]
struct AttributeUse {
  depth: usize,
  inner: bool,
  idents: BTreeSet<String>,
  tokens: String,
}

#[test]
fn first_party_rust_uses_only_the_audited_unsafe_allowlist() {
  let root = repo_root();
  let files = rust_source_files(&root);
  let mut errors = Vec::new();

  for relative in files {
    let source = fs::read_to_string(root.join(&relative))
      .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"));
    errors.extend(inspect_source(&relative, &source));
  }

  assert!(
    errors.is_empty(),
    "unsafe-code policy violations:\n{}",
    errors.join("\n")
  );
}

#[test]
fn manifests_apply_the_policy_to_every_first_party_workspace() {
  let root = repo_root();
  let root_manifest = root.join("Cargo.toml");
  assert_contains_all(
    &root_manifest,
    &[
      "[workspace.lints.rust]",
      "unsafe_code = \"deny\"",
      "unsafe_op_in_unsafe_fn = \"deny\"",
      "[workspace.lints.clippy]",
      "missing_safety_doc = \"deny\"",
      "multiple_unsafe_ops_per_block = \"deny\"",
      "undocumented_unsafe_blocks = \"deny\"",
    ],
  );
  let root_toml = fs::read_to_string(&root_manifest).expect("root Cargo.toml should be readable");
  let root_toml = toml::from_str::<toml::Value>(&root_toml)
    .expect("root Cargo.toml should parse for policy inspection");
  let members = root_toml
    .get("workspace")
    .and_then(|workspace| workspace.get("members"))
    .and_then(toml::Value::as_array)
    .expect("root Cargo.toml should declare workspace members")
    .iter()
    .map(|member| {
      let member = member
        .as_str()
        .expect("workspace member should be a literal path");
      assert!(
        !member
          .chars()
          .any(|character| matches!(character, '*' | '?' | '[' | ']')),
        "unsafe policy requires explicit workspace member paths, found {member}"
      );
      format!("{member}/Cargo.toml")
    })
    .collect::<BTreeSet<_>>();

  let manifests = repository_files(&root, &["Cargo.toml", ":(glob)**/Cargo.toml"]);
  for member in &members {
    assert!(
      manifests.contains(member),
      "workspace member manifest {member} should exist and be tracked or unignored"
    );
  }
  for manifest in manifests {
    if manifest == "Cargo.toml" {
      continue;
    }
    if members.contains(&manifest) {
      assert_contains_all(&root.join(manifest), &["[lints]", "workspace = true"]);
    } else {
      assert_contains_all(
        &root.join(manifest),
        &[
          "[lints.rust]",
          "unsafe_code = \"deny\"",
          "unsafe_op_in_unsafe_fn = \"deny\"",
          "[lints.clippy]",
          "missing_safety_doc = \"deny\"",
          "multiple_unsafe_ops_per_block = \"deny\"",
          "undocumented_unsafe_blocks = \"deny\"",
        ],
      );
    }
  }
}

#[test]
fn build_configuration_does_not_lower_the_unsafe_policy() {
  let root = repo_root();
  let mut files = repository_files(
    &root,
    &[
      "Cargo.toml",
      ":(glob)**/Cargo.toml",
      ":(glob).github/workflows/*.yml",
      ":(glob).github/workflows/*.yaml",
    ],
  )
  .into_iter()
  .map(|path| root.join(path))
  .collect::<Vec<_>>();
  for config in [root.join(".cargo/config"), root.join(".cargo/config.toml")] {
    if config.is_file() {
      files.push(config);
    }
  }

  for path in files {
    let contents = fs::read_to_string(&path)
      .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    for forbidden in [
      "--cap-lints",
      "-A unsafe_code",
      "--allow unsafe_code",
      "-Aunsafe_code",
    ] {
      assert!(
        !contents.contains(forbidden),
        "{} must not lower unsafe-code policy with {forbidden}",
        path.display()
      );
    }
  }
}

#[test]
fn policy_inspection_rejects_bypasses_and_stale_entries() {
  assert_has_error(
    "source/src/example.rs",
    "fn example() { unsafe { core::hint::unreachable_unchecked() } }",
    "unsafe keyword(s) outside the allowlist",
  );
  assert_has_error(
    "source/src/example.rs",
    "#[allow(unsafe_code)] fn example() {}",
    "weakens governed lint",
  );
  assert_has_error(
    "source/src/example.rs",
    "#[cfg_attr(target_os = \"linux\", allow(unsafe_code))] fn example() {}",
    "weakens governed lint",
  );
  assert_has_error(
    UNSAFE_ALLOWLIST[0],
    "#![allow(unsafe_code)] fn example() { unsafe {} }",
    "exactly one reasoned file-level",
  );
  assert_has_error(
    UNSAFE_ALLOWLIST[0],
    "#![cfg_attr(target_os = \"linux\", allow(unsafe_code, reason = \"conditional\"))] fn example() { unsafe {} }",
    "exactly one reasoned file-level",
  );
  assert_has_error(
    UNSAFE_ALLOWLIST[0],
    "#![allow(unsafe_code, dead_code, reason = \"combined\")] fn example() { unsafe {} }",
    "exactly one reasoned file-level",
  );
  assert_has_error(
    UNSAFE_ALLOWLIST[0],
    "#![allow(unsafe_code, reason = \"audited\")] fn example() {}",
    "allowlist entry contains no unsafe keyword",
  );
  assert!(
    inspect_source(
      UNSAFE_ALLOWLIST[0],
      "#![allow(unsafe_code, reason = \"audited syscall\")] fn example() { unsafe {} }",
    )
    .is_empty(),
    "the exact reasoned allowlist form should be accepted"
  );
}

fn inspect_source(relative: &str, source: &str) -> Vec<String> {
  let mut errors = Vec::new();
  if let Err(error) = syn::parse_file(source) {
    errors.push(format!("{relative}: Rust source did not parse: {error}"));
    return errors;
  }
  let tokens = match TokenStream::from_str(source) {
    Ok(tokens) => tokens,
    Err(error) => {
      errors.push(format!("{relative}: Rust tokens did not parse: {error}"));
      return errors;
    }
  };
  let unsafe_count = count_ident(&tokens, "unsafe");
  let allowlisted = UNSAFE_ALLOWLIST.contains(&relative);
  if !allowlisted && unsafe_count > 0 {
    errors.push(format!(
      "{relative}: found {unsafe_count} unsafe keyword(s) outside the allowlist"
    ));
  }
  if allowlisted && unsafe_count == 0 {
    errors.push(format!(
      "{relative}: allowlist entry contains no unsafe keyword and must be removed"
    ));
  }

  let mut attributes = Vec::new();
  collect_attributes(&tokens, 0, &mut attributes);
  let weakening = attributes
    .iter()
    .filter(|attribute| attribute_weakens_governed_lint(attribute))
    .collect::<Vec<_>>();
  if allowlisted {
    let permitted = weakening
      .iter()
      .filter(|attribute| permitted_file_allow(attribute))
      .count();
    if permitted != 1 || weakening.len() != 1 {
      errors.push(format!(
        "{relative}: allowlisted module must contain exactly one reasoned file-level allow(unsafe_code) and no other governed-lint weakening"
      ));
    }
  } else {
    for attribute in weakening {
      errors.push(format!(
        "{relative}: attribute `{}` weakens governed lint outside an allowlisted module",
        attribute.tokens
      ));
    }
  }
  errors
}

fn count_ident(tokens: &TokenStream, expected: &str) -> usize {
  tokens
    .clone()
    .into_iter()
    .map(|token| match token {
      TokenTree::Ident(ident) => usize::from(ident == expected),
      TokenTree::Group(group) => count_ident(&group.stream(), expected),
      TokenTree::Punct(_) | TokenTree::Literal(_) => 0,
    })
    .sum()
}

fn collect_attributes(tokens: &TokenStream, depth: usize, attributes: &mut Vec<AttributeUse>) {
  let trees = tokens.clone().into_iter().collect::<Vec<_>>();
  let mut index = 0;
  while index < trees.len() {
    if matches!(&trees[index], TokenTree::Punct(punct) if punct.as_char() == '#') {
      let inner =
        matches!(trees.get(index + 1), Some(TokenTree::Punct(punct)) if punct.as_char() == '!');
      let group_index = index + if inner { 2 } else { 1 };
      if let Some(TokenTree::Group(group)) = trees.get(group_index)
        && group.delimiter() == Delimiter::Bracket
      {
        let mut idents = BTreeSet::new();
        collect_idents(&group.stream(), &mut idents);
        attributes.push(AttributeUse {
          depth,
          inner,
          idents,
          tokens: group.stream().to_string(),
        });
      }
    }
    if let TokenTree::Group(group) = &trees[index] {
      collect_attributes(&group.stream(), depth + 1, attributes);
    }
    index += 1;
  }
}

fn collect_idents(tokens: &TokenStream, idents: &mut BTreeSet<String>) {
  for token in tokens.clone() {
    match token {
      TokenTree::Ident(ident) => {
        idents.insert(ident.to_string());
      }
      TokenTree::Group(group) => collect_idents(&group.stream(), idents),
      TokenTree::Punct(_) | TokenTree::Literal(_) => {}
    }
  }
}

fn attribute_weakens_governed_lint(attribute: &AttributeUse) -> bool {
  attribute
    .idents
    .iter()
    .any(|ident| LOWERING_ATTRIBUTES.contains(&ident.as_str()))
    && attribute
      .idents
      .iter()
      .any(|ident| GOVERNED_LINTS.contains(&ident.as_str()))
}

fn permitted_file_allow(attribute: &AttributeUse) -> bool {
  let exact_idents = ["allow", "reason", "unsafe_code"]
    .into_iter()
    .map(str::to_string)
    .collect::<BTreeSet<_>>();
  attribute.depth == 0
    && attribute.inner
    && attribute.idents == exact_idents
    && attribute.tokens.contains("reason =")
    && !attribute.tokens.contains("reason = \"\"")
}

fn rust_source_files(root: &Path) -> Vec<String> {
  repository_files(root, &["*.rs"])
}

fn repository_files(root: &Path, pathspecs: &[&str]) -> Vec<String> {
  let output = Command::new("git")
    .args(["ls-files", "-co", "--exclude-standard", "-z", "--"])
    .args(pathspecs)
    .current_dir(root)
    .output()
    .expect("unsafe policy should enumerate repository files with git ls-files");
  assert!(
    output.status.success(),
    "git ls-files failed: {}",
    String::from_utf8_lossy(&output.stderr)
  );
  let mut files = output
    .stdout
    .split(|byte| *byte == 0)
    .filter(|path| !path.is_empty())
    .map(|path| String::from_utf8(path.to_vec()).expect("Rust path should be UTF-8"))
    .collect::<Vec<_>>();
  files.sort();
  files.dedup();
  files
}

fn assert_contains_all(path: &Path, expected: &[&str]) {
  let contents = fs::read_to_string(path)
    .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
  for value in expected {
    assert!(
      contents.contains(value),
      "{} should contain {value}",
      path.display()
    );
  }
}

fn assert_has_error(path: &str, source: &str, expected: &str) {
  let errors = inspect_source(path, source);
  assert!(
    errors.iter().any(|error| error.contains(expected)),
    "expected `{expected}` in {errors:?}"
  );
}

fn repo_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source crate should live below the repository root")
    .to_path_buf()
}
