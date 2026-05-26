use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use url::Url;

use super::*;
use crate::cli::{Cli, Command, RulepackSourceArgs};

#[test]
fn rulepack_cli_parses_apply_url_safety_options() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "apply",
    "--url",
    "https://packs.example.test/vaultwarden.oxirule-rulepack.toml",
    "--sha256",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "--var",
    "admin_cidr=10.0.0.0/8",
  ])
  .expect("rulepack apply should parse");
  assert!(matches!(parsed.command, Command::Rulepack(_)));
}

#[test]
fn rulepack_url_apply_requires_pin() {
  let args = RulepackSourceArgs {
    file: None,
    dir: None,
    url: Some(Url::parse("https://packs.example.test/pack.oxirule-rulepack.toml").expect("url")),
    git: None,
    manifest: PathBuf::from("rulepack.oxirule-rulepack.toml"),
    ca_certs: Vec::new(),
    token_env: None,
    sha256: None,
    allow_unpinned_rulepack: false,
    allow_insecure_rulepack_url: false,
    git_ref: None,
  };
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let error = runtime
    .block_on(load_rulepack_source(&args, Duration::from_millis(10), true))
    .expect_err("unpinned URL apply should fail before network");
  assert!(error.to_string().contains("--sha256"));
}

#[test]
fn rulepack_source_requires_manifest_suffix() {
  let error = ensure_manifest_suffix(Path::new("pack.toml"))
    .expect_err("file manifest suffix should be fixed");
  assert!(error.to_string().contains(RULEPACK_FILE_SUFFIX));
  let url = Url::parse("https://packs.example.test/pack.toml").expect("url");
  let error = ensure_manifest_url_suffix(&url).expect_err("URL suffix should be fixed");
  assert!(error.to_string().contains(RULEPACK_FILE_SUFFIX));
}

#[test]
fn rulepack_url_rejects_userinfo() {
  let url = Url::parse("https://user:secret@packs.example.test/pack.toml").expect("url");
  let error = validate_rulepack_url(&url, false).expect_err("userinfo should fail");
  assert!(error.to_string().contains("username"));
}

#[test]
fn git_rulepack_url_requires_git_https() {
  let error = validate_git_url("https://github.com/example/packs.git")
    .expect_err("missing git+ prefix should fail");
  assert!(error.to_string().contains("git+https"));
  let error = validate_git_url("git+http://example.test/packs.git").expect_err("http should fail");
  assert!(error.to_string().contains("git+https"));
}

#[test]
fn installed_rulepack_path_rejects_path_separators() {
  assert!(installed_rulepack_path("vaultwarden").is_ok());
  assert!(installed_rulepack_path("../bad").is_err());
  assert!(installed_rulepack_path("bad/name").is_err());
}

#[test]
fn rulepack_source_resolves_regular_file_inside_source_dir() {
  let source = TempTree::new().expect("source temp");
  let rules_dir = source.path.join("rules");
  std::fs::create_dir(&rules_dir).expect("rules dir");
  let rule_path = rules_dir.join("ok.oxirule.toml");
  std::fs::write(&rule_path, "when = \"true\"\n").expect("rule file");

  let resolved =
    resolve_existing_local_source_file(&source.path, Path::new("rules/ok.oxirule.toml"))
      .expect("in-tree regular file should resolve");

  assert!(resolved.is_absolute());
  assert_eq!(
    std::fs::read_to_string(resolved).expect("resolved rule content"),
    "when = \"true\"\n"
  );
}

#[cfg(unix)]
#[test]
fn rulepack_source_rejects_symlink_escape() {
  let source = TempTree::new().expect("source temp");
  let outside = TempTree::new().expect("outside temp");
  let rules_dir = source.path.join("rules");
  std::fs::create_dir(&rules_dir).expect("rules dir");
  let outside_file = outside.path.join("leak.oxirule.toml");
  std::fs::write(&outside_file, "when = \"true\"\n").expect("outside rule file");
  std::os::unix::fs::symlink(&outside_file, rules_dir.join("leak.oxirule.toml")).expect("symlink");

  let error =
    resolve_existing_local_source_file(&source.path, Path::new("rules/leak.oxirule.toml"))
      .expect_err("symlink escape should fail");

  assert!(error.to_string().contains("must stay within"));
}
