use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, DEFAULT_ADMIN_URL};
use url::Url;

use super::*;
use crate::cli::{
  Cli, Command, OutputFormat, RulepackAdapterArg, RulepackModeArg, RulepackSourceArgs,
  RulepackSubcommand,
};

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
fn rulepack_cli_parses_openpgp_url_options() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "apply",
    "--url",
    "https://packs.example.test/vaultwarden.oxirule-rulepack.toml",
    "--require-rulepack-openpgp-signature",
    "--rulepack-openpgp-signature-url",
    "https://packs.example.test/vaultwarden.oxirule-rulepack.toml.sig",
    "--rulepack-openpgp-key",
    "publisher.asc",
    "--rulepack-openpgp-keyring",
    "trusted-publishers",
    "--rulepack-openpgp-fingerprint",
    "0123456789abcdef0123456789abcdef01234567",
  ])
  .expect("rulepack apply should parse OpenPGP options");

  let Command::Rulepack(command) = parsed.command else {
    panic!("expected rulepack command");
  };
  let RulepackSubcommand::Apply(args) = command.command else {
    panic!("expected rulepack apply");
  };
  assert!(args.source.require_openpgp_signature);
  assert!(args.source.openpgp_signature_url.is_some());
  assert_eq!(
    args.source.openpgp_key_files,
    vec![PathBuf::from("publisher.asc")]
  );
  assert_eq!(
    args.source.openpgp_keyring_dirs,
    vec![PathBuf::from("trusted-publishers")]
  );
  assert_eq!(
    args.source.openpgp_fingerprints,
    vec!["0123456789abcdef0123456789abcdef01234567"]
  );
}

#[test]
fn rulepack_cli_parses_fit_and_bind_options() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "fit",
    "--file",
    "vaultwarden.oxirule-rulepack.toml",
    "--values",
    "vaultwarden.values.toml",
    "--profile",
    "public-production",
    "--bind",
    "app_route=mmsecretvault",
    "--var",
    "admin_cidr=10.0.0.0/8",
  ])
  .expect("rulepack fit should parse");

  let Command::Rulepack(command) = parsed.command else {
    panic!("expected rulepack command");
  };
  let RulepackSubcommand::Fit(args) = command.command else {
    panic!("expected rulepack fit");
  };
  assert_eq!(args.values, Some(PathBuf::from("vaultwarden.values.toml")));
  assert_eq!(args.profile.as_deref(), Some("public-production"));
  assert_eq!(args.binds, vec!["app_route=mmsecretvault"]);
  assert_eq!(args.vars, vec!["admin_cidr=10.0.0.0/8"]);
}

#[test]
fn rulepack_cli_parses_plan_and_diff_options() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "plan",
    "--file",
    "vaultwarden.oxirule-rulepack.toml",
    "--values",
    "vaultwarden.values.toml",
    "--profile",
    "public-production",
    "--mode",
    "enforcing",
    "--force-mode",
    "--bind",
    "app_route=mmsecretvault",
    "--var",
    "admin_cidr=10.0.0.0/8",
  ])
  .expect("rulepack plan should parse");
  let Command::Rulepack(command) = parsed.command else {
    panic!("expected rulepack command");
  };
  let RulepackSubcommand::Plan(args) = command.command else {
    panic!("expected rulepack plan");
  };
  assert_eq!(args.values, Some(PathBuf::from("vaultwarden.values.toml")));
  assert_eq!(args.profile.as_deref(), Some("public-production"));
  assert_eq!(args.mode, Some(RulepackModeArg::Enforcing));
  assert!(args.force_mode);
  assert_eq!(args.binds, vec!["app_route=mmsecretvault"]);
  assert_eq!(args.vars, vec!["admin_cidr=10.0.0.0/8"]);

  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "diff",
    "--file",
    "vaultwarden.oxirule-rulepack.toml",
    "--values",
    "vaultwarden.values.toml",
    "--bind",
    "app_route=mmsecretvault",
  ])
  .expect("rulepack diff should parse");
  let Command::Rulepack(command) = parsed.command else {
    panic!("expected rulepack command");
  };
  let RulepackSubcommand::Diff(args) = command.command else {
    panic!("expected rulepack diff");
  };
  assert_eq!(args.values, Some(PathBuf::from("vaultwarden.values.toml")));
  assert_eq!(args.binds, vec!["app_route=mmsecretvault"]);
}

#[test]
fn rulepack_cli_parses_render_and_check_bind_options() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "render",
    "--file",
    "vaultwarden.oxirule-rulepack.toml",
    "--values",
    "vaultwarden.values.toml",
    "--profile",
    "public-production",
    "--bind",
    "app_route=mmsecretvault",
  ])
  .expect("rulepack render should parse");
  let Command::Rulepack(command) = parsed.command else {
    panic!("expected rulepack command");
  };
  let RulepackSubcommand::Render(args) = command.command else {
    panic!("expected rulepack render");
  };
  assert_eq!(args.values, Some(PathBuf::from("vaultwarden.values.toml")));
  assert_eq!(args.profile.as_deref(), Some("public-production"));
  assert_eq!(args.binds, vec!["app_route=mmsecretvault"]);

  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "check",
    "--file",
    "vaultwarden.oxirule-rulepack.toml",
    "--values",
    "vaultwarden.values.toml",
    "--profile",
    "public-production",
    "--bind",
    "app_route=mmsecretvault",
  ])
  .expect("rulepack check should parse");
  let Command::Rulepack(command) = parsed.command else {
    panic!("expected rulepack command");
  };
  let RulepackSubcommand::Check(args) = command.command else {
    panic!("expected rulepack check");
  };
  assert_eq!(args.values, Some(PathBuf::from("vaultwarden.values.toml")));
  assert_eq!(args.profile.as_deref(), Some("public-production"));
  assert_eq!(args.binds, vec!["app_route=mmsecretvault"]);
}

#[test]
fn rulepack_cli_parses_interactive_apply() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "apply",
    "--file",
    "vaultwarden.oxirule-rulepack.toml",
    "--values",
    "vaultwarden.values.toml",
    "--profile",
    "public-production",
    "--interactive",
    "--bind",
    "app_route=mmsecretvault",
  ])
  .expect("rulepack interactive apply should parse");

  let Command::Rulepack(command) = parsed.command else {
    panic!("expected rulepack command");
  };
  let RulepackSubcommand::Apply(args) = command.command else {
    panic!("expected rulepack apply");
  };
  assert!(args.interactive);
  assert_eq!(args.values, Some(PathBuf::from("vaultwarden.values.toml")));
  assert_eq!(args.profile.as_deref(), Some("public-production"));
  assert_eq!(args.binds, vec!["app_route=mmsecretvault"]);
}

#[test]
fn rulepack_cli_parses_apply_dry_run_fixture_and_replay() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "apply",
    "--file",
    "vaultwarden.oxirule-rulepack.toml",
    "--dry-run",
    "--fixture",
    "vaultwarden-login.json",
    "--replay",
    "captured.ndjson",
  ])
  .expect("rulepack apply dry-run should parse");

  let Command::Rulepack(command) = parsed.command else {
    panic!("expected rulepack command");
  };
  let RulepackSubcommand::Apply(args) = command.command else {
    panic!("expected rulepack apply");
  };
  assert!(args.dry_run);
  assert_eq!(args.fixture, Some(PathBuf::from("vaultwarden-login.json")));
  assert_eq!(args.replay, Some(PathBuf::from("captured.ndjson")));
}

#[test]
fn rulepack_cli_parses_adapt() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "adapt",
    "--adapter",
    "modsecurity-crs-exclusion",
    "--input",
    "exclusions.conf",
    "--output",
    "crs-patch.toml",
    "--route",
    "app-root",
    "--method",
    "POST",
    "--path-prefix",
    "/login",
    "--reason",
    "confirmed false positive",
    "--name-prefix",
    "local-crs",
    "--allow-global-disable",
    "--force",
  ])
  .expect("rulepack adapt should parse");

  let Command::Rulepack(command) = parsed.command else {
    panic!("expected rulepack command");
  };
  let RulepackSubcommand::Adapt(args) = command.command else {
    panic!("expected rulepack adapt");
  };
  assert_eq!(args.adapter, RulepackAdapterArg::ModsecurityCrsExclusion);
  assert_eq!(args.input, PathBuf::from("exclusions.conf"));
  assert_eq!(args.output, Some(PathBuf::from("crs-patch.toml")));
  assert_eq!(args.routes, vec!["app-root"]);
  assert_eq!(args.methods, vec!["POST"]);
  assert_eq!(args.path_prefixes, vec!["/login"]);
  assert_eq!(args.reason, "confirmed false positive");
  assert_eq!(args.name_prefix, "local-crs");
  assert!(args.allow_global_disable);
  assert!(args.force);
}

#[test]
fn rulepack_adapt_runs_locally_and_writes_output_file() {
  let source = TempTree::new().expect("source temp");
  let input = source.path().join("exclusions.conf");
  let output = source.path().join("crs-patch.toml");
  std::fs::write(&input, "SecRuleRemoveById 942100\n").expect("write exclusion input");
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "adapt",
    "--adapter",
    "modsecurity-crs-exclusion",
    "--input",
    input.to_str().expect("UTF-8 path"),
    "--output",
    output.to_str().expect("UTF-8 path"),
    "--route",
    "app-root",
  ])
  .expect("rulepack adapt should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");

  let handled = runtime
    .block_on(run_local_if_requested(&parsed.command))
    .expect("adapt should run locally");

  assert!(handled);
  let rendered = std::fs::read_to_string(&output).expect("output should be written");
  assert!(rendered.contains("[[waf.crs.allowlists]]"));
  assert!(rendered.contains("rule_ids = [\"942100\"]"));
}

#[test]
fn rulepack_cli_rejects_fixture_or_replay_without_dry_run() {
  let fixture = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "apply",
    "--file",
    "vaultwarden.oxirule-rulepack.toml",
    "--fixture",
    "vaultwarden-login.json",
  ])
  .expect_err("fixture without dry-run should fail");
  assert!(fixture.to_string().contains("--dry-run"));

  let replay = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "apply",
    "--file",
    "vaultwarden.oxirule-rulepack.toml",
    "--replay",
    "captured.ndjson",
  ])
  .expect_err("replay without dry-run should fail");
  assert!(replay.to_string().contains("--dry-run"));
}

#[test]
fn rulepack_render_check_plan_diff_and_dry_run_reject_schema_v1() {
  let source = TempTree::new().expect("source temp");
  let path = source.path().join("legacy.oxirule-rulepack.toml");
  std::fs::write(
    &path,
    r#"[rulepack]
schema_version = 1
name = "legacy"
version = "0.1.0"

[[rules]]
name = "legacy-rule"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#,
  )
  .expect("write legacy rulepack");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");

  for subcommand in ["render", "check"] {
    let parsed = Cli::try_parse_from([
      "oxibeltctl",
      "rulepack",
      subcommand,
      "--file",
      path.to_str().expect("UTF-8 path"),
    ])
    .expect("rulepack command should parse");
    let error = runtime
      .block_on(run_local_if_requested(&parsed.command))
      .expect_err("schema v1 should be rejected");

    assert!(error.to_string().contains("only schema_version 2"));
  }

  for subcommand in ["plan", "diff"] {
    let parsed = Cli::try_parse_from([
      "oxibeltctl",
      "rulepack",
      subcommand,
      "--file",
      path.to_str().expect("UTF-8 path"),
    ])
    .expect("rulepack command should parse");
    let error = runtime
      .block_on(run_remote_if_requested(
        &dummy_client(),
        &parsed.command,
        OutputFormat::PrettyJson,
      ))
      .expect_err("schema v1 should be rejected");
    assert!(error.to_string().contains("only schema_version 2"));
  }

  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "apply",
    "--file",
    path.to_str().expect("UTF-8 path"),
    "--dry-run",
  ])
  .expect("rulepack dry-run command should parse");
  let error = runtime
    .block_on(run_remote_if_requested(
      &dummy_client(),
      &parsed.command,
      OutputFormat::PrettyJson,
    ))
    .expect_err("schema v1 dry-run should be rejected");
  assert!(error.to_string().contains("only schema_version 2"));
}

#[test]
fn rulepack_plan_diff_and_dry_run_reject_legacy_variable_discovery() {
  let source = TempTree::new().expect("source temp");
  let path = source.path().join("legacy-discovery.oxirule-rulepack.toml");
  std::fs::write(
    &path,
    r#"[rulepack]
schema_version = 2
name = "legacy-discovery"
version = "0.1.0"

[[variables]]
name = "route_name"
type = "string"
required = true

[variables.discovery]
name_any = ["vault"]

[[rules]]
name = "legacy-rule"
phase = "request"
priority = 100
content = "when = \"Context.RouteName == '{{route_name}}'\"\n"
"#,
  )
  .expect("write legacy discovery rulepack");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");

  for subcommand in ["plan", "diff"] {
    let parsed = Cli::try_parse_from([
      "oxibeltctl",
      "rulepack",
      subcommand,
      "--file",
      path.to_str().expect("UTF-8 path"),
    ])
    .expect("rulepack command should parse");
    let error = runtime
      .block_on(run_remote_if_requested(
        &dummy_client(),
        &parsed.command,
        OutputFormat::PrettyJson,
      ))
      .expect_err("legacy discovery should be rejected");
    assert!(error.to_string().contains("[variables.discovery]"));
  }

  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "apply",
    "--file",
    path.to_str().expect("UTF-8 path"),
    "--dry-run",
  ])
  .expect("rulepack dry-run command should parse");
  let error = runtime
    .block_on(run_remote_if_requested(
      &dummy_client(),
      &parsed.command,
      OutputFormat::PrettyJson,
    ))
    .expect_err("legacy discovery dry-run should be rejected");
  assert!(error.to_string().contains("[variables.discovery]"));
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
    require_openpgp_signature: false,
    openpgp_signature_url: None,
    openpgp_signature_file: None,
    openpgp_key_files: Vec::new(),
    openpgp_keyring_dirs: Vec::new(),
    openpgp_fingerprints: Vec::new(),
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
fn http_rulepack_requires_signature_even_with_sha256() {
  let args = RulepackSourceArgs {
    file: None,
    dir: None,
    url: Some(Url::parse("http://packs.example.test/pack.oxirule-rulepack.toml").expect("url")),
    git: None,
    manifest: PathBuf::from("rulepack.oxirule-rulepack.toml"),
    ca_certs: Vec::new(),
    token_env: None,
    sha256: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
    allow_unpinned_rulepack: true,
    allow_insecure_rulepack_url: true,
    require_openpgp_signature: false,
    openpgp_signature_url: None,
    openpgp_signature_file: None,
    openpgp_key_files: Vec::new(),
    openpgp_keyring_dirs: Vec::new(),
    openpgp_fingerprints: Vec::new(),
    git_ref: None,
  };
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let error = runtime
    .block_on(load_rulepack_source(&args, Duration::from_millis(10), true))
    .expect_err("HTTP URL should require signature before network");
  assert!(error.to_string().contains("HTTP rulepack URL requires"));
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
fn rulepack_signature_url_rejects_userinfo() {
  let url = Url::parse("https://user:secret@packs.example.test/pack.sig").expect("url");
  let error = validate_rulepack_signature_url(&url, false).expect_err("userinfo should fail");
  assert!(error.to_string().contains("username"));
}

#[test]
fn token_is_only_sent_to_same_signature_origin() {
  let source = Url::parse("https://packs.example.test/pack.oxirule-rulepack.toml").expect("source");
  let same = Url::parse("https://packs.example.test/pack.sig").expect("signature");
  let different_scheme = Url::parse("http://packs.example.test/pack.sig").expect("signature");
  let different_host = Url::parse("https://other.example.test/pack.sig").expect("signature");

  assert!(same_origin(&source, &same));
  assert!(!same_origin(&source, &different_scheme));
  assert!(!same_origin(&source, &different_host));
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
  let rules_dir = source.path().join("rules");
  std::fs::create_dir(&rules_dir).expect("rules dir");
  let rule_path = rules_dir.join("ok.oxirule.toml");
  std::fs::write(&rule_path, "when = \"true\"\n").expect("rule file");

  let resolved =
    resolve_existing_local_source_file(source.path(), Path::new("rules/ok.oxirule.toml"))
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
  let rules_dir = source.path().join("rules");
  std::fs::create_dir(&rules_dir).expect("rules dir");
  let outside_file = outside.path().join("leak.oxirule.toml");
  std::fs::write(&outside_file, "when = \"true\"\n").expect("outside rule file");
  std::os::unix::fs::symlink(&outside_file, rules_dir.join("leak.oxirule.toml")).expect("symlink");

  let error =
    resolve_existing_local_source_file(source.path(), Path::new("rules/leak.oxirule.toml"))
      .expect_err("symlink escape should fail");

  assert!(error.to_string().contains("must stay within"));
}

fn dummy_client() -> AdminClient {
  oxibelt::tls::install_default_provider().expect("provider");
  let options = AdminClientOptions::new(
    Url::parse(DEFAULT_ADMIN_URL).expect("default URL"),
    "dummy-token".to_string(),
    Duration::from_millis(10),
  );
  AdminClient::new(options).expect("dummy client")
}
