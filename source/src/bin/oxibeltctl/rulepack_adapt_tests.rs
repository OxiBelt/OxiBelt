use std::path::PathBuf;

use super::*;
use crate::cli::{RulepackAdaptArgs, RulepackAdapterArg};

fn adapt_args() -> RulepackAdaptArgs {
  RulepackAdaptArgs {
    adapter: RulepackAdapterArg::ModsecurityCrsExclusion,
    input: PathBuf::from("exclusions.conf"),
    output: None,
    routes: Vec::new(),
    methods: Vec::new(),
    path_prefixes: Vec::new(),
    reason: "confirmed false positive".to_string(),
    name_prefix: "imported".to_string(),
    allow_global_disable: false,
    force: false,
  }
}

#[test]
fn modsecurity_crs_exclusion_converts_scoped_remove_by_id_to_allowlist() {
  let mut args = adapt_args();
  args.routes = vec!["app-root".to_string()];
  args.methods = vec!["POST".to_string()];
  let rendered = adapt_to_toml(
    &args,
    r#"
# scoped CRS exclusion
<Location "/admin">
SecRuleRemoveById 942110 942100
</Location>
"#,
  )
  .expect("scoped CRS exclusion should adapt");

  assert!(rendered.contains("[[waf.crs.allowlists]]"));
  assert!(rendered.contains("name = \"imported-allow-id-942100-942110\""));
  assert!(rendered.contains("rule_ids = ["));
  assert!(rendered.contains("\"942100\""));
  assert!(rendered.contains("\"942110\""));
  assert!(rendered.contains("methods = [\"POST\"]"));
  assert!(rendered.contains("routes = [\"app-root\"]"));
  assert!(rendered.contains("path_prefixes = [\"/admin\"]"));
  assert!(!rendered.contains("rule_overrides"));
  validate_generated_patch(&rendered).expect("generated patch should validate");
}

#[test]
fn modsecurity_crs_exclusion_converts_unscoped_rule_remove_only_with_global_opt_in() {
  let mut args = adapt_args();
  let error = adapt_to_toml(&args, "SecRuleRemoveByTag \"attack-sqli\"\n")
    .expect_err("unscoped removals should fail closed");
  assert!(
    error
      .to_string()
      .contains("would disable CRS rules globally")
  );

  args.allow_global_disable = true;
  let rendered = adapt_to_toml(&args, "SecRuleRemoveByTag \"attack-sqli\"\n")
    .expect("global opt-in should render a disabled rule override");

  assert!(rendered.contains("[[waf.crs.rule_overrides]]"));
  assert!(rendered.contains("name = \"imported-disable-tag-attack-sqli\""));
  assert!(rendered.contains("tags = [\"attack-sqli\"]"));
  assert!(rendered.contains("mode = \"disabled\""));
  assert!(!rendered.contains("allowlists"));
  validate_generated_patch(&rendered).expect("generated patch should validate");
}

#[test]
fn modsecurity_crs_exclusion_converts_msg_selector_with_cli_path_scope() {
  let mut args = adapt_args();
  args.path_prefixes = vec!["/login".to_string()];
  let rendered = adapt_to_toml(&args, "SecRuleRemoveByMsg \"SQL Injection Attack\"\n")
    .expect("message exclusion should adapt with CLI scope");

  assert!(rendered.contains("[[waf.crs.allowlists]]"));
  assert!(rendered.contains("msg_contains = [\"SQL Injection Attack\"]"));
  assert!(rendered.contains("path_prefixes = [\"/login\"]"));
}

#[test]
fn modsecurity_crs_exclusion_rejects_unsupported_and_ambiguous_inputs() {
  let mut args = adapt_args();
  args.routes = vec!["app-root".to_string()];
  let update_error = adapt_to_toml(&args, "SecRuleUpdateTargetById 942100 !ARGS:token\n")
    .expect_err("update directives should fail");
  assert!(update_error.to_string().contains("update directive"));

  let ctl_error = adapt_to_toml(
    &args,
    r#"SecRule REQUEST_URI "@contains /admin" "id:1,ctl:ruleRemoveById=942100""#,
  )
  .expect_err("ctl rule removals should fail");
  assert!(ctl_error.to_string().contains("ctl:ruleRemove"));

  let location_match_error = adapt_to_toml(
    &args,
    "<LocationMatch \"^/admin\">\nSecRuleRemoveById 942100\n</LocationMatch>\n",
  )
  .expect_err("LocationMatch should fail");
  assert!(location_match_error.to_string().contains("LocationMatch"));

  let range_error =
    adapt_to_toml(&args, "SecRuleRemoveById 942100-942200\n").expect_err("rule ranges should fail");
  assert!(range_error.to_string().contains("ranges"));
}

#[test]
fn modsecurity_crs_exclusion_rejects_invalid_method_and_path_scope() {
  let mut args = adapt_args();
  args.methods = vec!["BAD METHOD".to_string()];
  let method_error =
    adapt_to_toml(&args, "SecRuleRemoveById 942100\n").expect_err("method should fail");
  assert!(method_error.to_string().contains("invalid HTTP method"));

  let mut args = adapt_args();
  args.path_prefixes = vec!["/../admin".to_string()];
  let path_error =
    adapt_to_toml(&args, "SecRuleRemoveById 942100\n").expect_err("path should fail");
  assert!(path_error.to_string().contains(". or .. path components"));

  let mut args = adapt_args();
  args.path_prefixes = vec!["/admin".to_string()];
  let mixed_path_error = adapt_to_toml(
    &args,
    "<Location \"/login\">\nSecRuleRemoveById 942100\n</Location>\n",
  )
  .expect_err("CLI path prefix plus Location should fail");
  assert!(format!("{mixed_path_error:#}").contains("cannot combine --path-prefix"));
}

#[test]
fn modsecurity_crs_exclusion_names_are_deterministic_and_deduplicated() {
  let mut args = adapt_args();
  args.routes = vec!["app-root".to_string()];
  let raw = "SecRuleRemoveById 942100\nSecRuleRemoveById 942100\n";
  let first = adapt_to_toml(&args, raw).expect("first render should succeed");
  let second = adapt_to_toml(&args, raw).expect("second render should succeed");

  assert_eq!(first, second);
  assert!(first.contains("name = \"imported-allow-id-942100\""));
  assert!(first.contains("name = \"imported-allow-id-942100-2\""));
}

#[test]
fn adapt_output_file_requires_toml_and_does_not_overwrite_without_force() {
  let temp = tempfile::Builder::new()
    .prefix("oxibelt-rulepack-adapt-")
    .tempdir()
    .expect("temp dir");
  let input = temp.path().join("exclusions.conf");
  let output = temp.path().join("crs-patch.toml");
  std::fs::write(&input, "SecRuleRemoveById 942100\n").expect("write input");

  let mut args = adapt_args();
  args.input = input.clone();
  args.output = Some(output.clone());
  args.routes = vec!["app-root".to_string()];
  run_adapt(&args).expect("first file write should succeed");
  let written = std::fs::read_to_string(&output).expect("read output");
  assert!(written.contains("[[waf.crs.allowlists]]"));

  let overwrite_error = run_adapt(&args).expect_err("second write should require --force");
  assert!(format!("{overwrite_error:#}").contains("failed to create"));

  args.force = true;
  run_adapt(&args).expect("forced overwrite should succeed");

  args.output = Some(temp.path().join("crs-patch.txt"));
  let suffix_error = run_adapt(&args).expect_err("non-TOML output should fail");
  assert!(suffix_error.to_string().contains(".toml"));
}
