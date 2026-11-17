use super::*;

#[test]
fn binary_reports_no_allocator_override() {
  assert_eq!(
    oxibelt::ProcessGlobalReport::for_hooks(oxibelt::ProcessGlobalHooks::CallerManaged).allocator,
    oxibelt::ProcessGlobalHookReport::new(
      oxibelt::ProcessGlobalHookStatus::NotConfigured,
      oxibelt::ProcessGlobalReason::NotUsedByOxibelt,
    ),
  );
}

#[test]
fn version_flag_reports_canonical_build_identity() {
  let error =
    Cli::try_parse_from(["oxibelt", "--version"]).expect_err("--version should exit through Clap");
  assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
  assert!(
    error
      .to_string()
      .contains(oxibelt_build_identity::MACHINE_IDENTITY_MARKER)
  );
}

fn lifecycle_args(values: &[&str]) -> Vec<OsString> {
  std::iter::once(OsString::from("oxibelt"))
    .chain(values.iter().map(OsString::from))
    .collect()
}

#[test]
fn lifecycle_prestop_parser_accepts_bounded_waits() {
  assert_eq!(
    parse_lifecycle_prestop_args(&lifecycle_args(&[
      LIFECYCLE_PRESTOP_COMMAND,
      "--wait-seconds",
      "1",
    ]))
    .expect("minimum wait should parse"),
    Some(1)
  );
  assert_eq!(
    parse_lifecycle_prestop_args(&lifecycle_args(&[
      LIFECYCLE_PRESTOP_COMMAND,
      "--wait-seconds",
      "86400",
    ]))
    .expect("maximum wait should parse"),
    Some(86_400)
  );
}

#[test]
fn lifecycle_prestop_parser_rejects_unsafe_or_ambiguous_arguments() {
  for values in [
    vec![LIFECYCLE_PRESTOP_COMMAND, "--wait-seconds", "0"],
    vec![LIFECYCLE_PRESTOP_COMMAND, "--wait-seconds", "86401"],
    vec![LIFECYCLE_PRESTOP_COMMAND, "--wait-seconds", "invalid"],
    vec![LIFECYCLE_PRESTOP_COMMAND, "--wait-seconds", "1", "extra"],
    vec![LIFECYCLE_PRESTOP_COMMAND, "--other", "1"],
  ] {
    assert!(parse_lifecycle_prestop_args(&lifecycle_args(&values)).is_err());
  }
}

#[test]
fn lifecycle_prestop_parser_leaves_public_cli_unchanged() {
  assert_eq!(
    parse_lifecycle_prestop_args(&lifecycle_args(&["--config", "oxibelt.toml"]))
      .expect("public CLI should not be intercepted"),
    None
  );
}

#[test]
fn obsolete_runtime_probe_commands_are_rejected() {
  for probe in ["compio-probe", "compio-main"] {
    assert!(Cli::try_parse_from(["oxibelt", "__runtime-probe", probe]).is_err());
  }
}
