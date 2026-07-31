use super::*;

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
fn auto_main_runtime_treats_polling_compio_driver_as_unsafe() {
  assert!(!compio_driver_safe_for_auto_main_runtime(
    CompioDriverSelection::Polling
  ));
}

#[test]
fn auto_main_runtime_allows_production_compio_drivers() {
  assert!(compio_driver_safe_for_auto_main_runtime(
    CompioDriverSelection::IoUring
  ));
  assert!(compio_driver_safe_for_auto_main_runtime(
    CompioDriverSelection::Iocp
  ));
}

#[test]
fn active_main_runtime_projection_follows_the_resolved_topology() {
  let topology = RuntimeTopologySnapshot::external();

  assert_eq!(
    active_runtime_for_topology(&topology),
    ActiveMainRuntime::TokioHyper
  );
}
