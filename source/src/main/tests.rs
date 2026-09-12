use super::*;

#[cfg(not(all(
  feature = "allocator-mimalloc-experiment",
  target_os = "linux",
  target_arch = "x86_64",
  target_pointer_width = "64",
  any(target_env = "gnu", target_env = "musl")
)))]
#[test]
fn binary_with_system_allocator_reports_no_allocator_override() {
  assert_eq!(
    oxibelt::ProcessGlobalReport::for_hooks(oxibelt::ProcessGlobalHooks::CallerManaged).allocator,
    oxibelt::ProcessGlobalHookReport::new(
      oxibelt::ProcessGlobalHookStatus::NotConfigured,
      oxibelt::ProcessGlobalReason::NotUsedByOxibelt,
    ),
  );
}

#[cfg(oxibelt_strict_artifact)]
#[test]
fn strict_binary_does_not_enable_the_integrated_allocator_feature() {
  assert_eq!(
    oxibelt::ProcessGlobalReport::for_hooks(oxibelt::ProcessGlobalHooks::ApplySelected(
      oxibelt::ProcessGlobalSelection::all(),
    ))
    .allocator
    .reason,
    oxibelt::ProcessGlobalReason::NotUsedByOxibelt,
  );
}

#[cfg(all(
  feature = "allocator-mimalloc-experiment",
  target_os = "linux",
  target_arch = "x86_64",
  target_pointer_width = "64",
  any(target_env = "gnu", target_env = "musl")
))]
#[test]
fn mimalloc_binary_reports_its_allocator_ownership() {
  oxibelt::mark_binary_allocator_mimalloc_experiment();
  for hooks in [
    oxibelt::ProcessGlobalHooks::CallerManaged,
    oxibelt::ProcessGlobalHooks::VerifyOnly,
    oxibelt::ProcessGlobalHooks::ApplySelected(oxibelt::ProcessGlobalSelection::all()),
  ] {
    assert_eq!(
      oxibelt::ProcessGlobalReport::for_hooks(hooks).allocator,
      oxibelt::ProcessGlobalHookReport::new(
        oxibelt::ProcessGlobalHookStatus::Applied,
        oxibelt::ProcessGlobalReason::AppliedByOxibelt,
      ),
    );
  }
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
