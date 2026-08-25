use clap::Parser as _;

use crate::cli::{Cli, Command, CtPostgresSubcommand, CtSubcommand};

#[test]
fn ct_postgres_migrate_uses_secret_environment_by_default() {
  let cli = Cli::try_parse_from(["oxibeltctl", "ct", "postgres", "migrate"])
    .expect("CT migrate command should parse");
  let Command::Ct(command) = cli.command else {
    panic!("expected CT command");
  };
  let CtSubcommand::Postgres(command) = command.command else {
    panic!("expected CT PostgreSQL command");
  };
  let CtPostgresSubcommand::Migrate(args) = command.command else {
    panic!("expected CT migration");
  };
  assert!(args.database_url_env.is_none());
  assert!(args.database_url_file.is_none());
}

#[test]
fn ct_root_threshold_rejects_zero() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "ct",
    "roots",
    "verify",
    "--bundle",
    "roots.json",
    "--trusted-key",
    "operator=operator.pub",
    "--threshold",
    "0",
  ]);
  assert!(parsed.is_err());
}

#[test]
fn ct_monitor_requires_an_explicit_witness_and_key() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "ct",
    "monitor",
    "--url",
    "https://ct.example.test/log/",
    "--log-id",
    &"a".repeat(64),
  ]);
  assert!(parsed.is_err());
}

#[test]
fn ct_canonical_json_sorts_nested_keys() {
  let value = serde_json::json!({"z": 1, "a": {"d": 4, "b": 2}});
  assert_eq!(
    crate::ct_io::canonical_json_bytes(&value).expect("canonical JSON"),
    br#"{"a":{"b":2,"d":4},"z":1}"#
  );
}
