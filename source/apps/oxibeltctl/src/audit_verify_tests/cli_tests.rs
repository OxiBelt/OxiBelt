use super::*;

#[test]
fn audit_query_flags_keep_the_existing_command_shape() {
  let cli = Cli::try_parse_from([
    "oxibeltctl",
    "audit",
    "--actor",
    "operator",
    "--limit",
    "25",
  ])
  .expect("legacy audit query parses");
  let Command::Audit(args) = cli.command else {
    panic!("expected audit command");
  };
  assert!(args.command.is_none());
  assert_eq!(args.actor.as_deref(), Some("operator"));
  assert_eq!(args.limit, 25);
}

#[test]
fn audit_verify_parses_local_only_security_inputs() {
  let cli = Cli::try_parse_from([
    "oxibeltctl",
    "audit",
    "verify",
    "--expected-streams",
    "streams.json",
    "--trusted-key",
    "key-1=key-1.pub",
    "--trusted-key",
    "key-2=key-2.pub",
    "--trusted-hmac-key",
    "hmac-1=hmac-1.key",
    "--witness",
    "witness.json",
    "--initialize-witness",
  ])
  .expect("audit verifier parses");
  let Command::Audit(args) = cli.command else {
    panic!("expected audit command");
  };
  let Some(AdminAuditSubcommand::Verify(verify)) = args.command else {
    panic!("expected audit verify subcommand");
  };
  assert_eq!(verify.trusted_keys.len(), 2);
  assert_eq!(verify.trusted_hmac_keys.len(), 1);
  assert_eq!(verify.max_events, 1_000_000);
  assert_eq!(verify.max_checkpoints, 100_000);
  assert_eq!(verify.max_evidence_bytes, 536_870_912);
  assert_eq!(verify.max_event_bytes, 131_072);
  assert_eq!(verify.max_checkpoint_bytes, 65_536);
  assert!(verify.initialize_witness);
  assert_eq!(
    verify.local_postgres_url_env,
    "OXIBELT_AUDIT_VERIFY_LOCAL_POSTGRES_URL"
  );
  assert_eq!(
    verify.anchor_postgres_url_env,
    "OXIBELT_AUDIT_VERIFY_ANCHOR_POSTGRES_URL"
  );
}

#[test]
fn audit_verify_rejects_an_event_limit_above_the_transfer_budget() {
  let error = Cli::try_parse_from([
    "oxibeltctl",
    "audit",
    "verify",
    "--expected-streams",
    "streams.json",
    "--trusted-key",
    "key-1=key-1.pub",
    "--witness",
    "witness.json",
    "--max-event-bytes",
    "67108865",
  ])
  .expect_err("event limits above the page budget must fail closed");
  assert!(error.to_string().contains("67108865"));
}
