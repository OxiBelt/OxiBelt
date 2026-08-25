use std::collections::BTreeSet;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::cli::{CtProtocolArg, CtShardPlanArgs, CtShardSubcommand, CtShardValidateArgs};
use crate::ct_io::{
  MAX_DOCUMENT_BYTES, canonical_json_bytes, read_bounded, validate_identifier, write_new,
};

const MAX_SHARDS: usize = 10_000;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ShardPlan {
  schema_version: u32,
  log_prefix: String,
  protocol: String,
  mmd_seconds: u64,
  preprovision_seconds: u64,
  shards: Vec<Shard>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Shard {
  shard_id: String,
  provision_by_unix_seconds: i64,
  submission_start_unix_seconds: i64,
  submission_end_unix_seconds: i64,
}

pub(crate) fn run(command: &CtShardSubcommand) -> anyhow::Result<i32> {
  match command {
    CtShardSubcommand::Plan(args) => plan(args),
    CtShardSubcommand::Validate(args) => validate(args),
  }
}

fn plan(args: &CtShardPlanArgs) -> anyhow::Result<i32> {
  validate_identifier(&args.log_prefix, "CT shard log prefix")?;
  if args.start >= args.end {
    bail!("CT shard schedule start must precede end");
  }
  let period = i64::try_from(args.period_seconds).context("CT shard period exceeds i64")?;
  let preprovision =
    i64::try_from(args.preprovision_seconds).context("preprovision interval exceeds i64")?;
  let span = args
    .end
    .checked_sub(args.start)
    .context("CT shard schedule span overflows")?;
  let count = span
    .checked_add(period - 1)
    .context("CT shard count overflows")?
    / period;
  if count <= 0 || usize::try_from(count).unwrap_or(usize::MAX) > MAX_SHARDS {
    bail!("CT shard count is outside 1..={MAX_SHARDS}");
  }
  let mut shards = Vec::with_capacity(usize::try_from(count)?);
  let mut start = args.start;
  for index in 0..count {
    let end = start
      .checked_add(period)
      .context("CT shard interval end overflows")?
      .min(args.end);
    let shard_id = format!("{}-{index:05}", args.log_prefix);
    validate_identifier(&shard_id, "CT shard id")?;
    shards.push(Shard {
      shard_id,
      provision_by_unix_seconds: start
        .checked_sub(preprovision)
        .context("CT shard preprovision timestamp underflows")?,
      submission_start_unix_seconds: start,
      submission_end_unix_seconds: end,
    });
    start = end;
  }
  let plan = ShardPlan {
    schema_version: 1,
    log_prefix: args.log_prefix.clone(),
    protocol: protocol_name(args.protocol).to_string(),
    mmd_seconds: args.mmd_seconds,
    preprovision_seconds: args.preprovision_seconds,
    shards,
  };
  validate_plan(&plan)?;
  let bytes = canonical_json_bytes(&serde_json::to_value(plan)?)?;
  write_new(&args.output, &bytes, "CT shard plan")?;
  println!("{}", args.output.display());
  Ok(0)
}

fn validate(args: &CtShardValidateArgs) -> anyhow::Result<i32> {
  let bytes = read_bounded(&args.file, MAX_DOCUMENT_BYTES, "CT shard plan")?;
  let plan: ShardPlan = serde_json::from_slice(&bytes).context("failed to parse CT shard plan")?;
  if canonical_json_bytes(&serde_json::to_value(&plan)?)? != bytes {
    bail!("CT shard plan must use canonical JSON without trailing bytes");
  }
  validate_plan(&plan)?;
  println!(
    "{}",
    serde_json::to_string_pretty(&serde_json::json!({
      "valid": true,
      "log_prefix": plan.log_prefix,
      "protocol": plan.protocol,
      "shard_count": plan.shards.len(),
      "first_submission_start_unix_seconds": plan.shards[0].submission_start_unix_seconds,
      "last_submission_end_unix_seconds": plan.shards[plan.shards.len() - 1].submission_end_unix_seconds,
    }))?
  );
  Ok(0)
}

fn validate_plan(plan: &ShardPlan) -> anyhow::Result<()> {
  if plan.schema_version != 1 {
    bail!("unsupported CT shard plan schema version");
  }
  validate_identifier(&plan.log_prefix, "CT shard log prefix")?;
  if !matches!(plan.protocol.as_str(), "rfc6962-v1" | "rfc9162-v2") {
    bail!("unsupported CT shard protocol");
  }
  if plan.mmd_seconds == 0 || plan.mmd_seconds > 86_400 {
    bail!("CT shard MMD must be within 1..=86400 seconds");
  }
  if !(86_400..=31_536_000).contains(&plan.preprovision_seconds) {
    bail!("CT shard preprovision interval is outside the supported range");
  }
  if plan.shards.is_empty() || plan.shards.len() > MAX_SHARDS {
    bail!("CT shard count is outside 1..={MAX_SHARDS}");
  }
  let mut ids = BTreeSet::new();
  let mut previous_end = None;
  for shard in &plan.shards {
    validate_identifier(&shard.shard_id, "CT shard id")?;
    if !shard.shard_id.starts_with(&format!("{}-", plan.log_prefix)) {
      bail!("CT shard id is outside the configured log prefix");
    }
    if !ids.insert(&shard.shard_id) {
      bail!("CT shard ids must be unique");
    }
    if shard.submission_start_unix_seconds >= shard.submission_end_unix_seconds {
      bail!("CT shard submission interval is empty or reversed");
    }
    if previous_end.is_some_and(|end| end != shard.submission_start_unix_seconds) {
      bail!("CT shard submission intervals must be contiguous and ordered");
    }
    let expected_provision = shard
      .submission_start_unix_seconds
      .checked_sub(i64::try_from(plan.preprovision_seconds)?)
      .context("CT shard preprovision timestamp underflows")?;
    if shard.provision_by_unix_seconds != expected_provision {
      bail!("CT shard provision deadline does not match the plan interval");
    }
    let duration = shard
      .submission_end_unix_seconds
      .checked_sub(shard.submission_start_unix_seconds)
      .context("CT shard duration overflows")?;
    if u64::try_from(duration)? <= plan.mmd_seconds {
      bail!("CT shard duration must be longer than the MMD");
    }
    previous_end = Some(shard.submission_end_unix_seconds);
  }
  Ok(())
}

const fn protocol_name(protocol: CtProtocolArg) -> &'static str {
  match protocol {
    CtProtocolArg::Rfc6962V1 => "rfc6962-v1",
    CtProtocolArg::Rfc9162V2 => "rfc9162-v2",
  }
}
