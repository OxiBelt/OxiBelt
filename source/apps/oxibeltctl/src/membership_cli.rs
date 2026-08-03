use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub(crate) struct MembershipCommand {
  #[command(subcommand)]
  pub(crate) command: MembershipSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum MembershipSubcommand {
  Status,
  Propose(MembershipMutationFileArgs),
  Activate(MembershipTransitionMutationArgs),
  Cancel(MembershipTransitionMutationArgs),
  Catchup(MembershipTransitionArgs),
  Readiness(MembershipTransitionFileArgs),
}

#[derive(Debug, Args)]
pub(crate) struct MembershipMutationFileArgs {
  pub(crate) file: PathBuf,
  #[arg(long, required = true)]
  pub(crate) etag: String,
}

#[derive(Debug, Args)]
pub(crate) struct MembershipTransitionMutationArgs {
  pub(crate) transition_id: String,
  pub(crate) file: PathBuf,
  #[arg(long, required = true)]
  pub(crate) etag: String,
}

#[derive(Debug, Args)]
pub(crate) struct MembershipTransitionArgs {
  pub(crate) transition_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct MembershipTransitionFileArgs {
  pub(crate) transition_id: String,
  pub(crate) file: PathBuf,
}
