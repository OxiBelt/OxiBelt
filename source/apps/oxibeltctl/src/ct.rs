use crate::cli::{Command, CtSubcommand};

pub(crate) async fn run_if_requested(command: &Command) -> anyhow::Result<Option<i32>> {
  let Command::Ct(command) = command else {
    return Ok(None);
  };
  let code = match &command.command {
    CtSubcommand::Postgres(command) => crate::ct_postgres::run(&command.command).await?,
    CtSubcommand::Roots(command) => crate::ct_roots::run(&command.command)?,
    CtSubcommand::Shard(command) => crate::ct_shards::run(&command.command)?,
    CtSubcommand::Monitor(args) => crate::ct_monitor::run(args).await?,
  };
  Ok(Some(code))
}
