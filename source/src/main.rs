use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use oxibelt::config::Config;

#[derive(Debug, Parser)]
#[command(name = "oxibelt")]
#[command(about = "OxiBelt reverse proxy")]
struct Cli {
  #[arg(long, value_name = "FILE")]
  config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let cli = Cli::parse();
  let config = Config::load(&cli.config)
    .with_context(|| format!("failed to load {}", cli.config.display()))?;

  oxibelt::run(config).await
}
