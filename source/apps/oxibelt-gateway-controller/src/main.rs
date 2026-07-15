use anyhow::{Context, bail};
use clap::Parser;

#[path = "cli.rs"]
mod cli;
#[path = "gateway_policy.rs"]
mod gateway_policy;
#[path = "health.rs"]
mod health;
#[path = "model.rs"]
mod model;
#[path = "render.rs"]
mod render;
#[path = "rollout.rs"]
mod rollout;
#[path = "rollout_client.rs"]
mod rollout_client;
#[path = "rollout_decision.rs"]
mod rollout_decision;
#[path = "rollout_patch.rs"]
mod rollout_patch;
#[path = "rollout_status.rs"]
mod rollout_status;
#[path = "status.rs"]
mod status;
#[path = "translate.rs"]
mod translate;
#[path = "watch.rs"]
mod watch;

use cli::{Cli, Command};

#[tokio::main]
async fn main() {
  if let Err(error) = run().await {
    eprintln!("{error:#}");
    std::process::exit(1);
  }
}

async fn run() -> anyhow::Result<()> {
  let cli = Cli::parse();
  tracing_subscriber::fmt()
    .with_env_filter(
      tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "oxibelt_gateway_controller=info".into()),
    )
    .init();

  match &cli.command {
    Command::Render(args) => {
      let objects = render::load_objects(&args.input)?;
      let rendered = translate::translate_objects(&objects, &cli.shared)?;
      render::write_rendered(&args.output, &rendered.toml)?;
      status::print_diagnostics(&rendered.diagnostics);
      if rendered
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, model::DiagnosticSeverity::Error))
      {
        bail!("translation produced blocking diagnostics");
      }
    }
    Command::Run(args) => {
      let controller_health = health::ControllerHealth::default();
      let _health =
        health::spawn_if_configured(cli.shared.health_bind, controller_health.clone()).await?;
      let kubernetes = watch::KubernetesPoller::from_environment(&cli.shared)
        .context("failed to build Kubernetes API poller")?;
      watch::run_poll_loop(kubernetes, &cli.shared, args, controller_health).await?;
    }
  }
  Ok(())
}
