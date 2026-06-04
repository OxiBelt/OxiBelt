use anyhow::{Context, bail};
use clap::Parser;

#[path = "oxibelt_gateway_controller/admin_sync.rs"]
mod admin_sync;
#[path = "oxibelt_gateway_controller/cli.rs"]
mod cli;
#[path = "oxibelt_gateway_controller/health.rs"]
mod health;
#[path = "oxibelt_gateway_controller/model.rs"]
mod model;
#[path = "oxibelt_gateway_controller/render.rs"]
mod render;
#[path = "oxibelt_gateway_controller/status.rs"]
mod status;
#[path = "oxibelt_gateway_controller/translate.rs"]
mod translate;
#[path = "oxibelt_gateway_controller/watch.rs"]
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
      let _health = health::spawn_if_configured(cli.shared.health_bind).await?;
      let admin = admin_sync::AdminSync::from_args(&cli.shared)
        .context("failed to build Admin sync client")?;
      let kubernetes = watch::KubernetesPoller::from_environment(&cli.shared)
        .context("failed to build Kubernetes API poller")?;
      watch::run_poll_loop(kubernetes, admin, &cli.shared, args).await?;
    }
  }
  Ok(())
}
