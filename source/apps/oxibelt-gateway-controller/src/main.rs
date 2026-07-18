use anyhow::{Context, bail};
use clap::Parser;

#[path = "cli.rs"]
mod cli;
#[path = "gateway_policy.rs"]
mod gateway_policy;
#[path = "health.rs"]
mod health;
#[path = "kubernetes_time.rs"]
mod kubernetes_time;
#[path = "leader_election.rs"]
mod leader_election;
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
#[path = "rollout_proof.rs"]
mod rollout_proof;
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
      let election_config = leader_election::LeaderElectionConfig::from_args(args)?;
      let identity = leader_election::process_identity()?;
      let leadership = leader_election::Leadership::new(election_config.clone());
      let kubernetes = kubernetes.with_leadership(leadership.clone());
      let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
      let signal_tx = shutdown_tx.clone();
      tokio::spawn(async move {
        shutdown_signal().await;
        let _ = signal_tx.send(true);
      });
      let election = tokio::spawn(leader_election::run_leader_election(
        kubernetes.clone(),
        election_config,
        identity,
        leadership.clone(),
        controller_health.clone(),
        shutdown_rx.clone(),
      ));
      let reconcile_result = watch::run_poll_loop(
        kubernetes,
        &cli.shared,
        args,
        controller_health,
        leadership.clone(),
        shutdown_rx,
      )
      .await;
      leadership.revoke();
      let _ = shutdown_tx.send(true);
      election.await.context("leader-election task failed")??;
      reconcile_result?;
    }
  }
  Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() {
  use tokio::signal::unix::{SignalKind, signal};

  let terminate = signal(SignalKind::terminate());
  match terminate {
    Ok(mut terminate) => {
      tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
      }
    }
    Err(_) => {
      let _ = tokio::signal::ctrl_c().await;
    }
  }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
  let _ = tokio::signal::ctrl_c().await;
}
