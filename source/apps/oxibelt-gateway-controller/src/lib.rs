use anyhow::{Context, bail};
use clap::Parser;

mod cli;
mod gateway_policy;
mod health;
mod kubernetes_time;
mod leader_election;
mod model;
mod render;
mod rollout;
mod rollout_client;
mod rollout_decision;
mod rollout_patch;
mod rollout_proof;
mod rollout_status;
mod status;
mod translate;
mod watch;

#[cfg(feature = "fuzzing")]
pub mod fuzzing;

use cli::{Cli, Command};

/// Runs the Gateway Controller command-line application.
pub async fn run() -> anyhow::Result<()> {
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
      status::print_diagnostics(&rendered.diagnostics);
      if rendered
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, model::DiagnosticSeverity::Error))
      {
        bail!("translation produced blocking diagnostics");
      }
      render::write_rendered(&args.output, &rendered.toml)?;
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
      // Reconciliation must finish before election cleanup releases the Lease,
      // so no already-authorized Kubernetes mutation can follow the handoff.
      let (signal_tx, reconcile_shutdown_rx) = tokio::sync::watch::channel(false);
      let (election_shutdown_tx, election_shutdown_rx) = tokio::sync::watch::channel(false);
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
        election_shutdown_rx,
      ));
      let reconcile_result = watch::run_poll_loop(
        kubernetes,
        &cli.shared,
        args,
        controller_health,
        leadership.clone(),
        reconcile_shutdown_rx,
      )
      .await;
      let _ = election_shutdown_tx.send(true);
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
