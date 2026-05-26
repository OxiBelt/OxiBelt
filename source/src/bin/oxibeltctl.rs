use std::time::Duration;

use anyhow::bail;
use clap::Parser;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, read_token};

#[path = "oxibeltctl/cli.rs"]
mod cli;
#[path = "oxibeltctl/doctor.rs"]
mod doctor;
#[path = "oxibeltctl/doctor_plan.rs"]
mod doctor_plan;
#[path = "oxibeltctl/dynamic_policy_plan.rs"]
mod dynamic_policy_plan;
#[path = "oxibeltctl/output.rs"]
mod output;
#[path = "oxibeltctl/plan.rs"]
mod plan;
#[path = "oxibeltctl/profile_catalog.rs"]
mod profile_catalog;
#[path = "oxibeltctl/rulepack.rs"]
mod rulepack;

use cli::{AdminArgs, Cli, Command, selected_token_env};
use output::{print_permission_hint, print_response};
use plan::plan_command;

#[tokio::main]
async fn main() {
  if let Err(error) = run().await {
    eprintln!("{error:#}");
    std::process::exit(1);
  }
}

async fn run() -> anyhow::Result<()> {
  let cli = Cli::parse();
  oxibelt::tls::install_default_provider()?;
  if doctor::run_local_if_requested(&cli.command).await? {
    return Ok(());
  }
  if rulepack::run_local_if_requested(&cli.command).await? {
    return Ok(());
  }
  let client = build_client(&cli.admin)?;
  if rulepack::run_remote_if_requested(&client, &cli.command, cli.admin.output).await? {
    return Ok(());
  }
  let request = plan_command(&client, &cli.command).await?;
  let response = client
    .request_json(
      request.method,
      &request.endpoint,
      request.body,
      request.if_match.as_deref(),
    )
    .await?;
  if let Command::Doctor(args) = &cli.command {
    if response.status.is_success() {
      doctor::print_report_body(&response.body, args)?;
    } else {
      print_response(&response, cli.admin.output, &request.filter)?;
      if response.status == http::StatusCode::FORBIDDEN {
        print_permission_hint(&request.permission);
      }
      bail!("Admin request failed with {}", response.status);
    }
    return Ok(());
  }
  print_response(&response, cli.admin.output, &request.filter)?;
  if response.status == http::StatusCode::FORBIDDEN {
    print_permission_hint(&request.permission);
  }
  if !response.status.is_success() {
    bail!("Admin request failed with {}", response.status);
  }
  Ok(())
}

fn build_client(args: &AdminArgs) -> anyhow::Result<AdminClient> {
  let token_env = selected_token_env(args);
  let token = read_token(token_env, args.token_file.as_deref())?;
  let timeout = Duration::from_millis(args.timeout_ms);
  let mut options = AdminClientOptions::new(args.admin_url.clone(), token, timeout);
  options.ca_certs = args.ca_certs.clone();
  options.client_cert = args.client_cert.clone();
  options.client_key = args.client_key.clone();
  AdminClient::new(options)
}
