use std::time::Duration;

use anyhow::bail;
use clap::Parser;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, read_token};

#[path = "oxibeltctl/cli.rs"]
mod cli;
#[path = "oxibeltctl/config_compat.rs"]
mod config_compat;
#[path = "oxibeltctl/doctor.rs"]
mod doctor;
#[path = "oxibeltctl/doctor_plan.rs"]
mod doctor_plan;
#[cfg(test)]
#[path = "oxibeltctl/doctor_plan_tests.rs"]
mod doctor_plan_tests;
#[path = "oxibeltctl/dynamic_policy_plan.rs"]
mod dynamic_policy_plan;
#[path = "oxibeltctl/ipm_plan.rs"]
mod ipm_plan;
#[path = "oxibeltctl/output.rs"]
mod output;
#[path = "oxibeltctl/plan.rs"]
mod plan;
#[path = "oxibeltctl/pool_plan.rs"]
mod pool_plan;
#[path = "oxibeltctl/profile_catalog.rs"]
mod profile_catalog;
#[path = "oxibeltctl/resource_hint.rs"]
mod resource_hint;
#[path = "oxibeltctl/rulepack.rs"]
mod rulepack;
#[path = "oxibeltctl/rulepack_adapt.rs"]
mod rulepack_adapt;
#[path = "oxibeltctl/rulepack_catalog.rs"]
mod rulepack_catalog;
#[path = "oxibeltctl/rulepack_catalog_index.rs"]
mod rulepack_catalog_index;
#[path = "oxibeltctl/rulepack_catalog_registry.rs"]
mod rulepack_catalog_registry;
#[path = "oxibeltctl/rulepack_fit.rs"]
mod rulepack_fit;
#[path = "oxibeltctl/rulepack_install.rs"]
mod rulepack_install;
#[path = "oxibeltctl/rulepack_openpgp.rs"]
mod rulepack_openpgp;
#[path = "oxibeltctl/rulepack_plan.rs"]
mod rulepack_plan;
#[path = "oxibeltctl/rulepack_prompt.rs"]
mod rulepack_prompt;
#[path = "oxibeltctl/rulepack_render.rs"]
mod rulepack_render;
#[path = "oxibeltctl/rulepack_url.rs"]
mod rulepack_url;
#[path = "oxibeltctl/rulepack_values.rs"]
mod rulepack_values;

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
  if config_compat::run_local_if_requested(&cli.command)? {
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
