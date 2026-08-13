use std::time::Duration;

use anyhow::bail;
use clap::Parser;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, read_token};

#[path = "audit_verify.rs"]
mod audit_verify;
#[path = "audit_verify_evidence.rs"]
mod audit_verify_evidence;
#[path = "audit_verify_postgres.rs"]
mod audit_verify_postgres;
#[cfg(test)]
#[path = "audit_verify_tests.rs"]
mod audit_verify_tests;
#[path = "cli.rs"]
mod cli;
#[path = "config_compat.rs"]
mod config_compat;
#[path = "config_explain.rs"]
mod config_explain;
#[path = "config_filesystem_access.rs"]
mod config_filesystem_access;
#[path = "config_migrate.rs"]
mod config_migrate;
#[path = "config_migrate_transform.rs"]
mod config_migrate_transform;
#[path = "config_output.rs"]
mod config_output;
#[path = "config_plan.rs"]
mod config_plan;
#[path = "config_schema.rs"]
mod config_schema;
#[path = "config_validate.rs"]
mod config_validate;
#[path = "doctor.rs"]
mod doctor;
#[path = "doctor_plan.rs"]
mod doctor_plan;
#[cfg(test)]
#[path = "doctor_plan_tests.rs"]
mod doctor_plan_tests;
#[path = "dynamic_policy_plan.rs"]
mod dynamic_policy_plan;
#[path = "fingerprint.rs"]
mod fingerprint;
#[path = "ipm_plan.rs"]
mod ipm_plan;
#[path = "mutation_signer.rs"]
mod mutation_signer;
#[cfg(test)]
#[path = "mutation_signer_tests.rs"]
mod mutation_signer_tests;
#[path = "output.rs"]
mod output;
#[path = "plan.rs"]
mod plan;
#[path = "pool_plan.rs"]
mod pool_plan;
#[path = "profile_catalog.rs"]
mod profile_catalog;
#[path = "resource_hint.rs"]
mod resource_hint;
#[path = "rulepack.rs"]
mod rulepack;
#[path = "rulepack_adapt.rs"]
mod rulepack_adapt;
#[path = "rulepack_catalog.rs"]
mod rulepack_catalog;
#[path = "rulepack_catalog_index.rs"]
mod rulepack_catalog_index;
#[path = "rulepack_catalog_registry.rs"]
mod rulepack_catalog_registry;
#[path = "rulepack_fit.rs"]
mod rulepack_fit;
#[path = "rulepack_install.rs"]
mod rulepack_install;
#[path = "rulepack_openpgp.rs"]
mod rulepack_openpgp;
#[path = "rulepack_plan.rs"]
mod rulepack_plan;
#[path = "rulepack_prompt.rs"]
mod rulepack_prompt;
#[path = "rulepack_render.rs"]
mod rulepack_render;
#[path = "rulepack_url.rs"]
mod rulepack_url;
#[path = "rulepack_values.rs"]
mod rulepack_values;
#[path = "supply_chain.rs"]
mod supply_chain;
#[path = "supply_chain_admission.rs"]
mod supply_chain_admission;
#[path = "supply_chain_bundle.rs"]
mod supply_chain_bundle;
#[path = "supply_chain_workload_policy.rs"]
mod supply_chain_workload_policy;
#[cfg(test)]
#[path = "test_support.rs"]
mod test_support;

use cli::{AdminArgs, Cli, Command, selected_token_env};
use output::{print_permission_hint, print_response};
use plan::plan_command;

#[tokio::main]
async fn main() {
  match run().await {
    Ok(code) if code != 0 => std::process::exit(code),
    Ok(_) => {}
    Err(error) => {
      eprintln!("{error:#}");
      std::process::exit(1);
    }
  }
}

async fn run() -> anyhow::Result<i32> {
  let cli = Cli::parse();
  oxibelt::tls::install_default_provider()?;
  if let Some(code) = config_schema::run_if_requested(&cli.command, cli.admin.output)? {
    return Ok(code);
  }
  if let Some(code) = config_explain::run_local_if_requested(&cli.command, cli.admin.output)? {
    return Ok(code);
  }
  if let Some(code) = config_filesystem_access::run_if_requested(&cli.command)? {
    return Ok(code);
  }
  if let Some(code) = config_migrate::run_if_requested(&cli.command, cli.admin.output)? {
    return Ok(code);
  }
  let prepared_config_plan = match config_plan::prepare_if_requested(&cli.command)? {
    config_plan::ConfigPlanDispatch::NotRequested => None,
    config_plan::ConfigPlanDispatch::Complete(code) => return Ok(code),
    config_plan::ConfigPlanDispatch::Online(prepared) => Some(prepared),
  };
  let prepared_validation =
    match config_validate::prepare_if_requested(&cli.command, cli.admin.output)? {
      config_validate::ValidationDispatch::NotRequested => None,
      config_validate::ValidationDispatch::Complete(code) => return Ok(code),
      config_validate::ValidationDispatch::Remote(prepared) => Some(prepared),
    };
  if let Some(code) = audit_verify::run_local_if_requested(&cli.command, cli.admin.output).await? {
    return Ok(code);
  }
  if doctor::run_local_if_requested(&cli.command).await? {
    return Ok(0);
  }
  if rulepack::run_local_if_requested(&cli.command).await? {
    return Ok(0);
  }
  if config_compat::run_local_if_requested(&cli.command)? {
    return Ok(0);
  }
  if let Some(code) = supply_chain::run_if_requested(&cli.command).await? {
    return Ok(code);
  }
  let client = build_client(&cli.admin)?;
  if let Some(prepared) = prepared_config_plan {
    let request = prepared.request_plan();
    let response = mutation_signer::request_json(
      &client,
      None,
      request.method,
      &request.endpoint,
      request.body,
      None,
    )
    .await?;
    if response.status == http::StatusCode::FORBIDDEN {
      print_permission_hint(&request.permission);
    }
    return prepared.finish(&response);
  }
  let mutation_signer = mutation_signer::MutationSigner::from_args(&cli.admin.mutation)?;
  if rulepack::run_remote_if_requested_signed(
    &client,
    &cli.command,
    cli.admin.output,
    mutation_signer.as_ref(),
  )
  .await?
  {
    return Ok(0);
  }
  if let Some(prepared) = prepared_validation {
    let request = prepared.request_plan();
    let response = mutation_signer::request_json(
      &client,
      mutation_signer.as_ref(),
      request.method,
      &request.endpoint,
      request.body,
      request.if_match.as_deref(),
    )
    .await?;
    if response.status == http::StatusCode::FORBIDDEN {
      print_permission_hint(&request.permission);
    }
    return prepared.finish(&response, cli.admin.output);
  }
  let request = plan_command(&client, &cli.command).await?;
  let response = mutation_signer::request_json(
    &client,
    mutation_signer.as_ref(),
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
    return Ok(0);
  }
  print_response(&response, cli.admin.output, &request.filter)?;
  if response.status == http::StatusCode::FORBIDDEN {
    print_permission_hint(&request.permission);
  }
  if !response.status.is_success() {
    bail!("Admin request failed with {}", response.status);
  }
  Ok(0)
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
