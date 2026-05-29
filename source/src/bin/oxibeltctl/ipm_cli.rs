use std::net::IpAddr;
use std::path::PathBuf;

use clap::{ArgGroup, Args, Subcommand};

#[derive(Debug, Args)]
pub(crate) struct IpmCommand {
  #[command(subcommand)]
  pub(crate) command: IpmSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IpmSubcommand {
  Status,
  List(IpmListArgs),
  Simulate(Box<IpmSimulateArgs>),
  Principal(IpmPrincipalCommand),
  Credential(IpmCredentialCommand),
  Policy(IpmPolicyCommand),
  Binding(IpmBindingCommand),
  Audit(IpmAuditArgs),
}

#[derive(Debug, Args)]
pub(crate) struct IpmSimulateArgs {
  #[arg(long)]
  pub(crate) action: String,
  #[arg(long)]
  pub(crate) resource: String,
  #[arg(long)]
  pub(crate) principal: Option<String>,
  #[arg(long)]
  pub(crate) credential: Option<String>,
  #[arg(long)]
  pub(crate) subject: Option<String>,
  #[arg(long = "group")]
  pub(crate) groups: Vec<String>,
  #[arg(long = "source-ip")]
  pub(crate) source_ip: Option<IpAddr>,
  #[arg(long)]
  pub(crate) method: Option<String>,
  #[arg(long)]
  pub(crate) host: Option<String>,
  #[arg(long)]
  pub(crate) path: Option<String>,
  #[arg(long)]
  pub(crate) route: Option<String>,
  #[arg(long)]
  pub(crate) protocol: Option<String>,
  #[arg(long = "claim", value_name = "KEY=VALUE")]
  pub(crate) claims: Vec<String>,
  #[arg(long, value_name = "FILE")]
  pub(crate) overlay: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct IpmListArgs {
  #[command(subcommand)]
  pub(crate) target: IpmListTarget,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IpmListTarget {
  Principals,
  Credentials,
  Policies,
  Bindings,
}

#[derive(Debug, Args)]
pub(crate) struct IpmPrincipalCommand {
  #[command(subcommand)]
  pub(crate) command: IpmPrincipalSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IpmPrincipalSubcommand {
  List,
  Get(IpmIdArg),
  Create(IpmPrincipalCreateArgs),
  Patch(IpmPrincipalPatchArgs),
  Delete(IpmMutatingIdArg),
}

#[derive(Debug, Args)]
pub(crate) struct IpmPrincipalCreateArgs {
  pub(crate) id: String,
  #[arg(long)]
  pub(crate) subject: String,
  #[arg(long = "group")]
  pub(crate) groups: Vec<String>,
  #[arg(long)]
  pub(crate) disabled: bool,
  #[arg(long)]
  pub(crate) etag: Option<String>,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("enabled_state").args(["enable", "disable"])))]
pub(crate) struct IpmPrincipalPatchArgs {
  pub(crate) id: String,
  #[arg(long)]
  pub(crate) subject: Option<String>,
  #[arg(long = "group")]
  pub(crate) groups: Vec<String>,
  #[arg(long)]
  pub(crate) enable: bool,
  #[arg(long)]
  pub(crate) disable: bool,
  #[arg(long)]
  pub(crate) etag: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct IpmCredentialCommand {
  #[command(subcommand)]
  pub(crate) command: IpmCredentialSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IpmCredentialSubcommand {
  List,
  Get(IpmIdArg),
  Create(IpmCredentialCreateArgs),
  Patch(IpmCredentialPatchArgs),
  Rotate(IpmCredentialRotateArgs),
  Revoke(IpmCredentialRevokeArgs),
  Delete(IpmMutatingIdArg),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("expiry").required(true).args(["expires", "no_expiry"])))]
pub(crate) struct IpmCredentialCreateArgs {
  pub(crate) id: String,
  #[arg(long)]
  pub(crate) principal: String,
  #[arg(long, value_parser = super::parse_ttl_seconds)]
  pub(crate) expires: Option<i64>,
  #[arg(long = "no-expiry")]
  pub(crate) no_expiry: bool,
  #[arg(long)]
  pub(crate) etag: Option<String>,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("enabled_state").args(["enable", "disable"])))]
pub(crate) struct IpmCredentialPatchArgs {
  pub(crate) id: String,
  #[arg(long)]
  pub(crate) principal: Option<String>,
  #[arg(long)]
  pub(crate) enable: bool,
  #[arg(long)]
  pub(crate) disable: bool,
  #[arg(long, value_parser = super::parse_ttl_seconds)]
  pub(crate) expires: Option<i64>,
  #[arg(long)]
  pub(crate) etag: Option<String>,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("expiry").required(true).args(["expires", "no_expiry"])))]
pub(crate) struct IpmCredentialRotateArgs {
  pub(crate) id: String,
  #[arg(long, value_parser = super::parse_ttl_seconds)]
  pub(crate) expires: Option<i64>,
  #[arg(long = "no-expiry")]
  pub(crate) no_expiry: bool,
  #[arg(long, value_parser = super::parse_ttl_seconds, default_value = "24h")]
  pub(crate) overlap: i64,
  #[arg(long)]
  pub(crate) etag: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct IpmCredentialRevokeArgs {
  pub(crate) id: String,
  #[arg(long)]
  pub(crate) reason: Option<String>,
  #[arg(long)]
  pub(crate) etag: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct IpmPolicyCommand {
  #[command(subcommand)]
  pub(crate) command: IpmPolicySubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IpmPolicySubcommand {
  List,
  Get(IpmIdArg),
  Create(IpmJsonMutationArg),
  Patch(IpmPolicyPatchArgs),
  Delete(IpmMutatingIdArg),
}

#[derive(Debug, Args)]
pub(crate) struct IpmPolicyPatchArgs {
  pub(crate) id: String,
  #[arg(long = "json", value_name = "FILE")]
  pub(crate) json: PathBuf,
  #[arg(long)]
  pub(crate) etag: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct IpmBindingCommand {
  #[command(subcommand)]
  pub(crate) command: IpmBindingSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IpmBindingSubcommand {
  List,
  Create(IpmBindingCreateArgs),
  Delete(IpmMutatingIdArg),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("binding_subject").required(true).args(["principal", "group"])))]
pub(crate) struct IpmBindingCreateArgs {
  #[arg(long)]
  pub(crate) id: Option<String>,
  #[arg(long)]
  pub(crate) principal: Option<String>,
  #[arg(long)]
  pub(crate) group: Option<String>,
  #[arg(long)]
  pub(crate) policy: String,
  #[arg(long)]
  pub(crate) disabled: bool,
  #[arg(long)]
  pub(crate) etag: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct IpmAuditArgs {
  #[arg(long = "target-kind")]
  pub(crate) target_kind: Option<String>,
  #[arg(long = "target-id")]
  pub(crate) target_id: Option<String>,
  #[arg(long)]
  pub(crate) outcome: Option<String>,
  #[arg(long)]
  pub(crate) actor: Option<String>,
  #[arg(long, default_value_t = 100)]
  pub(crate) limit: i64,
}

#[derive(Debug, Args)]
pub(crate) struct IpmJsonMutationArg {
  #[arg(long = "json", value_name = "FILE")]
  pub(crate) json: PathBuf,
  #[arg(long)]
  pub(crate) etag: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct IpmIdArg {
  pub(crate) id: String,
}

#[derive(Debug, Args)]
pub(crate) struct IpmMutatingIdArg {
  pub(crate) id: String,
  #[arg(long)]
  pub(crate) etag: Option<String>,
}
