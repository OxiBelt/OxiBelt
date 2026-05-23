use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use base64::Engine;
use clap::{Parser, Subcommand};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;

use oxibelt::config::{AdminPermission, AdminRole};

#[derive(Debug, Parser)]
#[command(name = "oxibelt-admin-token")]
#[command(about = "OxiBelt Admin API token bootstrap helper")]
struct Cli {
  #[command(subcommand)]
  command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
  GenerateKeypair,
  Mint {
    #[arg(long, default_value = "OXIBELT_ADMIN_TOKEN_PRIVATE_KEY")]
    private_key_env: String,
    #[arg(long)]
    issuer: String,
    #[arg(long)]
    audience: String,
    #[arg(long)]
    subject: String,
    #[arg(long)]
    token_id: String,
    #[arg(long, default_value_t = 3600, value_parser = parse_positive_i64)]
    ttl_seconds: i64,
    #[arg(long)]
    seed_sql: bool,
    #[arg(long, default_value = "oxibelt")]
    namespace: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(long = "role")]
    roles: Vec<String>,
    #[arg(long = "permission")]
    permissions: Vec<String>,
    #[arg(long = "deny-permission")]
    deny_permissions: Vec<String>,
  },
}

#[derive(Debug, Serialize)]
struct TokenHeader<'a> {
  alg: &'a str,
  typ: &'a str,
}

#[derive(Debug, Serialize)]
struct TokenClaims<'a> {
  iss: &'a str,
  aud: &'a str,
  sub: &'a str,
  jti: &'a str,
  iat: i64,
  exp: i64,
}

fn main() -> anyhow::Result<()> {
  let cli = Cli::parse();
  match cli.command {
    Command::GenerateKeypair => generate_keypair(),
    Command::Mint {
      private_key_env,
      issuer,
      audience,
      subject,
      token_id,
      ttl_seconds,
      seed_sql,
      namespace,
      name,
      roles,
      permissions,
      deny_permissions,
    } => mint_token(MintInput {
      private_key_env,
      issuer,
      audience,
      subject,
      token_id,
      ttl_seconds,
      seed_sql,
      namespace,
      name,
      roles,
      permissions,
      deny_permissions,
    }),
  }
}

struct MintInput {
  private_key_env: String,
  issuer: String,
  audience: String,
  subject: String,
  token_id: String,
  ttl_seconds: i64,
  seed_sql: bool,
  namespace: String,
  name: Option<String>,
  roles: Vec<String>,
  permissions: Vec<String>,
  deny_permissions: Vec<String>,
}

fn generate_keypair() -> anyhow::Result<()> {
  let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
    .map_err(|_| anyhow::anyhow!("failed to generate Ed25519 keypair"))?;
  let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
    .map_err(|_| anyhow::anyhow!("generated Ed25519 keypair failed to parse"))?;
  println!(
    "private_key_pkcs8_base64={}",
    base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref())
  );
  println!(
    "public_key_base64={}",
    base64::engine::general_purpose::STANDARD.encode(pair.public_key().as_ref())
  );
  Ok(())
}

fn mint_token(input: MintInput) -> anyhow::Result<()> {
  validate_runtime_identifier("token_id", &input.token_id)?;
  validate_non_empty("issuer", &input.issuer)?;
  validate_non_empty("audience", &input.audience)?;
  validate_non_empty("subject", &input.subject)?;
  let key_pair = load_private_key(&input.private_key_env)?;
  let issued_at = now_unix()?;
  let expires_at = issued_at + input.ttl_seconds;
  let token = sign_token(
    &key_pair,
    &input.issuer,
    &input.audience,
    &input.subject,
    &input.token_id,
    issued_at,
    expires_at,
  )?;
  println!("{token}");

  if input.seed_sql {
    let name = input
      .name
      .as_deref()
      .ok_or_else(|| anyhow::anyhow!("--seed-sql requires --name"))?;
    validate_non_empty("name", name)?;
    validate_authz(&input.roles, &input.permissions)?;
    validate_permissions(&input.roles, &input.permissions, &input.deny_permissions)?;
    print_seed_sql(&input, name, expires_at);
  }
  Ok(())
}

fn load_private_key(env_name: &str) -> anyhow::Result<Ed25519KeyPair> {
  let raw = std::env::var(env_name)
    .with_context(|| format!("failed to read Admin token private key env {env_name}"))?;
  let pkcs8 = base64::engine::general_purpose::STANDARD
    .decode(raw.trim())
    .context("Admin token private key env must contain base64 PKCS#8 bytes")?;
  Ed25519KeyPair::from_pkcs8(&pkcs8)
    .map_err(|_| anyhow::anyhow!("Admin token private key env is not a valid Ed25519 PKCS#8 key"))
}

fn sign_token(
  key_pair: &Ed25519KeyPair,
  issuer: &str,
  audience: &str,
  subject: &str,
  token_id: &str,
  issued_at: i64,
  expires_at: i64,
) -> anyhow::Result<String> {
  let header = TokenHeader {
    alg: "EdDSA",
    typ: "oxibelt-admin-token+jwt",
  };
  let claims = TokenClaims {
    iss: issuer,
    aud: audience,
    sub: subject,
    jti: token_id,
    iat: issued_at,
    exp: expires_at,
  };
  let encoded_header = encode_segment(&serde_json::to_vec(&header)?);
  let encoded_claims = encode_segment(&serde_json::to_vec(&claims)?);
  let signed = format!("{encoded_header}.{encoded_claims}");
  let signature = key_pair.sign(signed.as_bytes());
  Ok(format!("{signed}.{}", encode_segment(signature.as_ref())))
}

fn print_seed_sql(input: &MintInput, name: &str, expires_at: i64) {
  println!();
  println!(
    "INSERT INTO oxibelt_admin_tokens (namespace, token_id, subject, name, enabled, roles, permissions, deny_permissions, expires_at)"
  );
  println!(
    "VALUES ({}, {}, {}, {}, true, {}, {}, {}, to_timestamp({expires_at}));",
    sql_string(&input.namespace),
    sql_string(&input.token_id),
    sql_string(&input.subject),
    sql_string(name),
    sql_array(&input.roles),
    sql_array(&input.permissions),
    sql_array(&input.deny_permissions),
  );
  println!("INSERT INTO oxibelt_admin_token_generation (namespace, generation, updated_at)");
  println!(
    "VALUES ({}, 1, now()) ON CONFLICT (namespace) DO UPDATE SET generation = oxibelt_admin_token_generation.generation + 1, updated_at = now();",
    sql_string(&input.namespace)
  );
}

fn validate_permissions(
  roles: &[String],
  permissions: &[String],
  deny_permissions: &[String],
) -> anyhow::Result<()> {
  for role in roles {
    role.parse::<AdminRole>()?;
  }
  for permission in permissions.iter().chain(deny_permissions) {
    permission.parse::<AdminPermission>()?;
  }
  Ok(())
}

fn validate_authz(roles: &[String], permissions: &[String]) -> anyhow::Result<()> {
  if roles.is_empty() && permissions.is_empty() {
    bail!("--seed-sql requires at least one --role or --permission");
  }
  Ok(())
}

fn validate_runtime_identifier(field: &str, value: &str) -> anyhow::Result<()> {
  validate_non_empty(field, value)?;
  if !value
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
  {
    bail!("{field} must contain only ASCII letters, digits, '.', '_' or '-'");
  }
  Ok(())
}

fn validate_non_empty(field: &str, value: &str) -> anyhow::Result<()> {
  if value.trim().is_empty() {
    bail!("{field} must not be empty");
  }
  Ok(())
}

fn sql_string(value: &str) -> String {
  format!("'{}'", value.replace('\'', "''"))
}

fn sql_array(values: &[String]) -> String {
  if values.is_empty() {
    return "ARRAY[]::text[]".to_string();
  }
  let joined = values
    .iter()
    .map(|value| sql_string(value))
    .collect::<Vec<_>>();
  format!("ARRAY[{}]::text[]", joined.join(", "))
}

fn encode_segment(value: &[u8]) -> String {
  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

fn now_unix() -> anyhow::Result<i64> {
  let duration = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .context("system clock is before UNIX epoch")?;
  i64::try_from(duration.as_secs()).context("system time does not fit in i64")
}

fn parse_positive_i64(value: &str) -> anyhow::Result<i64> {
  let parsed = value
    .parse::<i64>()
    .with_context(|| format!("invalid positive integer {value}"))?;
  if parsed <= 0 {
    bail!("value must be greater than 0");
  }
  Ok(parsed)
}
