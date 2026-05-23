use std::collections::BTreeSet;
use std::io::{BufReader, Write};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use crate::config::{
  Config, DatabaseTlsMode, HttpVersion, SharedStateBackendConfig, SharedStateBackendKind,
};

use super::{DiagnosticReport, DiagnosticSeverity, DoctorOptions, ExternalProbeKind};

pub(super) async fn run_external_probes(
  config: &Config,
  options: &DoctorOptions,
  report: &mut DiagnosticReport,
) {
  for probe in options.expanded_external_probes() {
    match probe {
      ExternalProbeKind::SharedState => probe_shared_state(config, report).await,
      ExternalProbeKind::IpmStore => probe_ipm_store(config, report).await,
      ExternalProbeKind::RemoteSigner => probe_remote_signer(config, report).await,
      ExternalProbeKind::Upstream => probe_upstreams(config, report).await,
      ExternalProbeKind::All => {}
    }
  }
}

pub(super) fn external_probe_target_resources(
  config: &Config,
  options: &DoctorOptions,
) -> Vec<String> {
  let mut resources = BTreeSet::new();
  for probe in options.expanded_external_probes() {
    match probe {
      ExternalProbeKind::SharedState => collect_shared_state_targets(config, &mut resources),
      ExternalProbeKind::IpmStore => collect_ipm_store_targets(config, &mut resources),
      ExternalProbeKind::RemoteSigner => collect_remote_signer_targets(config, &mut resources),
      ExternalProbeKind::Upstream => collect_upstream_targets(config, &mut resources),
      ExternalProbeKind::All => {}
    }
  }
  resources.into_iter().collect()
}

fn collect_shared_state_targets(config: &Config, resources: &mut BTreeSet<String>) {
  if !config.shared_state.enabled {
    return;
  }
  for backend in &config.shared_state.backends {
    if let Some(resource) = shared_state_backend_resource("shared_state", backend) {
      resources.insert(resource);
    }
  }
}

fn collect_ipm_store_targets(config: &Config, resources: &mut BTreeSet<String>) {
  if !config.ipm.enabled {
    return;
  }
  let Some(name) = config.ipm_backend_name() else {
    return;
  };
  let Some(backend) = config
    .shared_state
    .backends
    .iter()
    .find(|backend| backend.name == name)
  else {
    return;
  };
  if let Some(resource) = shared_state_backend_resource("ipm_store", backend) {
    resources.insert(resource);
  }
}

fn collect_remote_signer_targets(config: &Config, resources: &mut BTreeSet<String>) {
  if config.tls.remote_signer.enabled {
    resources.insert(format!(
      "probe/remote_signer/unix/{}",
      config.tls.remote_signer.socket_path.display()
    ));
  }
}

fn collect_upstream_targets(config: &Config, resources: &mut BTreeSet<String>) {
  for upstream in &config.upstreams {
    if upstream.max_http_version == HttpVersion::H3 {
      continue;
    }
    if let Some(resource) = tcp_resource_from_url("upstream", &upstream.origin, None) {
      resources.insert(resource);
    }
  }
  for pool in &config.upstream_pools {
    for server in &pool.servers {
      if let Some(resource) = tcp_resource_from_url("upstream", &server.origin, None) {
        resources.insert(resource);
      }
    }
  }
}

fn shared_state_backend_resource(kind: &str, backend: &SharedStateBackendConfig) -> Option<String> {
  let raw = backend
    .connection_url_with_prefix(&format!("shared_state.backends.{}", backend.name))
    .ok()?;
  let url = Url::parse(&raw).ok()?;
  let default_port = match backend.kind {
    SharedStateBackendKind::Redis => 6379,
    SharedStateBackendKind::Postgres => 5432,
  };
  tcp_resource_from_url(kind, &url, Some(default_port))
}

fn tcp_resource_from_url(kind: &str, url: &Url, default_port: Option<u16>) -> Option<String> {
  let host = normalized_probe_host(url.host_str()?);
  let port = url.port_or_known_default().or(default_port)?;
  Some(format!("probe/{kind}/tcp/{host}:{port}"))
}

fn normalized_probe_host(host: &str) -> String {
  match host.parse::<IpAddr>() {
    Ok(IpAddr::V4(ip)) => ip.to_string(),
    Ok(IpAddr::V6(ip)) => format!("[{ip}]"),
    Err(_) => host.to_ascii_lowercase(),
  }
}

async fn probe_shared_state(config: &Config, report: &mut DiagnosticReport) {
  if !config.shared_state.enabled {
    report.probe(
      "shared_state",
      "shared_state",
      "skipped",
      "shared_state is disabled",
    );
    return;
  }
  for backend in &config.shared_state.backends {
    probe_shared_state_backend(backend, report, "shared_state").await;
  }
}

async fn probe_ipm_store(config: &Config, report: &mut DiagnosticReport) {
  if !config.ipm.enabled {
    report.probe("ipm_store", "ipm", "skipped", "IPM is disabled");
    return;
  }
  let Some(name) = config.ipm_backend_name() else {
    report.probe(
      "ipm_store",
      "ipm",
      "skipped",
      "IPM has no PostgreSQL backend configured",
    );
    return;
  };
  let Some(backend) = config
    .shared_state
    .backends
    .iter()
    .find(|backend| backend.name == name)
  else {
    report.probe("ipm_store", name, "error", "IPM backend was not found");
    report.push(
      DiagnosticSeverity::Error,
      "probe.ipm_store_failed",
      "probe",
      format!("ipm.backend.{name}"),
      "IPM backend was not found",
      "Fix ipm.backend or shared_state backend names.",
    );
    return;
  };
  probe_postgres_backend(backend, report, "ipm_store").await;
}

async fn probe_shared_state_backend(
  backend: &SharedStateBackendConfig,
  report: &mut DiagnosticReport,
  kind: &str,
) {
  match backend.kind {
    SharedStateBackendKind::Redis => match probe_redis_backend(backend).await {
      Ok(()) => report.probe(kind, &backend.name, "ok", "Redis PING succeeded"),
      Err(error) => push_probe_error(report, kind, &backend.name, error),
    },
    SharedStateBackendKind::Postgres => probe_postgres_backend(backend, report, kind).await,
  }
}

async fn probe_postgres_backend(
  backend: &SharedStateBackendConfig,
  report: &mut DiagnosticReport,
  kind: &str,
) {
  match postgres_select_one(backend).await {
    Ok(()) => report.probe(kind, &backend.name, "ok", "PostgreSQL SELECT 1 succeeded"),
    Err(error) => push_probe_error(report, kind, &backend.name, error),
  }
}

async fn probe_remote_signer(config: &Config, report: &mut DiagnosticReport) {
  if !config.tls.remote_signer.enabled {
    report.probe(
      "remote_signer",
      "tls.remote_signer",
      "skipped",
      "remote signer is disabled",
    );
    return;
  }
  match remote_signer_describe_key(config) {
    Ok(()) => report.probe(
      "remote_signer",
      "tls.remote_signer",
      "ok",
      "DescribeKey succeeded and matched the configured certificate",
    ),
    Err(error) => push_probe_error(report, "remote_signer", "tls.remote_signer", error),
  }
}

async fn probe_upstreams(config: &Config, report: &mut DiagnosticReport) {
  for upstream in &config.upstreams {
    if upstream.max_http_version == HttpVersion::H3 {
      report.probe(
        "upstream",
        &upstream.name,
        "skipped",
        "HTTP/3 upstream probes are not implemented in doctor v1",
      );
      continue;
    }
    probe_url_connect(
      report,
      "upstream",
      &upstream.name,
      &upstream.origin,
      upstream.connect_timeout_ms,
    )
    .await;
  }
  for pool in &config.upstream_pools {
    for (index, server) in pool.servers.iter().enumerate() {
      let target = server
        .id
        .as_deref()
        .map(|id| format!("{}.{}", pool.name, id))
        .unwrap_or_else(|| format!("{}.server{index}", pool.name));
      probe_url_connect(report, "upstream", &target, &server.origin, 3_000).await;
    }
  }
}

async fn probe_url_connect(
  report: &mut DiagnosticReport,
  kind: &str,
  target: &str,
  url: &Url,
  timeout_ms: u64,
) {
  let Some(host) = url.host_str() else {
    push_probe_error(report, kind, target, anyhow!("URL is missing host"));
    return;
  };
  let Some(port) = url.port_or_known_default() else {
    push_probe_error(report, kind, target, anyhow!("URL is missing port"));
    return;
  };
  match tokio::time::timeout(
    Duration::from_millis(timeout_ms),
    tokio::net::TcpStream::connect((host, port)),
  )
  .await
  {
    Ok(Ok(_)) => report.probe(
      kind,
      target,
      "ok",
      format!("TCP connect to {host}:{port} succeeded"),
    ),
    Ok(Err(error)) => push_probe_error(report, kind, target, error.into()),
    Err(_) => push_probe_error(report, kind, target, anyhow!("connect timed out")),
  }
}

fn push_probe_error(report: &mut DiagnosticReport, kind: &str, target: &str, error: anyhow::Error) {
  let message = error.to_string();
  report.probe(kind, target, "error", &message);
  report.push(
    DiagnosticSeverity::Error,
    &format!("probe.{kind}_failed"),
    "probe",
    target,
    format!("{kind} probe failed: {message}"),
    "Fix the dependency endpoint, credentials, network policy, or disable this external probe for offline validation.",
  );
}

async fn probe_redis_backend(backend: &SharedStateBackendConfig) -> anyhow::Result<()> {
  let raw =
    backend.connection_url_with_prefix(&format!("shared_state.backends.{}", backend.name))?;
  let url = Url::parse(&raw).context("failed to parse Redis URL")?;
  let host = url
    .host_str()
    .ok_or_else(|| anyhow!("Redis URL is missing host"))?;
  let port = url.port().unwrap_or(6379);
  let timeout = Duration::from_millis(backend.connect_timeout_ms);
  let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port)))
    .await
    .map_err(|_| anyhow!("Redis connect timed out"))??;

  if let Some(password) = url.password().filter(|value| !value.is_empty()) {
    let mut args = vec!["AUTH".to_string()];
    if !url.username().is_empty() {
      args.push(url.username().to_string());
    }
    args.push(password.to_string());
    redis_round_trip(&mut stream, &args, timeout)
      .await
      .context("Redis AUTH failed")?;
  }
  if let Some(db) = url
    .path()
    .strip_prefix('/')
    .filter(|value| !value.is_empty())
  {
    redis_round_trip(
      &mut stream,
      &["SELECT".to_string(), db.to_string()],
      timeout,
    )
    .await
    .context("Redis SELECT failed")?;
  }
  let line = redis_round_trip(&mut stream, &["PING".to_string()], timeout).await?;
  if line != "+PONG" {
    bail!("unexpected Redis PING response {line}");
  }
  Ok(())
}

async fn redis_round_trip(
  stream: &mut tokio::net::TcpStream,
  args: &[String],
  timeout: Duration,
) -> anyhow::Result<String> {
  let mut encoded = Vec::new();
  write!(&mut encoded, "*{}\r\n", args.len())?;
  for arg in args {
    write!(&mut encoded, "${}\r\n", arg.len())?;
    encoded.extend_from_slice(arg.as_bytes());
    encoded.extend_from_slice(b"\r\n");
  }
  tokio::time::timeout(timeout, stream.write_all(&encoded))
    .await
    .map_err(|_| anyhow!("Redis write timed out"))??;
  let line = tokio::time::timeout(timeout, read_redis_line(stream))
    .await
    .map_err(|_| anyhow!("Redis read timed out"))??;
  if let Some(error) = line.strip_prefix('-') {
    bail!("Redis error: {error}");
  }
  Ok(line)
}

async fn read_redis_line(stream: &mut tokio::net::TcpStream) -> anyhow::Result<String> {
  let mut bytes = Vec::new();
  loop {
    let mut byte = [0_u8; 1];
    let read = stream.read(&mut byte).await?;
    if read == 0 {
      bail!("Redis closed the connection");
    }
    bytes.push(byte[0]);
    if bytes.ends_with(b"\r\n") {
      bytes.truncate(bytes.len().saturating_sub(2));
      return String::from_utf8(bytes).context("Redis response line was not UTF-8");
    }
    if bytes.len() > 16 * 1024 {
      bail!("Redis response line exceeded 16 KiB");
    }
  }
}

async fn postgres_select_one(backend: &SharedStateBackendConfig) -> anyhow::Result<()> {
  let connection_url =
    backend.connection_url_with_prefix(&format!("shared_state.backends.{}", backend.name))?;
  let mut options = PgConnectOptions::from_str(&connection_url)?
    .application_name("oxibelt-doctor")
    .ssl_mode(match backend.tls.mode {
      DatabaseTlsMode::Off => PgSslMode::Disable,
      DatabaseTlsMode::VerifyFull => PgSslMode::VerifyFull,
    });
  if let Some(ca_cert) = &backend.tls.ca_cert {
    options = options.ssl_root_cert(ca_cert);
  }
  if let (Some(client_cert), Some(client_key)) = (&backend.tls.client_cert, &backend.tls.client_key)
  {
    options = options
      .ssl_client_cert(client_cert)
      .ssl_client_key(client_key);
  }
  let pool = PgPoolOptions::new()
    .max_connections(1)
    .acquire_timeout(Duration::from_millis(backend.connect_timeout_ms))
    .connect_with(options)
    .await?;
  sqlx::query("SELECT 1").execute(&pool).await?;
  Ok(())
}

fn remote_signer_describe_key(config: &Config) -> anyhow::Result<()> {
  let file = std::fs::File::open(&config.tls.cert_chain)
    .with_context(|| format!("failed to read {}", config.tls.cert_chain.display()))?;
  let certs = rustls_pemfile::certs(&mut BufReader::new(file))
    .collect::<Result<Vec<_>, _>>()
    .context("failed to parse configured TLS certificate chain")?;
  let cert = certs
    .first()
    .ok_or_else(|| anyhow!("configured TLS certificate chain is empty"))?;
  let _ = crate::remote_signer::RemoteSigningKey::connect(
    &config.tls.remote_signer,
    &config.tls.remote_signer.key_id,
    cert,
  )?;
  Ok(())
}
