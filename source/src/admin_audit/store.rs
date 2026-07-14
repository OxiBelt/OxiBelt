use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::time::Duration;

use anyhow::bail;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{Pool, Postgres, Row};
use tokio::sync::mpsc;
use tracing::warn;

use crate::config::{DatabaseTlsMode, SharedStateBackendConfig};

use super::{AdminAuditEvent, AdminAuditQuery, AdminAuditRecord, request};

type AttemptFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
type SleepFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

pub(super) async fn connect_pool(
  backend: &SharedStateBackendConfig,
) -> anyhow::Result<Pool<Postgres>> {
  let connection_url =
    backend.connection_url_with_prefix(&format!("shared_state.backends.{}", backend.name))?;
  let mut options = PgConnectOptions::from_str(&connection_url)?
    .application_name("oxibelt-admin-audit")
    .ssl_mode(pg_ssl_mode(backend.tls.mode));
  if let Some(ca_cert) = &backend.tls.ca_cert {
    options = options.ssl_root_cert(ca_cert);
  }
  if let (Some(client_cert), Some(client_key)) = (&backend.tls.client_cert, &backend.tls.client_key)
  {
    options = options
      .ssl_client_cert(client_cert)
      .ssl_client_key(client_key);
  }
  PgPoolOptions::new()
    .max_connections(backend.max_connections)
    .acquire_timeout(Duration::from_millis(backend.connect_timeout_ms))
    .connect_with(options)
    .await
    .map_err(Into::into)
}

fn pg_ssl_mode(mode: DatabaseTlsMode) -> PgSslMode {
  match mode {
    DatabaseTlsMode::Off => PgSslMode::Disable,
    DatabaseTlsMode::VerifyFull => PgSslMode::VerifyFull,
  }
}

pub(super) async fn init_postgres(pool: &Pool<Postgres>) -> anyhow::Result<()> {
  for statement in [
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_audit (
       id bigserial PRIMARY KEY,
       namespace text NOT NULL,
       request_id text NOT NULL,
       actor text NULL,
       principal text NULL,
       subject text NULL,
       groups text[] NOT NULL DEFAULT ARRAY[]::text[],
       workload_identity_kind text NULL,
       workload_identity text NULL,
       workload_principal text NULL,
       certificate_fingerprint_sha256 text NULL,
       credential_kind text NULL,
       credential_identity text NULL,
       credential_principal text NULL,
       authentication_reason text NULL,
       peer text NOT NULL,
       source_ip text NULL,
       scheme text NOT NULL,
       method text NOT NULL,
       path text NOT NULL,
       service text NULL,
       operation text NOT NULL,
       action text NULL,
       resource text NULL,
       target_kind text NULL,
       target_id text NULL,
       status integer NOT NULL,
       outcome text NOT NULL,
       error text NULL,
       request_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
       created_at timestamptz NOT NULL DEFAULT now()
     )",
    "ALTER TABLE oxibelt_admin_audit
       ADD COLUMN IF NOT EXISTS workload_identity_kind text NULL",
    "ALTER TABLE oxibelt_admin_audit
       ADD COLUMN IF NOT EXISTS workload_identity text NULL",
    "ALTER TABLE oxibelt_admin_audit
       ADD COLUMN IF NOT EXISTS workload_principal text NULL",
    "ALTER TABLE oxibelt_admin_audit
       ADD COLUMN IF NOT EXISTS certificate_fingerprint_sha256 text NULL",
    "ALTER TABLE oxibelt_admin_audit
       ADD COLUMN IF NOT EXISTS credential_kind text NULL",
    "ALTER TABLE oxibelt_admin_audit
       ADD COLUMN IF NOT EXISTS credential_identity text NULL",
    "ALTER TABLE oxibelt_admin_audit
       ADD COLUMN IF NOT EXISTS credential_principal text NULL",
    "ALTER TABLE oxibelt_admin_audit
       ADD COLUMN IF NOT EXISTS authentication_reason text NULL",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_audit_ns_id_idx
       ON oxibelt_admin_audit (namespace, id DESC)",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_audit_request_id_idx
       ON oxibelt_admin_audit (namespace, request_id)",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_audit_actor_idx
       ON oxibelt_admin_audit (namespace, actor, id DESC)",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_audit_filter_idx
       ON oxibelt_admin_audit (namespace, service, operation, outcome, id DESC)",
  ] {
    sqlx::query(statement).execute(pool).await?;
  }
  Ok(())
}

pub(super) async fn run_database_writer(
  pool: Pool<Postgres>,
  namespace: String,
  mut receiver: mpsc::Receiver<AdminAuditEvent>,
) {
  while let Some(event) = receiver.recv().await {
    insert_record_with_retry(&pool, &namespace, &event).await;
  }
}

async fn insert_record_with_retry(pool: &Pool<Postgres>, namespace: &str, event: &AdminAuditEvent) {
  retry_insert_loop(
    || Box::pin(insert_record(pool, namespace, event)),
    |delay| Box::pin(tokio::time::sleep(delay)),
  )
  .await;
}

async fn retry_insert_loop<'a, A, S>(mut attempt: A, mut sleep: S)
where
  A: FnMut() -> AttemptFuture<'a>,
  S: FnMut(Duration) -> SleepFuture<'a>,
{
  let mut failures = 0_u32;
  loop {
    match attempt().await {
      Ok(()) => return,
      Err(error) => {
        let delay = retry_delay(failures);
        warn!(
          error = %error,
          retry_ms = delay.as_millis(),
          "failed to write admin audit record to PostgreSQL; retrying"
        );
        failures = failures.saturating_add(1);
        sleep(delay).await;
      }
    }
  }
}

fn retry_delay(failures: u32) -> Duration {
  let exponent = failures.min(6);
  let millis = 50_u64.saturating_mul(1_u64 << exponent);
  Duration::from_millis(millis.min(5_000))
}

async fn insert_record(
  pool: &Pool<Postgres>,
  namespace: &str,
  event: &AdminAuditEvent,
) -> anyhow::Result<()> {
  insert_record_returning_id(pool, namespace, event)
    .await
    .map(|_| ())
}

pub(super) async fn insert_record_returning_id(
  pool: &Pool<Postgres>,
  namespace: &str,
  event: &AdminAuditEvent,
) -> anyhow::Result<i64> {
  let request_summary = serde_json::to_string(&request::sanitize_summary_for_storage(
    &event.request_summary,
  ))?;
  let row = sqlx::query(
    "INSERT INTO oxibelt_admin_audit
       (namespace, request_id, actor, principal, subject, groups,
        workload_identity_kind, workload_identity, workload_principal,
        certificate_fingerprint_sha256, credential_kind, credential_identity,
        credential_principal, authentication_reason, peer, source_ip, scheme,
        method, path, service, operation, action, resource, target_kind, target_id,
        status, outcome, error, request_summary)
     VALUES
       ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
        $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29::jsonb)
     RETURNING id",
  )
  .bind(namespace)
  .bind(&event.request_id)
  .bind(&event.actor)
  .bind(&event.principal)
  .bind(&event.subject)
  .bind(&event.groups)
  .bind(&event.workload_identity_kind)
  .bind(&event.workload_identity)
  .bind(&event.workload_principal)
  .bind(&event.certificate_fingerprint_sha256)
  .bind(&event.credential_kind)
  .bind(&event.credential_identity)
  .bind(&event.credential_principal)
  .bind(&event.authentication_reason)
  .bind(&event.peer)
  .bind(&event.source_ip)
  .bind(event.scheme)
  .bind(&event.method)
  .bind(&event.path)
  .bind(&event.service)
  .bind(&event.operation)
  .bind(&event.action)
  .bind(&event.resource)
  .bind(&event.target_kind)
  .bind(&event.target_id)
  .bind(i32::from(event.status))
  .bind(&event.outcome)
  .bind(&event.error)
  .bind(request_summary)
  .fetch_one(pool)
  .await?;
  row.try_get("id").map_err(Into::into)
}

pub(super) async fn select_records(
  pool: &Pool<Postgres>,
  namespace: &str,
  query: AdminAuditQuery,
) -> anyhow::Result<Vec<AdminAuditRecord>> {
  let limit = if query.limit == 0 { 100 } else { query.limit };
  if !(1..=1000).contains(&limit) {
    bail!("limit must be between 1 and 1000");
  }
  let path_prefix = query.path_prefix.as_ref().map(|value| format!("{value}%"));
  let rows = sqlx::query(
    "SELECT id, namespace, request_id, actor, principal, subject, groups,
            workload_identity_kind, workload_identity, workload_principal,
            certificate_fingerprint_sha256, credential_kind, credential_identity,
            credential_principal, authentication_reason, peer, source_ip, scheme,
            method, path, service, operation, action, resource, target_kind, target_id,
            status, outcome, error, request_summary::text AS request_summary,
            created_at::text AS created_at
       FROM oxibelt_admin_audit
      WHERE namespace = $1
        AND ($2::text IS NULL OR outcome = $2)
        AND ($3::text IS NULL OR actor = $3)
        AND ($4::text IS NULL OR principal = $4)
        AND ($5::text IS NULL OR service = $5)
        AND ($6::text IS NULL OR operation = $6)
        AND ($7::text IS NULL OR request_id = $7)
        AND ($8::text IS NULL OR path LIKE $8)
        AND ($9::bigint IS NULL OR id < $9)
      ORDER BY id DESC
      LIMIT $10",
  )
  .bind(namespace)
  .bind(&query.outcome)
  .bind(&query.actor)
  .bind(&query.principal)
  .bind(&query.service)
  .bind(&query.operation)
  .bind(&query.request_id)
  .bind(&path_prefix)
  .bind(query.before_id)
  .bind(limit)
  .fetch_all(pool)
  .await?;
  rows.iter().map(record_from_row).collect()
}

fn record_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<AdminAuditRecord> {
  let request_summary: String = row.try_get("request_summary")?;
  Ok(AdminAuditRecord {
    id: row.try_get("id")?,
    namespace: row.try_get("namespace")?,
    request_id: row.try_get("request_id")?,
    actor: row.try_get("actor")?,
    principal: row.try_get("principal")?,
    subject: row.try_get("subject")?,
    groups: row.try_get("groups")?,
    workload_identity_kind: row.try_get("workload_identity_kind")?,
    workload_identity: row.try_get("workload_identity")?,
    workload_principal: row.try_get("workload_principal")?,
    certificate_fingerprint_sha256: row.try_get("certificate_fingerprint_sha256")?,
    credential_kind: row.try_get("credential_kind")?,
    credential_identity: row.try_get("credential_identity")?,
    credential_principal: row.try_get("credential_principal")?,
    authentication_reason: row.try_get("authentication_reason")?,
    peer: row.try_get("peer")?,
    source_ip: row.try_get("source_ip")?,
    scheme: row.try_get("scheme")?,
    method: row.try_get("method")?,
    path: row.try_get("path")?,
    service: row.try_get("service")?,
    operation: row.try_get("operation")?,
    action: row.try_get("action")?,
    resource: row.try_get("resource")?,
    target_kind: row.try_get("target_kind")?,
    target_id: row.try_get("target_id")?,
    status: row.try_get("status")?,
    outcome: row.try_get("outcome")?,
    error: row.try_get("error")?,
    request_summary: serde_json::from_str(&request_summary)
      .unwrap_or_else(|_| serde_json::json!({})),
    created_at: row.try_get("created_at")?,
  })
}

#[cfg(test)]
mod tests {
  use super::super::AdminAuditEvent;
  use super::*;
  use serde_json::json;
  use std::sync::{Arc, Mutex};

  #[test]
  fn retry_delay_is_bounded_exponential_backoff() {
    assert_eq!(retry_delay(0), Duration::from_millis(50));
    assert_eq!(retry_delay(1), Duration::from_millis(100));
    assert_eq!(retry_delay(6), Duration::from_millis(3_200));
    assert_eq!(retry_delay(100), Duration::from_millis(3_200));
  }

  #[test]
  fn storage_summary_sanitizes_nested_control_text_before_serializing() {
    let summary = json!({
      "outer\0": [
        "value\0",
        {
          "inner": "bad\u{1f}",
          "ok": true,
          "count": 7,
          "nothing": null,
        },
      ],
    });

    let sanitized = request::sanitize_summary_for_storage(&summary);

    assert_no_control_text(&sanitized);
    assert_eq!(sanitized["outer\\u0000"][0], "value\\u0000");
    assert_eq!(sanitized["outer\\u0000"][1]["inner"], "bad\\u001f");
    assert_eq!(sanitized["outer\\u0000"][1]["ok"], true);
    assert_eq!(sanitized["outer\\u0000"][1]["count"], 7);
    assert!(sanitized["outer\\u0000"][1]["nothing"].is_null());
    serde_json::to_string(&sanitized).expect("sanitized summary should serialize");
  }

  #[tokio::test]
  async fn retry_insert_loop_retries_same_event_until_success() {
    let event = AdminAuditEvent {
      request_id: "req-retry".to_string(),
      actor: None,
      principal: None,
      subject: None,
      groups: Vec::new(),
      workload_identity_kind: None,
      workload_identity: None,
      workload_principal: None,
      certificate_fingerprint_sha256: None,
      credential_kind: None,
      credential_identity: None,
      credential_principal: None,
      authentication_reason: None,
      peer: "127.0.0.1:12345".to_string(),
      source_ip: Some("127.0.0.1".to_string()),
      scheme: "http",
      method: "POST".to_string(),
      path: "/admin/v1/config/load".to_string(),
      service: Some("config".to_string()),
      operation: "post.config.load".to_string(),
      action: None,
      resource: None,
      target_kind: None,
      target_id: None,
      status: 503,
      outcome: "rejected".to_string(),
      error: Some("temporary insert failure".to_string()),
      request_summary: json!({"body": {"bytes": 2}}),
    };
    let event = Arc::new(event);
    let attempts = Arc::new(Mutex::new(Vec::new()));

    retry_insert_loop(
      || {
        let attempts = Arc::clone(&attempts);
        let event = Arc::clone(&event);
        Box::pin(async move {
          let mut attempts = attempts.lock().expect("attempts lock poisoned");
          attempts.push(event.request_id.clone());
          if attempts.len() == 1 {
            Err(anyhow::anyhow!("transient insert failure"))
          } else {
            Ok(())
          }
        })
      },
      |_delay| Box::pin(async {}),
    )
    .await;

    let attempts = attempts.lock().expect("attempts lock poisoned");
    assert_eq!(attempts.as_slice(), ["req-retry", "req-retry"]);
  }

  fn assert_no_control_text(value: &serde_json::Value) {
    match value {
      serde_json::Value::String(value) => {
        assert!(
          !value.chars().any(char::is_control),
          "string contains control character: {value:?}"
        );
      }
      serde_json::Value::Array(values) => {
        for value in values {
          assert_no_control_text(value);
        }
      }
      serde_json::Value::Object(values) => {
        for (key, value) in values {
          assert!(
            !key.chars().any(char::is_control),
            "key contains control character: {key:?}"
          );
          assert_no_control_text(value);
        }
      }
      _ => {}
    }
  }
}
