use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use sqlx::{Pool, Postgres, Row};
use tracing::{info, warn};

use crate::config::{
  AdminPermission, AdminRole, AdminTokenStoreConfig, Config, SharedStateBackendKind,
};

pub mod admin;
mod store;
mod token;
pub use admin::{AdminTokenAdminCreate, AdminTokenAdminPatch};

#[derive(Clone)]
pub struct AdminTokenRuntime {
  pub(crate) inner: Option<Arc<AdminTokenInner>>,
}

pub(crate) struct AdminTokenInner {
  config: AdminTokenStoreConfig,
  namespace: Arc<str>,
  pool: Pool<Postgres>,
  snapshot: RwLock<Arc<AdminTokenSnapshot>>,
  public_key: [u8; 32],
}

#[derive(Debug, Clone)]
struct AdminTokenSnapshot {
  generation: i64,
  fingerprint: u64,
  tokens: Arc<HashMap<String, AdminTokenRecord>>,
}

#[derive(Debug, Clone)]
struct AdminTokenRecord {
  token_id: String,
  subject: String,
  name: String,
  roles: Vec<AdminRole>,
  permissions: Vec<AdminPermission>,
  deny_permissions: Vec<AdminPermission>,
  expires_at_unix: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct VerifiedAdminToken {
  pub name: String,
  pub roles: Vec<AdminRole>,
  pub permissions: Vec<AdminPermission>,
  pub deny_permissions: Vec<AdminPermission>,
}

#[derive(Debug, Clone)]
struct TokenRow {
  token_id: String,
  subject: String,
  name: String,
  roles: Vec<String>,
  permissions: Vec<String>,
  deny_permissions: Vec<String>,
  expires_at_unix: Option<i64>,
}

impl AdminTokenRuntime {
  pub async fn new(config: &Config) -> anyhow::Result<Self> {
    if !config.admin.token_store.enabled {
      return Ok(Self::disabled());
    }

    let Some(backend_name) = config.admin_tokens_backend_name() else {
      bail!("admin token store backend is not configured");
    };
    let backend = config
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == backend_name)
      .ok_or_else(|| anyhow!("admin token store backend {backend_name} was not found"))?;
    if backend.kind != SharedStateBackendKind::Postgres {
      bail!("admin token store backend {backend_name} must use kind = \"postgres\"");
    }

    let public_key = crate::config::load_public_key(&config.admin.token_store.public_key_env)?;
    let namespace = Arc::from(config.shared_state.namespace.as_str());
    let pool = match store::connect_postgres_pool(backend).await {
      Ok(pool) => pool,
      Err(error) if !config.admin.token_store.fail_closed => {
        warn!(error = %error, "admin token PostgreSQL connection failed; starting with admin token store disabled");
        return Ok(Self::disabled());
      }
      Err(error) => return Err(error).context("failed to connect admin token PostgreSQL backend"),
    };
    store::init_postgres(&pool)
      .await
      .context("failed to initialize admin token PostgreSQL tables")?;
    let snapshot = match load_snapshot(&pool, &namespace).await {
      Ok(snapshot) => snapshot,
      Err(error) if !config.admin.token_store.fail_closed => {
        warn!(error = %error, "admin token startup load failed; starting with empty snapshot");
        AdminTokenSnapshot::empty()
      }
      Err(error) => return Err(error).context("failed to load initial admin token snapshot"),
    };

    let inner = Arc::new(AdminTokenInner {
      config: config.admin.token_store.clone(),
      namespace,
      pool,
      snapshot: RwLock::new(Arc::new(snapshot)),
      public_key,
    });
    spawn_refresh_task(&inner);
    Ok(Self { inner: Some(inner) })
  }

  pub fn disabled() -> Self {
    Self { inner: None }
  }

  pub fn enabled(&self) -> bool {
    self.inner.is_some()
  }

  pub fn verify_bearer(&self, bearer: &str) -> Option<VerifiedAdminToken> {
    let inner = self.inner.as_ref()?;
    let now = now_unix().ok()?;
    let claims = token::verify_bearer_token(&inner.config, &inner.public_key, bearer, now).ok()?;
    let snapshot = inner.snapshot()?;
    let record = snapshot.tokens.get(&claims.token_id)?;
    if record.subject != claims.subject {
      return None;
    }
    if let Some(expires_at) = record.expires_at_unix
      && expires_at <= now
    {
      return None;
    }
    if claims.expires_at <= now {
      return None;
    }
    Some(VerifiedAdminToken {
      name: record.name.clone(),
      roles: record.roles.clone(),
      permissions: record.permissions.clone(),
      deny_permissions: record.deny_permissions.clone(),
    })
  }

  #[cfg(test)]
  fn test_with_snapshot(
    config: AdminTokenStoreConfig,
    record: AdminTokenRecord,
    public_key: [u8; 32],
  ) -> Self {
    let mut tokens = HashMap::new();
    tokens.insert(record.token_id.clone(), record);
    Self {
      inner: Some(Arc::new(AdminTokenInner {
        config,
        namespace: Arc::from("test"),
        pool: Pool::<Postgres>::connect_lazy("postgres://localhost/test")
          .expect("test PostgreSQL URL should parse"),
        snapshot: RwLock::new(Arc::new(AdminTokenSnapshot {
          generation: 0,
          fingerprint: 0,
          tokens: Arc::new(tokens),
        })),
        public_key,
      })),
    }
  }
}

impl AdminTokenInner {
  fn snapshot(&self) -> Option<Arc<AdminTokenSnapshot>> {
    self.snapshot.read().ok().map(|snapshot| snapshot.clone())
  }

  fn replace_snapshot(&self, snapshot: AdminTokenSnapshot) {
    if let Ok(mut current) = self.snapshot.write() {
      *current = Arc::new(snapshot);
    }
  }
}

impl AdminTokenSnapshot {
  fn empty() -> Self {
    Self {
      generation: 0,
      fingerprint: 0,
      tokens: Arc::new(HashMap::new()),
    }
  }
}

fn spawn_refresh_task(inner: &Arc<AdminTokenInner>) {
  let weak = Arc::downgrade(inner);
  let interval = Duration::from_millis(inner.config.snapshot_refresh_interval_ms);
  tokio::spawn(async move {
    refresh_loop(weak, interval).await;
  });
}

async fn refresh_loop(inner: Weak<AdminTokenInner>, interval: Duration) {
  loop {
    tokio::time::sleep(interval).await;
    let Some(inner) = inner.upgrade() else {
      break;
    };
    match load_snapshot(&inner.pool, &inner.namespace).await {
      Ok(snapshot) => {
        let should_replace = inner.snapshot().is_none_or(|current| {
          snapshot.generation != current.generation || snapshot.fingerprint != current.fingerprint
        });
        if should_replace {
          inner.replace_snapshot(snapshot);
          info!("admin token snapshot refreshed");
        }
      }
      Err(error) => {
        warn!(error = %error, "failed to refresh admin token snapshot");
      }
    }
  }
}

async fn load_snapshot(
  pool: &Pool<Postgres>,
  namespace: &str,
) -> anyhow::Result<AdminTokenSnapshot> {
  let generation = load_generation(pool, namespace).await?;
  let rows = sqlx::query(
    "SELECT token_id, subject, name, roles, permissions, deny_permissions,
            EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix
       FROM oxibelt_admin_tokens
      WHERE namespace = $1
        AND enabled = true
        AND revoked = false
        AND (expires_at IS NULL OR expires_at > now())
      ORDER BY token_id ASC",
  )
  .bind(namespace)
  .fetch_all(pool)
  .await?;

  let mut hasher = std::collections::hash_map::DefaultHasher::new();
  generation.hash(&mut hasher);
  let mut tokens = HashMap::with_capacity(rows.len());
  for row in rows {
    let row = token_row_from_pg(&row)?;
    hash_token_row(&row, &mut hasher);
    let record = validate_token_row(row)?;
    tokens.insert(record.token_id.clone(), record);
  }
  Ok(AdminTokenSnapshot {
    generation,
    fingerprint: hasher.finish(),
    tokens: Arc::new(tokens),
  })
}

fn token_row_from_pg(row: &sqlx::postgres::PgRow) -> anyhow::Result<TokenRow> {
  Ok(TokenRow {
    token_id: row.try_get("token_id")?,
    subject: row.try_get("subject")?,
    name: row.try_get("name")?,
    roles: row.try_get("roles")?,
    permissions: row.try_get("permissions")?,
    deny_permissions: row.try_get("deny_permissions")?,
    expires_at_unix: row.try_get("expires_at_unix")?,
  })
}

fn hash_token_row(row: &TokenRow, hasher: &mut impl Hasher) {
  row.token_id.hash(hasher);
  row.subject.hash(hasher);
  row.name.hash(hasher);
  row.roles.hash(hasher);
  row.permissions.hash(hasher);
  row.deny_permissions.hash(hasher);
  row.expires_at_unix.hash(hasher);
}

fn validate_token_row(row: TokenRow) -> anyhow::Result<AdminTokenRecord> {
  crate::config::validate_runtime_identifier("admin token token_id", &row.token_id)?;
  if row.subject.trim().is_empty() || row.name.trim().is_empty() {
    bail!(
      "admin token {} subject and name must not be empty",
      row.token_id
    );
  }
  let roles = row
    .roles
    .iter()
    .map(|role| role.parse())
    .collect::<anyhow::Result<Vec<AdminRole>>>()?;
  let permissions = row
    .permissions
    .iter()
    .map(|permission| permission.parse())
    .collect::<anyhow::Result<Vec<AdminPermission>>>()?;
  let deny_permissions = row
    .deny_permissions
    .iter()
    .map(|permission| permission.parse())
    .collect::<anyhow::Result<Vec<AdminPermission>>>()?;
  if roles.is_empty() && permissions.is_empty() {
    bail!(
      "admin token {} must include at least one role or permission",
      row.token_id
    );
  }
  Ok(AdminTokenRecord {
    token_id: row.token_id,
    subject: row.subject,
    name: row.name,
    roles,
    permissions,
    deny_permissions,
    expires_at_unix: row.expires_at_unix,
  })
}

async fn load_generation(pool: &Pool<Postgres>, namespace: &str) -> anyhow::Result<i64> {
  let generation: Option<i64> = sqlx::query_scalar(
    "SELECT generation FROM oxibelt_admin_token_generation WHERE namespace = $1",
  )
  .bind(namespace)
  .fetch_optional(pool)
  .await?;
  Ok(generation.unwrap_or(0))
}

fn now_unix() -> anyhow::Result<i64> {
  let duration = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .context("system clock is before UNIX epoch")?;
  i64::try_from(duration.as_secs()).context("system time does not fit in i64")
}

pub(crate) fn base64_url_no_pad(bytes: &[u8]) -> String {
  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
  use super::*;
  use ring::rand::SystemRandom;
  use ring::signature::{Ed25519KeyPair, KeyPair};

  fn test_config() -> AdminTokenStoreConfig {
    AdminTokenStoreConfig {
      enabled: true,
      issuer: "issuer".to_string(),
      audience: "audience".to_string(),
      token_ttl_seconds: 60,
      ..AdminTokenStoreConfig::default()
    }
  }

  fn key_pair() -> Ed25519KeyPair {
    let pkcs8 =
      Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("test keypair should generate");
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("test keypair should parse")
  }

  #[tokio::test]
  async fn signed_token_uses_snapshot_authorization() {
    let key_pair = key_pair();
    let config = test_config();
    let now = now_unix().expect("system clock should be valid");
    let token = token::sign_for_tests(
      &key_pair,
      &config.issuer,
      &config.audience,
      "operator",
      "token-1",
      now - 10,
      now + 50,
    )
    .expect("token should sign");
    let runtime = AdminTokenRuntime::test_with_snapshot(
      config,
      AdminTokenRecord {
        token_id: "token-1".to_string(),
        subject: "operator".to_string(),
        name: "operator-token".to_string(),
        roles: vec![AdminRole::Viewer],
        permissions: vec![AdminPermission::AdminTokensRead],
        deny_permissions: Vec::new(),
        expires_at_unix: None,
      },
      key_pair
        .public_key()
        .as_ref()
        .try_into()
        .expect("public key length"),
    );

    let actor = runtime
      .verify_bearer(&token)
      .expect("signed token should verify");
    assert_eq!(actor.name, "operator-token");
    assert_eq!(actor.roles, vec![AdminRole::Viewer]);
    assert_eq!(actor.permissions, vec![AdminPermission::AdminTokensRead]);
  }

  #[tokio::test]
  async fn unknown_or_bad_signature_tokens_fail_closed() {
    let verifier_key_pair = key_pair();
    let signer_key_pair = key_pair();
    let config = test_config();
    let now = now_unix().expect("system clock should be valid");
    let token = token::sign_for_tests(
      &signer_key_pair,
      &config.issuer,
      &config.audience,
      "operator",
      "token-1",
      now - 10,
      now + 50,
    )
    .expect("token should sign");
    let runtime = AdminTokenRuntime::test_with_snapshot(
      config,
      AdminTokenRecord {
        token_id: "token-1".to_string(),
        subject: "operator".to_string(),
        name: "operator-token".to_string(),
        roles: vec![AdminRole::Viewer],
        permissions: Vec::new(),
        deny_permissions: Vec::new(),
        expires_at_unix: None,
      },
      verifier_key_pair
        .public_key()
        .as_ref()
        .try_into()
        .expect("public key length"),
    );

    assert!(runtime.verify_bearer(&token).is_none());
    assert!(runtime.verify_bearer("not.a.valid.token").is_none());
  }
}
