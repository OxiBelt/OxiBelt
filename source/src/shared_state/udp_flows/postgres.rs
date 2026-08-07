//! PostgreSQL durable UDP-flow transitions.
//!
//! Every mutation uses database time and a scope-row lock. The scope row owns
//! capacity, fencing, and new-flow admission, so a flow insert and its token
//! debit commit or roll back together.

use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row, Transaction};

use super::*;

pub(in crate::shared_state) async fn init_postgres_udp_flows(
  tx: &mut Transaction<'_, Postgres>,
) -> anyhow::Result<()> {
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_udp_flow_scopes (
       namespace text NOT NULL,
       scope_digest bytea NOT NULL CHECK (octet_length(scope_digest) = 32),
       record_version smallint NOT NULL CHECK (record_version = 1),
       config_generation bytea NOT NULL CHECK (octet_length(config_generation) = 32),
       max_flows bigint NOT NULL CHECK (max_flows > 0 AND max_flows <= 1048576),
       active_flows bigint NOT NULL CHECK (active_flows >= 0 AND active_flows <= max_flows),
       next_fence bigint NOT NULL CHECK (next_fence >= 0 AND next_fence <= 9007199254740991),
       new_flow_rate_micros_per_second bigint NULL,
       new_flow_burst bigint NULL,
       new_flow_token_balance_micros bigint NULL,
       new_flow_token_refill_at_ms bigint NULL,
       updated_at_ms bigint NOT NULL,
       PRIMARY KEY (namespace, scope_digest),
       CHECK (
         (new_flow_rate_micros_per_second IS NULL
          AND new_flow_burst IS NULL
          AND new_flow_token_balance_micros IS NULL
          AND new_flow_token_refill_at_ms IS NULL)
         OR
         (new_flow_rate_micros_per_second > 0
          AND new_flow_rate_micros_per_second <= 1048576000000
          AND new_flow_burst > 0
          AND new_flow_burst <= 1048576
          AND new_flow_token_balance_micros >= 0
          AND new_flow_token_balance_micros <= new_flow_burst * 1000000
          AND new_flow_token_refill_at_ms >= 0)
       )
     )",
  )
  .execute(&mut **tx)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_udp_flows (
       namespace text NOT NULL,
       scope_digest bytea NOT NULL CHECK (octet_length(scope_digest) = 32),
       flow_digest bytea NOT NULL CHECK (octet_length(flow_digest) = 32),
       record_version smallint NOT NULL CHECK (record_version = 1),
       config_generation bytea NOT NULL CHECK (octet_length(config_generation) = 32),
       route_digest bytea NOT NULL CHECK (octet_length(route_digest) = 32),
       target_digest bytea NOT NULL CHECK (octet_length(target_digest) = 32),
       owner_digest bytea NOT NULL CHECK (octet_length(owner_digest) = 32),
       owner_generation bytea NOT NULL CHECK (octet_length(owner_generation) = 32),
       fence bigint NOT NULL CHECK (fence > 0 AND fence <= 9007199254740991),
       owner_expires_at_ms bigint NOT NULL CHECK (owner_expires_at_ms >= 0),
       idle_expires_at_ms bigint NOT NULL CHECK (idle_expires_at_ms >= owner_expires_at_ms),
       token_balance_micros bigint NOT NULL CHECK (
         token_balance_micros >= 0 AND token_balance_micros <= 1048576000000
       ),
       token_refill_at_ms bigint NOT NULL CHECK (token_refill_at_ms >= 0),
       PRIMARY KEY (namespace, scope_digest, flow_digest),
       FOREIGN KEY (namespace, scope_digest)
         REFERENCES oxibelt_udp_flow_scopes (namespace, scope_digest)
         ON DELETE CASCADE
     )",
  )
  .execute(&mut **tx)
  .await?;
  sqlx::query(
    "CREATE INDEX IF NOT EXISTS oxibelt_udp_flows_expiry
     ON oxibelt_udp_flows (namespace, scope_digest, idle_expires_at_ms, flow_digest)",
  )
  .execute(&mut **tx)
  .await?;
  Ok(())
}

#[derive(Debug)]
struct PostgresScope {
  max_flows: usize,
  active_flows: usize,
  next_fence: u64,
  new_flow_rate: Option<UdpFlowRateLimit>,
  new_flow_token_balance_micros: u64,
  new_flow_token_refill_at_ms: i64,
}

impl PostgresScope {
  fn from_row(row: &PgRow) -> anyhow::Result<Self> {
    let version: i16 = row.try_get("record_version")?;
    if version != i16::from(UDP_FLOW_RECORD_VERSION) {
      bail!("unsupported durable UDP flow scope record version {version}");
    }
    let rate = row.try_get::<Option<i64>, _>("new_flow_rate_micros_per_second")?;
    let burst = row.try_get::<Option<i64>, _>("new_flow_burst")?;
    let balance = row.try_get::<Option<i64>, _>("new_flow_token_balance_micros")?;
    let refill_at = row.try_get::<Option<i64>, _>("new_flow_token_refill_at_ms")?;
    let (new_flow_rate, new_flow_token_balance_micros, new_flow_token_refill_at_ms) =
      match (rate, burst, balance, refill_at) {
        (None, None, None, None) => (None, 0, 0),
        (Some(rate), Some(burst), Some(balance), Some(refill_at)) => {
          let rate = UdpFlowRateLimit {
            refill_micros_per_second: positive_u64(rate, "new-flow refill rate")?,
            burst: positive_u32(burst, "new-flow burst")?,
          };
          validate_rate_limit(rate, "stored durable UDP new-flow")?;
          (
            Some(rate),
            nonnegative_u64(balance, "new-flow token balance")?,
            nonnegative_i64(refill_at, "new-flow refill timestamp")?,
          )
        }
        _ => bail!("durable UDP flow scope has incomplete new-flow token state"),
      };
    // Retain and validate the original scope field for storage compatibility,
    // but keep routing authorization on each flow record.
    let _legacy_generation =
      digest_from_bytes(row.try_get("config_generation")?, "config_generation")?;
    let scope = Self {
      max_flows: positive_usize(row.try_get("max_flows")?, "max_flows")?,
      active_flows: nonnegative_usize(row.try_get("active_flows")?, "active_flows")?,
      next_fence: nonnegative_u64(row.try_get("next_fence")?, "next_fence")?,
      new_flow_rate,
      new_flow_token_balance_micros,
      new_flow_token_refill_at_ms,
    };
    if scope.active_flows > scope.max_flows
      || scope.next_fence > MAX_EXACT_BACKEND_INTEGER
      || scope
        .new_flow_rate
        .is_some_and(|rate| scope.new_flow_token_balance_micros > initial_token_micros(rate.burst))
    {
      bail!("durable UDP flow scope contains values outside supported bounds");
    }
    Ok(scope)
  }

  fn configuration_matches(&self, request: &UdpFlowClaimRequest) -> bool {
    udp_flow_scope_configuration_matches(self.max_flows, self.new_flow_rate, request)
  }

  fn reconfigure(&mut self, request: &UdpFlowClaimRequest, now: i64) {
    self.max_flows = request.max_flows;
    self.new_flow_rate = request.new_flow_rate;
    self.new_flow_token_balance_micros = request
      .new_flow_rate
      .map(|rate| initial_token_micros(rate.burst))
      .unwrap_or(0);
    self.new_flow_token_refill_at_ms = request.new_flow_rate.map(|_| now).unwrap_or(0);
  }

  fn next_fence(&mut self) -> anyhow::Result<u64> {
    let next = self.peek_next_fence()?;
    self.next_fence = next;
    Ok(next)
  }

  fn peek_next_fence(&self) -> anyhow::Result<u64> {
    self
      .next_fence
      .checked_add(1)
      .filter(|value| *value <= MAX_EXACT_BACKEND_INTEGER)
      .ok_or_else(|| anyhow!("durable UDP flow fence space exhausted"))
  }

  fn take_new_flow_token(&mut self, now: i64) -> Option<u64> {
    let rate = self.new_flow_rate?;
    self.new_flow_token_balance_micros = refill_balance(
      self.new_flow_token_balance_micros,
      self.new_flow_token_refill_at_ms,
      now,
      rate,
    );
    self.new_flow_token_refill_at_ms = now;
    if self.new_flow_token_balance_micros < TOKEN_MICROS {
      return Some(retry_after_ms(
        TOKEN_MICROS.saturating_sub(self.new_flow_token_balance_micros),
        rate.refill_micros_per_second,
      ));
    }
    self.new_flow_token_balance_micros -= TOKEN_MICROS;
    None
  }
}

impl PostgresBackend {
  pub(super) async fn udp_flow_lookup(
    &self,
    namespace: &str,
    identity: &UdpFlowIdentity,
    generation: UdpFlowGeneration,
  ) -> anyhow::Result<UdpFlowLookupOutcome> {
    let mut tx = self.pool.begin().await?;
    let now = postgres_now(&mut tx).await?;
    let row = select_flow(&mut tx, namespace, identity, false).await?;
    let outcome = match row {
      None => UdpFlowLookupOutcome::Missing { server_now_ms: now },
      Some(row) => {
        let record = stored_from_row(identity, &row)?;
        if record.idle_expires_at_ms <= now {
          UdpFlowLookupOutcome::Missing { server_now_ms: now }
        } else if record.generation != generation {
          UdpFlowLookupOutcome::GenerationMismatch { server_now_ms: now }
        } else {
          record.validate(now)?;
          UdpFlowLookupOutcome::Found(record.record(now))
        }
      }
    };
    tx.commit().await?;
    Ok(outcome)
  }

  pub(super) async fn udp_flow_claim(
    &self,
    namespace: &str,
    request: &UdpFlowClaimRequest,
  ) -> anyhow::Result<UdpFlowClaimOutcome> {
    let mut tx = self.pool.begin().await?;
    let now = postgres_now(&mut tx).await?;
    insert_scope_if_missing(&mut tx, namespace, request, now).await?;
    let mut scope = lock_scope(&mut tx, namespace, request.identity.scope).await?;
    let deleted = collect_expired(&mut tx, namespace, request.identity.scope, now).await?;
    scope.active_flows = scope.active_flows.checked_sub(deleted).ok_or_else(|| {
      anyhow!("durable UDP flow scope active count underflow during bounded collection")
    })?;

    if !scope.configuration_matches(request) {
      if scope.active_flows != 0 {
        write_scope(&mut tx, namespace, request.identity.scope, &scope, now).await?;
        tx.commit().await?;
        return Ok(UdpFlowClaimOutcome::GenerationMismatch { server_now_ms: now });
      }
      scope.reconfigure(request, now);
    }

    if let Some(row) = select_flow(&mut tx, namespace, &request.identity, true).await? {
      let mut record = stored_from_row(&request.identity, &row)?;
      if record.idle_expires_at_ms <= now {
        delete_flow(&mut tx, namespace, &request.identity).await?;
        scope.active_flows = scope.active_flows.checked_sub(1).ok_or_else(|| {
          anyhow!("durable UDP flow scope active count underflow deleting target")
        })?;
      } else {
        record.validate(now)?;
        if record.generation != request.generation {
          write_scope(&mut tx, namespace, request.identity.scope, &scope, now).await?;
          tx.commit().await?;
          return Ok(UdpFlowClaimOutcome::GenerationMismatch { server_now_ms: now });
        }
        if record.owner_expires_at_ms > now && record.owner != request.owner {
          let retry_after_ms =
            u64::try_from(record.owner_expires_at_ms.saturating_sub(now)).unwrap_or(u64::MAX);
          write_scope(&mut tx, namespace, request.identity.scope, &scope, now).await?;
          tx.commit().await?;
          return Ok(UdpFlowClaimOutcome::Busy {
            record: record.record(now),
            retry_after_ms,
          });
        }
        let was_owned = record.owner_expires_at_ms > now && record.owner == request.owner;
        if !was_owned {
          record.owner = request.owner.clone();
          record.fence = scope.next_fence()?;
        }
        record.owner_expires_at_ms = deadline(now, request.owner_ttl)?;
        record.idle_expires_at_ms = deadline(now, request.idle_ttl)?;
        record.validate(now)?;
        update_claimed_flow(&mut tx, namespace, &record).await?;
        write_scope(&mut tx, namespace, request.identity.scope, &scope, now).await?;
        tx.commit().await?;
        return Ok(if was_owned {
          UdpFlowClaimOutcome::Owned(record.lease(now))
        } else {
          UdpFlowClaimOutcome::Recovered(record.lease(now))
        });
      }
    }

    if scope.active_flows >= scope.max_flows {
      write_scope(&mut tx, namespace, request.identity.scope, &scope, now).await?;
      tx.commit().await?;
      return Ok(UdpFlowClaimOutcome::CapacityReached { server_now_ms: now });
    }

    let fence = scope.peek_next_fence()?;
    if let Some(retry_after_ms) = scope.take_new_flow_token(now) {
      write_scope(&mut tx, namespace, request.identity.scope, &scope, now).await?;
      tx.commit().await?;
      return Ok(UdpFlowClaimOutcome::RateLimited {
        retry_after_ms,
        server_now_ms: now,
      });
    }
    scope.next_fence = fence;
    let record = stored_from_claim(request, now, fence)?;
    record.validate(now)?;
    insert_flow(&mut tx, namespace, &record).await?;
    scope.active_flows = scope
      .active_flows
      .checked_add(1)
      .filter(|active| *active <= scope.max_flows)
      .ok_or_else(|| anyhow!("durable UDP flow scope active count overflow"))?;
    write_scope(&mut tx, namespace, request.identity.scope, &scope, now).await?;
    tx.commit().await?;
    Ok(UdpFlowClaimOutcome::Created(record.lease(now)))
  }

  pub(super) async fn udp_flow_touch_batch(
    &self,
    namespace: &str,
    requests: &[UdpFlowTouchRequest],
  ) -> anyhow::Result<Vec<UdpFlowTouchOutcome>> {
    if requests.is_empty() || requests.len() > MAX_UDP_FLOW_BATCH {
      bail!("PostgreSQL durable UDP flow touch batch must contain 1-{MAX_UDP_FLOW_BATCH} records");
    }
    let payload = postgres_touch_payload(requests)?;
    let mut tx = self.pool.begin().await?;
    let rows = sqlx::query(
      "WITH server_time AS MATERIALIZED (
         SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint AS now_ms
       ),
       raw_input AS MATERIALIZED (
         SELECT *
         FROM jsonb_to_recordset($2::jsonb) AS item(
           ordinal bigint,
           scope_hex text,
           flow_hex text,
           generation_hex text,
           owner_hex text,
           owner_generation_hex text,
           fence bigint,
           owner_ttl_ms bigint,
           idle_ttl_ms bigint,
           touch_idle boolean
         )
       ),
       input AS MATERIALIZED (
         SELECT ordinal,
                decode(scope_hex, 'hex') AS scope_digest,
                decode(flow_hex, 'hex') AS flow_digest,
                decode(generation_hex, 'hex') AS requested_generation,
                decode(owner_hex, 'hex') AS requested_owner,
                decode(owner_generation_hex, 'hex') AS requested_owner_generation,
                fence AS requested_fence,
                owner_ttl_ms,
                idle_ttl_ms,
                touch_idle
         FROM raw_input
       ),
       locked AS MATERIALIZED (
         SELECT input.*,
                flow.flow_digest IS NOT NULL AS found,
                flow.record_version AS stored_record_version,
                flow.config_generation AS stored_generation,
                flow.owner_digest AS stored_owner,
                flow.owner_generation AS stored_owner_generation,
                flow.fence AS stored_fence,
                flow.owner_expires_at_ms AS stored_owner_expires_at_ms,
                flow.idle_expires_at_ms AS stored_idle_expires_at_ms
         FROM input
         LEFT JOIN LATERAL (
           SELECT record_version, config_generation, owner_digest, owner_generation,
                  fence, owner_expires_at_ms, idle_expires_at_ms, flow_digest
           FROM oxibelt_udp_flows
           WHERE namespace = $1
             AND scope_digest = input.scope_digest
             AND flow_digest = input.flow_digest
           FOR UPDATE
         ) AS flow ON TRUE
       ),
       updated AS (
         UPDATE oxibelt_udp_flows AS flow
         SET owner_expires_at_ms = LEAST(
               server_time.now_ms + locked.owner_ttl_ms,
               CASE
                 WHEN locked.touch_idle
                   THEN server_time.now_ms + locked.idle_ttl_ms
                 ELSE flow.idle_expires_at_ms
               END
             ),
             idle_expires_at_ms = CASE
               WHEN locked.touch_idle
                 THEN server_time.now_ms + locked.idle_ttl_ms
               ELSE flow.idle_expires_at_ms
             END
         FROM locked
         CROSS JOIN server_time
         WHERE flow.namespace = $1
           AND flow.scope_digest = locked.scope_digest
           AND flow.flow_digest = locked.flow_digest
           AND locked.found
           AND locked.stored_record_version = $3
           AND locked.stored_generation = locked.requested_generation
           AND locked.stored_idle_expires_at_ms > server_time.now_ms
           AND locked.stored_owner_expires_at_ms > server_time.now_ms
           AND locked.stored_owner = locked.requested_owner
           AND locked.stored_owner_generation = locked.requested_owner_generation
           AND locked.stored_fence = locked.requested_fence
         RETURNING flow.scope_digest AS updated_scope_digest,
                   flow.flow_digest AS updated_flow_digest,
                   flow.record_version,
                   flow.config_generation,
                   flow.route_digest,
                   flow.target_digest,
                   flow.owner_digest,
                   flow.owner_generation,
                   flow.fence,
                   flow.owner_expires_at_ms,
                   flow.idle_expires_at_ms,
                   flow.token_balance_micros,
                   flow.token_refill_at_ms
       )
       SELECT locked.ordinal,
              server_time.now_ms AS server_now_ms,
              CASE
                WHEN NOT locked.found THEN 'lost'
                WHEN locked.stored_record_version <> $3 THEN 'error'
                WHEN locked.stored_generation <> locked.requested_generation
                  THEN 'generation_mismatch'
                WHEN locked.stored_idle_expires_at_ms <= server_time.now_ms
                  OR locked.stored_owner_expires_at_ms <= server_time.now_ms
                  OR locked.stored_owner <> locked.requested_owner
                  OR locked.stored_owner_generation <> locked.requested_owner_generation
                  OR locked.stored_fence <> locked.requested_fence
                  THEN 'lost'
                WHEN updated.updated_flow_digest IS NOT NULL THEN 'renewed'
                ELSE 'error'
              END AS outcome,
              updated.record_version,
              updated.config_generation,
              updated.route_digest,
              updated.target_digest,
              updated.owner_digest,
              updated.owner_generation,
              updated.fence,
              updated.owner_expires_at_ms,
              updated.idle_expires_at_ms,
              updated.token_balance_micros,
              updated.token_refill_at_ms
       FROM locked
       CROSS JOIN server_time
       LEFT JOIN updated
         ON updated.updated_scope_digest = locked.scope_digest
        AND updated.updated_flow_digest = locked.flow_digest
       ORDER BY locked.ordinal",
    )
    .bind(namespace)
    .bind(payload)
    .bind(i16::from(UDP_FLOW_RECORD_VERSION))
    .fetch_all(&mut *tx)
    .await?;
    let outcomes = match postgres_touch_outcomes(&rows, requests) {
      Ok(outcomes) => outcomes,
      Err(error) => {
        tx.rollback().await?;
        return Err(error);
      }
    };
    if outcomes.len() != requests.len() {
      tx.rollback().await?;
      bail!("PostgreSQL durable UDP flow touch batch omitted an outcome");
    }
    tx.commit().await?;
    Ok(outcomes)
  }

  pub(super) async fn udp_flow_tokens(
    &self,
    namespace: &str,
    request: &UdpFlowTokenRequest,
  ) -> anyhow::Result<UdpFlowTokenOutcome> {
    let mut tx = self.pool.begin().await?;
    let now = postgres_now(&mut tx).await?;
    let Some(row) = select_flow(&mut tx, namespace, request.lease.identity(), true).await? else {
      tx.commit().await?;
      return Ok(UdpFlowTokenOutcome::Lost { server_now_ms: now });
    };
    let mut record = stored_from_row(request.lease.identity(), &row)?;
    if record.generation != request.lease.generation() {
      tx.commit().await?;
      return Ok(UdpFlowTokenOutcome::GenerationMismatch { server_now_ms: now });
    }
    if record.idle_expires_at_ms <= now
      || record.owner_expires_at_ms <= now
      || !lease_owns(&record, &request.lease)
    {
      tx.commit().await?;
      return Ok(UdpFlowTokenOutcome::Lost { server_now_ms: now });
    }
    let rate = UdpFlowRateLimit {
      refill_micros_per_second: request.refill_micros_per_second,
      burst: request.burst,
    };
    record.token_balance_micros = refill_balance(
      record.token_balance_micros,
      record.token_refill_at_ms,
      now,
      rate,
    );
    record.token_refill_at_ms = now;
    let granted_tokens =
      take_available_tokens(&mut record.token_balance_micros, request.requested_tokens);
    let outcome = if granted_tokens > 0 {
      UdpFlowTokenOutcome::Granted {
        tokens: granted_tokens,
        server_now_ms: now,
      }
    } else {
      UdpFlowTokenOutcome::RateLimited {
        retry_after_ms: retry_after_ms(
          TOKEN_MICROS.saturating_sub(record.token_balance_micros),
          request.refill_micros_per_second,
        ),
        server_now_ms: now,
      }
    };
    update_flow_tokens(&mut tx, namespace, &record).await?;
    tx.commit().await?;
    Ok(outcome)
  }

  pub(super) async fn udp_flow_release(
    &self,
    namespace: &str,
    lease: &UdpFlowLease,
  ) -> anyhow::Result<UdpFlowReleaseOutcome> {
    let mut tx = self.pool.begin().await?;
    let now = postgres_now(&mut tx).await?;
    let Some(row) = select_flow(&mut tx, namespace, lease.identity(), true).await? else {
      tx.commit().await?;
      return Ok(UdpFlowReleaseOutcome::Missing { server_now_ms: now });
    };
    let mut record = stored_from_row(lease.identity(), &row)?;
    if record.generation != lease.generation() {
      tx.commit().await?;
      return Ok(UdpFlowReleaseOutcome::GenerationMismatch { server_now_ms: now });
    }
    if !lease_owns(&record, lease) {
      tx.commit().await?;
      return Ok(UdpFlowReleaseOutcome::Lost { server_now_ms: now });
    }
    record.owner_expires_at_ms = now.min(record.idle_expires_at_ms);
    record.validate(now)?;
    update_claimed_flow(&mut tx, namespace, &record).await?;
    tx.commit().await?;
    Ok(UdpFlowReleaseOutcome::Released { server_now_ms: now })
  }

  pub(super) async fn udp_flow_abort_created(
    &self,
    namespace: &str,
    lease: &UdpFlowLease,
  ) -> anyhow::Result<UdpFlowAbortOutcome> {
    let mut tx = self.pool.begin().await?;
    let now = postgres_now(&mut tx).await?;
    let Some(mut scope) = lock_scope_optional(&mut tx, namespace, lease.identity().scope).await?
    else {
      tx.commit().await?;
      return Ok(UdpFlowAbortOutcome::Missing { server_now_ms: now });
    };
    let Some(row) = select_flow(&mut tx, namespace, lease.identity(), true).await? else {
      tx.commit().await?;
      return Ok(UdpFlowAbortOutcome::Missing { server_now_ms: now });
    };
    let record = stored_from_row(lease.identity(), &row)?;
    record.validate(now)?;
    if record.generation != lease.generation() {
      tx.commit().await?;
      return Ok(UdpFlowAbortOutcome::GenerationMismatch { server_now_ms: now });
    }
    if !lease_owns(&record, lease) {
      tx.commit().await?;
      return Ok(UdpFlowAbortOutcome::Lost { server_now_ms: now });
    }
    delete_flow(&mut tx, namespace, lease.identity()).await?;
    scope.active_flows = scope
      .active_flows
      .checked_sub(1)
      .ok_or_else(|| anyhow!("durable UDP flow scope active count underflow during abort"))?;
    write_scope(&mut tx, namespace, lease.identity().scope, &scope, now).await?;
    tx.commit().await?;
    Ok(UdpFlowAbortOutcome::Aborted { server_now_ms: now })
  }
}

pub(super) fn postgres_touch_payload(requests: &[UdpFlowTouchRequest]) -> anyhow::Result<String> {
  let items = requests
    .iter()
    .enumerate()
    .map(|(ordinal, request)| {
      let identity = request.lease.identity();
      Ok(serde_json::json!({
        "ordinal": i64::try_from(ordinal)?,
        "scope_hex": identity.scope.hex(),
        "flow_hex": identity.flow.hex(),
        "generation_hex": request.lease.generation().0.hex(),
        "owner_hex": request.lease.owner().id.hex(),
        "owner_generation_hex": request.lease.owner().generation.hex(),
        "fence": request.lease.fence(),
        "owner_ttl_ms": duration_ms(request.owner_ttl)?,
        "idle_ttl_ms": duration_ms(request.idle_ttl)?,
        "touch_idle": request.touch_idle,
      }))
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
  serde_json::to_string(&items).context("failed to encode PostgreSQL durable UDP touch batch")
}

fn postgres_touch_outcomes(
  rows: &[PgRow],
  requests: &[UdpFlowTouchRequest],
) -> anyhow::Result<Vec<UdpFlowTouchOutcome>> {
  if rows.len() != requests.len() {
    bail!("PostgreSQL durable UDP flow touch batch returned the wrong number of rows");
  }
  let mut outcomes = Vec::with_capacity(rows.len());
  let mut batch_now = None;
  for (index, (row, request)) in rows.iter().zip(requests).enumerate() {
    let ordinal = nonnegative_usize(row.try_get("ordinal")?, "touch batch ordinal")?;
    if ordinal != index {
      bail!("PostgreSQL durable UDP flow touch batch reordered an outcome");
    }
    let now = nonnegative_i64(
      row.try_get("server_now_ms")?,
      "touch batch server timestamp",
    )?;
    if batch_now
      .replace(now)
      .is_some_and(|previous| previous != now)
    {
      bail!("PostgreSQL durable UDP flow touch batch returned inconsistent server timestamps");
    }
    let outcome: String = row.try_get("outcome")?;
    outcomes.push(match outcome.as_str() {
      "renewed" => {
        let record = stored_from_row(request.lease.identity(), row)?;
        record.validate(now)?;
        if record.generation != request.lease.generation() || !lease_owns(&record, &request.lease) {
          bail!("PostgreSQL durable UDP flow touch returned an unfenced renewed record");
        }
        UdpFlowTouchOutcome::Renewed(record.lease(now))
      }
      "lost" => UdpFlowTouchOutcome::Lost { server_now_ms: now },
      "generation_mismatch" => UdpFlowTouchOutcome::GenerationMismatch { server_now_ms: now },
      "error" => bail!("PostgreSQL durable UDP flow touch rejected malformed backend state"),
      other => bail!("unexpected PostgreSQL durable UDP flow touch outcome {other}"),
    });
  }
  Ok(outcomes)
}

async fn postgres_now(tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<i64> {
  let now: i64 =
    sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint")
      .fetch_one(&mut **tx)
      .await?;
  nonnegative_i64(now, "PostgreSQL server timestamp")
}

async fn insert_scope_if_missing(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  request: &UdpFlowClaimRequest,
  now: i64,
) -> anyhow::Result<()> {
  let (rate, burst, balance, refill_at) = postgres_rate_fields(request.new_flow_rate, now);
  sqlx::query(
    "INSERT INTO oxibelt_udp_flow_scopes (
       namespace, scope_digest, record_version, config_generation, max_flows,
       active_flows, next_fence, new_flow_rate_micros_per_second, new_flow_burst,
       new_flow_token_balance_micros, new_flow_token_refill_at_ms, updated_at_ms
     ) VALUES ($1, $2, $3, $4, $5, 0, 0, $6, $7, $8, $9, $10)
     ON CONFLICT (namespace, scope_digest) DO NOTHING",
  )
  .bind(namespace)
  .bind(request.identity.scope.0.as_slice())
  .bind(i16::from(UDP_FLOW_RECORD_VERSION))
  .bind(request.generation.0.0.as_slice())
  .bind(i64::try_from(request.max_flows)?)
  .bind(rate)
  .bind(burst)
  .bind(balance)
  .bind(refill_at)
  .bind(now)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

async fn lock_scope(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  scope: Digest,
) -> anyhow::Result<PostgresScope> {
  lock_scope_optional(tx, namespace, scope)
    .await?
    .ok_or_else(|| anyhow!("durable UDP flow scope disappeared before lock"))
}

async fn lock_scope_optional(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  scope: Digest,
) -> anyhow::Result<Option<PostgresScope>> {
  let row = sqlx::query(
    "SELECT record_version, config_generation, max_flows, active_flows, next_fence,
            new_flow_rate_micros_per_second, new_flow_burst,
            new_flow_token_balance_micros, new_flow_token_refill_at_ms
     FROM oxibelt_udp_flow_scopes
     WHERE namespace = $1 AND scope_digest = $2
     FOR UPDATE",
  )
  .bind(namespace)
  .bind(scope.0.as_slice())
  .fetch_optional(&mut **tx)
  .await?;
  row.as_ref().map(PostgresScope::from_row).transpose()
}

async fn collect_expired(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  scope: Digest,
  now: i64,
) -> anyhow::Result<usize> {
  let deleted: i64 = sqlx::query_scalar(
    "WITH candidates AS (
       SELECT flow_digest
       FROM oxibelt_udp_flows
       WHERE namespace = $1 AND scope_digest = $2 AND idle_expires_at_ms <= $3
       ORDER BY idle_expires_at_ms, flow_digest
       LIMIT $4
       FOR UPDATE
     ),
     deleted AS (
       DELETE FROM oxibelt_udp_flows AS flows
       USING candidates
       WHERE flows.namespace = $1
         AND flows.scope_digest = $2
         AND flows.flow_digest = candidates.flow_digest
         AND flows.idle_expires_at_ms <= $3
       RETURNING 1
     )
     SELECT count(*)::bigint FROM deleted",
  )
  .bind(namespace)
  .bind(scope.0.as_slice())
  .bind(now)
  .bind(i64::try_from(MAX_UDP_FLOW_GC_PER_OPERATION)?)
  .fetch_one(&mut **tx)
  .await?;
  nonnegative_usize(deleted, "bounded expired-flow count")
}

async fn select_flow(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  identity: &UdpFlowIdentity,
  for_update: bool,
) -> anyhow::Result<Option<PgRow>> {
  let sql = if for_update {
    "SELECT record_version, config_generation, route_digest, target_digest,
            owner_digest, owner_generation, fence, owner_expires_at_ms,
            idle_expires_at_ms, token_balance_micros, token_refill_at_ms
     FROM oxibelt_udp_flows
     WHERE namespace = $1 AND scope_digest = $2 AND flow_digest = $3
     FOR UPDATE"
  } else {
    "SELECT record_version, config_generation, route_digest, target_digest,
            owner_digest, owner_generation, fence, owner_expires_at_ms,
            idle_expires_at_ms, token_balance_micros, token_refill_at_ms
     FROM oxibelt_udp_flows
     WHERE namespace = $1 AND scope_digest = $2 AND flow_digest = $3"
  };
  sqlx::query(sql)
    .bind(namespace)
    .bind(identity.scope.0.as_slice())
    .bind(identity.flow.0.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(Into::into)
}

fn stored_from_row(identity: &UdpFlowIdentity, row: &PgRow) -> anyhow::Result<StoredUdpFlow> {
  let version: i16 = row.try_get("record_version")?;
  if version != i16::from(UDP_FLOW_RECORD_VERSION) {
    bail!("unsupported durable UDP flow record version {version}");
  }
  Ok(StoredUdpFlow {
    identity: identity.clone(),
    generation: UdpFlowGeneration(Digest(digest_from_bytes(
      row.try_get("config_generation")?,
      "config_generation",
    )?)),
    target: UdpFlowTarget {
      route: Digest(digest_from_bytes(
        row.try_get("route_digest")?,
        "route_digest",
      )?),
      target: Digest(digest_from_bytes(
        row.try_get("target_digest")?,
        "target_digest",
      )?),
    },
    owner: UdpFlowOwner {
      id: Digest(digest_from_bytes(
        row.try_get("owner_digest")?,
        "owner_digest",
      )?),
      generation: Digest(digest_from_bytes(
        row.try_get("owner_generation")?,
        "owner_generation",
      )?),
    },
    fence: positive_u64(row.try_get("fence")?, "flow fence")?,
    owner_expires_at_ms: nonnegative_i64(row.try_get("owner_expires_at_ms")?, "owner expiry")?,
    idle_expires_at_ms: nonnegative_i64(row.try_get("idle_expires_at_ms")?, "idle expiry")?,
    token_balance_micros: nonnegative_u64(
      row.try_get("token_balance_micros")?,
      "flow token balance",
    )?,
    token_refill_at_ms: nonnegative_i64(
      row.try_get("token_refill_at_ms")?,
      "flow token refill timestamp",
    )?,
  })
}

async fn write_scope(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  scope_digest: Digest,
  scope: &PostgresScope,
  now: i64,
) -> anyhow::Result<()> {
  let (rate, burst, balance, refill_at) = match scope.new_flow_rate {
    Some(rate) => (
      Some(i64::try_from(rate.refill_micros_per_second)?),
      Some(i64::from(rate.burst)),
      Some(i64::try_from(scope.new_flow_token_balance_micros)?),
      Some(scope.new_flow_token_refill_at_ms),
    ),
    None => (None, None, None, None),
  };
  let result = sqlx::query(
    "UPDATE oxibelt_udp_flow_scopes
     SET record_version = $3, max_flows = $4,
         active_flows = $5, next_fence = $6,
         new_flow_rate_micros_per_second = $7, new_flow_burst = $8,
         new_flow_token_balance_micros = $9, new_flow_token_refill_at_ms = $10,
         updated_at_ms = $11
     WHERE namespace = $1 AND scope_digest = $2",
  )
  .bind(namespace)
  .bind(scope_digest.0.as_slice())
  .bind(i16::from(UDP_FLOW_RECORD_VERSION))
  .bind(i64::try_from(scope.max_flows)?)
  .bind(i64::try_from(scope.active_flows)?)
  .bind(i64::try_from(scope.next_fence)?)
  .bind(rate)
  .bind(burst)
  .bind(balance)
  .bind(refill_at)
  .bind(now)
  .execute(&mut **tx)
  .await?;
  if result.rows_affected() != 1 {
    bail!("durable UDP flow scope disappeared during locked update");
  }
  Ok(())
}

async fn insert_flow(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  record: &StoredUdpFlow,
) -> anyhow::Result<()> {
  let result = sqlx::query(
    "INSERT INTO oxibelt_udp_flows (
       namespace, scope_digest, flow_digest, record_version, config_generation,
       route_digest, target_digest, owner_digest, owner_generation, fence,
       owner_expires_at_ms, idle_expires_at_ms, token_balance_micros,
       token_refill_at_ms
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
  )
  .bind(namespace)
  .bind(record.identity.scope.0.as_slice())
  .bind(record.identity.flow.0.as_slice())
  .bind(i16::from(UDP_FLOW_RECORD_VERSION))
  .bind(record.generation.0.0.as_slice())
  .bind(record.target.route.0.as_slice())
  .bind(record.target.target.0.as_slice())
  .bind(record.owner.id.0.as_slice())
  .bind(record.owner.generation.0.as_slice())
  .bind(i64::try_from(record.fence)?)
  .bind(record.owner_expires_at_ms)
  .bind(record.idle_expires_at_ms)
  .bind(i64::try_from(record.token_balance_micros)?)
  .bind(record.token_refill_at_ms)
  .execute(&mut **tx)
  .await?;
  if result.rows_affected() != 1 {
    bail!("durable UDP flow insert did not create exactly one record");
  }
  Ok(())
}

async fn update_claimed_flow(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  record: &StoredUdpFlow,
) -> anyhow::Result<()> {
  let result = sqlx::query(
    "UPDATE oxibelt_udp_flows
     SET owner_digest = $4, owner_generation = $5, fence = $6,
         owner_expires_at_ms = $7, idle_expires_at_ms = $8
     WHERE namespace = $1 AND scope_digest = $2 AND flow_digest = $3",
  )
  .bind(namespace)
  .bind(record.identity.scope.0.as_slice())
  .bind(record.identity.flow.0.as_slice())
  .bind(record.owner.id.0.as_slice())
  .bind(record.owner.generation.0.as_slice())
  .bind(i64::try_from(record.fence)?)
  .bind(record.owner_expires_at_ms)
  .bind(record.idle_expires_at_ms)
  .execute(&mut **tx)
  .await?;
  if result.rows_affected() != 1 {
    bail!("durable UDP flow disappeared during locked update");
  }
  Ok(())
}

async fn update_flow_tokens(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  record: &StoredUdpFlow,
) -> anyhow::Result<()> {
  let result = sqlx::query(
    "UPDATE oxibelt_udp_flows
     SET token_balance_micros = $4, token_refill_at_ms = $5
     WHERE namespace = $1 AND scope_digest = $2 AND flow_digest = $3",
  )
  .bind(namespace)
  .bind(record.identity.scope.0.as_slice())
  .bind(record.identity.flow.0.as_slice())
  .bind(i64::try_from(record.token_balance_micros)?)
  .bind(record.token_refill_at_ms)
  .execute(&mut **tx)
  .await?;
  if result.rows_affected() != 1 {
    bail!("durable UDP flow disappeared during locked token update");
  }
  Ok(())
}

async fn delete_flow(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  identity: &UdpFlowIdentity,
) -> anyhow::Result<()> {
  let result = sqlx::query(
    "DELETE FROM oxibelt_udp_flows
     WHERE namespace = $1 AND scope_digest = $2 AND flow_digest = $3",
  )
  .bind(namespace)
  .bind(identity.scope.0.as_slice())
  .bind(identity.flow.0.as_slice())
  .execute(&mut **tx)
  .await?;
  if result.rows_affected() != 1 {
    bail!("durable UDP flow disappeared during locked delete");
  }
  Ok(())
}

fn stored_from_claim(
  request: &UdpFlowClaimRequest,
  now: i64,
  fence: u64,
) -> anyhow::Result<StoredUdpFlow> {
  Ok(StoredUdpFlow {
    identity: request.identity.clone(),
    generation: request.generation,
    target: request.proposed_target.clone(),
    owner: request.owner.clone(),
    fence,
    owner_expires_at_ms: deadline(now, request.owner_ttl)?,
    idle_expires_at_ms: deadline(now, request.idle_ttl)?,
    token_balance_micros: initial_token_micros(request.initial_tokens),
    token_refill_at_ms: now,
  })
}

fn deadline(now: i64, ttl: Duration) -> anyhow::Result<i64> {
  Ok(now.saturating_add(duration_ms(ttl)?))
}

fn lease_owns(record: &StoredUdpFlow, lease: &UdpFlowLease) -> bool {
  &record.owner == lease.owner() && record.fence == lease.fence()
}

fn postgres_rate_fields(
  rate: Option<UdpFlowRateLimit>,
  now: i64,
) -> (Option<i64>, Option<i64>, Option<i64>, Option<i64>) {
  match rate {
    Some(rate) => (
      i64::try_from(rate.refill_micros_per_second).ok(),
      Some(i64::from(rate.burst)),
      i64::try_from(initial_token_micros(rate.burst)).ok(),
      Some(now),
    ),
    None => (None, None, None, None),
  }
}

fn digest_from_bytes(bytes: Vec<u8>, field: &str) -> anyhow::Result<[u8; 32]> {
  bytes
    .try_into()
    .map_err(|_| anyhow!("durable UDP flow {field} must contain exactly 32 bytes"))
}

fn positive_u64(value: i64, field: &str) -> anyhow::Result<u64> {
  let value = nonnegative_u64(value, field)?;
  if value == 0 {
    bail!("durable UDP flow {field} must be greater than zero");
  }
  Ok(value)
}

fn nonnegative_u64(value: i64, field: &str) -> anyhow::Result<u64> {
  u64::try_from(value).with_context(|| format!("durable UDP flow {field} must not be negative"))
}

fn positive_u32(value: i64, field: &str) -> anyhow::Result<u32> {
  let value =
    u32::try_from(value).with_context(|| format!("durable UDP flow {field} is too large"))?;
  if value == 0 {
    bail!("durable UDP flow {field} must be greater than zero");
  }
  Ok(value)
}

fn positive_usize(value: i64, field: &str) -> anyhow::Result<usize> {
  let value = nonnegative_usize(value, field)?;
  if value == 0 {
    bail!("durable UDP flow {field} must be greater than zero");
  }
  Ok(value)
}

fn nonnegative_usize(value: i64, field: &str) -> anyhow::Result<usize> {
  usize::try_from(value).with_context(|| format!("durable UDP flow {field} must not be negative"))
}

fn nonnegative_i64(value: i64, field: &str) -> anyhow::Result<i64> {
  if value < 0 {
    bail!("durable UDP flow {field} must not be negative");
  }
  Ok(value)
}
