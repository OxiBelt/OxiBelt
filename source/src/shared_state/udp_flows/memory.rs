//! Deterministic in-memory durable UDP-flow transitions for unit tests.

use std::collections::{BTreeSet, HashMap};

use super::*;

#[derive(Debug)]
pub(in crate::shared_state) struct MemoryUdpFlowScope {
  max_flows: usize,
  next_fence: u64,
  new_flow_rate: Option<UdpFlowRateLimit>,
  new_flow_token_balance_micros: u64,
  new_flow_token_refill_at_ms: i64,
  flows: HashMap<Digest, StoredUdpFlow>,
  expiry_index: BTreeSet<(i64, Digest)>,
}

impl MemoryUdpFlowScope {
  fn new(request: &UdpFlowClaimRequest, now: i64) -> Self {
    let new_flow_token_balance_micros = request
      .new_flow_rate
      .map(|rate| initial_token_micros(rate.burst))
      .unwrap_or(0);
    Self {
      max_flows: request.max_flows,
      next_fence: 0,
      new_flow_rate: request.new_flow_rate,
      new_flow_token_balance_micros,
      new_flow_token_refill_at_ms: now,
      flows: HashMap::new(),
      expiry_index: BTreeSet::new(),
    }
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
    self.new_flow_token_refill_at_ms = now;
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

  fn collect_expired(&mut self, now: i64) {
    let expired = self
      .expiry_index
      .range(..=(now, Digest([u8::MAX; 32])))
      .take(MAX_UDP_FLOW_GC_PER_OPERATION)
      .copied()
      .collect::<Vec<_>>();
    for (deadline, flow) in expired {
      self.expiry_index.remove(&(deadline, flow));
      if self
        .flows
        .get(&flow)
        .is_some_and(|record| record.idle_expires_at_ms <= now)
      {
        self.flows.remove(&flow);
      }
    }
  }

  fn remove(&mut self, flow: Digest) -> Option<StoredUdpFlow> {
    let record = self.flows.remove(&flow)?;
    self.expiry_index.remove(&(record.idle_expires_at_ms, flow));
    Some(record)
  }

  fn insert(&mut self, record: StoredUdpFlow) {
    let flow = record.identity.flow;
    if let Some(previous) = self.flows.insert(flow, record.clone()) {
      self
        .expiry_index
        .remove(&(previous.idle_expires_at_ms, flow));
    }
    self.expiry_index.insert((record.idle_expires_at_ms, flow));
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
}

impl MemoryBackend {
  pub(super) fn udp_flow_lookup(
    &self,
    namespace: &str,
    identity: &UdpFlowIdentity,
    generation: UdpFlowGeneration,
  ) -> anyhow::Result<UdpFlowLookupOutcome> {
    self.maybe_fail()?;
    let now = super::super::now_unix_ms();
    let mut scopes = self
      .udp_flows
      .lock()
      .expect("memory UDP flow lock poisoned");
    let Some(scope) = scopes.get_mut(&scope_key(namespace, identity)) else {
      return Ok(UdpFlowLookupOutcome::Missing { server_now_ms: now });
    };
    let Some(record) = scope.flows.get(&identity.flow).cloned() else {
      return Ok(UdpFlowLookupOutcome::Missing { server_now_ms: now });
    };
    if record.idle_expires_at_ms <= now {
      scope.remove(identity.flow);
      return Ok(UdpFlowLookupOutcome::Missing { server_now_ms: now });
    }
    if record.generation != generation {
      return Ok(UdpFlowLookupOutcome::GenerationMismatch { server_now_ms: now });
    }
    record.validate(now)?;
    Ok(UdpFlowLookupOutcome::Found(record.record(now)))
  }

  pub(super) fn udp_flow_claim(
    &self,
    namespace: &str,
    request: &UdpFlowClaimRequest,
  ) -> anyhow::Result<UdpFlowClaimOutcome> {
    self.maybe_fail()?;
    let now = super::super::now_unix_ms();
    let mut scopes = self
      .udp_flows
      .lock()
      .expect("memory UDP flow lock poisoned");
    let scope = scopes
      .entry(scope_key(namespace, &request.identity))
      .or_insert_with(|| MemoryUdpFlowScope::new(request, now));
    scope.collect_expired(now);
    if !scope.configuration_matches(request) {
      if !scope.flows.is_empty() {
        return Ok(UdpFlowClaimOutcome::GenerationMismatch { server_now_ms: now });
      }
      scope.reconfigure(request, now);
    }

    if let Some(mut record) = scope.flows.get(&request.identity.flow).cloned() {
      if record.idle_expires_at_ms <= now {
        scope.remove(request.identity.flow);
      } else {
        record.validate(now)?;
        if record.generation != request.generation {
          return Ok(UdpFlowClaimOutcome::GenerationMismatch { server_now_ms: now });
        }
        if record.owner_expires_at_ms > now && record.owner != request.owner {
          let retry_after_ms =
            u64::try_from(record.owner_expires_at_ms.saturating_sub(now)).unwrap_or(u64::MAX);
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
        refresh_claim_deadlines(&mut record, now, request)?;
        scope.insert(record.clone());
        return Ok(if was_owned {
          UdpFlowClaimOutcome::Owned(record.lease(now))
        } else {
          UdpFlowClaimOutcome::Recovered(record.lease(now))
        });
      }
    }

    if scope.flows.len() >= scope.max_flows {
      return Ok(UdpFlowClaimOutcome::CapacityReached { server_now_ms: now });
    }
    let fence = scope.peek_next_fence()?;
    if let Some(retry_after_ms) = scope.take_new_flow_token(now) {
      return Ok(UdpFlowClaimOutcome::RateLimited {
        retry_after_ms,
        server_now_ms: now,
      });
    }
    scope.next_fence = fence;
    let record = stored_from_claim(request, now, fence)?;
    record.validate(now)?;
    scope.insert(record.clone());
    Ok(UdpFlowClaimOutcome::Created(record.lease(now)))
  }

  pub(super) fn udp_flow_touch_batch(
    &self,
    namespace: &str,
    requests: &[UdpFlowTouchRequest],
  ) -> anyhow::Result<Vec<UdpFlowTouchOutcome>> {
    self.maybe_fail()?;
    let now = super::super::now_unix_ms();
    let mut scopes = self
      .udp_flows
      .lock()
      .expect("memory UDP flow lock poisoned");
    requests
      .iter()
      .map(|request| memory_touch(&mut scopes, namespace, request, now))
      .collect()
  }

  pub(super) fn udp_flow_tokens(
    &self,
    namespace: &str,
    request: &UdpFlowTokenRequest,
  ) -> anyhow::Result<UdpFlowTokenOutcome> {
    self.maybe_fail()?;
    let now = super::super::now_unix_ms();
    let mut scopes = self
      .udp_flows
      .lock()
      .expect("memory UDP flow lock poisoned");
    let Some(scope) = scopes.get_mut(&scope_key(namespace, request.lease.identity())) else {
      return Ok(UdpFlowTokenOutcome::Lost { server_now_ms: now });
    };
    let flow = request.lease.identity().flow;
    let Some(mut record) = scope.flows.get(&flow).cloned() else {
      return Ok(UdpFlowTokenOutcome::Lost { server_now_ms: now });
    };
    if record.generation != request.lease.generation() {
      return Ok(UdpFlowTokenOutcome::GenerationMismatch { server_now_ms: now });
    }
    if record.idle_expires_at_ms <= now {
      scope.remove(flow);
      return Ok(UdpFlowTokenOutcome::Lost { server_now_ms: now });
    }
    if record.owner_expires_at_ms <= now || !lease_owns(&record, &request.lease) {
      return Ok(UdpFlowTokenOutcome::Lost { server_now_ms: now });
    }
    refill_tokens(&mut record, now, request);
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
    scope.insert(record);
    Ok(outcome)
  }

  pub(super) fn udp_flow_release(
    &self,
    namespace: &str,
    lease: &UdpFlowLease,
  ) -> anyhow::Result<UdpFlowReleaseOutcome> {
    self.maybe_fail()?;
    let now = super::super::now_unix_ms();
    let mut scopes = self
      .udp_flows
      .lock()
      .expect("memory UDP flow lock poisoned");
    let Some(scope) = scopes.get_mut(&scope_key(namespace, lease.identity())) else {
      return Ok(UdpFlowReleaseOutcome::Missing { server_now_ms: now });
    };
    let Some(record) = scope.flows.get(&lease.identity().flow) else {
      return Ok(UdpFlowReleaseOutcome::Missing { server_now_ms: now });
    };
    if record.generation != lease.generation() {
      return Ok(UdpFlowReleaseOutcome::GenerationMismatch { server_now_ms: now });
    }
    if !lease_owns(record, lease) {
      return Ok(UdpFlowReleaseOutcome::Lost { server_now_ms: now });
    }
    let mut record = record.clone();
    record.owner_expires_at_ms = now.min(record.idle_expires_at_ms);
    record.validate(now)?;
    scope.insert(record);
    Ok(UdpFlowReleaseOutcome::Released { server_now_ms: now })
  }

  pub(super) fn udp_flow_abort_created(
    &self,
    namespace: &str,
    lease: &UdpFlowLease,
  ) -> anyhow::Result<UdpFlowAbortOutcome> {
    self.maybe_fail()?;
    let now = super::super::now_unix_ms();
    let mut scopes = self
      .udp_flows
      .lock()
      .expect("memory UDP flow lock poisoned");
    let Some(scope) = scopes.get_mut(&scope_key(namespace, lease.identity())) else {
      return Ok(UdpFlowAbortOutcome::Missing { server_now_ms: now });
    };
    let Some(record) = scope.flows.get(&lease.identity().flow) else {
      return Ok(UdpFlowAbortOutcome::Missing { server_now_ms: now });
    };
    if record.generation != lease.generation() {
      return Ok(UdpFlowAbortOutcome::GenerationMismatch { server_now_ms: now });
    }
    if !lease_owns(record, lease) {
      return Ok(UdpFlowAbortOutcome::Lost { server_now_ms: now });
    }
    scope.remove(lease.identity().flow);
    Ok(UdpFlowAbortOutcome::Aborted { server_now_ms: now })
  }

  fn maybe_fail(&self) -> anyhow::Result<()> {
    if self.take_forced_failure() {
      bail!("injected shared-state memory backend failure");
    }
    Ok(())
  }
}

fn scope_key(namespace: &str, identity: &UdpFlowIdentity) -> String {
  format!("{namespace}:{}", identity.scope.hex())
}

fn memory_touch(
  scopes: &mut HashMap<String, MemoryUdpFlowScope>,
  namespace: &str,
  request: &UdpFlowTouchRequest,
  now: i64,
) -> anyhow::Result<UdpFlowTouchOutcome> {
  let Some(scope) = scopes.get_mut(&scope_key(namespace, request.lease.identity())) else {
    return Ok(UdpFlowTouchOutcome::Lost { server_now_ms: now });
  };
  let flow = request.lease.identity().flow;
  let Some(mut record) = scope.flows.get(&flow).cloned() else {
    return Ok(UdpFlowTouchOutcome::Lost { server_now_ms: now });
  };
  if record.generation != request.lease.generation() {
    return Ok(UdpFlowTouchOutcome::GenerationMismatch { server_now_ms: now });
  }
  if record.idle_expires_at_ms <= now {
    scope.remove(flow);
    return Ok(UdpFlowTouchOutcome::Lost { server_now_ms: now });
  }
  if record.owner_expires_at_ms <= now || !lease_owns(&record, &request.lease) {
    return Ok(UdpFlowTouchOutcome::Lost { server_now_ms: now });
  }
  let idle_expiry = if request.touch_idle {
    deadline(now, request.idle_ttl)?
  } else {
    record.idle_expires_at_ms
  };
  record.owner_expires_at_ms = deadline(now, request.owner_ttl)?.min(idle_expiry);
  record.idle_expires_at_ms = idle_expiry;
  record.validate(now)?;
  scope.insert(record.clone());
  Ok(UdpFlowTouchOutcome::Renewed(record.lease(now)))
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

fn refresh_claim_deadlines(
  record: &mut StoredUdpFlow,
  now: i64,
  request: &UdpFlowClaimRequest,
) -> anyhow::Result<()> {
  record.owner_expires_at_ms = deadline(now, request.owner_ttl)?;
  record.idle_expires_at_ms = deadline(now, request.idle_ttl)?;
  Ok(())
}

fn deadline(now: i64, ttl: Duration) -> anyhow::Result<i64> {
  Ok(now.saturating_add(duration_ms(ttl)?))
}

fn lease_owns(record: &StoredUdpFlow, lease: &UdpFlowLease) -> bool {
  &record.owner == lease.owner() && record.fence == lease.fence()
}

fn refill_tokens(record: &mut StoredUdpFlow, now: i64, request: &UdpFlowTokenRequest) {
  record.token_balance_micros = refill_balance(
    record.token_balance_micros,
    record.token_refill_at_ms,
    now,
    UdpFlowRateLimit {
      refill_micros_per_second: request.refill_micros_per_second,
      burst: request.burst,
    },
  );
  record.token_refill_at_ms = now;
}
