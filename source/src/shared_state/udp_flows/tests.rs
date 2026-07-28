use std::sync::Arc;
use std::time::Duration;

use super::super::failure_policy::BackendFailureBinding;
use super::*;
use crate::config::SharedStateFailurePolicies;
use crate::metrics::Metrics;
use http::StatusCode;

fn store(secret: [u8; 32], boot: [u8; 32]) -> UdpFlowStore {
  let backend = Arc::new(Backend::Memory(MemoryBackend::default()));
  let failure_registry = Arc::new(BackendFailureRegistry::new(
    &SharedStateFailurePolicies::default(),
    std::array::from_fn(|_| BackendFailureBinding::from_backend(Some(backend.as_ref()))),
    Metrics::new(),
  ));
  UdpFlowStore::new(
    Arc::from("udp-flow-test"),
    backend,
    secret,
    Arc::new(boot),
    failure_registry,
  )
}

fn request(
  store: &UdpFlowStore,
  flow: &[u8],
  owner: &[u8],
  max_flows: usize,
  new_flow_rate: Option<UdpFlowRateLimit>,
) -> UdpFlowClaimRequest {
  UdpFlowClaimRequest {
    identity: store
      .derive_identity(b"listener/udp/443", flow)
      .expect("identity"),
    generation: store
      .generation_for(b"activation-generation")
      .expect("generation"),
    owner: store.owner_for(owner).expect("owner"),
    proposed_target: store
      .target_for(b"route-a", b"pool-a/server-a")
      .expect("target"),
    max_flows,
    owner_ttl: Duration::from_secs(10),
    idle_ttl: Duration::from_secs(60),
    initial_tokens: 8,
    new_flow_rate,
  }
}

#[test]
fn keyed_identities_targets_and_boot_owners_are_domain_separated() {
  let first = store([0x11; 32], [0x22; 32]);
  let other_key = store([0x12; 32], [0x22; 32]);
  let other_boot = store([0x11; 32], [0x23; 32]);

  let first_identity = first
    .derive_identity(b"listener", b"198.51.100.7:53000")
    .unwrap();
  let other_identity = other_key
    .derive_identity(b"listener", b"198.51.100.7:53000")
    .unwrap();
  assert_ne!(first_identity, other_identity);
  assert_ne!(
    first.target_for(b"route", b"server").unwrap().route,
    first.target_for(b"server", b"route").unwrap().route
  );

  let owner = first.owner_for(b"pod-a").unwrap();
  let same_process_owner = first.owner_for(b"pod-a").unwrap();
  let restarted_owner = other_boot.owner_for(b"pod-a").unwrap();
  assert_eq!(owner, same_process_owner);
  assert_eq!(owner.id, restarted_owner.id);
  assert_ne!(owner.generation, restarted_owner.generation);
}

#[tokio::test]
async fn release_retains_target_and_stale_release_cannot_clear_successor() {
  let store = store([0x31; 32], [0x41; 32]);
  let first_request = request(&store, b"client-a", b"pod-a", 8, None);
  let first_target = first_request.proposed_target.clone();
  let first = match store.claim_or_create(first_request.clone()).await.unwrap() {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected created lease, got {other:?}"),
  };
  assert!(matches!(
    store.release_if_generation(&first).await.unwrap(),
    UdpFlowReleaseOutcome::Released { .. }
  ));

  let mut successor_request = first_request;
  successor_request.owner = store.owner_for(b"pod-b").unwrap();
  successor_request.proposed_target = store.target_for(b"route-a", b"pool-a/server-b").unwrap();
  let successor = match store.claim_or_create(successor_request).await.unwrap() {
    UdpFlowClaimOutcome::Recovered(lease) => lease,
    other => panic!("expected recovered lease, got {other:?}"),
  };
  assert_eq!(successor.target(), &first_target);
  assert!(successor.fence() > first.fence());
  assert!(matches!(
    store.release_if_generation(&first).await.unwrap(),
    UdpFlowReleaseOutcome::Lost { .. }
  ));
}

#[tokio::test]
async fn touch_batch_preserves_order_and_per_record_fencing() {
  let store = store([0x42; 32], [0x43; 32]);
  let first_request = request(&store, b"client-a", b"pod-a", 8, None);
  let first = match store.claim_or_create(first_request.clone()).await.unwrap() {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected first created lease, got {other:?}"),
  };
  let second = match store
    .claim_or_create(request(&store, b"client-b", b"pod-a", 8, None))
    .await
    .unwrap()
  {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected second created lease, got {other:?}"),
  };
  let third = match store
    .claim_or_create(request(&store, b"client-c", b"pod-a", 8, None))
    .await
    .unwrap()
  {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected third created lease, got {other:?}"),
  };

  store.release_if_generation(&first).await.unwrap();
  let mut successor_request = first_request;
  successor_request.owner = store.owner_for(b"pod-b").unwrap();
  let successor = match store.claim_or_create(successor_request).await.unwrap() {
    UdpFlowClaimOutcome::Recovered(lease) => lease,
    other => panic!("expected recovered successor, got {other:?}"),
  };
  let mut wrong_generation = third;
  wrong_generation.0.generation = store.generation_for(b"other-generation").unwrap();
  let requests = [
    UdpFlowTouchRequest {
      lease: second.clone(),
      owner_ttl: Duration::from_secs(10),
      idle_ttl: Duration::from_secs(60),
      touch_idle: true,
    },
    UdpFlowTouchRequest {
      lease: first,
      owner_ttl: Duration::from_secs(10),
      idle_ttl: Duration::from_secs(60),
      touch_idle: true,
    },
    UdpFlowTouchRequest {
      lease: wrong_generation,
      owner_ttl: Duration::from_secs(10),
      idle_ttl: Duration::from_secs(60),
      touch_idle: true,
    },
  ];
  let outcomes = store.renew_and_touch_batch(&requests).await.unwrap();
  assert!(matches!(
    &outcomes[0],
    UdpFlowTouchOutcome::Renewed(lease) if lease.identity() == second.identity()
  ));
  assert!(matches!(&outcomes[1], UdpFlowTouchOutcome::Lost { .. }));
  assert!(matches!(
    &outcomes[2],
    UdpFlowTouchOutcome::GenerationMismatch { .. }
  ));
  let server_times = outcomes
    .iter()
    .map(|outcome| match outcome {
      UdpFlowTouchOutcome::Renewed(lease) => lease.record().server_now_ms(),
      UdpFlowTouchOutcome::Lost { server_now_ms }
      | UdpFlowTouchOutcome::GenerationMismatch { server_now_ms } => *server_now_ms,
    })
    .collect::<Vec<_>>();
  assert!(server_times.windows(2).all(|times| times[0] == times[1]));
  assert!(matches!(
    store
      .lookup(successor.identity(), successor.generation())
      .await
      .unwrap(),
    UdpFlowLookupOutcome::Found(record) if record.fence() == successor.fence()
  ));
}

#[tokio::test]
async fn new_flow_bucket_debits_only_actual_creations() {
  let store = store([0x51; 32], [0x61; 32]);
  let rate = Some(UdpFlowRateLimit {
    refill_micros_per_second: 1,
    burst: 1,
  });
  let first_request = request(&store, b"client-a", b"pod-a", 8, rate);
  let first = match store.claim_or_create(first_request.clone()).await.unwrap() {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected created lease, got {other:?}"),
  };

  assert!(matches!(
    store.claim_or_create(first_request.clone()).await.unwrap(),
    UdpFlowClaimOutcome::Owned(_)
  ));
  let second_request = request(&store, b"client-b", b"pod-a", 8, rate);
  assert!(matches!(
    store.claim_or_create(second_request).await.unwrap(),
    UdpFlowClaimOutcome::RateLimited { .. }
  ));

  store.release_if_generation(&first).await.unwrap();
  let mut recovery = first_request;
  recovery.owner = store.owner_for(b"pod-b").unwrap();
  assert!(matches!(
    store.claim_or_create(recovery).await.unwrap(),
    UdpFlowClaimOutcome::Recovered(_)
  ));
}

#[tokio::test]
async fn capacity_and_scope_policy_changes_fail_closed() {
  let store = store([0x71; 32], [0x81; 32]);
  let first = request(&store, b"client-a", b"pod-a", 1, None);
  store.claim_or_create(first).await.unwrap();
  let second = request(&store, b"client-b", b"pod-a", 1, None);
  assert!(matches!(
    store.claim_or_create(second).await.unwrap(),
    UdpFlowClaimOutcome::CapacityReached { .. }
  ));

  let changed = request(&store, b"client-c", b"pod-a", 2, None);
  assert!(matches!(
    store.claim_or_create(changed).await.unwrap(),
    UdpFlowClaimOutcome::GenerationMismatch { .. }
  ));
}

#[tokio::test]
async fn routing_generations_share_scope_without_reusing_mismatched_flows() {
  let store = store([0x72; 32], [0x82; 32]);
  let first_request = request(&store, b"client-a", b"pod-a", 2, None);
  let first_target = first_request.proposed_target.clone();
  let first = match store.claim_or_create(first_request.clone()).await.unwrap() {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected first created lease, got {other:?}"),
  };

  let next_generation = store.generation_for(b"next-routing-generation").unwrap();
  let next_target = store.target_for(b"route-b", b"pool-b/server-b").unwrap();
  let mut second_request = request(&store, b"client-b", b"pod-b", 2, None);
  second_request.generation = next_generation;
  second_request.proposed_target = next_target.clone();
  let second = match store.claim_or_create(second_request).await.unwrap() {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected next-generation flow creation, got {other:?}"),
  };
  assert!(second.fence() > first.fence());
  assert_eq!(second.target(), &next_target);

  let mut mismatched_first = first_request;
  mismatched_first.generation = next_generation;
  mismatched_first.proposed_target = next_target;
  assert!(matches!(
    store.claim_or_create(mismatched_first).await.unwrap(),
    UdpFlowClaimOutcome::GenerationMismatch { .. }
  ));
  assert!(matches!(
    store
      .lookup(first.identity(), next_generation)
      .await
      .unwrap(),
    UdpFlowLookupOutcome::GenerationMismatch { .. }
  ));
  assert!(matches!(
    store
      .lookup(first.identity(), first.generation())
      .await
      .unwrap(),
    UdpFlowLookupOutcome::Found(record) if record.target() == &first_target
  ));

  let renewed = store
    .renew_and_touch_batch(&[UdpFlowTouchRequest {
      lease: first.clone(),
      owner_ttl: Duration::from_secs(10),
      idle_ttl: Duration::from_secs(60),
      touch_idle: true,
    }])
    .await
    .unwrap();
  assert!(matches!(&renewed[0], UdpFlowTouchOutcome::Renewed(_)));

  let mut third_request = request(&store, b"client-c", b"pod-b", 2, None);
  third_request.generation = next_generation;
  assert!(matches!(
    store.claim_or_create(third_request).await.unwrap(),
    UdpFlowClaimOutcome::CapacityReached { .. }
  ));
}

#[tokio::test]
async fn mixed_routing_generations_share_new_flow_rate() {
  let store = store([0x73; 32], [0x83; 32]);
  let rate = Some(UdpFlowRateLimit {
    refill_micros_per_second: 1,
    burst: 2,
  });
  let first_request = request(&store, b"client-a", b"pod-a", 3, rate);
  assert!(matches!(
    store.claim_or_create(first_request).await.unwrap(),
    UdpFlowClaimOutcome::Created(_)
  ));
  let next_generation = store.generation_for(b"next-routing-generation").unwrap();
  let mut second_request = request(&store, b"client-b", b"pod-b", 3, rate);
  second_request.generation = next_generation;
  assert!(matches!(
    store.claim_or_create(second_request).await.unwrap(),
    UdpFlowClaimOutcome::Created(_)
  ));
  let mut third_request = request(&store, b"client-c", b"pod-b", 3, rate);
  third_request.generation = next_generation;
  assert!(matches!(
    store.claim_or_create(third_request).await.unwrap(),
    UdpFlowClaimOutcome::RateLimited { .. }
  ));
}

#[tokio::test]
async fn stale_generation_cleanup_cannot_delete_a_successor() {
  let store = store([0x74; 32], [0x84; 32]);
  let first_request = request(&store, b"client-a", b"pod-a", 2, None);
  let first = match store.claim_or_create(first_request.clone()).await.unwrap() {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected first created lease, got {other:?}"),
  };
  assert!(matches!(
    store.abort_created(&first).await.unwrap(),
    UdpFlowAbortOutcome::Aborted { .. }
  ));
  let mut successor_request = first_request;
  successor_request.generation = store.generation_for(b"next-routing-generation").unwrap();
  successor_request.owner = store.owner_for(b"pod-b").unwrap();
  let successor = match store.claim_or_create(successor_request).await.unwrap() {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected successor creation, got {other:?}"),
  };
  assert!(matches!(
    store.abort_created(&first).await.unwrap(),
    UdpFlowAbortOutcome::GenerationMismatch { .. }
  ));
  assert!(matches!(
    store.release_if_generation(&first).await.unwrap(),
    UdpFlowReleaseOutcome::GenerationMismatch { .. }
  ));
  assert!(matches!(
    store
      .lookup(successor.identity(), successor.generation())
      .await
      .unwrap(),
    UdpFlowLookupOutcome::Found(record) if record.fence() == successor.fence()
  ));
}

#[tokio::test]
async fn abort_created_releases_capacity_and_stale_abort_cannot_delete_successor() {
  let store = store([0x79; 32], [0x89; 32]);
  let first_request = request(&store, b"client-a", b"pod-a", 1, None);
  let first = match store.claim_or_create(first_request).await.unwrap() {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected created lease, got {other:?}"),
  };
  assert!(matches!(
    store.abort_created(&first).await.unwrap(),
    UdpFlowAbortOutcome::Aborted { .. }
  ));
  assert!(matches!(
    store
      .lookup(first.identity(), first.generation())
      .await
      .unwrap(),
    UdpFlowLookupOutcome::Missing { .. }
  ));

  let second_request = request(&store, b"client-b", b"pod-a", 1, None);
  let second = match store.claim_or_create(second_request.clone()).await.unwrap() {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected capacity to be released, got {other:?}"),
  };
  store.release_if_generation(&second).await.unwrap();
  let mut successor_request = second_request;
  successor_request.owner = store.owner_for(b"pod-b").unwrap();
  let successor = match store.claim_or_create(successor_request).await.unwrap() {
    UdpFlowClaimOutcome::Recovered(lease) => lease,
    other => panic!("expected recovered successor, got {other:?}"),
  };
  assert!(matches!(
    store.abort_created(&second).await.unwrap(),
    UdpFlowAbortOutcome::Lost { .. }
  ));
  assert!(matches!(
    store
      .lookup(successor.identity(), successor.generation())
      .await
      .unwrap(),
    UdpFlowLookupOutcome::Found(record) if record.fence() == successor.fence()
  ));
}

#[tokio::test]
async fn abort_created_does_not_refund_or_reset_new_flow_admission() {
  let store = store([0x7a; 32], [0x8a; 32]);
  let rate = Some(UdpFlowRateLimit {
    refill_micros_per_second: 1,
    burst: 1,
  });
  let first_request = request(&store, b"client-a", b"pod-a", 1, rate);
  let first = match store.claim_or_create(first_request).await.unwrap() {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected created lease, got {other:?}"),
  };
  assert!(matches!(
    store.abort_created(&first).await.unwrap(),
    UdpFlowAbortOutcome::Aborted { .. }
  ));
  assert!(matches!(
    store
      .claim_or_create(request(&store, b"client-b", b"pod-a", 1, rate))
      .await
      .unwrap(),
    UdpFlowClaimOutcome::RateLimited { .. }
  ));
}

#[test]
fn one_refilled_token_is_granted_without_waiting_for_the_full_request() {
  let rate = UdpFlowRateLimit {
    refill_micros_per_second: TOKEN_MICROS,
    burst: 16,
  };
  let mut balance = refill_balance(0, 1_000, 2_000, rate);
  assert_eq!(balance, TOKEN_MICROS);
  assert_eq!(take_available_tokens(&mut balance, 16), 1);
  assert_eq!(balance, 0);
}

#[test]
fn available_token_grant_saturates_before_narrowing() {
  let mut balance = u64::MAX;
  assert_eq!(take_available_tokens(&mut balance, u32::MAX), u32::MAX);
  assert_eq!(
    balance,
    u64::MAX - u64::from(u32::MAX).saturating_mul(TOKEN_MICROS)
  );
}

#[tokio::test]
async fn backend_errors_and_successes_update_udp_failure_health() {
  let store = store([0x82; 32], [0x83; 32]);
  let request = request(&store, b"client-a", b"pod-a", 8, None);
  let Backend::Memory(memory) = store.backend.as_ref() else {
    panic!("test store must use memory backend");
  };
  memory.inject_failure_once();
  assert!(
    store
      .lookup(&request.identity, request.generation)
      .await
      .is_err()
  );
  assert!(store.failure_registry.is_degraded());
  assert!(matches!(
    store
      .lookup(&request.identity, request.generation)
      .await
      .unwrap(),
    UdpFlowLookupOutcome::Missing { .. }
  ));
  assert!(!store.failure_registry.is_degraded());
}

#[tokio::test]
async fn recovered_flow_adopts_connection_slot_and_stale_release_is_noop() {
  let state = SharedState::test_memory("udp-connection-adoption");
  let store = state.udp_flow_store().expect("UDP flow store");
  let first_request = request(&store, b"client-a", b"pod-a", 8, None);
  let first_flow = match store.claim_or_create(first_request.clone()).await.unwrap() {
    UdpFlowClaimOutcome::Created(lease) => lease,
    other => panic!("expected created flow, got {other:?}"),
  };
  let scope = [super::super::ConnectionScope {
    key: "global",
    limit: 1,
    status: StatusCode::SERVICE_UNAVAILABLE,
  }];
  let first_connection = match state
    .acquire_connections_with_udp_marker(&scope, &store.connection_lease_marker(&first_flow))
    .await
    .unwrap()
  {
    super::super::SharedConnectionAcquire::Acquired(lease) => lease,
    super::super::SharedConnectionAcquire::Denied(status) => {
      panic!("first connection unexpectedly denied with {status}")
    }
  };

  store.release_if_generation(&first_flow).await.unwrap();
  let mut successor_request = first_request;
  successor_request.owner = store.owner_for(b"pod-b").unwrap();
  let successor_flow = match store.claim_or_create(successor_request).await.unwrap() {
    UdpFlowClaimOutcome::Recovered(lease) => lease,
    other => panic!("expected recovered flow, got {other:?}"),
  };
  let successor_connection = match state
    .acquire_connections_with_udp_marker(&scope, &store.connection_lease_marker(&successor_flow))
    .await
    .unwrap()
  {
    super::super::SharedConnectionAcquire::Acquired(lease) => lease,
    super::super::SharedConnectionAcquire::Denied(status) => {
      panic!("successor connection unexpectedly denied with {status}")
    }
  };

  let backend = state
    .connection_limits
    .as_ref()
    .expect("connection backend");
  let counter_key = state.key("conn:global");
  assert_eq!(backend.counter_get(&counter_key).await.unwrap(), 1);
  state.release_connections(first_connection).await;
  assert_eq!(backend.counter_get(&counter_key).await.unwrap(), 1);
  state.release_connections(successor_connection).await;
  assert_eq!(backend.counter_get(&counter_key).await.unwrap(), 0);
}

#[test]
fn backend_digest_parser_is_strict_and_bounded() {
  assert!(Digest::from_hex(&"a5".repeat(32)).is_ok());
  assert!(Digest::from_hex(&"a5".repeat(31)).is_err());
  assert!(Digest::from_hex(&"zz".repeat(32)).is_err());

  let configuration = "a5".repeat(32);
  let valid_marker = format!("{configuration}:{}", "b6".repeat(32));
  assert_eq!(
    super::super::SharedCounterLease::stored_configuration_fingerprint(valid_marker.as_bytes()),
    Some(configuration.as_bytes())
  );
  let uppercase_holder = format!("{configuration}:{}", "B6".repeat(32));
  assert!(
    super::super::SharedCounterLease::stored_configuration_fingerprint(uppercase_holder.as_bytes())
      .is_none()
  );
}

#[test]
fn redis_claim_arguments_match_the_lua_contract_exactly() {
  let store = store([0x91; 32], [0xa1; 32]);
  let request = request(
    &store,
    b"client-a",
    b"pod-a",
    123,
    Some(UdpFlowRateLimit {
      refill_micros_per_second: 4_500_000,
      burst: 17,
    }),
  );
  let keys = store.redis_keys(&request.identity);
  let arguments = super::redis::redis_claim_arguments(&keys, &request).unwrap();
  assert_eq!(arguments.len(), 17);
  assert_eq!(arguments[0], UDP_FLOW_RECORD_VERSION.to_string());
  assert_eq!(arguments[1], request.generation.0.hex());
  assert_eq!(arguments[2], "123");
  assert_eq!(arguments[3], "4500000");
  assert_eq!(arguments[4], "17");
  assert_eq!(arguments[5], "10000");
  assert_eq!(arguments[6], "60000");
  assert_eq!(arguments[7], request.proposed_target.route.hex());
  assert_eq!(arguments[8], request.proposed_target.target.hex());
  assert_eq!(arguments[9], request.owner.id.hex());
  assert_eq!(arguments[10], request.owner.generation.hex());
  assert_eq!(arguments[11], "8000000");
  assert_eq!(arguments[12], keys.flow_prefix);
  assert_eq!(arguments[13], keys.member);
  assert_eq!(arguments[14], "64");
  assert_eq!(arguments[15], "1000000");
  assert_eq!(arguments[16], MAX_EXACT_BACKEND_INTEGER.to_string());
}

#[test]
fn redis_scope_admission_ignores_generation_but_flow_fencing_does_not() {
  let (claim, abort) = super::redis::redis_generation_scripts_for_test();
  let scope_admission = claim
    .split_once("local config_matches =")
    .expect("Redis claim script should define scope compatibility")
    .1
    .split_once("if redis.call('EXISTS', KEYS[3]) == 0 then")
    .expect("scope compatibility should precede flow lookup")
    .0;

  assert!(!scope_admission.contains("s[2] == generation"));
  assert!(!scope_admission.contains("'g',generation"));
  assert!(claim.contains("'v',version,'g',generation,'m',max_flows"));
  assert!(claim.contains("if f[2] ~= generation then return {'generation_mismatch', now} end"));
  assert!(abort.contains("if f[2] ~= ARGV[2] then return {'generation_mismatch', now} end"));
  assert!(!abort.contains("s[2] ~= ARGV[2]"));
}

#[test]
fn postgres_scope_generation_remains_compatibility_metadata() {
  let postgres = include_str!("postgres.rs");
  let abort = postgres
    .split_once("pub(super) async fn udp_flow_abort_created(")
    .expect("PostgreSQL backend should define durable flow abort")
    .1
    .split_once("\n}\n\npub(super) fn postgres_touch_payload")
    .expect("durable flow abort should precede touch payload encoding")
    .0;
  let write_scope = postgres
    .split_once("async fn write_scope(")
    .expect("PostgreSQL backend should define scope persistence")
    .1
    .split_once("\n}\n\nasync fn insert_flow(")
    .expect("scope persistence should precede flow insertion")
    .0;

  assert!(
    postgres.contains(
      "udp_flow_scope_configuration_matches(self.max_flows, self.new_flow_rate, request)"
    )
  );
  assert!(abort.contains("record.generation != lease.generation()"));
  assert!(!abort.contains("scope.generation"));
  assert!(!write_scope.contains("config_generation ="));
  assert!(
    postgres.contains("namespace, scope_digest, record_version, config_generation, max_flows,")
  );
}

#[tokio::test]
async fn batch_touch_backend_payloads_preserve_input_order() {
  let store = store([0x92; 32], [0xa2; 32]);
  let first = request(&store, b"client-a", b"pod-a", 8, None);
  let second = request(&store, b"client-b", b"pod-a", 8, None);
  let leases = [
    match store.claim_or_create(first).await.unwrap() {
      UdpFlowClaimOutcome::Created(lease) => lease,
      other => panic!("expected first created lease, got {other:?}"),
    },
    match store.claim_or_create(second).await.unwrap() {
      UdpFlowClaimOutcome::Created(lease) => lease,
      other => panic!("expected second created lease, got {other:?}"),
    },
  ];
  let requests = leases.map(|lease| UdpFlowTouchRequest {
    lease,
    owner_ttl: Duration::from_secs(10),
    idle_ttl: Duration::from_secs(60),
    touch_idle: true,
  });
  let keys = store.redis_keys(requests[0].lease.identity());
  let command =
    RedisBackend::udp_flow_touch_command_for_test(&keys, &requests[0]).expect("Redis command");
  assert_eq!(command[0], b"EVAL");
  assert_eq!(command[2], b"3");
  assert_eq!(command[3], keys.scope.as_bytes());
  assert_eq!(command[4], keys.index.as_bytes());
  assert_eq!(command[5], keys.flow.as_bytes());

  let payload = super::postgres::postgres_touch_payload(&requests).expect("PostgreSQL payload");
  let payload: serde_json::Value = serde_json::from_str(&payload).expect("payload JSON");
  assert_eq!(payload[0]["ordinal"], 0);
  assert_eq!(payload[1]["ordinal"], 1);
  assert_eq!(
    payload[0]["flow_hex"],
    requests[0].lease.identity().flow.hex()
  );
  assert_eq!(
    payload[1]["flow_hex"],
    requests[1].lease.identity().flow.hex()
  );
}
