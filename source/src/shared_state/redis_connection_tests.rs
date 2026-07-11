use super::RedisEndpoint;
use crate::config::{RedisAuthConfig, RedisPlaintextPolicy, RedisTlsConfig};

fn parse(url: &str) -> anyhow::Result<RedisEndpoint> {
  RedisEndpoint::parse(
    url,
    "test",
    RedisPlaintextPolicy::Allow,
    &RedisTlsConfig::default(),
    &RedisAuthConfig::default(),
  )
}

#[test]
fn redis_endpoint_accepts_rediss_and_rejects_ambiguous_url_forms() {
  for url in [
    "redis://cache.example.test:6379/0?insecure=true",
    "redis://cache.example.test:6379/not-a-database",
  ] {
    assert!(
      parse(url).is_err(),
      "{url} must not be accepted by the Redis pool"
    );
  }
  let endpoint = parse("rediss://cache.example.test:6379/0").expect("rediss endpoint should parse");
  assert!(endpoint.uses_tls());
}

#[test]
fn redis_endpoint_enforces_plaintext_policy() {
  assert!(
    RedisEndpoint::parse(
      "redis://cache.example.test:6379/0",
      "test",
      RedisPlaintextPolicy::Deny,
      &RedisTlsConfig::default(),
      &RedisAuthConfig::default(),
    )
    .is_err()
  );
  assert!(
    RedisEndpoint::parse(
      "redis://127.0.0.1:6379/0",
      "test",
      RedisPlaintextPolicy::LoopbackOnly,
      &RedisTlsConfig::default(),
      &RedisAuthConfig::default(),
    )
    .is_ok()
  );
}

#[test]
fn redis_endpoint_debug_representation_redacts_credentials() {
  let endpoint =
    parse("redis://user:secret@cache.example.test:6380/2").expect("Redis endpoint should parse");
  assert_eq!(endpoint.redacted(), "redis://cache.example.test:6380/2");
}
