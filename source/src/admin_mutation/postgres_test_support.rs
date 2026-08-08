//! Shared opt-in PostgreSQL test connection policy.

use sqlx::{PgPool, postgres::PgPoolOptions};

pub(crate) async fn connect(test_name: &str) -> Option<PgPool> {
  let required = std::env::var("OXIBELT_REQUIRE_MUTATION_POSTGRES_TESTS")
    .ok()
    .is_some_and(|value| value == "1");
  let url = match std::env::var("OXIBELT_TEST_MUTATION_POSTGRES_URL") {
    Ok(value) if !value.trim().is_empty() => value,
    _ if required => panic!(
      "{test_name} requires OXIBELT_TEST_MUTATION_POSTGRES_URL because \
       OXIBELT_REQUIRE_MUTATION_POSTGRES_TESTS=1"
    ),
    _ => return None,
  };
  match PgPoolOptions::new().max_connections(4).connect(&url).await {
    Ok(pool) => Some(pool),
    Err(error) if required => panic!("required {test_name} PostgreSQL connection failed: {error}"),
    Err(error) => panic!("{test_name} PostgreSQL connection failed: {error}"),
  }
}
