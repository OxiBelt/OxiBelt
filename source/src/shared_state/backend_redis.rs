//! Redis backend connection and health mechanics.

use super::*;

impl RedisBackend {
  pub(super) async fn command(&self, args: &[Vec<u8>]) -> anyhow::Result<Resp> {
    self.pool.command(args).await
  }

  pub(super) async fn put_if_absent(
    &self,
    key: &str,
    value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<bool> {
    let mut args = vec![
      b"SET".to_vec(),
      key.as_bytes().to_vec(),
      value.to_vec(),
      b"NX".to_vec(),
    ];
    if let Some(ttl) = ttl {
      args.push(b"PX".to_vec());
      args.push(
        ttl
          .as_millis()
          .min(i64::MAX as u128)
          .to_string()
          .into_bytes(),
      );
    }
    match self.command(&args).await? {
      Resp::Simple(value) if value == "OK" => Ok(true),
      Resp::Bulk(None) => Ok(false),
      Resp::Nil => Ok(false),
      other => bail!("unexpected Redis SET NX response: {other:?}"),
    }
  }

  pub(super) async fn take_key(&self, key: &str) -> anyhow::Result<bool> {
    let script = "local v = redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]); return 1; end; return 0";
    Ok(
      self
        .command(&[
          b"EVAL".to_vec(),
          script.as_bytes().to_vec(),
          b"1".to_vec(),
          key.as_bytes().to_vec(),
        ])
        .await?
        .into_i64()?
        == 1,
    )
  }

  pub(super) async fn put(
    &self,
    key: &str,
    value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<()> {
    let args = if let Some(ttl) = ttl {
      vec![
        b"PSETEX".to_vec(),
        key.as_bytes().to_vec(),
        ttl
          .as_millis()
          .min(i64::MAX as u128)
          .to_string()
          .into_bytes(),
        value.to_vec(),
      ]
    } else {
      vec![b"SET".to_vec(), key.as_bytes().to_vec(), value.to_vec()]
    };
    expect_ok(self.command(&args).await?)
  }

  pub(super) async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    match self
      .command(&[b"GET".to_vec(), key.as_bytes().to_vec()])
      .await?
    {
      Resp::Bulk(Some(value)) => Ok(Some(value)),
      Resp::Bulk(None) | Resp::Nil => Ok(None),
      other => bail!("unexpected Redis GET response: {other:?}"),
    }
  }

  pub(super) async fn delete(&self, key: &str) -> anyhow::Result<()> {
    let _ = self
      .command(&[b"DEL".to_vec(), key.as_bytes().to_vec()])
      .await?;
    Ok(())
  }

  pub(super) async fn unlock(&self, key: &str, token: &str) -> anyhow::Result<()> {
    let script = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]); end; return 0";
    let _ = self
      .command(&[
        b"EVAL".to_vec(),
        script.as_bytes().to_vec(),
        b"1".to_vec(),
        key.as_bytes().to_vec(),
        token.as_bytes().to_vec(),
      ])
      .await?;
    Ok(())
  }

  pub(super) async fn health_get(&self, key: &str) -> anyhow::Result<Option<HealthRecord>> {
    match self
      .command(&[b"GET".to_vec(), key.as_bytes().to_vec()])
      .await?
    {
      Resp::Bulk(Some(bytes)) => Ok(Some(serde_json::from_slice(&bytes)?)),
      Resp::Bulk(None) | Resp::Nil => Ok(None),
      other => bail!("unexpected Redis health response: {other:?}"),
    }
  }

  pub(super) async fn counter_get(&self, key: &str) -> anyhow::Result<usize> {
    match self
      .command(&[b"GET".to_vec(), key.as_bytes().to_vec()])
      .await?
    {
      Resp::Bulk(Some(bytes)) => Ok(
        String::from_utf8_lossy(&bytes)
          .parse::<usize>()
          .unwrap_or(0),
      ),
      Resp::Bulk(None) | Resp::Nil => Ok(0),
      other => bail!("unexpected Redis counter response: {other:?}"),
    }
  }
}
