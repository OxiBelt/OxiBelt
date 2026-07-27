//! Redis durable UDP-flow transitions.
//!
//! All keys for one listener scope share a Redis Cluster hash tag. Lua scripts
//! obtain Redis server time and atomically update the scope capacity/fence,
//! expiry index, new-flow bucket, and one flow record.

use std::vec::IntoIter;

use super::*;
use crate::shared_state::Resp;

const LOOKUP_SCRIPT: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
if redis.call('EXISTS', KEYS[3]) == 0 then
  return {'missing', now}
end
local v = redis.call('HMGET', KEYS[3], 'v','g','r','t','o','og','f','oe','ie','tb','tr')
for i = 1, 11 do
  if v[i] == false then return {'error', now, 'malformed_flow'} end
end
if v[1] ~= ARGV[1] then return {'error', now, 'flow_version'} end
local idle = tonumber(v[9])
if not idle then return {'error', now, 'flow_idle'} end
if idle <= now then
  redis.call('DEL', KEYS[3])
  redis.call('ZREM', KEYS[2], ARGV[3])
  local active = tonumber(redis.call('HGET', KEYS[1], 'a'))
  if active and active > 0 then redis.call('HINCRBY', KEYS[1], 'a', -1) end
  return {'missing', now}
end
if v[2] ~= ARGV[2] then return {'generation_mismatch', now} end
return {'found', now, v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10],v[11]}
"#;

const CLAIM_SCRIPT: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local version = ARGV[1]
local generation = ARGV[2]
local max_flows = tonumber(ARGV[3])
local rate = tonumber(ARGV[4])
local burst = tonumber(ARGV[5])
local owner_ttl = tonumber(ARGV[6])
local idle_ttl = tonumber(ARGV[7])
local token = tonumber(ARGV[16])
local max_fence = tonumber(ARGV[17])
if not max_flows or not rate or not burst or not owner_ttl or not idle_ttl
   or not token or not max_fence then
  return {'error', now, 'invalid_argument'}
end
local full_balance = burst * token
if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('HSET', KEYS[1],
    'v',version,'g',generation,'m',max_flows,'a',0,'f',0,
    'rr',rate,'rb',burst,'rl',full_balance,'rt',now,'u',now)
end
local s = redis.call('HMGET', KEYS[1], 'v','g','m','a','f','rr','rb','rl','rt')
for i = 1, 9 do
  if s[i] == false then return {'error', now, 'malformed_scope'} end
end
if s[1] ~= version then return {'error', now, 'scope_version'} end
local active = tonumber(s[4])
local next_fence = tonumber(s[5])
local stored_rate = tonumber(s[6])
local stored_burst = tonumber(s[7])
local balance = tonumber(s[8])
local refill_at = tonumber(s[9])
if not active or active < 0 or not next_fence or next_fence < 0
   or not stored_rate or stored_rate < 0 or not stored_burst or stored_burst < 0
   or not balance or balance < 0 or not refill_at or refill_at < 0 then
  return {'error', now, 'scope_number'}
end

local expired = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', now, 'LIMIT', 0, ARGV[15])
for _, member in ipairs(expired) do
  local flow_key = ARGV[13] .. member
  local idle = tonumber(redis.call('HGET', flow_key, 'ie'))
  if not idle or idle <= now then
    redis.call('DEL', flow_key)
    redis.call('ZREM', KEYS[2], member)
    if active > 0 then active = active - 1 end
  end
end
redis.call('HSET', KEYS[1], 'a', active, 'u', now)

local config_matches =
  s[2] == generation and tonumber(s[3]) == max_flows
  and stored_rate == rate and stored_burst == burst
if not config_matches and active ~= 0 then
  return {'generation_mismatch', now}
end
if active == 0 and not config_matches then
  stored_rate = rate
  stored_burst = burst
  balance = full_balance
  refill_at = now
  redis.call('HSET', KEYS[1],
    'g',generation,'m',max_flows,'rr',rate,'rb',burst,
    'rl',balance,'rt',refill_at,'u',now)
end

if redis.call('EXISTS', KEYS[3]) == 0 then
  if redis.call('ZREM', KEYS[2], ARGV[14]) == 1 and active > 0 then
    active = active - 1
    redis.call('HSET', KEYS[1], 'a', active, 'u', now)
  end
else
  local f = redis.call('HMGET', KEYS[3], 'v','g','r','t','o','og','f','oe','ie','tb','tr')
  for i = 1, 11 do
    if f[i] == false then return {'error', now, 'malformed_flow'} end
  end
  if f[1] ~= version then return {'error', now, 'flow_version'} end
  local fence = tonumber(f[7])
  local owner_expiry = tonumber(f[8])
  local idle_expiry = tonumber(f[9])
  local flow_balance = tonumber(f[10])
  local flow_refill = tonumber(f[11])
  if not fence or fence <= 0 or not owner_expiry or owner_expiry < 0
     or not idle_expiry or idle_expiry < owner_expiry
     or not flow_balance or flow_balance < 0 or not flow_refill or flow_refill < 0 then
    return {'error', now, 'flow_number'}
  end
  if idle_expiry <= now then
    redis.call('DEL', KEYS[3])
    redis.call('ZREM', KEYS[2], ARGV[14])
    if active > 0 then active = active - 1 end
    redis.call('HSET', KEYS[1], 'a', active, 'u', now)
  else
    if f[2] ~= generation then return {'generation_mismatch', now} end
    if owner_expiry > now and (f[5] ~= ARGV[10] or f[6] ~= ARGV[11]) then
      return {'busy', now, f[2],f[3],f[4],f[5],f[6],f[7],f[8],f[9],f[10],f[11],
              owner_expiry - now}
    end
    local owned = owner_expiry > now and f[5] == ARGV[10] and f[6] == ARGV[11]
    if not owned then
      if next_fence >= max_fence then return {'error', now, 'fence_exhausted'} end
      next_fence = next_fence + 1
      fence = next_fence
    end
    local new_owner_expiry = now + owner_ttl
    local new_idle_expiry = now + idle_ttl
    redis.call('HSET', KEYS[3],
      'o',ARGV[10],'og',ARGV[11],'f',fence,'oe',new_owner_expiry,'ie',new_idle_expiry)
    redis.call('ZADD', KEYS[2], new_idle_expiry, ARGV[14])
    redis.call('PEXPIREAT', KEYS[3], new_idle_expiry)
    redis.call('HSET', KEYS[1], 'f',next_fence,'a',active,'u',now)
    if owned then
      return {'owned', now, f[2],f[3],f[4],ARGV[10],ARGV[11],fence,
              new_owner_expiry,new_idle_expiry,f[10],f[11]}
    end
    return {'recovered', now, f[2],f[3],f[4],ARGV[10],ARGV[11],fence,
            new_owner_expiry,new_idle_expiry,f[10],f[11]}
  end
end

if active >= max_flows then return {'capacity', now} end
if rate > 0 then
  if stored_rate ~= rate or stored_burst ~= burst or balance > full_balance then
    return {'error', now, 'scope_rate'}
  end
  local elapsed = math.max(0, now - refill_at)
  if elapsed > 0 then
    local fill_ms = math.ceil((full_balance * 1000) / rate)
    if elapsed >= fill_ms then
      balance = full_balance
    else
      balance = math.min(full_balance, balance + math.floor((elapsed * rate) / 1000))
    end
  end
  refill_at = now
  if balance < token then
    local retry = math.ceil(((token - balance) * 1000) / rate)
    redis.call('HSET', KEYS[1], 'rl',balance,'rt',refill_at,'a',active,'u',now)
    return {'rate_limited', now, retry}
  end
  balance = balance - token
end
if next_fence >= max_fence then return {'error', now, 'fence_exhausted'} end
next_fence = next_fence + 1
local owner_expiry = now + owner_ttl
local idle_expiry = now + idle_ttl
redis.call('HSET', KEYS[3],
  'v',version,'g',generation,'r',ARGV[8],'t',ARGV[9],
  'o',ARGV[10],'og',ARGV[11],'f',next_fence,
  'oe',owner_expiry,'ie',idle_expiry,'tb',ARGV[12],'tr',now)
redis.call('ZADD', KEYS[2], idle_expiry, ARGV[14])
redis.call('PEXPIREAT', KEYS[3], idle_expiry)
active = active + 1
redis.call('HSET', KEYS[1],
  'a',active,'f',next_fence,'rl',balance,'rt',refill_at,'u',now)
return {'created', now, generation,ARGV[8],ARGV[9],ARGV[10],ARGV[11],
        next_fence,owner_expiry,idle_expiry,ARGV[12],now}
"#;

const TOUCH_SCRIPT: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
if redis.call('EXISTS', KEYS[3]) == 0 then return {'lost', now} end
local f = redis.call('HMGET', KEYS[3], 'v','g','r','t','o','og','f','oe','ie','tb','tr')
for i = 1, 11 do
  if f[i] == false then return {'error', now, 'malformed_flow'} end
end
if f[1] ~= ARGV[1] then return {'error', now, 'flow_version'} end
if f[2] ~= ARGV[2] then return {'generation_mismatch', now} end
local fence = tonumber(f[7])
local owner_expiry = tonumber(f[8])
local idle_expiry = tonumber(f[9])
if not fence or not owner_expiry or not idle_expiry then
  return {'error', now, 'flow_number'}
end
if idle_expiry <= now or owner_expiry <= now
   or f[5] ~= ARGV[3] or f[6] ~= ARGV[4] or fence ~= tonumber(ARGV[5]) then
  return {'lost', now}
end
local next_idle = idle_expiry
if ARGV[8] == '1' then next_idle = now + tonumber(ARGV[7]) end
local next_owner = math.min(now + tonumber(ARGV[6]), next_idle)
redis.call('HSET', KEYS[3], 'oe',next_owner,'ie',next_idle)
redis.call('ZADD', KEYS[2], next_idle, ARGV[9])
redis.call('PEXPIREAT', KEYS[3], next_idle)
return {'renewed', now, f[2],f[3],f[4],f[5],f[6],f[7],
        next_owner,next_idle,f[10],f[11]}
"#;

const TOKEN_SCRIPT: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
if redis.call('EXISTS', KEYS[1]) == 0 then return {'lost', now} end
local f = redis.call('HMGET', KEYS[1], 'v','g','o','og','f','oe','ie','tb','tr')
for i = 1, 9 do
  if f[i] == false then return {'error', now, 'malformed_flow'} end
end
if f[1] ~= ARGV[1] then return {'error', now, 'flow_version'} end
if f[2] ~= ARGV[2] then return {'generation_mismatch', now} end
local fence = tonumber(f[5])
local owner_expiry = tonumber(f[6])
local idle_expiry = tonumber(f[7])
local balance = tonumber(f[8])
local refill_at = tonumber(f[9])
local requested_tokens = tonumber(ARGV[6])
local rate = tonumber(ARGV[7])
local burst = tonumber(ARGV[8])
local token = tonumber(ARGV[9])
if not fence or fence <= 0 or not owner_expiry or owner_expiry < 0
   or not idle_expiry or idle_expiry < owner_expiry
   or not balance or balance < 0 or not refill_at or refill_at < 0 or refill_at > now
   or not requested_tokens or requested_tokens < 1
   or not rate or rate < 1 or not burst or not token or token < 1
   or burst < token or requested_tokens > math.floor(burst / token) then
  return {'error', now, 'flow_number'}
end
if idle_expiry <= now or owner_expiry <= now
   or f[3] ~= ARGV[3] or f[4] ~= ARGV[4] or fence ~= tonumber(ARGV[5]) then
  return {'lost', now}
end
if balance > burst then return {'error', now, 'token_balance'} end
local elapsed = math.max(0, now - refill_at)
if elapsed > 0 then
  local fill_ms = math.ceil((burst * 1000) / rate)
  if elapsed >= fill_ms then
    balance = burst
  else
    balance = math.min(burst, balance + math.floor((elapsed * rate) / 1000))
  end
end
local available_tokens = math.floor(balance / token)
if available_tokens < 1 then
  local retry = math.ceil(((token - balance) * 1000) / rate)
  redis.call('HSET', KEYS[1], 'tb',balance,'tr',now)
  return {'rate_limited', now, retry}
end
local granted_tokens = math.min(requested_tokens, available_tokens)
balance = balance - granted_tokens * token
redis.call('HSET', KEYS[1], 'tb',balance,'tr',now)
return {'granted', now, granted_tokens}
"#;

const RELEASE_SCRIPT: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
if redis.call('EXISTS', KEYS[1]) == 0 then return {'missing', now} end
local f = redis.call('HMGET', KEYS[1], 'v','g','o','og','f','ie')
for i = 1, 6 do
  if f[i] == false then return {'error', now, 'malformed_flow'} end
end
if f[1] ~= ARGV[1] then return {'error', now, 'flow_version'} end
if f[2] ~= ARGV[2] then return {'generation_mismatch', now} end
if f[3] ~= ARGV[3] or f[4] ~= ARGV[4] or tonumber(f[5]) ~= tonumber(ARGV[5]) then
  return {'lost', now}
end
local idle = tonumber(f[6])
if not idle then return {'error', now, 'flow_idle'} end
redis.call('HSET', KEYS[1], 'oe',math.min(now, idle))
return {'released', now}
"#;

const ABORT_CREATED_SCRIPT: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
if redis.call('EXISTS', KEYS[3]) == 0 then return {'missing', now} end
local f = redis.call('HMGET', KEYS[3], 'v','g','o','og','f')
for i = 1, 5 do
  if f[i] == false then return {'error', now, 'malformed_flow'} end
end
if f[1] ~= ARGV[1] then return {'error', now, 'flow_version'} end
if f[2] ~= ARGV[2] then return {'generation_mismatch', now} end
local fence = tonumber(f[5])
if not fence or fence <= 0 then return {'error', now, 'flow_fence'} end
if f[3] ~= ARGV[3] or f[4] ~= ARGV[4] or fence ~= tonumber(ARGV[5]) then
  return {'lost', now}
end
local s = redis.call('HMGET', KEYS[1], 'v','g','a')
for i = 1, 3 do
  if s[i] == false then return {'error', now, 'malformed_scope'} end
end
local active = tonumber(s[3])
if s[1] ~= ARGV[1] or s[2] ~= ARGV[2] or not active or active < 1 then
  return {'error', now, 'scope_state'}
end
if redis.call('ZSCORE', KEYS[2], ARGV[6]) == false then
  return {'error', now, 'missing_expiry_index'}
end
redis.call('DEL', KEYS[3])
redis.call('ZREM', KEYS[2], ARGV[6])
redis.call('HSET', KEYS[1], 'a', active - 1, 'u', now)
return {'aborted', now}
"#;

impl RedisBackend {
  pub(super) async fn udp_flow_lookup(
    &self,
    keys: &RedisUdpFlowKeys,
    identity: &UdpFlowIdentity,
    generation: UdpFlowGeneration,
  ) -> anyhow::Result<UdpFlowLookupOutcome> {
    let response = self
      .udp_flow_eval(
        LOOKUP_SCRIPT,
        [&keys.scope, &keys.index, &keys.flow],
        vec![
          UDP_FLOW_RECORD_VERSION.to_string(),
          generation.0.hex(),
          keys.member.clone(),
        ],
      )
      .await?;
    let mut reply = RedisReply::new(response)?;
    let status = reply.text()?;
    let now = reply.nonnegative_i64("server time")?;
    let outcome = match status.as_str() {
      "missing" => UdpFlowLookupOutcome::Missing { server_now_ms: now },
      "generation_mismatch" => UdpFlowLookupOutcome::GenerationMismatch { server_now_ms: now },
      "found" => {
        let record = reply.record(identity.clone(), now)?;
        record.validate(now)?;
        UdpFlowLookupOutcome::Found(record.record(now))
      }
      "error" => bail!("Redis durable UDP flow lookup rejected malformed backend state"),
      other => bail!("unexpected Redis durable UDP flow lookup outcome {other}"),
    };
    reply.finish()?;
    Ok(outcome)
  }

  pub(super) async fn udp_flow_claim(
    &self,
    keys: &RedisUdpFlowKeys,
    request: &UdpFlowClaimRequest,
  ) -> anyhow::Result<UdpFlowClaimOutcome> {
    let response = self
      .udp_flow_eval(
        CLAIM_SCRIPT,
        [&keys.scope, &keys.index, &keys.flow],
        redis_claim_arguments(keys, request)?,
      )
      .await?;
    let mut reply = RedisReply::new(response)?;
    let status = reply.text()?;
    let now = reply.nonnegative_i64("server time")?;
    let outcome = match status.as_str() {
      "created" => {
        let record = reply.record(request.identity.clone(), now)?;
        record.validate(now)?;
        UdpFlowClaimOutcome::Created(record.lease(now))
      }
      "recovered" => {
        let record = reply.record(request.identity.clone(), now)?;
        record.validate(now)?;
        UdpFlowClaimOutcome::Recovered(record.lease(now))
      }
      "owned" => {
        let record = reply.record(request.identity.clone(), now)?;
        record.validate(now)?;
        UdpFlowClaimOutcome::Owned(record.lease(now))
      }
      "busy" => {
        let record = reply.record(request.identity.clone(), now)?;
        record.validate(now)?;
        UdpFlowClaimOutcome::Busy {
          record: record.record(now),
          retry_after_ms: reply.nonnegative_u64("busy retry")?,
        }
      }
      "capacity" => UdpFlowClaimOutcome::CapacityReached { server_now_ms: now },
      "rate_limited" => UdpFlowClaimOutcome::RateLimited {
        retry_after_ms: reply.nonnegative_u64("new-flow retry")?,
        server_now_ms: now,
      },
      "generation_mismatch" => UdpFlowClaimOutcome::GenerationMismatch { server_now_ms: now },
      "error" => bail!("Redis durable UDP flow claim rejected malformed backend state"),
      other => bail!("unexpected Redis durable UDP flow claim outcome {other}"),
    };
    reply.finish()?;
    Ok(outcome)
  }

  pub(super) async fn udp_flow_touch_batch(
    &self,
    keys: &[RedisUdpFlowKeys],
    requests: &[UdpFlowTouchRequest],
  ) -> anyhow::Result<Vec<UdpFlowTouchOutcome>> {
    if keys.len() != requests.len() || requests.len() > MAX_UDP_FLOW_BATCH {
      bail!("Redis durable UDP flow touch pipeline inputs are not aligned and bounded");
    }
    let commands = keys
      .iter()
      .zip(requests)
      .map(|(keys, request)| {
        Ok(udp_flow_eval_command(
          TOUCH_SCRIPT,
          [&keys.scope, &keys.index, &keys.flow],
          vec![
            UDP_FLOW_RECORD_VERSION.to_string(),
            request.lease.generation().0.hex(),
            request.lease.owner().id.hex(),
            request.lease.owner().generation.hex(),
            request.lease.fence().to_string(),
            duration_ms(request.owner_ttl)?.to_string(),
            duration_ms(request.idle_ttl)?.to_string(),
            if request.touch_idle { "1" } else { "0" }.to_string(),
            keys.member.clone(),
          ],
        ))
      })
      .collect::<anyhow::Result<Vec<_>>>()?;
    let responses = self.pool.pipeline(&commands).await?;
    if responses.len() != requests.len() {
      bail!("Redis durable UDP flow touch pipeline omitted a response");
    }
    responses
      .into_iter()
      .zip(requests)
      .map(|(response, request)| Self::parse_touch_response(response, request.lease.identity()))
      .collect()
  }

  #[cfg(test)]
  pub(super) fn udp_flow_touch_command_for_test(
    keys: &RedisUdpFlowKeys,
    request: &UdpFlowTouchRequest,
  ) -> anyhow::Result<Vec<Vec<u8>>> {
    Ok(udp_flow_eval_command(
      TOUCH_SCRIPT,
      [&keys.scope, &keys.index, &keys.flow],
      vec![
        UDP_FLOW_RECORD_VERSION.to_string(),
        request.lease.generation().0.hex(),
        request.lease.owner().id.hex(),
        request.lease.owner().generation.hex(),
        request.lease.fence().to_string(),
        duration_ms(request.owner_ttl)?.to_string(),
        duration_ms(request.idle_ttl)?.to_string(),
        if request.touch_idle { "1" } else { "0" }.to_string(),
        keys.member.clone(),
      ],
    ))
  }

  fn parse_touch_response(
    response: Resp,
    identity: &UdpFlowIdentity,
  ) -> anyhow::Result<UdpFlowTouchOutcome> {
    let mut reply = RedisReply::new(response)?;
    let status = reply.text()?;
    let now = reply.nonnegative_i64("server time")?;
    let outcome = match status.as_str() {
      "renewed" => {
        let record = reply.record(identity.clone(), now)?;
        record.validate(now)?;
        UdpFlowTouchOutcome::Renewed(record.lease(now))
      }
      "lost" => UdpFlowTouchOutcome::Lost { server_now_ms: now },
      "generation_mismatch" => UdpFlowTouchOutcome::GenerationMismatch { server_now_ms: now },
      "error" => bail!("Redis durable UDP flow touch rejected malformed backend state"),
      other => bail!("unexpected Redis durable UDP flow touch outcome {other}"),
    };
    reply.finish()?;
    Ok(outcome)
  }

  pub(super) async fn udp_flow_tokens(
    &self,
    keys: &RedisUdpFlowKeys,
    request: &UdpFlowTokenRequest,
  ) -> anyhow::Result<UdpFlowTokenOutcome> {
    let response = self
      .udp_flow_eval(
        TOKEN_SCRIPT,
        [&keys.flow],
        vec![
          UDP_FLOW_RECORD_VERSION.to_string(),
          request.lease.generation().0.hex(),
          request.lease.owner().id.hex(),
          request.lease.owner().generation.hex(),
          request.lease.fence().to_string(),
          request.requested_tokens.to_string(),
          request.refill_micros_per_second.to_string(),
          initial_token_micros(request.burst).to_string(),
          TOKEN_MICROS.to_string(),
        ],
      )
      .await?;
    let mut reply = RedisReply::new(response)?;
    let status = reply.text()?;
    let now = reply.nonnegative_i64("server time")?;
    let outcome = match status.as_str() {
      "granted" => {
        let tokens = u32::try_from(reply.nonnegative_u64("granted tokens")?)
          .context("Redis durable UDP granted token count is too large")?;
        if tokens == 0 || tokens > request.requested_tokens {
          bail!("Redis durable UDP token lease returned an invalid partial grant");
        }
        UdpFlowTokenOutcome::Granted {
          tokens,
          server_now_ms: now,
        }
      }
      "rate_limited" => UdpFlowTokenOutcome::RateLimited {
        retry_after_ms: reply.nonnegative_u64("token retry")?,
        server_now_ms: now,
      },
      "lost" => UdpFlowTokenOutcome::Lost { server_now_ms: now },
      "generation_mismatch" => UdpFlowTokenOutcome::GenerationMismatch { server_now_ms: now },
      "error" => bail!("Redis durable UDP token lease rejected malformed backend state"),
      other => bail!("unexpected Redis durable UDP token outcome {other}"),
    };
    reply.finish()?;
    Ok(outcome)
  }

  pub(super) async fn udp_flow_release(
    &self,
    keys: &RedisUdpFlowKeys,
    lease: &UdpFlowLease,
  ) -> anyhow::Result<UdpFlowReleaseOutcome> {
    let response = self
      .udp_flow_eval(
        RELEASE_SCRIPT,
        [&keys.flow],
        vec![
          UDP_FLOW_RECORD_VERSION.to_string(),
          lease.generation().0.hex(),
          lease.owner().id.hex(),
          lease.owner().generation.hex(),
          lease.fence().to_string(),
        ],
      )
      .await?;
    let mut reply = RedisReply::new(response)?;
    let status = reply.text()?;
    let now = reply.nonnegative_i64("server time")?;
    let outcome = match status.as_str() {
      "released" => UdpFlowReleaseOutcome::Released { server_now_ms: now },
      "missing" => UdpFlowReleaseOutcome::Missing { server_now_ms: now },
      "lost" => UdpFlowReleaseOutcome::Lost { server_now_ms: now },
      "generation_mismatch" => UdpFlowReleaseOutcome::GenerationMismatch { server_now_ms: now },
      "error" => bail!("Redis durable UDP flow release rejected malformed backend state"),
      other => bail!("unexpected Redis durable UDP flow release outcome {other}"),
    };
    reply.finish()?;
    Ok(outcome)
  }

  pub(super) async fn udp_flow_abort_created(
    &self,
    keys: &RedisUdpFlowKeys,
    lease: &UdpFlowLease,
  ) -> anyhow::Result<UdpFlowAbortOutcome> {
    let response = self
      .udp_flow_eval(
        ABORT_CREATED_SCRIPT,
        [&keys.scope, &keys.index, &keys.flow],
        vec![
          UDP_FLOW_RECORD_VERSION.to_string(),
          lease.generation().0.hex(),
          lease.owner().id.hex(),
          lease.owner().generation.hex(),
          lease.fence().to_string(),
          keys.member.clone(),
        ],
      )
      .await?;
    let mut reply = RedisReply::new(response)?;
    let status = reply.text()?;
    let now = reply.nonnegative_i64("server time")?;
    let outcome = match status.as_str() {
      "aborted" => UdpFlowAbortOutcome::Aborted { server_now_ms: now },
      "missing" => UdpFlowAbortOutcome::Missing { server_now_ms: now },
      "lost" => UdpFlowAbortOutcome::Lost { server_now_ms: now },
      "generation_mismatch" => UdpFlowAbortOutcome::GenerationMismatch { server_now_ms: now },
      "error" => bail!("Redis durable UDP flow abort rejected malformed backend state"),
      other => bail!("unexpected Redis durable UDP flow abort outcome {other}"),
    };
    reply.finish()?;
    Ok(outcome)
  }

  async fn udp_flow_eval<const N: usize>(
    &self,
    script: &str,
    keys: [&str; N],
    arguments: Vec<String>,
  ) -> anyhow::Result<Resp> {
    let command = udp_flow_eval_command(script, keys, arguments);
    self.command(&command).await
  }
}

fn udp_flow_eval_command<const N: usize>(
  script: &str,
  keys: [&str; N],
  arguments: Vec<String>,
) -> Vec<Vec<u8>> {
  let mut command = Vec::with_capacity(3 + N + arguments.len());
  command.push(b"EVAL".to_vec());
  command.push(script.as_bytes().to_vec());
  command.push(N.to_string().into_bytes());
  command.extend(keys.into_iter().map(|key| key.as_bytes().to_vec()));
  command.extend(arguments.into_iter().map(String::into_bytes));
  command
}

pub(super) fn redis_claim_arguments(
  keys: &RedisUdpFlowKeys,
  request: &UdpFlowClaimRequest,
) -> anyhow::Result<Vec<String>> {
  let rate = request.new_flow_rate;
  Ok(vec![
    UDP_FLOW_RECORD_VERSION.to_string(),
    request.generation.0.hex(),
    request.max_flows.to_string(),
    rate
      .map(|rate| rate.refill_micros_per_second)
      .unwrap_or(0)
      .to_string(),
    rate.map(|rate| rate.burst).unwrap_or(0).to_string(),
    duration_ms(request.owner_ttl)?.to_string(),
    duration_ms(request.idle_ttl)?.to_string(),
    request.proposed_target.route.hex(),
    request.proposed_target.target.hex(),
    request.owner.id.hex(),
    request.owner.generation.hex(),
    initial_token_micros(request.initial_tokens).to_string(),
    keys.flow_prefix.clone(),
    keys.member.clone(),
    MAX_UDP_FLOW_GC_PER_OPERATION.to_string(),
    TOKEN_MICROS.to_string(),
    MAX_EXACT_BACKEND_INTEGER.to_string(),
  ])
}

struct RedisReply {
  items: IntoIter<Resp>,
}

impl RedisReply {
  fn new(response: Resp) -> anyhow::Result<Self> {
    let Resp::Array(items) = response else {
      bail!("Redis durable UDP flow script returned a non-array response");
    };
    Ok(Self {
      items: items.into_iter(),
    })
  }

  fn next(&mut self, field: &str) -> anyhow::Result<Resp> {
    self
      .items
      .next()
      .ok_or_else(|| anyhow!("Redis durable UDP flow response omitted {field}"))
  }

  fn text(&mut self) -> anyhow::Result<String> {
    match self.next("text field")? {
      Resp::Bulk(Some(bytes)) => String::from_utf8(bytes).map_err(Into::into),
      Resp::Simple(value) => Ok(value),
      other => bail!("Redis durable UDP flow response contains non-text field {other:?}"),
    }
  }

  fn nonnegative_i64(&mut self, field: &str) -> anyhow::Result<i64> {
    let value = match self.next(field)? {
      Resp::Int(value) => value,
      Resp::Bulk(Some(bytes)) => String::from_utf8(bytes)?.parse()?,
      other => bail!("Redis durable UDP flow response contains invalid {field}: {other:?}"),
    };
    if value < 0 {
      bail!("Redis durable UDP flow response contains negative {field}");
    }
    Ok(value)
  }

  fn nonnegative_u64(&mut self, field: &str) -> anyhow::Result<u64> {
    u64::try_from(self.nonnegative_i64(field)?)
      .with_context(|| format!("Redis durable UDP flow {field} is too large"))
  }

  fn digest(&mut self, field: &str) -> anyhow::Result<Digest> {
    Digest::from_hex(&self.text()?).with_context(|| format!("invalid Redis UDP flow {field}"))
  }

  fn record(
    &mut self,
    identity: UdpFlowIdentity,
    server_now_ms: i64,
  ) -> anyhow::Result<StoredUdpFlow> {
    let record = StoredUdpFlow {
      identity,
      generation: UdpFlowGeneration(self.digest("generation")?),
      target: UdpFlowTarget {
        route: self.digest("route")?,
        target: self.digest("target")?,
      },
      owner: UdpFlowOwner {
        id: self.digest("owner")?,
        generation: self.digest("owner generation")?,
      },
      fence: self.nonnegative_u64("fence")?,
      owner_expires_at_ms: self.nonnegative_i64("owner expiry")?,
      idle_expires_at_ms: self.nonnegative_i64("idle expiry")?,
      token_balance_micros: self.nonnegative_u64("token balance")?,
      token_refill_at_ms: self.nonnegative_i64("token refill timestamp")?,
    };
    record.validate(server_now_ms)?;
    Ok(record)
  }

  fn finish(mut self) -> anyhow::Result<()> {
    if self.items.next().is_some() {
      bail!("Redis durable UDP flow response contains unexpected trailing fields");
    }
    Ok(())
  }
}
