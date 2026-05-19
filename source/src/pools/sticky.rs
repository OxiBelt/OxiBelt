use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use http::HeaderValue;
use ring::rand::SecureRandom;
use ring::{hmac, rand};

use crate::config::{LoadBalancingAlgorithm, UpstreamPoolConfig};
use crate::shared_state::SharedState;

use super::{
  PoolRuntime, PoolServerRuntime, build_sticky_fallback, server_capacity_available, server_config,
  server_healthy,
};

pub(super) fn select_sticky_cookie(
  pool: &Arc<PoolRuntime>,
  client_ip: IpAddr,
  hash_key: &str,
  cookie_header: Option<&HeaderValue>,
) -> (Option<Arc<PoolServerRuntime>>, Option<HeaderValue>) {
  if let Some(server) = cookie_header
    .and_then(|value| value.to_str().ok())
    .and_then(|raw| cookie_value(raw, &pool.config.sticky_cookie.cookie_name))
    .and_then(|value| verify_sticky_cookie(pool, value))
    .and_then(|server_id| sticky_server(pool, &server_id))
  {
    return (Some(server), None);
  }

  let fallback: LoadBalancingAlgorithm = pool.config.sticky_cookie.fallback_algorithm.into();
  let server = build_sticky_fallback(pool, fallback, client_ip, hash_key);
  let sticky_cookie = server
    .as_ref()
    .and_then(|server| build_sticky_cookie(pool, &server.server_id));
  (server, sticky_cookie)
}

pub(super) fn sticky_secret_for_pool(
  config: &UpstreamPoolConfig,
  shared_state: Option<&Arc<SharedState>>,
) -> [u8; 32] {
  if let Ok(raw) = std::env::var(&config.sticky_cookie.secret_env)
    && !raw.trim().is_empty()
  {
    match base64::engine::general_purpose::STANDARD.decode(raw.trim()) {
      Ok(bytes) if bytes.len() == 32 => {
        return bytes.try_into().expect("checked sticky secret length");
      }
      _ => {
        tracing::warn!(
          pool = %config.name,
          env = %config.sticky_cookie.secret_env,
          "sticky cookie secret env value is invalid; falling back to generated runtime secret"
        );
      }
    }
  }
  if let Some(shared) = shared_state
    && shared.has_sticky_sessions()
  {
    match shared.sticky_session_secret(&config.name) {
      Ok(Some(secret)) => return secret,
      Ok(None) => {}
      Err(error) => {
        tracing::warn!(pool = %config.name, error = %error, "failed to load shared sticky session secret");
      }
    }
  }
  let mut secret = [0u8; 32];
  if rand::SystemRandom::new().fill(&mut secret).is_err() {
    tracing::warn!(
      pool = %config.name,
      "failed to generate sticky cookie secret with system random; using process-local fallback"
    );
    let fallback = format!("{}:{}", config.name, now_unix_seconds());
    let digest = ring::digest::digest(&ring::digest::SHA256, fallback.as_bytes());
    secret.copy_from_slice(digest.as_ref());
  }
  secret
}

fn sticky_server(pool: &Arc<PoolRuntime>, server_id: &str) -> Option<Arc<PoolServerRuntime>> {
  pool
    .servers
    .iter()
    .enumerate()
    .find(|(index, server)| {
      server.server_id == server_id
        && server_config(pool, *index).state.accepts_new_requests()
        && server_healthy(pool, server)
        && server_capacity_available(pool, *index, server)
    })
    .map(|(_, server)| server.clone())
}

fn cookie_value<'a>(cookie_header: &'a str, cookie_name: &str) -> Option<&'a str> {
  cookie_header.split(';').find_map(|part| {
    let (name, value) = part.trim().split_once('=')?;
    (name == cookie_name).then_some(value)
  })
}

fn verify_sticky_cookie(pool: &Arc<PoolRuntime>, value: &str) -> Option<String> {
  let mut parts = value.split('.');
  let version = parts.next()?;
  let encoded_server_id = parts.next()?;
  let expires = parts.next()?;
  let signature = parts.next()?;
  if version != "v1" || parts.next().is_some() {
    return None;
  }
  let expires_at = expires.parse::<u64>().ok()?;
  if expires_at <= now_unix_seconds() {
    return None;
  }
  let signed = format!("{version}.{encoded_server_id}.{expires}");
  let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(signature)
    .ok()?;
  let key = hmac::Key::new(hmac::HMAC_SHA256, &pool.sticky_secret);
  hmac::verify(&key, signed.as_bytes(), &signature).ok()?;
  let server_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(encoded_server_id)
    .ok()?;
  String::from_utf8(server_id).ok()
}

fn build_sticky_cookie(pool: &Arc<PoolRuntime>, server_id: &str) -> Option<HeaderValue> {
  let cookie = &pool.config.sticky_cookie;
  let expires = now_unix_seconds().saturating_add(cookie.ttl_seconds);
  let encoded_server_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_id);
  let signed = format!("v1.{encoded_server_id}.{expires}");
  let key = hmac::Key::new(hmac::HMAC_SHA256, &pool.sticky_secret);
  let signature = hmac::sign(&key, signed.as_bytes());
  let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref());
  let mut value = format!(
    "{}={signed}.{signature}; Max-Age={}; Path={}; SameSite={}",
    cookie.cookie_name,
    cookie.ttl_seconds,
    cookie.path,
    cookie.same_site.as_str()
  );
  if cookie.http_only {
    value.push_str("; HttpOnly");
  }
  if cookie.secure {
    value.push_str("; Secure");
  }
  HeaderValue::from_str(&value).ok()
}

fn now_unix_seconds() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}
