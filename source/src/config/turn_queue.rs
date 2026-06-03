//! TURN queue configuration validation.
//! Queue bounds are checked before TURN relay work can be admitted.

use anyhow::bail;
use serde::Deserialize;

pub(super) const DEFAULT_TURN_STREAM_OUTBOUND_QUEUE_CAPACITY: usize = 32;
const MAX_TURN_STREAM_OUTBOUND_QUEUE_CAPACITY: usize = 256;
const AUTO_TURN_STREAM_OUTBOUND_QUEUE_PER_WORKER: usize = 8;
const AUTO_TURN_STREAM_OUTBOUND_QUEUE_MIN: usize = 32;
const AUTO_TURN_STREAM_OUTBOUND_QUEUE_MAX: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum TurnStreamOutboundQueueCapacitySetting {
  Auto,
  Fixed(usize),
}

impl TurnStreamOutboundQueueCapacitySetting {
  pub(super) fn resolve(
    self,
    listener_name: &str,
    available_parallelism: usize,
  ) -> anyhow::Result<usize> {
    match self {
      Self::Auto => Ok(auto_turn_stream_outbound_queue_capacity(
        available_parallelism,
      )),
      Self::Fixed(value) if value <= MAX_TURN_STREAM_OUTBOUND_QUEUE_CAPACITY => Ok(value),
      Self::Fixed(_) => bail!(
        "WebRTC TURN listener {} stream_outbound_queue_capacity must be at most {}",
        listener_name,
        MAX_TURN_STREAM_OUTBOUND_QUEUE_CAPACITY
      ),
    }
  }
}

impl<'de> Deserialize<'de> for TurnStreamOutboundQueueCapacitySetting {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
      type Value = TurnStreamOutboundQueueCapacitySetting;

      fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a positive integer or \"auto\"")
      }

      fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
      where
        E: serde::de::Error,
      {
        let value = usize::try_from(value)
          .map_err(|_| E::custom("stream outbound queue capacity is too large"))?;
        fixed_turn_stream_outbound_queue_capacity(value).map_err(E::custom)
      }

      fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
      where
        E: serde::de::Error,
      {
        if value < 0 {
          return Err(E::custom(
            "stream outbound queue capacity must be greater than 0",
          ));
        }
        fixed_turn_stream_outbound_queue_capacity(value as usize).map_err(E::custom)
      }

      fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
      where
        E: serde::de::Error,
      {
        if value == "auto" {
          Ok(TurnStreamOutboundQueueCapacitySetting::Auto)
        } else {
          Err(E::custom(
            "stream outbound queue capacity string must be \"auto\"",
          ))
        }
      }
    }

    deserializer.deserialize_any(Visitor)
  }
}

pub(super) fn default_turn_stream_outbound_queue_capacity() -> usize {
  DEFAULT_TURN_STREAM_OUTBOUND_QUEUE_CAPACITY
}

fn fixed_turn_stream_outbound_queue_capacity(
  value: usize,
) -> Result<TurnStreamOutboundQueueCapacitySetting, &'static str> {
  if value == 0 {
    Err("stream outbound queue capacity must be greater than 0")
  } else {
    Ok(TurnStreamOutboundQueueCapacitySetting::Fixed(value))
  }
}

fn auto_turn_stream_outbound_queue_capacity(available_parallelism: usize) -> usize {
  available_parallelism
    .saturating_mul(AUTO_TURN_STREAM_OUTBOUND_QUEUE_PER_WORKER)
    .clamp(
      AUTO_TURN_STREAM_OUTBOUND_QUEUE_MIN,
      AUTO_TURN_STREAM_OUTBOUND_QUEUE_MAX,
    )
}
