//! Raw negative conformance scenarios. Every failure must remain stream-scoped.

use anyhow::{anyhow, bail};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{
  acknowledge_data, capsule, control_capsule, data_payload, parse_settings, prepare_client_streams,
  read_frame_at, stream_capsule, validate_settings, validate_settings_ack, validate_window_update,
  write_data, write_frame, CapsuleEvent, PeerCredit, ACK, DATA, GOAWAY, PING, RST_STREAM, SETTINGS,
  WINDOW_UPDATE, WT_CLOSE_SESSION, WT_ENABLED, WT_RESET_STREAM,
};

const EXPECTED_PROXY_STREAM_CREDIT: usize = 1024;
const EXPECTED_PROXY_STREAM_LIMIT: u64 = 4;
const PROTOCOL_ERROR: u32 = 1;
const FLOW_CONTROL_ERROR: u32 = 3;
const PING_PAYLOAD: &[u8; 8] = b"wt-sib-1";
const WAF_CLOSE_CODE: u32 = 91;
const WAF_CLOSE_REASON: &str = "blocked WebTransport payload";
const SHAPED_BYTES: usize = 192;
const SHAPED_MINIMUM: std::time::Duration = std::time::Duration::from_millis(1_500);

pub(super) async fn run<T>(
  scenario: &str,
  io: &mut T,
  deadline: tokio::time::Instant,
  peer_credit: PeerCredit,
) -> anyhow::Result<()>
where
  T: AsyncRead + AsyncWrite + Unpin,
{
  match scenario {
    "waf-payload" => return waf_payload(io, deadline, peer_credit).await,
    "shaped" => return shaped(io, deadline, peer_credit).await,
    "admin-drain-target" => return admin_drain_target(io, deadline).await,
    _ => {}
  }
  let (wire, end_stream, expected_reset) = match scenario {
    "malformed" | "zero-window-reset" => {
      let mut invalid_close = vec![0, 0, 0, 0];
      invalid_close.push(0xff);
      (
        capsule(WT_CLOSE_SESSION, &invalid_close)?,
        false,
        PROTOCOL_ERROR,
      )
    }
    "truncated" => {
      let mut truncated = super::encode_varint(WT_CLOSE_SESSION);
      truncated.extend(super::encode_varint(8));
      truncated.push(0);
      (truncated, true, PROTOCOL_ERROR)
    }
    "oversized" => {
      let mut oversized = super::encode_varint(WT_RESET_STREAM);
      oversized.extend(super::encode_varint(25));
      (oversized, false, PROTOCOL_ERROR)
    }
    "flow-violation" => (
      stream_capsule(0, &vec![0x46; EXPECTED_PROXY_STREAM_CREDIT + 1], true)?,
      false,
      FLOW_CONTROL_ERROR,
    ),
    "stream-limit" => (
      stream_capsule(EXPECTED_PROXY_STREAM_LIMIT * 4, &[], true)?,
      false,
      FLOW_CONTROL_ERROR,
    ),
    "sibling-isolation" => (
      control_capsule(WT_RESET_STREAM, &[0, 7, 1])?,
      false,
      PROTOCOL_ERROR,
    ),
    _ => bail!("webtransport-h2 scenario {scenario} is not implemented"),
  };

  write_data(io, &wire, end_stream).await?;
  expect_stream_reset(io, deadline, expected_reset).await?;
  ping_roundtrip(io, deadline).await?;
  println!(
    "{}",
    serde_json::json!({
      "scenario": scenario,
      "reset_reason": expected_reset,
      "sibling_ping": "acknowledged",
    })
  );
  Ok(())
}

async fn admin_drain_target<T>(io: &mut T, deadline: tokio::time::Instant) -> anyhow::Result<()>
where
  T: AsyncRead + AsyncWrite + Unpin,
{
  println!("{}", serde_json::json!({"drain_target":"ready"}));
  std::io::Write::flush(&mut std::io::stdout())?;
  let mut decoder = super::CapsuleDecoder::default();
  let mut close_seen = false;
  loop {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      DATA if frame.stream_id == 1 => {
        let payload = data_payload(&frame)?;
        decoder.push(payload)?;
        while let Some(event) = decoder.next()? {
          match event {
            CapsuleEvent::Close { code: 77, reason } if reason == "bounded admin drain" => {
              if close_seen {
                bail!("Admin drain sent its close capsule more than once");
              }
              close_seen = true;
            }
            CapsuleEvent::Close { code, reason } => {
              bail!("Admin drain close was ({code}): {reason}")
            }
            CapsuleEvent::Stream { .. } | CapsuleEvent::Datagram(_) => {
              bail!("Admin drain sent application data before closing")
            }
            CapsuleEvent::Control { .. } | CapsuleEvent::Drain => {}
          }
        }
        acknowledge_data(io, 1, payload.len()).await?;
        if frame.flags & super::END_STREAM != 0 {
          decoder.finish()?;
          if !close_seen {
            bail!("Admin drain ended CONNECT without its close capsule");
          }
          write_data(io, &[], true).await?;
          println!(
            "{}",
            serde_json::json!({
              "scenario":"admin-drain-target",
              "close_code":77,
              "reason":"bounded admin drain",
              "connect_end":"clean",
            })
          );
          return Ok(());
        }
      }
      SETTINGS if frame.flags & ACK == 0 => {
        validate_settings(&frame.payload)?;
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
      }
      SETTINGS => validate_settings_ack(&frame)?,
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      WINDOW_UPDATE => validate_window_update(&frame)?,
      RST_STREAM if frame.stream_id == 1 => bail!("Admin drain reset CONNECT"),
      GOAWAY => bail!("Admin drain closed the HTTP/2 connection"),
      _ => {}
    }
  }
}

async fn waf_payload<T>(
  io: &mut T,
  deadline: tokio::time::Instant,
  peer_credit: PeerCredit,
) -> anyhow::Result<()>
where
  T: AsyncRead + AsyncWrite + Unpin,
{
  let mut decoder = prepare_client_streams(io, deadline, peer_credit).await?;
  write_data(io, &stream_capsule(0, b"waf-block-stream", true)?, false).await?;
  loop {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      DATA if frame.stream_id == 1 => {
        let payload = data_payload(&frame)?;
        decoder.push(payload)?;
        while let Some(event) = decoder.next()? {
          match event {
            CapsuleEvent::Close { code, reason }
              if code == WAF_CLOSE_CODE && reason == WAF_CLOSE_REASON =>
            {
              println!(
                "{}",
                serde_json::json!({
                  "scenario":"waf-payload",
                  "close_code":code,
                  "reason":reason,
                })
              );
              return Ok(());
            }
            CapsuleEvent::Close { code, reason } => {
              bail!("WAF close was ({code}): {reason}")
            }
            CapsuleEvent::Stream { id: 0, data, .. } if !data.is_empty() => {
              bail!("WAF-blocked stream payload was echoed")
            }
            _ => {}
          }
        }
        acknowledge_data(io, 1, payload.len()).await?;
      }
      SETTINGS if frame.flags & ACK == 0 => {
        validate_settings(&frame.payload)?;
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
      }
      SETTINGS => validate_settings_ack(&frame)?,
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      RST_STREAM if frame.stream_id == 1 => bail!("WAF reset CONNECT without a close capsule"),
      GOAWAY => bail!("WAF closed the HTTP/2 connection instead of the session"),
      WINDOW_UPDATE => validate_window_update(&frame)?,
      _ => {}
    }
  }
}

async fn shaped<T>(
  io: &mut T,
  deadline: tokio::time::Instant,
  peer_credit: PeerCredit,
) -> anyhow::Result<()>
where
  T: AsyncRead + AsyncWrite + Unpin,
{
  let mut decoder = prepare_client_streams(io, deadline, peer_credit).await?;
  let payload = vec![b'S'; SHAPED_BYTES];
  let started = tokio::time::Instant::now();
  write_data(io, &stream_capsule(0, &payload, true)?, false).await?;
  let mut echoed = Vec::with_capacity(SHAPED_BYTES);
  let mut finished = false;
  while !finished {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      DATA if frame.stream_id == 1 => {
        let data = data_payload(&frame)?;
        decoder.push(data)?;
        while let Some(event) = decoder.next()? {
          match event {
            CapsuleEvent::Stream { id: 0, data, fin } => {
              super::append_bounded(&mut echoed, &data, SHAPED_BYTES)?;
              finished |= fin;
            }
            CapsuleEvent::Close { code, reason } => {
              bail!("shaped session closed ({code}): {reason}")
            }
            _ => {}
          }
        }
        acknowledge_data(io, 1, data.len()).await?;
      }
      SETTINGS if frame.flags & ACK == 0 => {
        validate_settings(&frame.payload)?;
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
      }
      SETTINGS => validate_settings_ack(&frame)?,
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      RST_STREAM if frame.stream_id == 1 => bail!("shaped CONNECT was reset"),
      GOAWAY => bail!("shaped transfer closed its HTTP/2 connection"),
      WINDOW_UPDATE => validate_window_update(&frame)?,
      _ => {}
    }
  }
  if echoed != payload {
    bail!("shaped transfer changed the stream payload");
  }
  let elapsed = started.elapsed();
  if elapsed < SHAPED_MINIMUM {
    bail!(
      "192-byte shaped echo completed in {} ms, below the 1500 ms enforcement floor",
      elapsed.as_millis()
    );
  }
  write_data(io, &super::close_capsule(0, b"shaped complete")?, true).await?;
  super::wait_for_connect_end(
    io,
    tokio::time::Instant::now() + std::time::Duration::from_secs(2),
  )
  .await?;
  println!(
    "{}",
    serde_json::json!({
      "scenario":"shaped",
      "echo_bytes":SHAPED_BYTES,
      "elapsed_ms":elapsed.as_millis(),
      "minimum_ms":SHAPED_MINIMUM.as_millis(),
    })
  );
  Ok(())
}

pub(super) async fn tls12_setting_suppression<T>(
  io: &mut T,
  deadline: tokio::time::Instant,
) -> anyhow::Result<()>
where
  T: AsyncRead + AsyncWrite + Unpin,
{
  loop {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      SETTINGS if frame.flags & ACK == 0 => {
        let values = parse_settings(&frame.payload)?;
        if values.keys().any(|id| (WT_ENABLED..=0x2b66).contains(id)) {
          bail!("TLS 1.2 HTTP/2 advertised WebTransport SETTINGS");
        }
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
        break;
      }
      SETTINGS => validate_settings_ack(&frame)?,
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      GOAWAY => bail!("TLS 1.2 HTTP/2 sent GOAWAY before SETTINGS"),
      _ => {}
    }
  }
  ping_roundtrip(io, deadline).await?;
  println!(
    "{}",
    serde_json::json!({
      "scenario": "tls12-setting-suppression",
      "webtransport_settings": "absent",
      "sibling_ping": "acknowledged",
    })
  );
  Ok(())
}

async fn expect_stream_reset<T>(
  io: &mut T,
  deadline: tokio::time::Instant,
  expected: u32,
) -> anyhow::Result<()>
where
  T: AsyncRead + AsyncWrite + Unpin,
{
  loop {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      RST_STREAM if frame.stream_id == 1 => {
        let payload: [u8; 4] = frame
          .payload
          .as_slice()
          .try_into()
          .map_err(|_| anyhow!("RST_STREAM reason was not four bytes"))?;
        let actual = u32::from_be_bytes(payload);
        if actual != expected {
          bail!("WebTransport reset reason was {actual}, expected {expected}");
        }
        return Ok(());
      }
      DATA if frame.stream_id == 1 => {
        let length = data_payload(&frame)?.len();
        acknowledge_data(io, 1, length).await?;
      }
      SETTINGS if frame.flags & ACK == 0 => {
        validate_settings(&frame.payload)?;
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
      }
      SETTINGS => validate_settings_ack(&frame)?,
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      WINDOW_UPDATE => validate_window_update(&frame)?,
      GOAWAY => bail!("malformed WebTransport session closed its HTTP/2 connection"),
      _ => {}
    }
  }
}

async fn ping_roundtrip<T>(io: &mut T, deadline: tokio::time::Instant) -> anyhow::Result<()>
where
  T: AsyncRead + AsyncWrite + Unpin,
{
  write_frame(io, PING, 0, 0, PING_PAYLOAD).await?;
  loop {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      PING if frame.flags & ACK != 0 && frame.payload == PING_PAYLOAD => return Ok(()),
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      SETTINGS if frame.flags & ACK == 0 => {
        validate_settings(&frame.payload)?;
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
      }
      SETTINGS => validate_settings_ack(&frame)?,
      WINDOW_UPDATE => validate_window_update(&frame)?,
      GOAWAY => bail!("sibling PING observed GOAWAY after a session-scoped failure"),
      _ => {}
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn negative_scenarios_have_explicit_reset_classes() {
    assert_eq!(PROTOCOL_ERROR, 1);
    assert_eq!(FLOW_CONTROL_ERROR, 3);
    assert_eq!(EXPECTED_PROXY_STREAM_LIMIT * 4, 16);
    assert!(EXPECTED_PROXY_STREAM_CREDIT < super::super::STREAM_CREDIT as usize);
  }
}
