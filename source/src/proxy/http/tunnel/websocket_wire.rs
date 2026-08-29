use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::TunnelActivity;
use crate::bandwidth::BandwidthFlow;
use crate::metrics::{BandwidthTrafficClass, Metrics};

const PAYLOAD_CHUNK_BYTES: usize = 16 * 1024;

pub(super) async fn copy_one_way<R, W>(
  mut reader: R,
  mut writer: W,
  activity: mpsc::Sender<TunnelActivity>,
  mut bandwidth: Option<BandwidthFlow>,
  metrics: Option<Arc<Metrics>>,
) -> anyhow::Result<()>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  let mut payload = vec![0u8; PAYLOAD_CHUNK_BYTES];
  loop {
    let Some((header, opcode, mut remaining)) = read_header(&mut reader, &activity).await? else {
      writer.shutdown().await?;
      return Ok(());
    };
    if is_control(opcode) && (header[0] & 0x80 == 0 || remaining > 125) {
      anyhow::bail!("invalid fragmented or oversized WebSocket control frame");
    }
    writer.write_all(&header).await?;

    while remaining != 0 {
      let chunk = usize::try_from(remaining.min(payload.len() as u64)).unwrap_or(payload.len());
      read_exact_with_activity(&mut reader, &mut payload[..chunk], &activity).await?;
      write_payload(
        &mut writer,
        &payload[..chunk],
        opcode,
        &activity,
        bandwidth.as_mut(),
        metrics.as_deref(),
      )
      .await?;
      remaining -= chunk as u64;
    }
  }
}

async fn read_header<R>(
  reader: &mut R,
  activity: &mpsc::Sender<TunnelActivity>,
) -> anyhow::Result<Option<(Vec<u8>, u8, u64)>>
where
  R: AsyncRead + Unpin,
{
  let mut base = [0u8; 2];
  let read = reader.read(&mut base).await?;
  if read == 0 {
    return Ok(None);
  }
  report_network(activity);
  read_exact_with_activity(reader, &mut base[read..], activity).await?;

  let opcode = base[0] & 0x0f;
  let encoded_length = base[1] & 0x7f;
  let extended_bytes = match encoded_length {
    126 => 2,
    127 => 8,
    _ => 0,
  };
  let mut header = Vec::with_capacity(2 + extended_bytes + 4);
  header.extend_from_slice(&base);
  let remaining = if extended_bytes == 0 {
    u64::from(encoded_length)
  } else {
    let mut extended = [0u8; 8];
    read_exact_with_activity(reader, &mut extended[..extended_bytes], activity).await?;
    header.extend_from_slice(&extended[..extended_bytes]);
    if extended_bytes == 2 {
      u64::from(u16::from_be_bytes([extended[0], extended[1]]))
    } else {
      u64::from_be_bytes(extended)
    }
  };
  if base[1] & 0x80 != 0 {
    let mut mask = [0u8; 4];
    read_exact_with_activity(reader, &mut mask, activity).await?;
    header.extend_from_slice(&mask);
  }
  Ok(Some((header, opcode, remaining)))
}

async fn read_exact_with_activity<R>(
  reader: &mut R,
  mut buffer: &mut [u8],
  activity: &mpsc::Sender<TunnelActivity>,
) -> std::io::Result<()>
where
  R: AsyncRead + Unpin,
{
  while !buffer.is_empty() {
    let read = reader.read(buffer).await?;
    if read == 0 {
      return Err(Error::new(
        ErrorKind::UnexpectedEof,
        "partial WebSocket frame",
      ));
    }
    report_network(activity);
    buffer = &mut buffer[read..];
  }
  Ok(())
}

async fn write_payload<W>(
  writer: &mut W,
  payload: &[u8],
  opcode: u8,
  activity: &mpsc::Sender<TunnelActivity>,
  bandwidth: Option<&mut BandwidthFlow>,
  metrics: Option<&Metrics>,
) -> anyhow::Result<()>
where
  W: AsyncWrite + Unpin,
{
  if is_control(opcode) {
    writer.write_all(payload).await?;
    return Ok(());
  }
  let Some(flow) = bandwidth else {
    writer.write_all(payload).await?;
    return Ok(());
  };
  let mut offset = 0;
  while offset < payload.len() {
    let limited = flow.is_limited()?;
    let (granted, waited) = if limited {
      let _ = activity.send(TunnelActivity::BandwidthWaitStarted).await;
      let acquired = flow.acquire(payload.len() - offset).await;
      let _ = activity.send(TunnelActivity::BandwidthWaitEnded).await;
      let grant = acquired?;
      (grant.bytes(), grant.waited())
    } else {
      (payload.len() - offset, Duration::ZERO)
    };
    writer.write_all(&payload[offset..offset + granted]).await?;
    if limited && let Some(metrics) = metrics {
      metrics.record_bandwidth_shaped_bytes(
        flow.direction(),
        BandwidthTrafficClass::WebSocket,
        granted as u64,
      );
      if !waited.is_zero() {
        metrics.record_bandwidth_wait(flow.direction(), BandwidthTrafficClass::WebSocket, waited);
      }
    }
    offset += granted;
  }
  Ok(())
}

fn is_control(opcode: u8) -> bool {
  matches!(opcode, 0x8..=0xa)
}

fn report_network(activity: &mpsc::Sender<TunnelActivity>) {
  let _ = activity.try_send(TunnelActivity::Network);
}

#[cfg(test)]
mod tests {
  use std::num::NonZeroU64;

  use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

  use super::*;
  use crate::bandwidth::{
    BandwidthDirection, BandwidthPolicy, BandwidthRate, RouteBandwidthLimiter,
  };

  #[tokio::test]
  async fn preserves_rsv_masking_and_extended_frames_byte_for_byte() {
    let (mut source, bridge_reader) = duplex(1024);
    let (bridge_writer, mut destination) = duplex(1024);
    let (activity, _observed) = mpsc::channel(16);
    let copy = tokio::spawn(copy_one_way(
      bridge_reader,
      bridge_writer,
      activity,
      None,
      None,
    ));
    let mask = [1, 2, 3, 4];
    let mut encoded = vec![0xc2, 0xfe, 1, 0];
    encoded.extend_from_slice(&mask);
    encoded.extend((0..256).map(|index| (index as u8) ^ mask[index % mask.len()]));
    source.write_all(&encoded).await.unwrap();
    source.shutdown().await.unwrap();

    let mut received = Vec::new();
    destination.read_to_end(&mut received).await.unwrap();
    copy.await.unwrap().unwrap();
    assert_eq!(received, encoded);
  }

  #[tokio::test(start_paused = true)]
  async fn ping_payload_bypasses_an_exhausted_data_budget() {
    let (mut source, bridge_reader) = duplex(512);
    let (bridge_writer, mut destination) = duplex(512);
    let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::new(
      BandwidthRate::BytesPerSecond(NonZeroU64::new(1).unwrap()),
      BandwidthRate::Unlimited,
    ));
    let mut flow = limiter.flow(BandwidthDirection::Upload);
    flow.acquire(1).await.unwrap();
    let (activity, _observed) = mpsc::channel(16);
    let copy = tokio::spawn(copy_one_way(
      bridge_reader,
      bridge_writer,
      activity,
      Some(flow),
      None,
    ));
    let mut ping = vec![0x89, 125];
    ping.extend(std::iter::repeat_n(0x5a, 125));
    source.write_all(&ping).await.unwrap();

    let mut received = vec![0; ping.len()];
    let read = destination.read_exact(&mut received);
    tokio::pin!(read);
    tokio::task::yield_now().await;
    assert!(futures_util::poll!(read.as_mut()).is_ready());
    assert_eq!(received, ping);
    copy.abort();
  }

  #[tokio::test]
  async fn rejects_oversized_pong_before_forwarding_it() {
    let (mut source, bridge_reader) = duplex(512);
    let (bridge_writer, mut destination) = duplex(512);
    let (activity, _observed) = mpsc::channel(16);
    let copy = tokio::spawn(copy_one_way(
      bridge_reader,
      bridge_writer,
      activity,
      None,
      None,
    ));
    let mut pong = vec![0x8a, 126, 0, 126];
    pong.extend(std::iter::repeat_n(0x5a, 126));
    source.write_all(&pong).await.unwrap();

    assert!(copy.await.unwrap().is_err());
    let mut received = Vec::new();
    destination.read_to_end(&mut received).await.unwrap();
    assert!(received.is_empty());
  }

  #[tokio::test(start_paused = true)]
  async fn active_frame_observes_unlimited_to_limited_reload() {
    const HALF: usize = PAYLOAD_CHUNK_BYTES;
    let (mut source, bridge_reader) = duplex(HALF * 3);
    let (bridge_writer, mut destination) = duplex(HALF * 3);
    let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::UNLIMITED);
    let flow = limiter.flow(BandwidthDirection::Upload);
    let (activity, _observed) = mpsc::channel(16);
    let copy = tokio::spawn(copy_one_way(
      bridge_reader,
      bridge_writer,
      activity,
      Some(flow),
      None,
    ));
    let mut first = vec![0x82, 126, 0x80, 0x00];
    first.extend(std::iter::repeat_n(b'a', HALF));
    source.write_all(&first).await.unwrap();
    let mut received = vec![0; first.len()];
    destination.read_exact(&mut received).await.unwrap();
    assert_eq!(received, first);

    limiter
      .update(BandwidthPolicy::new(
        BandwidthRate::BytesPerSecond(NonZeroU64::new(4).unwrap()),
        BandwidthRate::Unlimited,
      ))
      .unwrap();
    source.write_all(&vec![b'b'; HALF]).await.unwrap();
    let next = destination.read_u8();
    tokio::pin!(next);
    assert!(futures_util::poll!(next.as_mut()).is_pending());
    tokio::time::advance(Duration::from_millis(249)).await;
    assert!(futures_util::poll!(next.as_mut()).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(next.await.unwrap(), b'b');
    copy.abort();
  }

  #[tokio::test]
  async fn reports_activity_for_an_incomplete_header() {
    let (mut source, bridge_reader) = duplex(16);
    let (bridge_writer, _destination) = duplex(16);
    let (activity, mut observed) = mpsc::channel(1);
    let copy = tokio::spawn(copy_one_way(
      bridge_reader,
      bridge_writer,
      activity,
      None,
      None,
    ));
    source.write_all(&[0x82]).await.unwrap();
    assert!(matches!(
      observed.recv().await,
      Some(TunnelActivity::Network)
    ));
    copy.abort();
  }
}
