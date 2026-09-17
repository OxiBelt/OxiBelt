//! Independent wire validation of the Admin operation-event subscription.

use super::*;

pub(super) async fn events<T: AsyncRead + AsyncWrite + Unpin>(
  io: &mut T,
  deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
  let mut decoder = CapsuleDecoder::default();
  let mut pending = Vec::new();
  let mut received = 0u64;
  let mut previous_sequence = None;
  let mut operation_id = None;
  let mut terminal = false;
  let mut finished = false;
  let mut events = 0usize;
  // Admin accepts control capsules and bounded discarded datagrams while
  // advertising no client application-stream credit.
  write_data(io, &capsule(WT_DATAGRAM, b"discard-admin-datagram")?, false).await?;
  loop {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      DATA if frame.stream_id == 1 => {
        let payload = data_payload(&frame)?;
        decoder.push(payload)?;
        while let Some(event) = decoder.next()? {
          match event {
            CapsuleEvent::Stream { id: 3, data, fin } => {
              if finished {
                bail!("Admin sent data after its event stream FIN");
              }
              received += data.len() as u64;
              append_bounded(&mut pending, &data, MAX_CAPSULE)?;
              while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                let value: serde_json::Value = serde_json::from_slice(&pending[..end])
                  .context("Admin event was not valid NDJSON")?;
                pending.drain(..=end);
                if value["event"].as_str() == Some("heartbeat") {
                  continue;
                }
                let sequence = value["sequence"]
                  .as_u64()
                  .context("event sequence missing")?;
                if previous_sequence.is_some_and(|previous| sequence <= previous) {
                  bail!("Admin event sequence did not increase");
                }
                previous_sequence = Some(sequence);
                let id = value["operation"]["id"]
                  .as_str()
                  .context("operation id missing")?;
                if operation_id
                  .as_deref()
                  .is_some_and(|expected| expected != id)
                {
                  bail!("Admin subscription mixed operation identities");
                }
                operation_id = Some(id.to_owned());
                if value["event"].as_str().is_none() {
                  bail!("Admin event name missing");
                }
                terminal |= matches!(
                  value["operation"]["state"].as_str(),
                  Some("succeeded" | "failed" | "cancelled" | "expired")
                );
                events += 1;
              }
              finished = fin;
              if !finished {
                let mut credit = control_capsule(
                  WT_MAX_STREAM_DATA,
                  &[3, u64::from(STREAM_CREDIT) + received],
                )?;
                credit.extend(control_capsule(
                  WT_MAX_DATA,
                  &[u64::from(SESSION_CREDIT) + received],
                )?);
                write_data(io, &credit, false).await?;
              }
            }
            CapsuleEvent::Stream { id, .. } => bail!("Admin opened unexpected stream {id}"),
            CapsuleEvent::Control { .. } | CapsuleEvent::Drain => {}
            CapsuleEvent::Datagram(_) => bail!("Admin unexpectedly sent a datagram"),
            CapsuleEvent::Close { code, reason } => {
              if code != 0 || !terminal || !finished {
                bail!("Admin closed before terminal event FIN ({code}): {reason}");
              }
            }
          }
        }
        acknowledge_data(io, 1, payload.len()).await?;
        if frame.flags & END_STREAM != 0 {
          if !terminal || !finished || !pending.is_empty() {
            bail!("Admin CONNECT ended without complete terminal NDJSON");
          }
          write_data(io, &[], true).await?;
          println!(
            "{}",
            serde_json::json!({"status":200,"admin_events":events,"terminal":true})
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
      RST_STREAM if frame.stream_id == 1 => bail!("Admin CONNECT was reset"),
      GOAWAY => bail!("Admin connection closed before event completion"),
      _ => {}
    }
  }
}
