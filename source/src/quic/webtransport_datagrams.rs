//! Bound forwarded H3 datagrams independently of aggregate queue memory.
//!
//! At the supported 1200-byte UDP floor, reserve flags(1), CID(20), packet
//! number(4), AEAD tag(16), Quinn DATAGRAM overhead(9), and upstream WT ID(8).
//! That leaves 1142 application bytes. A downstream peer can omit the frame
//! length and use a one-byte WT ID, so a complete 1144-byte frame fits that
//! application bound even when the two legs have different ID widths.

pub(crate) const DOWNSTREAM_FRAME_LIMIT: u32 = 1144;

pub(crate) fn required_upstream_payload(
  frame_limit: usize,
  downstream_id_width: usize,
) -> Option<usize> {
  // Zero/absent DATAGRAM support cannot establish a forwarding session.
  frame_limit
    .checked_sub(1 + downstream_id_width)
    .filter(|capacity| *capacity > 0)
}

pub(crate) fn validate_upstream_capacity(
  required: Option<usize>,
  available: usize,
) -> anyhow::Result<()> {
  let required =
    required.ok_or_else(|| anyhow::anyhow!("downstream WebTransport datagrams are disabled"))?;
  anyhow::ensure!(
    available >= required,
    "upstream WebTransport datagram capacity is insufficient (required {} bytes, maximum {} bytes)",
    required,
    available
  );
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn frame_cap_survives_mtu_fallback_cid_rotation_and_session_id_widths() {
    for mtu in [1200, 1280, 1452] {
      for cid in [0, 8, 20] {
        for upstream_id in [1, 2, 4, 8] {
          let upstream = mtu - (1 + cid + 4 + 16) - 9 - upstream_id;
          for downstream_id in [1, 2, 4, 8] {
            let required =
              required_upstream_payload(DOWNSTREAM_FRAME_LIMIT as usize, downstream_id).unwrap();
            assert!(upstream >= required);
          }
        }
      }
    }
  }

  #[test]
  fn capacity_check_accepts_boundary_and_rejects_undersized_or_disabled_peer() {
    let required = required_upstream_payload(1144, 1);
    assert!(validate_upstream_capacity(required, 1142).is_ok());
    assert!(validate_upstream_capacity(required, 1141).is_err());
    assert!(validate_upstream_capacity(required, 0).is_err());
    assert!(validate_upstream_capacity(required_upstream_payload(0, 1), 65_535).is_err());
  }

  #[test]
  fn upstream_transport_and_queue_budgets_are_independent_of_downstream_cap() {
    let config = crate::config::QuicTransportConfig::default();
    let upstream = crate::quic::transport_config(&config, "test").unwrap();
    let downstream = crate::quic::downstream_transport_config(&config).unwrap();
    assert_eq!(
      upstream.get_datagram_max_frame_size().unwrap().into_inner(),
      65_535
    );
    assert_eq!(
      downstream
        .get_datagram_max_frame_size()
        .unwrap()
        .into_inner(),
      1144
    );
    // Both builders retain the configured queue values; the limit is not a
    // smaller queue and does not change HTTP/2's separate capsule ceiling.
    assert!(format!("{downstream:?}").contains(&format!(
      "datagram_receive_buffer_size: Some({})",
      config.datagram_receive_buffer_bytes
    )));
  }
}
