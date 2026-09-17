use super::*;

fn decode_chunks(wire: &[u8], size: usize) -> io::Result<Vec<Event>> {
  let mut decoder = Decoder::default();
  let mut result = Vec::new();
  for part in wire.chunks(size) {
    let mut part = Bytes::copy_from_slice(part);
    while let Some(event) = decoder.next(&mut part)? {
      result.push(event);
    }
  }
  decoder.finish()?;
  Ok(result)
}

#[test]
fn varints_accept_every_width_and_boundary() {
  for value in [0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, VARINT_MAX] {
    let mut encoded = BytesMut::new();
    put_varint(&mut encoded, value).unwrap();
    assert_eq!(read_varint(&encoded), Some((value, encoded.len())));
    for prefix in 0..encoded.len() {
      assert_eq!(read_varint(&encoded[..prefix]), None);
    }
  }
  assert!(put_varint(&mut BytesMut::new(), VARINT_MAX + 1).is_err());
  assert_eq!(read_varint(&[0xc0, 0, 0, 0, 0, 0, 0, 1]), Some((1, 8)));
}

#[test]
fn every_fragmentation_preserves_stream_payload_and_fin() {
  let payload = vec![0x5a; 2 * QUANTUM + 7];
  let wire = stream(70, &payload, true).unwrap();
  for size in [1, 2, 3, 7, 8, 15, 31, QUANTUM, wire.len()] {
    let events = decode_chunks(&wire, size).unwrap();
    let mut recovered = Vec::new();
    let mut fins = 0;
    let mut starts = 0;
    for event in events {
      let Event::Stream {
        id,
        data,
        fin,
        start,
      } = event
      else {
        panic!("expected stream");
      };
      assert_eq!(id, 70);
      assert!(data.len() <= QUANTUM);
      recovered.extend_from_slice(&data);
      fins += usize::from(fin);
      starts += usize::from(start);
    }
    assert_eq!(recovered, payload);
    assert_eq!(fins, 1);
    assert_eq!(starts, 1);
  }
}

#[test]
fn controls_are_exact_length_and_reset_code_is_not_fixed_width() {
  let wire = control(RESET_STREAM, &[3, u32::MAX as u64, 0]).unwrap();
  for size in 1..wire.len() {
    assert_eq!(
      decode_chunks(&wire, size).unwrap(),
      vec![Event::Control {
        kind: RESET_STREAM,
        values: vec![3, u32::MAX as u64, 0]
      }]
    );
  }
  assert!(decode_chunks(&encode(MAX_DATA, &[]).unwrap(), 1).is_err());
  assert!(decode_chunks(&encode(MAX_DATA, &[0, 0]).unwrap(), 1).is_err());
  assert!(decode_chunks(&encode(DRAIN_SESSION, &[0]).unwrap(), 1).is_err());
}

#[test]
fn truncated_capsules_never_become_clean_eof() {
  let wire = stream(4, b"payload", false).unwrap();
  for prefix in 1..wire.len() {
    assert!(decode_chunks(&wire[..prefix], 1).is_err());
  }
  assert!(decode_chunks(&encode(STREAM, &[]).unwrap(), 1).is_err());
}

#[test]
fn oversized_datagrams_and_unknown_capsules_are_skipped_incrementally() {
  let mut wire = encode(DATAGRAM, &vec![1; MAX_DATAGRAM + 1])
    .unwrap()
    .to_vec();
  wire.extend_from_slice(&encode(0x123456, &vec![9; MAX_DATAGRAM + 3]).unwrap());
  wire.extend_from_slice(&control(MAX_DATA, &[17]).unwrap());
  assert_eq!(
    decode_chunks(&wire, 7).unwrap(),
    vec![Event::Control {
      kind: MAX_DATA,
      values: vec![17]
    }]
  );
}

#[test]
fn closes_preserve_application_code_and_utf8_boundaries() {
  let wire = close(u32::MAX, "é".repeat(700).as_bytes()).unwrap();
  let events = decode_chunks(&wire, 1).unwrap();
  assert_eq!(
    events,
    vec![Event::Close {
      code: u32::MAX,
      reason: "é".repeat(512)
    }]
  );
  assert!(decode_chunks(&encode(CLOSE_SESSION, &[0, 0, 0, 0, 0xff]).unwrap(), 1).is_err());
  assert!(decode_chunks(&encode(CLOSE_SESSION, &vec![0; 1029]).unwrap(), 1).is_err());
}
