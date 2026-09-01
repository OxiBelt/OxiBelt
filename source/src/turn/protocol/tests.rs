use super::*;
use proptest::prelude::*;

fn scalar_crc32_reference(bytes: &[u8]) -> u32 {
  let mut crc = 0xffff_ffffu32;
  for byte in bytes {
    crc ^= u32::from(*byte);
    for _ in 0..8 {
      let mask = 0u32.wrapping_sub(crc & 1);
      crc = (crc >> 1) ^ (0xedb8_8320 & mask);
    }
  }
  !crc
}

#[test]
fn crc32_matches_independent_ieee_vector_and_scalar_reference() {
  assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
  for bytes in [
    &b""[..],
    &b"a"[..],
    &b"unaligned payload"[..],
    &b"0123456789abcdef0123456789abcdef tail"[..],
  ] {
    assert_eq!(crc32(bytes), scalar_crc32_reference(bytes));
  }
}

#[test]
fn stun_success_round_trips_with_fingerprint() {
  let txid = [7u8; 12];
  let mapped: SocketAddr = "192.0.2.10:54321".parse().unwrap();
  let encoded = encode_success(
    BINDING_REQUEST,
    txid,
    &[(ATTR_XOR_MAPPED_ADDRESS, encode_xor_address(mapped, &txid))],
  );
  let parsed = parse_stun(&encoded).expect("STUN response should parse");
  assert_eq!(parsed.message_type, success_type(BINDING_REQUEST));
  assert_eq!(
    attr_xor_addr(&parsed, ATTR_XOR_MAPPED_ADDRESS)
      .unwrap()
      .unwrap(),
    mapped
  );
  assert!(verify_fingerprint(&parsed).unwrap());
}

#[test]
fn error_code_uses_rfc_class_and_number_octets() {
  assert_eq!(&encode_error_code(438, "Stale Nonce")[..4], &[0, 0, 4, 38]);

  let encoded = encode_error(
    BINDING_REQUEST,
    [8u8; 12],
    438,
    "Stale Nonce",
    Some("example.test"),
    Some("replacement-nonce"),
  );
  let parsed = parse_stun(&encoded).expect("STUN error response should parse");
  assert_eq!(
    &attr_bytes(&parsed, ATTR_ERROR_CODE).expect("ERROR-CODE must be present")[..4],
    &[0, 0, 4, 38]
  );
}

#[test]
fn channel_data_round_trips() {
  let encoded = encode_channel_data(0x4001, b"hello").expect("valid channel data");
  let parsed = parse_channel_data(&encoded).expect("ChannelData should parse");
  assert_eq!(parsed.channel, 0x4001);
  assert_eq!(parsed.payload, b"hello");
}

#[test]
fn channel_data_rejects_obsolete_or_oversized_encodings() {
  assert!(encode_channel_data(0x5000, b"reserved").is_err());
  assert!(parse_channel_data(&[0x50, 0x00, 0x00, 0x00]).is_err());
  assert!(encode_channel_data(0x4000, &vec![0; usize::from(u16::MAX) + 1]).is_err());
}

#[test]
fn stun_datagram_rejects_trailing_bytes() {
  let mut encoded = encode_binding_request([3u8; 12]);
  encoded.push(0);
  assert!(parse_stun(&encoded).is_err());
}

#[test]
fn sha256_integrity_round_trips() {
  let encoded = with_message_integrity_sha256(
    encode_message(BINDING_REQUEST, [4u8; 12], &[]),
    b"sha256-test-key",
  );
  let parsed = parse_stun(&encoded).expect("STUN message should parse");
  assert!(verify_message_integrity_sha256(&parsed, b"sha256-test-key").unwrap());
}

#[test]
fn password_algorithm_attributes_use_zero_length_parameters() {
  assert_eq!(
    encode_password_algorithm(PASSWORD_ALGORITHM_SHA256),
    vec![0, 2, 0, 0]
  );
  assert_eq!(
    encode_password_algorithms(&[PASSWORD_ALGORITHM_SHA256, PASSWORD_ALGORITHM_MD5]),
    vec![0, 2, 0, 0, 0, 1, 0, 0]
  );
}

#[test]
fn password_algorithm_helpers_reject_parameters_and_truncated_lists() {
  assert_eq!(
    password_algorithm_selection(&encode_password_algorithm(PASSWORD_ALGORITHM_SHA256)),
    Some(PASSWORD_ALGORITHM_SHA256)
  );
  assert_eq!(password_algorithm_selection(&[0, 2, 0, 1]), None);
  assert!(password_algorithms_contains(
    &encode_password_algorithms(&[PASSWORD_ALGORITHM_SHA256, PASSWORD_ALGORITHM_MD5]),
    PASSWORD_ALGORITHM_MD5
  ));
  assert!(!password_algorithms_contains(
    &[0, 2, 0],
    PASSWORD_ALGORITHM_SHA256
  ));
}

#[test]
fn unknown_attributes_are_sorted_and_deduplicated() {
  assert_eq!(
    encode_unknown_attributes(&[0x1234, 0x0001, 0x1234, 0x0020]),
    vec![0x00, 0x01, 0x00, 0x20, 0x12, 0x34]
  );
}

#[test]
fn fingerprint_finalizer_follows_response_integrity() {
  let signed = with_message_integrity_sha256(
    encode_message(BINDING_REQUEST, [5; 12], &[]),
    b"response-integrity-key",
  );
  let response = with_fingerprint(signed);
  let parsed = parse_stun(&response).expect("response must parse");
  assert!(validate_attribute_ordering(&parsed).is_ok());
  assert!(verify_message_integrity_sha256(&parsed, b"response-integrity-key").unwrap());
  assert!(verify_fingerprint(&parsed).unwrap());
}

#[test]
fn duplicate_singleton_security_attributes_are_rejected() {
  let encoded = encode_message(
    BINDING_REQUEST,
    [6; 12],
    &[
      (ATTR_REALM, b"example.test".to_vec()),
      (ATTR_REALM, b"attacker.test".to_vec()),
    ],
  );
  let parsed = parse_stun(&encoded).expect("frame must parse structurally");
  assert!(validate_attribute_ordering(&parsed).is_err());
}

#[test]
fn attributes_after_integrity_are_ignored_for_method_semantics() {
  let key = b"semantic-boundary-key";
  let mut encoded = with_message_integrity(
    encode_message(
      REFRESH_REQUEST,
      [7; 12],
      &[(ATTR_LIFETIME, 600u32.to_be_bytes().to_vec())],
    ),
    key,
  );
  append_attr(&mut encoded, ATTR_LIFETIME, &0u32.to_be_bytes());
  append_attr(&mut encoded, 0x1234, b"ignored");
  let len = u16::try_from(encoded.len() - HEADER_LEN).unwrap();
  encoded[2..4].copy_from_slice(&len.to_be_bytes());

  let parsed = parse_stun(&encoded).expect("frame with ignored tail must parse");
  assert!(validate_attribute_ordering(&parsed).is_ok());
  assert!(verify_message_integrity(&parsed, key).unwrap());
  assert_eq!(attr_u32(&parsed, ATTR_LIFETIME), Some(600));
  assert!(unknown_required_attributes(&parsed).is_empty());
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(32))]

  #[test]
  fn encoded_stun_frames_are_exactly_consumed(
    transaction_id in any::<[u8; 12]>(),
    payload in proptest::collection::vec(any::<u8>(), 0..96),
  ) {
    let encoded = encode_message(
      BINDING_REQUEST,
      transaction_id,
      &[(ATTR_DATA, payload.clone())],
    );
    let parsed = parse_stun(&encoded).expect("encoded frame must parse");
    prop_assert_eq!(parsed.transaction_id, transaction_id);
    prop_assert_eq!(attr_bytes(&parsed, ATTR_DATA), Some(payload.as_slice()));

    let mut trailing = encoded;
    trailing.push(0);
    prop_assert!(parse_stun(&trailing).is_err());
  }

  #[test]
  fn sha256_integrity_detects_tampering(
    transaction_id in any::<[u8; 12]>(),
    payload in proptest::collection::vec(any::<u8>(), 1..96),
  ) {
    let key = b"bounded-property-key";
    let encoded = with_message_integrity_sha256(
      encode_message(BINDING_REQUEST, transaction_id, &[(ATTR_DATA, payload)]),
      key,
    );
    let parsed = parse_stun(&encoded).expect("encoded frame must parse");
    prop_assert!(verify_message_integrity_sha256(&parsed, key).expect("integrity check must run"));

    let mut tampered = encoded;
    tampered[HEADER_LEN + 4] ^= 1;
    let parsed = parse_stun(&tampered).expect("tampered frame remains syntactically valid");
    prop_assert!(!verify_message_integrity_sha256(&parsed, key).expect("integrity check must run"));
  }
}
