use rustls::NamedGroup;

#[test]
fn secp256r1mlkem768_is_opt_in_and_uses_the_final_rfc10024_group() {
  let defaults = oxibelt::tls::aws_lc_provider_with_secp256r1mlkem768(false);
  let enabled = oxibelt::tls::aws_lc_provider_with_secp256r1mlkem768(true);
  let names = |provider: &rustls::crypto::CryptoProvider| {
    provider
      .kx_groups
      .iter()
      .map(|group| group.name())
      .collect::<Vec<_>>()
  };
  assert_eq!(
    names(&defaults),
    names(&rustls::crypto::aws_lc_rs::default_provider())
  );
  assert!(!names(&defaults).contains(&NamedGroup::secp256r1MLKEM768));
  assert_eq!(
    names(&enabled),
    vec![
      NamedGroup::X25519MLKEM768,
      NamedGroup::secp256r1MLKEM768,
      NamedGroup::X25519,
      NamedGroup::secp256r1,
      NamedGroup::secp384r1
    ]
  );
  assert_eq!(u16::from(NamedGroup::secp256r1MLKEM768), 0x11eb);
}

#[test]
fn rfc10024_native_key_exchange_layout_and_invalid_shares() {
  let group = rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768;
  let client = group.start().expect("client key generation");
  assert_eq!(client.pub_key().len(), 1249);
  assert_eq!(
    client.pub_key()[0],
    4,
    "uncompressed P-256 point comes first"
  );
  let server = group
    .start_and_complete(client.pub_key())
    .expect("server key exchange");
  assert_eq!(server.pub_key.len(), 1153);
  assert_eq!(server.pub_key[0], 4);
  let secret = client.complete(&server.pub_key).expect("client completion");
  assert_eq!(secret.secret_bytes().len(), 64);
  assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
  for length in [0, 65, 1184, 1248, 1250] {
    assert!(group.start_and_complete(&vec![0; length]).is_err());
  }
  let client = group.start().expect("client key generation");
  let mut invalid_point = client.pub_key().to_vec();
  invalid_point[..65].fill(0);
  assert!(group.start_and_complete(&invalid_point).is_err());
  assert!(client.complete(&vec![0; 1152]).is_err());
}

#[test]
fn aws_lc_provider_prefers_x25519mlkem768() {
  let provider = rustls::crypto::aws_lc_rs::default_provider();
  assert!(
    provider
      .kx_groups
      .iter()
      .any(|group| group.name() == NamedGroup::X25519MLKEM768),
    "the current aws-lc-rs provider should offer X25519MLKEM768",
  );
  assert_eq!(
    provider.kx_groups[0].name(),
    NamedGroup::X25519MLKEM768,
    "the aws-lc-rs provider should prefer X25519MLKEM768 first",
  );
}

#[test]
fn aws_lc_provider_still_offers_x25519() {
  let provider = rustls::crypto::aws_lc_rs::default_provider();
  assert!(
    provider
      .kx_groups
      .iter()
      .any(|group| group.name() == NamedGroup::X25519),
    "the aws-lc-rs provider should continue to offer X25519",
  );
}
