use rustls::NamedGroup;

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
