use super::*;
use proptest::prelude::*;

use crate::turn::protocol::{
  ALLOCATE_REQUEST, BINDING_REQUEST, encode_message, encode_password_algorithm,
  encode_password_algorithms, parse_stun, verify_message_integrity,
  verify_message_integrity_sha256, with_message_integrity, with_message_integrity_sha256,
};

fn static_auth() -> TurnAuthConfig {
  TurnAuthConfig {
    mode: TurnAuthMode::Validate,
    static_credentials: vec![crate::config::TurnStaticCredentialConfig {
      username: "user".into(),
      password: Some("password".into()),
      password_env: None,
      password_file: None,
    }],
    ..TurnAuthConfig::default()
  }
}

#[test]
fn modern_sha256_long_term_auth_requires_exact_realm() {
  let auth = static_auth();
  let key = long_term_key(
    "user",
    "example.test",
    "password",
    TurnPasswordAlgorithm::Sha256,
  );
  let raw = with_message_integrity_sha256(
    encode_message(
      ALLOCATE_REQUEST,
      [7; 12],
      &[
        (ATTR_USERNAME, b"user".to_vec()),
        (ATTR_REALM, b"example.test".to_vec()),
        (
          ATTR_PASSWORD_ALGORITHMS,
          password_algorithms_challenge_value(&auth),
        ),
        (ATTR_PASSWORD_ALGORITHM, vec![0, 2, 0, 0]),
      ],
    ),
    &key,
  );
  let message = parse_stun(&raw).expect("valid STUN");
  assert_eq!(
    validate_message(&auth, "example.test", &message).unwrap(),
    AuthDecision::Pass
  );
  assert_eq!(
    validate_message(&auth, "other.test", &message).unwrap(),
    AuthDecision::Invalid
  );

  let normalized_realm = "caf\u{e9}";
  let decomposed_realm = "cafe\u{301}";
  let key = long_term_key(
    "user",
    normalized_realm,
    "password",
    TurnPasswordAlgorithm::Sha256,
  );
  let raw = with_message_integrity_sha256(
    encode_message(
      ALLOCATE_REQUEST,
      [8; 12],
      &[
        (ATTR_USERNAME, b"user".to_vec()),
        (ATTR_REALM, decomposed_realm.as_bytes().to_vec()),
        (
          ATTR_PASSWORD_ALGORITHMS,
          password_algorithms_challenge_value(&auth),
        ),
        (ATTR_PASSWORD_ALGORITHM, vec![0, 2, 0, 0]),
      ],
    ),
    &key,
  );
  assert_eq!(
    validate_message(&auth, normalized_realm, &parse_stun(&raw).unwrap()).unwrap(),
    AuthDecision::Pass,
    "realm comparison must use the same RFC 8265 normalization as key derivation"
  );
}

#[test]
fn nonce_is_bound_to_the_observed_source_tuple() {
  let auth = static_auth();
  let source = NonceSourceBinding::from_peer("192.0.2.1:9999".parse().unwrap());
  let nonce = create_nonce_for_source("example.test", source, &auth).unwrap();
  let second_nonce = create_nonce_for_source("example.test", source, &auth).unwrap();
  assert_eq!(&nonce[..9], "obMatJos2");
  assert_eq!(&nonce[9..13], "wAAA");
  assert!(nonce.starts_with("obMatJos2wAAA:v2:"));
  assert!(nonce.len() < 128);
  assert_ne!(nonce, second_nonce, "new nonces need fresh CSPRNG material");
  assert!(verify_nonce_for_source(&nonce, "example.test", source, &auth).unwrap());
  assert!(verify_nonce_for_source(&second_nonce, "example.test", source, &auth).unwrap());
  let feature_tampered = nonce.replacen("obMatJos2wAAA", "obMatJos2gAAA", 1);
  assert!(
    !verify_nonce_for_source(&feature_tampered, "example.test", source, &auth).unwrap(),
    "the nonce feature set is part of the authenticated policy"
  );
  assert!(
    !verify_nonce_for_source(
      &nonce,
      "example.test",
      NonceSourceBinding::from_peer("192.0.2.2:9999".parse().unwrap()),
      &auth
    )
    .unwrap()
  );

  let mut downgraded = auth.clone();
  downgraded.password_algorithms = vec![TurnPasswordAlgorithm::Md5];
  assert!(
    !verify_nonce_for_source(&nonce, "example.test", source, &downgraded).unwrap(),
    "nonce must not survive an advertised-algorithm downgrade"
  );

  let rest_only = TurnAuthConfig {
    rest_shared_secret: Some("rest-secret".into()),
    ..TurnAuthConfig::default()
  };
  let rest_nonce = create_nonce_for_source("example.test", source, &rest_only).unwrap();
  assert!(rest_nonce.starts_with("obMatJos2gAAA:v2:"));
  assert!(verify_nonce_for_source(&rest_nonce, "example.test", source, &rest_only).unwrap());
}

#[test]
fn authenticated_context_hides_the_key_and_signs_with_the_selected_algorithm() {
  let auth = static_auth();
  let key = long_term_key(
    "user",
    "example.test",
    "password",
    TurnPasswordAlgorithm::Sha256,
  );
  let raw = with_message_integrity_sha256(
    encode_message(
      ALLOCATE_REQUEST,
      [8; 12],
      &[
        (ATTR_USERNAME, b"user".to_vec()),
        (ATTR_REALM, b"example.test".to_vec()),
        (
          ATTR_PASSWORD_ALGORITHMS,
          password_algorithms_challenge_value(&auth),
        ),
        (
          ATTR_PASSWORD_ALGORITHM,
          super::super::protocol::encode_password_algorithm(PASSWORD_ALGORITHM_SHA256),
        ),
      ],
    ),
    &key,
  );
  let message = parse_stun(&raw).unwrap();
  let AuthenticatedContextDecision::Pass(context) =
    authenticated_context_for_source(&auth, "example.test", None, &message).unwrap()
  else {
    panic!("expected an authenticated context");
  };
  assert_eq!(context.username(), "user");
  assert_eq!(context.password_algorithm(), TurnPasswordAlgorithm::Sha256);
  assert!(!format!("{context:?}").contains("\"password\""));

  let signed = context.with_response_integrity(encode_message(BINDING_REQUEST, [8; 12], &[]));
  assert!(verify_message_integrity_sha256(&parse_stun(&signed).unwrap(), &key).unwrap());
}

#[test]
fn modern_md5_derivation_still_uses_sha256_response_integrity() {
  let auth = static_auth();
  let key = long_term_key(
    "user",
    "example.test",
    "password",
    TurnPasswordAlgorithm::Md5,
  );
  let raw = with_message_integrity_sha256(
    encode_message(
      ALLOCATE_REQUEST,
      [11; 12],
      &[
        (ATTR_USERNAME, b"user".to_vec()),
        (ATTR_REALM, b"example.test".to_vec()),
        (
          ATTR_PASSWORD_ALGORITHMS,
          password_algorithms_challenge_value(&auth),
        ),
        (
          ATTR_PASSWORD_ALGORITHM,
          encode_password_algorithm(PASSWORD_ALGORITHM_MD5),
        ),
      ],
    ),
    &key,
  );
  let message = parse_stun(&raw).unwrap();
  let AuthenticatedContextDecision::Pass(context) =
    authenticated_context_for_source(&auth, "example.test", None, &message).unwrap()
  else {
    panic!("expected modern MD5-derived credentials to authenticate");
  };
  let response = context.with_response_integrity(encode_message(BINDING_REQUEST, [11; 12], &[]));
  let response = parse_stun(&response).unwrap();
  assert!(verify_message_integrity_sha256(&response, &key).unwrap());
  assert!(!verify_message_integrity(&response, &key).unwrap());
}

#[test]
fn modern_auth_requires_the_exact_echoed_algorithm_list_and_selection() {
  let auth = static_auth();
  let key = long_term_key(
    "user",
    "example.test",
    "password",
    TurnPasswordAlgorithm::Sha256,
  );
  let raw = with_message_integrity_sha256(
    encode_message(
      ALLOCATE_REQUEST,
      [12; 12],
      &[
        (ATTR_USERNAME, b"user".to_vec()),
        (ATTR_REALM, b"example.test".to_vec()),
        (
          ATTR_PASSWORD_ALGORITHMS,
          encode_password_algorithms(&[PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256]),
        ),
        (
          ATTR_PASSWORD_ALGORITHM,
          encode_password_algorithm(PASSWORD_ALGORITHM_SHA256),
        ),
      ],
    ),
    &key,
  );
  assert!(matches!(
    authenticated_context_for_source(&auth, "example.test", None, &parse_stun(&raw).unwrap())
      .unwrap(),
    AuthenticatedContextDecision::BadRequest
  ));

  let raw = with_message_integrity_sha256(
    encode_message(
      ALLOCATE_REQUEST,
      [13; 12],
      &[
        (ATTR_USERNAME, b"user".to_vec()),
        (ATTR_REALM, b"example.test".to_vec()),
        (
          ATTR_PASSWORD_ALGORITHMS,
          password_algorithms_challenge_value(&auth),
        ),
        (ATTR_PASSWORD_ALGORITHM, encode_password_algorithm(0x7fff)),
      ],
    ),
    &key,
  );
  assert!(matches!(
    authenticated_context_for_source(&auth, "example.test", None, &parse_stun(&raw).unwrap())
      .unwrap(),
    AuthenticatedContextDecision::BadRequest
  ));
}

#[test]
fn no_integrity_is_unauthorized_but_modern_omissions_are_bad_requests() {
  let auth = static_auth();
  let no_integrity_bytes = encode_message(
    ALLOCATE_REQUEST,
    [14; 12],
    &[(ATTR_USERNAME, b"user".to_vec())],
  );
  let no_integrity = parse_stun(&no_integrity_bytes).unwrap();
  assert!(matches!(
    authenticated_context_for_source(&auth, "example.test", None, &no_integrity).unwrap(),
    AuthenticatedContextDecision::Missing
  ));

  let key = long_term_key(
    "user",
    "example.test",
    "password",
    TurnPasswordAlgorithm::Sha256,
  );
  let missing_list = with_message_integrity_sha256(
    encode_message(
      ALLOCATE_REQUEST,
      [15; 12],
      &[
        (ATTR_USERNAME, b"user".to_vec()),
        (ATTR_REALM, b"example.test".to_vec()),
        (
          ATTR_PASSWORD_ALGORITHM,
          encode_password_algorithm(PASSWORD_ALGORITHM_SHA256),
        ),
      ],
    ),
    &key,
  );
  assert!(matches!(
    authenticated_context_for_source(
      &auth,
      "example.test",
      None,
      &parse_stun(&missing_list).unwrap()
    )
    .unwrap(),
    AuthenticatedContextDecision::BadRequest
  ));

  let invalid_credentials = with_message_integrity_sha256(
    encode_message(
      ALLOCATE_REQUEST,
      [16; 12],
      &[
        (ATTR_USERNAME, b"user".to_vec()),
        (ATTR_REALM, b"example.test".to_vec()),
        (
          ATTR_PASSWORD_ALGORITHMS,
          password_algorithms_challenge_value(&auth),
        ),
        (
          ATTR_PASSWORD_ALGORITHM,
          encode_password_algorithm(PASSWORD_ALGORITHM_SHA256),
        ),
      ],
    ),
    b"incorrect-key",
  );
  assert!(matches!(
    authenticated_context_for_source(
      &auth,
      "example.test",
      None,
      &parse_stun(&invalid_credentials).unwrap()
    )
    .unwrap(),
    AuthenticatedContextDecision::Invalid
  ));
}

#[test]
fn missing_nonce_is_bad_request_and_stale_nonce_is_distinguished_after_authentication() {
  let mut auth = static_auth();
  auth.mode = TurnAuthMode::Enforce;
  let source = NonceSourceBinding::from_peer("192.0.2.11:3478".parse().unwrap());
  let key = long_term_key(
    "user",
    "example.test",
    "password",
    TurnPasswordAlgorithm::Sha256,
  );
  let attrs = |nonce: Option<String>| {
    let mut attrs = vec![
      (ATTR_USERNAME, b"user".to_vec()),
      (ATTR_REALM, b"example.test".to_vec()),
      (
        ATTR_PASSWORD_ALGORITHMS,
        password_algorithms_challenge_value(&auth),
      ),
      (
        ATTR_PASSWORD_ALGORITHM,
        encode_password_algorithm(PASSWORD_ALGORITHM_SHA256),
      ),
    ];
    if let Some(nonce) = nonce {
      attrs.push((ATTR_NONCE, nonce.into_bytes()));
    }
    attrs
  };
  let missing_nonce = with_message_integrity_sha256(
    encode_message(ALLOCATE_REQUEST, [17; 12], &attrs(None)),
    &key,
  );
  assert!(matches!(
    enforce_authenticated_context_for_source(
      &auth,
      "example.test",
      source,
      &parse_stun(&missing_nonce).unwrap()
    )
    .unwrap(),
    AuthenticatedContextDecision::BadRequestAuthenticated(_)
  ));

  let stale_nonce = format!(
    "{}x",
    create_nonce_for_source("example.test", source, &auth).unwrap()
  );
  let stale = with_message_integrity_sha256(
    encode_message(ALLOCATE_REQUEST, [18; 12], &attrs(Some(stale_nonce))),
    &key,
  );
  assert!(matches!(
    enforce_authenticated_context_for_source(
      &auth,
      "example.test",
      source,
      &parse_stun(&stale).unwrap()
    )
    .unwrap(),
    AuthenticatedContextDecision::StaleNonce(_)
  ));
}

#[test]
fn challenge_advertises_configured_password_algorithms_in_order() {
  let auth = static_auth();
  assert_eq!(
    password_algorithms_challenge_attribute(&auth),
    (
      super::super::protocol::ATTR_PASSWORD_ALGORITHMS,
      vec![0, 2, 0, 0, 0, 1, 0, 0]
    )
  );
}

#[test]
fn runtime_secret_file_read_rejects_an_oversized_post_admission_replacement() {
  let directory = tempfile::tempdir().expect("temporary directory");
  let path = directory.path().join("turn-secret");
  std::fs::write(&path, vec![b'x'; MAX_TURN_SECRET_FILE_BYTES + 1])
    .expect("oversized replacement must be written");
  let error = read_secret_file(
    &path,
    "TURN static credential password file",
    MAX_TURN_SECRET_FILE_BYTES,
  )
  .expect_err("runtime read must enforce its size limit");
  assert!(error.to_string().contains("exceeds the permitted size"));
  assert!(!error.to_string().contains("turn-secret"));
}

#[test]
fn legacy_md5_integrity_remains_compatible() {
  let auth = static_auth();
  let key = long_term_key(
    "user",
    "example.test",
    "password",
    TurnPasswordAlgorithm::Md5,
  );
  let raw = with_message_integrity(
    encode_message(
      ALLOCATE_REQUEST,
      [7; 12],
      &[
        (ATTR_USERNAME, b"user".to_vec()),
        (ATTR_REALM, b"example.test".to_vec()),
      ],
    ),
    &key,
  );
  assert_eq!(
    validate_message(&auth, "example.test", &parse_stun(&raw).unwrap()).unwrap(),
    AuthDecision::Pass
  );
}

#[test]
fn long_term_keys_apply_rfc8265_opaque_string_processing() {
  let normalized = long_term_key_checked(
    "user",
    "caf\u{e9}",
    "open sesame",
    TurnPasswordAlgorithm::Sha256,
  )
  .unwrap();
  let mapped = long_term_key_checked(
    "user",
    "cafe\u{301}",
    "open\u{a0}sesame",
    TurnPasswordAlgorithm::Sha256,
  )
  .unwrap();
  assert_eq!(mapped, normalized, "NFC and non-ASCII space mapping apply");
  assert!(
    long_term_key_checked(
      "user",
      "example.test",
      "password\u{7}",
      TurnPasswordAlgorithm::Sha256,
    )
    .is_err(),
    "disallowed PRECIS code points must fail closed"
  );
}

#[test]
fn modern_integrity_pair_is_accepted_but_kept_distinct_from_legacy_md5() {
  let auth = static_auth();
  let md5_key = long_term_key(
    "user",
    "example.test",
    "password",
    TurnPasswordAlgorithm::Md5,
  );
  let modern = with_message_integrity(
    with_message_integrity_sha256(
      encode_message(
        ALLOCATE_REQUEST,
        [21; 12],
        &[
          (ATTR_USERNAME, b"user".to_vec()),
          (ATTR_REALM, b"example.test".to_vec()),
          (
            ATTR_PASSWORD_ALGORITHMS,
            password_algorithms_challenge_value(&auth),
          ),
          (
            ATTR_PASSWORD_ALGORITHM,
            encode_password_algorithm(PASSWORD_ALGORITHM_MD5),
          ),
        ],
      ),
      &md5_key,
    ),
    &md5_key,
  );
  let modern = parse_stun(&modern).expect("modern integrity pair must parse");
  let AuthenticatedContextDecision::Pass(modern_context) =
    authenticated_context_for_source(&auth, "example.test", None, &modern).unwrap()
  else {
    panic!("modern integrity pair must authenticate");
  };

  let legacy = with_message_integrity(
    encode_message(
      ALLOCATE_REQUEST,
      [22; 12],
      &[
        (ATTR_USERNAME, b"user".to_vec()),
        (ATTR_REALM, b"example.test".to_vec()),
      ],
    ),
    &md5_key,
  );
  let legacy = parse_stun(&legacy).expect("legacy request must parse");
  let AuthenticatedContextDecision::Pass(legacy_context) =
    authenticated_context_for_source(&auth, "example.test", None, &legacy).unwrap()
  else {
    panic!("legacy request must authenticate");
  };

  assert!(!modern_context.has_same_credentials(&legacy_context));
}

#[test]
fn userhash_authentication_resolves_a_static_credential() {
  let auth = static_auth();
  let userhash = Sha256::digest(b"user:example.test").to_vec();
  let key = long_term_key(
    "user",
    "example.test",
    "password",
    TurnPasswordAlgorithm::Sha256,
  );
  let raw = with_message_integrity_sha256(
    encode_message(
      ALLOCATE_REQUEST,
      [9; 12],
      &[
        (ATTR_USERHASH, userhash),
        (ATTR_REALM, b"example.test".to_vec()),
        (
          ATTR_PASSWORD_ALGORITHMS,
          password_algorithms_challenge_value(&auth),
        ),
        (
          ATTR_PASSWORD_ALGORITHM,
          super::super::protocol::encode_password_algorithm(PASSWORD_ALGORITHM_SHA256),
        ),
      ],
    ),
    &key,
  );
  assert_eq!(
    validate_message(&auth, "example.test", &parse_stun(&raw).unwrap()).unwrap(),
    AuthDecision::Pass
  );
}

#[test]
fn unknown_well_formed_userhash_is_invalid_credentials() {
  let auth = static_auth();
  let key = long_term_key(
    "user",
    "example.test",
    "password",
    TurnPasswordAlgorithm::Sha256,
  );
  let raw = with_message_integrity_sha256(
    encode_message(
      ALLOCATE_REQUEST,
      [23; 12],
      &[
        (ATTR_USERHASH, vec![0x5a; 32]),
        (ATTR_REALM, b"example.test".to_vec()),
        (
          ATTR_PASSWORD_ALGORITHMS,
          password_algorithms_challenge_value(&auth),
        ),
        (
          ATTR_PASSWORD_ALGORITHM,
          encode_password_algorithm(PASSWORD_ALGORITHM_SHA256),
        ),
      ],
    ),
    &key,
  );
  assert!(matches!(
    authenticated_context_for_source(&auth, "example.test", None, &parse_stun(&raw).unwrap())
      .unwrap(),
    AuthenticatedContextDecision::Invalid
  ));
}

#[test]
fn username_and_userhash_combination_is_rejected() {
  let auth = static_auth();
  let userhash = Sha256::digest(b"user:example.test").to_vec();
  let key = long_term_key(
    "user",
    "example.test",
    "password",
    TurnPasswordAlgorithm::Sha256,
  );
  let raw = with_message_integrity_sha256(
    encode_message(
      ALLOCATE_REQUEST,
      [10; 12],
      &[
        (ATTR_USERNAME, b"user".to_vec()),
        (ATTR_USERHASH, userhash),
        (ATTR_REALM, b"example.test".to_vec()),
        (
          ATTR_PASSWORD_ALGORITHMS,
          password_algorithms_challenge_value(&auth),
        ),
        (
          ATTR_PASSWORD_ALGORITHM,
          super::super::protocol::encode_password_algorithm(PASSWORD_ALGORITHM_SHA256),
        ),
      ],
    ),
    &key,
  );
  assert_eq!(
    validate_message(&auth, "example.test", &parse_stun(&raw).unwrap()).unwrap(),
    AuthDecision::Invalid
  );
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(32))]

  #[test]
  fn nonce_rejects_tampering_and_a_different_source_tuple(
    peer_octets in any::<[u8; 4]>(),
    port in 1u16..=u16::MAX,
  ) {
    let auth = static_auth();
    let peer = SocketAddr::from((peer_octets, port));
    let source = NonceSourceBinding::from_peer(peer);
    let nonce = create_nonce_for_source("example.test", source, &auth).expect("nonce must be created");
    prop_assert!(verify_nonce_for_source(&nonce, "example.test", source, &auth).expect("nonce must verify"));

    let mut tampered = nonce.clone().into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).expect("nonce stays ASCII");
    prop_assert!(!verify_nonce_for_source(&tampered, "example.test", source, &auth).expect("tampered nonce must be checked"));

    let other_port = if port == u16::MAX { 1 } else { port + 1 };
    let different_source = NonceSourceBinding::from_peer(SocketAddr::from((peer_octets, other_port)));
    prop_assert!(!verify_nonce_for_source(&nonce, "example.test", different_source, &auth).expect("nonce must be checked"));
  }
}
