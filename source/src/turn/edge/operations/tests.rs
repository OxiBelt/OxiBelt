use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::config::{
  TurnAuthConfig, TurnAuthMode, TurnEdgeRelayLimitsConfig, TurnEdgeRelayPeerPolicyConfig,
  TurnListenerTlsConfig, TurnPasswordAlgorithm, TurnRelayFamilyConfig, TurnRelayPortRange,
  TurnStaticCredentialConfig, WebRtcTurnListenerMode,
};

use super::*;

const USERNAME: &str = "edge-test-user";
const PASSWORD: &str = "edge-test-password";
const REALM: &str = "edge.example.test";

fn config(start: u16, end: u16) -> WebRtcTurnListenerConfig {
  WebRtcTurnListenerConfig {
    name: "edge-test".to_string(),
    mode: WebRtcTurnListenerMode::EdgeRelay,
    bind_udp: Some("127.0.0.1:3478".parse().expect("UDP bind")),
    bind_udp_additional: Vec::new(),
    bind_tcp: Some("127.0.0.1:3478".parse().expect("TCP bind")),
    bind_tcp_additional: Vec::new(),
    bind_tls: None,
    bind_tls_additional: Vec::new(),
    idle_timeout_ms: 75_000,
    realm: REALM.to_string(),
    auth: TurnAuthConfig {
      mode: TurnAuthMode::Enforce,
      static_credentials: vec![TurnStaticCredentialConfig {
        username: USERNAME.to_string(),
        password: Some(PASSWORD.to_string()),
        password_env: None,
        password_file: None,
      }],
      password_algorithms: vec![TurnPasswordAlgorithm::Sha256],
      ..TurnAuthConfig::default()
    },
    udp_pool: None,
    tcp_pool: None,
    tls_pool: None,
    public_ip: Some("127.0.0.1".parse().expect("public IP")),
    relay_bind_ip: Some("127.0.0.1".parse().expect("relay IP")),
    relay_port_range: Some(TurnRelayPortRange { start, end }),
    relay_families: vec![TurnRelayFamilyConfig {
      family: TurnRelayAddressFamily::Ipv4,
      public_ip: "127.0.0.1".parse().expect("public IP"),
      relay_bind_ip: "127.0.0.1".parse().expect("relay IP"),
      relay_port_range: TurnRelayPortRange { start, end },
    }],
    limits: TurnEdgeRelayLimitsConfig::default(),
    peer_policy: TurnEdgeRelayPeerPolicyConfig::default(),
    stream_outbound_queue_capacity: 32,
    tls: TurnListenerTlsConfig::default(),
  }
}

fn udp_client(port: u16) -> EdgeClient {
  EdgeClient::Udp {
    peer: SocketAddr::from(([127, 0, 0, 1], port)),
    local: "127.0.0.1:3478".parse().expect("listener"),
  }
}

fn authenticated_request(
  config: &WebRtcTurnListenerConfig,
  client: EdgeClient,
  message_type: u16,
  transaction_id: [u8; 12],
  mut attrs: Vec<(u16, Vec<u8>)>,
) -> Vec<u8> {
  let nonce = auth::create_nonce_for_source(
    &config.realm,
    NonceSourceBinding::from_peer(client.peer()),
    &config.auth,
  )
  .expect("nonce");
  attrs.extend([
    (ATTR_USERNAME, USERNAME.as_bytes().to_vec()),
    (ATTR_REALM, config.realm.as_bytes().to_vec()),
    (ATTR_NONCE, nonce.into_bytes()),
    auth::password_algorithms_challenge_attribute(&config.auth),
    (
      ATTR_PASSWORD_ALGORITHM,
      encode_password_algorithm(PASSWORD_ALGORITHM_SHA256),
    ),
  ]);
  let key = Sha256::digest(format!("{USERNAME}:{}:{PASSWORD}", config.realm).as_bytes());
  with_message_integrity_sha256(encode_message(message_type, transaction_id, &attrs), &key)
}

fn error_code(response: &[u8]) -> u16 {
  let message = parse_stun(response).expect("STUN response");
  let value = attr_bytes(&message, ATTR_ERROR_CODE).expect("ERROR-CODE");
  u16::from(value[2]) * 100 + u16::from(value[3])
}

async fn run_request(
  edge: EdgeState,
  config: &WebRtcTurnListenerConfig,
  client: EdgeClient,
  request: &[u8],
) -> Vec<u8> {
  let (tx, mut rx) = mpsc::channel(4);
  process_frame(edge, config, client, EdgeSender::Stream(tx), request)
    .await
    .expect("process TURN request");
  rx.recv().await.expect("TURN response")
}

fn available_pair_config() -> WebRtcTurnListenerConfig {
  for _ in 0..128 {
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe");
    let port = probe.local_addr().expect("probe address").port();
    let even = if port % 2 == 0 {
      port
    } else {
      port.saturating_sub(1)
    };
    drop(probe);
    if even == 0 {
      continue;
    }
    if std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], even))).is_ok()
      && std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], even + 1))).is_ok()
    {
      return config(even, even + 1);
    }
  }
  panic!("failed to find adjacent UDP relay ports")
}

#[tokio::test]
async fn authentication_precedes_unknown_attributes_and_indications_never_respond() {
  let config = config(49_152, 49_160);
  let edge = EdgeState::new(crate::runtime_introspection::RuntimeIntrospectionState::new());
  let client = udp_client(50_000);
  let unauthenticated = encode_message(
    ALLOCATE_REQUEST,
    [1; 12],
    &[
      (ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0]),
      (0x003f, Vec::new()),
    ],
  );
  assert_eq!(
    error_code(&run_request(edge.clone(), &config, client, &unauthenticated).await),
    401
  );

  let authenticated = authenticated_request(
    &config,
    client,
    ALLOCATE_REQUEST,
    [2; 12],
    vec![
      (ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0]),
      (0x003f, Vec::new()),
    ],
  );
  assert_eq!(
    error_code(&run_request(edge.clone(), &config, client, &authenticated).await),
    420
  );

  for attrs in [
    vec![(0x003f, Vec::new())],
    vec![(ATTR_DONT_FRAGMENT, Vec::new())],
  ] {
    let indication = encode_message(SEND_INDICATION, [3; 12], &attrs);
    let (tx, mut rx) = mpsc::channel(1);
    let sender = EdgeSender::Stream(tx);
    process_frame(edge.clone(), &config, client, sender.clone(), &indication)
      .await
      .expect("discard indication");
    assert!(matches!(
      rx.try_recv(),
      Err(mpsc::error::TryRecvError::Empty)
    ));
  }
}

#[tokio::test]
async fn allocate_error_precedence_is_fail_closed() {
  let config = config(49_152, 49_160);
  let edge = EdgeState::new(crate::runtime_introspection::RuntimeIntrospectionState::new());
  let udp = udp_client(50_001);
  let tcp_over_udp = authenticated_request(
    &config,
    udp,
    ALLOCATE_REQUEST,
    [4; 12],
    vec![(ATTR_REQUESTED_TRANSPORT, vec![6, 0, 0, 0])],
  );
  assert_eq!(
    error_code(&run_request(edge.clone(), &config, udp, &tcp_over_udp).await),
    400
  );

  let stream = EdgeClient::Stream {
    id: 7,
    peer: udp.peer(),
  };
  let forbidden = authenticated_request(
    &config,
    stream,
    ALLOCATE_REQUEST,
    [5; 12],
    vec![
      (ATTR_REQUESTED_TRANSPORT, vec![6, 0, 0, 0]),
      (ATTR_DONT_FRAGMENT, Vec::new()),
      (ATTR_REQUESTED_ADDRESS_FAMILY, vec![2, 0, 0, 0]),
    ],
  );
  assert_eq!(
    error_code(&run_request(edge, &config, stream, &forbidden).await),
    400
  );
}

#[tokio::test]
async fn dont_fragment_is_an_authenticated_420_and_existing_tuple_wins_attribute_errors() {
  let config = available_pair_config();
  let edge = EdgeState::new(crate::runtime_introspection::RuntimeIntrospectionState::new());
  let client = udp_client(50_002);
  let dont_fragment = authenticated_request(
    &config,
    client,
    ALLOCATE_REQUEST,
    [6; 12],
    vec![
      (ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0]),
      (ATTR_DONT_FRAGMENT, Vec::new()),
    ],
  );
  assert_eq!(
    error_code(&run_request(edge.clone(), &config, client, &dont_fragment).await),
    420
  );

  let allocate = authenticated_request(
    &config,
    client,
    ALLOCATE_REQUEST,
    [7; 12],
    vec![(ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0])],
  );
  let first = run_request(edge.clone(), &config, client, &allocate).await;
  assert_eq!(
    parse_stun(&first).expect("success").message_type,
    success_type(ALLOCATE_REQUEST)
  );
  let replay = run_request(edge.clone(), &config, client, &allocate).await;
  assert_eq!(
    parse_stun(&replay).expect("replay").message_type,
    success_type(ALLOCATE_REQUEST)
  );

  let malformed_new = authenticated_request(&config, client, ALLOCATE_REQUEST, [8; 12], Vec::new());
  assert_eq!(
    error_code(&run_request(edge, &config, client, &malformed_new).await),
    437
  );
}

#[tokio::test]
async fn even_port_reservation_is_consumed_once_by_another_five_tuple() {
  let config = available_pair_config();
  let edge = EdgeState::new(crate::runtime_introspection::RuntimeIntrospectionState::new());
  let first_client = udp_client(50_003);
  let even = authenticated_request(
    &config,
    first_client,
    ALLOCATE_REQUEST,
    [9; 12],
    vec![
      (ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0]),
      (ATTR_EVEN_PORT, vec![0x80]),
    ],
  );
  let first = run_request(edge.clone(), &config, first_client, &even).await;
  let first = parse_stun(&first).expect("EVEN-PORT success");
  assert_eq!(first.message_type, success_type(ALLOCATE_REQUEST));
  let first_addr = attr_xor_addr(&first, ATTR_XOR_RELAYED_ADDRESS)
    .expect("relayed address")
    .expect("relayed address present");
  assert_eq!(first_addr.port() % 2, 0);
  let token = attr_bytes(&first, ATTR_RESERVATION_TOKEN)
    .expect("reservation token")
    .to_vec();
  assert_eq!(token.len(), 8);

  let second_client = udp_client(50_004);
  let consume = authenticated_request(
    &config,
    second_client,
    ALLOCATE_REQUEST,
    [10; 12],
    vec![
      (ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0]),
      (ATTR_RESERVATION_TOKEN, token.clone()),
    ],
  );
  let second = run_request(edge.clone(), &config, second_client, &consume).await;
  let second = parse_stun(&second).expect("reservation success");
  let second_addr = attr_xor_addr(&second, ATTR_XOR_RELAYED_ADDRESS)
    .expect("relayed address")
    .expect("relayed address present");
  assert_eq!(second_addr.port(), first_addr.port() + 1);
  assert!(attr_bytes(&second, ATTR_RESERVATION_TOKEN).is_none());

  let third_client = udp_client(50_005);
  let reuse = authenticated_request(
    &config,
    third_client,
    ALLOCATE_REQUEST,
    [11; 12],
    vec![
      (ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0]),
      (ATTR_RESERVATION_TOKEN, token),
    ],
  );
  assert_eq!(
    error_code(&run_request(edge, &config, third_client, &reuse).await),
    508
  );
}
