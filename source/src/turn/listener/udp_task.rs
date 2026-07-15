//! Activation and lifecycle reporting for the TURN UDP listener task.

use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::config::WebRtcTurnListenerConfig;
use crate::state::AppHandle;

use super::{EdgeState, serve_turn_udp};

pub(super) fn spawn(
  tasks: &mut Vec<JoinHandle<()>>,
  udp: std::net::UdpSocket,
  config: WebRtcTurnListenerConfig,
  state: AppHandle,
  shutdown: watch::Receiver<bool>,
  edge: EdgeState,
  error_tx: mpsc::UnboundedSender<anyhow::Error>,
) {
  let udp = match UdpSocket::from_std(udp) {
    Ok(udp) => Arc::new(udp),
    Err(error) => {
      let _ = error_tx
        .send(anyhow::Error::new(error).context("failed to activate WebRTC TURN UDP listener"));
      return;
    }
  };
  tasks.push(tokio::spawn(async move {
    if let Err(error) = serve_turn_udp(udp, config, state, shutdown, edge).await {
      let _ = error_tx.send(error.context("WebRTC TURN UDP listener failed"));
    }
  }));
}
