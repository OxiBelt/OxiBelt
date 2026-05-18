use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioTimer};

use crate::config::ProxyHttp2Config;

pub(crate) fn apply_server_defaults(
  builder: &mut hyper::server::conn::http2::Builder<TokioExecutor>,
  config: &ProxyHttp2Config,
) {
  builder.adaptive_window(config.adaptive_window);
  builder.max_concurrent_streams(Some(config.max_concurrent_streams));
  builder.max_send_buf_size(config.max_send_buf_size);
  apply_server_keep_alive(builder, config);
}

pub(crate) fn apply_legacy_client_defaults(
  builder: &mut hyper_util::client::legacy::Builder,
  config: &ProxyHttp2Config,
) {
  builder.timer(TokioTimer::new());
  builder.http2_adaptive_window(config.adaptive_window);
  builder.http2_initial_max_send_streams(Some(config.max_concurrent_streams as usize));
  builder.http2_max_send_buf_size(config.max_send_buf_size);
  builder.http2_keep_alive_interval(keep_alive_interval(config));
  builder.http2_keep_alive_timeout(Duration::from_millis(config.keep_alive_timeout_ms));
  builder.http2_keep_alive_while_idle(config.keep_alive_while_idle);
}

pub(crate) fn apply_client_conn_defaults(
  builder: &mut hyper::client::conn::http2::Builder<TokioExecutor>,
  config: &ProxyHttp2Config,
) {
  builder.timer(TokioTimer::new());
  builder.adaptive_window(config.adaptive_window);
  builder.initial_max_send_streams(Some(config.max_concurrent_streams as usize));
  builder.max_send_buf_size(config.max_send_buf_size);
  builder.keep_alive_interval(keep_alive_interval(config));
  builder.keep_alive_timeout(Duration::from_millis(config.keep_alive_timeout_ms));
  builder.keep_alive_while_idle(config.keep_alive_while_idle);
}

fn apply_server_keep_alive(
  builder: &mut hyper::server::conn::http2::Builder<TokioExecutor>,
  config: &ProxyHttp2Config,
) {
  builder.keep_alive_interval(keep_alive_interval(config));
  builder.keep_alive_timeout(Duration::from_millis(config.keep_alive_timeout_ms));
}

fn keep_alive_interval(config: &ProxyHttp2Config) -> Option<Duration> {
  (config.keep_alive_interval_ms > 0).then(|| Duration::from_millis(config.keep_alive_interval_ms))
}
