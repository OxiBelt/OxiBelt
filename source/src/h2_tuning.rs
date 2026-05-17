use hyper_util::rt::{TokioExecutor, TokioTimer};

const MAX_CONCURRENT_STREAMS: u32 = 1024;
const MAX_SEND_BUF_SIZE: usize = 1024 * 1024;

pub(crate) fn apply_server_defaults(
  builder: &mut hyper::server::conn::http2::Builder<TokioExecutor>,
) {
  builder.adaptive_window(true);
  builder.max_concurrent_streams(Some(MAX_CONCURRENT_STREAMS));
  builder.max_send_buf_size(MAX_SEND_BUF_SIZE);
}

pub(crate) fn apply_legacy_client_defaults(builder: &mut hyper_util::client::legacy::Builder) {
  builder.timer(TokioTimer::new());
  builder.pool_timer(TokioTimer::new());
  builder.http2_adaptive_window(true);
  builder.http2_initial_max_send_streams(Some(MAX_CONCURRENT_STREAMS as usize));
  builder.http2_max_send_buf_size(MAX_SEND_BUF_SIZE);
}

pub(crate) fn apply_client_conn_defaults(
  builder: &mut hyper::client::conn::http2::Builder<TokioExecutor>,
) {
  builder.adaptive_window(true);
  builder.initial_max_send_streams(Some(MAX_CONCURRENT_STREAMS as usize));
  builder.max_send_buf_size(MAX_SEND_BUF_SIZE);
}
