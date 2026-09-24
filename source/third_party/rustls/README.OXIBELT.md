# OxiBelt rustls patch

This directory starts from the crates.io `rustls` 0.23.45 source archive
(`0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634`).
It remains licensed under Apache-2.0 OR ISC OR MIT.

The local changes address RFC 9846 requirements that cannot be expressed
through the released rustls API:

- Bound the sender's TLS 1.3 key-update epoch to `2^48-1`, and avoid a second
  `update_requested` until the peer sends a KeyUpdate.
- Refuse buffered and unbuffered application writes after `close_notify` when
  an exhausted sending epoch closes the connection.
- Silently ignore NewSessionTicket when `Resumption::disabled()` is selected.
- Recognize the `general_error` alert code.
- Provide an explicit, default-off TLS 1.2 downgrade sentinel setting for
  applications that select distinct TLS 1.2 and TLS 1.3 server configs.

The root `Cargo.toml` patches crates.io rustls to this source so all workspace
dependents use the same implementation. Keep this patch narrow and compare it
with each future upstream rustls release before updating the archive.
