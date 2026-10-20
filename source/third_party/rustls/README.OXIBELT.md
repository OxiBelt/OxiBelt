# OxiBelt rustls patch

This directory starts from the crates.io `rustls` 0.23.46 source archive
(`48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf`).
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

The 0.23.46 rebase retains the post-`close_notify` application-write guard
when adopting the upstream record-limit and key-refresh loop. All local
RFC 9846 epoch, outstanding-request, ticket, alert, and downgrade-sentinel
changes remain in place. The shipped upstream `Cargo.lock` is copied unchanged
from the checksum-verified 0.23.46 archive; the root lock owns production.
