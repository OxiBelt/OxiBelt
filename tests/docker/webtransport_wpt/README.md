# WebTransport WPT gate

The required CI job runs the complete WebTransport tree from web-platform-tests
revision `ece2d7fdc436d4b9a3856877163b07ec15c05354` in Chrome for Testing
`154.0.8037.57` and Firefox `156.0`. The helper image checks out and verifies
the exact WPT Git commit and verifies Chrome downloads against pinned SHA-256
digests. The Firefox helper image
uses its existing pinned Firefox and geckodriver downloads.
Firefox test preferences come from Firefox 156 source commit
`3bf8f468258c2181f455e23d4ffcd6acb8f4cdb1` and are verified against
`firefox-profiles.sha256` when the WPT helper image builds. Browser runs use
those local preferences without fetching them from GitHub.

With prebuilt OxiBelt and Firefox helper images loaded, run:

```sh
OXIBELT_DOCKER_IMAGE=oxibelt:alpine-musl-amd64 \
OXIBELT_TEST_ARTIFACT_DIR=/tmp/oxibelt-webtransport-wpt \
  tests/scripts/run-webtransport-wpt-gate.sh
```

The script builds the pinned WPT helper image if necessary. It runs every
`webtransport/` WPT testharness and crashtest case directly and through
OxiBelt with the same browser
URL and WPT certificate. Each browser must pass session, bidirectional stream,
unidirectional stream, datagram, and close controls on both paths. The gate
rejects missing tests or subtests and any difference in direct and proxied
test or subtest status. If the first Chrome comparison differs only because the
direct worker or shared worker `Close and abort unidirectional stream` subtest
reports the pinned `FIN` timing failure while the proxy passes, the gate runs
one complete direct Chrome replay and requires strict parity against the saved
proxy report. If the first Chrome comparison differs only because the
serviceworker variant of that subtest passes directly and fails through the
proxy with the same exact `FIN` assertion, with both harness results `OK`, the
gate runs one complete proxied Chrome replay and requires strict parity against
the original direct report. The replay must also prove browser packet traversal
through the proxy. Other Chrome mismatches fail immediately, and a replay cannot
trigger another replay. The existing Firefox path permits one complete proxied
replay after a parity mismatch. It retains
both initial and replay JSON reports and run logs under
`OXIBELT_TEST_ARTIFACT_DIR`;
on failure it also retains the proxy log. The runner needs Docker support for
`NET_ADMIN` in its isolated test container to redirect browser WebTransport
UDP traffic while the WPT server stays on loopback.
The proxy fixture disables H1/H2 and enables
`proxy.http3.webtransport_only_connections` on its isolated H3 endpoint so
session close events can close that QUIC connection;
the default shared H3 setting remains disabled in normal configurations.
