# Verified client identity over upstream mTLS

OxiBelt can authenticate a downstream client, forward its verified leaf
certificate in the HTTP `Client-Cert` header, and authenticate separately to
the application upstream with OxiBelt's own client certificate. These are
existing configuration features composed into one deployment.

| Connection or field | Identity | Verifier |
| --- | --- | --- |
| Downstream TLS client | End user's client certificate | OxiBelt's `tls.client_auth` policy |
| Upstream TLS client | OxiBelt's configured upstream certificate | Backend TLS authentication and authorization |
| `Client-Cert` request header | Verified downstream leaf certificate | Backend application, after authenticating OxiBelt |

The backend must require and authorize OxiBelt's upstream TLS identity before
trusting `Client-Cert`. Use a dedicated upstream-client CA or an explicit
backend identity allowlist, and restrict backend access to authorized proxies.
The backend continues to apply its own application authorization to the
forwarded client identity. A valid downstream certificate alone does not grant
access to every application resource.

OxiBelt receives no downstream client private key. It sends the leaf as the
colon-delimited Base64 DER byte sequence specified by
[RFC 9440](https://www.rfc-editor.org/rfc/rfc9440.html#section-2.2); no private
key or certificate chain is forwarded. Client-supplied certificate header
values and their case/hyphen/underscore aliases cannot replace this value.
See [the forwarding contract](Configuration.md#forwarding-verified-downstream-client-certificates)
for header limits, cache isolation, compression, and optional-authentication
behavior.

## Native deployment

Use [the complete TOML example](../source/config/verified-client-identity.toml),
adjusting the public hostname, backend address, and certificate paths for the
deployment. For a config at `/etc/oxibelt/config/oxibelt.toml`, the referenced
files are relative to `/etc/oxibelt/cert`:

| Path below the certificate root | Purpose |
| --- | --- |
| `edge/server.pem`, `edge/server.key` | OxiBelt's downstream server identity |
| `downstream/ca.pem` | CA trusted to issue downstream client certificates |
| `backend/ca.pem` | CA used to verify the upstream server |
| `upstream-client/orders/client.pem`, `upstream-client/orders/client.key` | OxiBelt's separate upstream client identity |

Issue server certificates for the configured server names and client
certificates for client authentication. Keep each private key with its owner;
OxiBelt needs neither the downstream client's private key nor any CA signing
key. Upstream client keys must meet the existing secure-file checks; local
owner-only `0600` files or the supported read-only Secret projection are
appropriate. Do not place credential material in TOML or version control.

After installing the files, validate before starting the service:

```sh
oxibelt --config /etc/oxibelt/config/oxibelt.toml --check
```

`tls.client_auth.mode = "require"` rejects clients without an accepted
certificate at the TLS handshake. The backend must also require client
authentication: configuring `upstreams.tls.client_identity` makes a credential
available when the backend requests it. Upstream CA and hostname verification
remain enabled independently.

For direct Helm deployments, use the existing
[`upstreamTls.clientIdentitySecretProjections` support](KubernetesDeployment.md)
to mount the upstream pair, and keep downstream client-authentication policy
in the operator's base configuration.

## Rotation and failure behavior

Native upstream identity files are full-reload inputs. Validate and activate a
full replacement configuration snapshot after replacing the pair; a
downstream-only TLS refresh does not rotate upstream credentials. New snapshots
construct the upstream clients with the replacement material. Existing
connections follow the normal drain lifecycle; rotation does not promise
instant revocation of an established connection.

Absent optional downstream credentials would cause an absent header under the
existing forwarding contract. This example selects required downstream mTLS
instead. Missing or invalid upstream credentials cannot authenticate to the
mTLS-required backend. Invalid configuration material rejects activation;
runtime TLS failures do not authorize an anonymous fallback.

## Reproduce the native qualification

The test generates disposable CAs and separate credentials, exercises
HTTP/1.1, HTTP/2, HTTP/3, WebSocket, and WebTransport, and checks the backend's
authenticated peer identity together with the exact RFC 9440 header.
It also checks spoofed headers, cache separation, upstream HTTP/3 connection
reuse across clients, downstream session resumption, and certificate rejection
on both TLS connections.

```sh
tests/scripts/run-proxy-integration-matrix.sh protocol-proxying client-certificate-forwarding-mtls-rfc9440
tests/scripts/run-proxy-integration-matrix.sh protocol-proxying client-certificate-forwarding-real-protocols
```

The second command retains the existing optional-authentication and encoding
regressions. Test prerequisites and cleanup conventions are described in
[tests/README.md](../tests/README.md).
