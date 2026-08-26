# Certificate Transparency operations and downstream verification

OxiBelt keeps its CT Log operator role separate from its optional downstream TLS certificate-health role. The top-level `certificate_transparency` configuration below runs a Log. The independent `[tls.ct]` configuration verifies RFC 6962 v1 SCTs already embedded in configured downstream leaf certificates and can audit or reject non-compliant certificate activation and new handshakes.

Downstream verification reconstructs the RFC 6962 precertificate `TBSCertificate` by removing only the final certificate's SCT-list extension, hashes the issuing certificate's SubjectPublicKeyInfo, and verifies each SCT signature against an authenticated Chromium v3 Log-list key. Parsing, reconstruction, signature verification, and browser-policy evaluation occur during snapshot construction or background refresh, never on the TLS handshake path. Multi-SNI certificates receive independent results bound to the exact certificate identity, and TCP TLS plus HTTP/3 share the same gate.

Managed mode uses the official Chromium v3 detached signature and a build-pinned list-signing public key, persistently and atomically replaces a locked last-known-good bundle, rejects an authenticated update older than the available LKG, and treats a 70-day-old list as stale. Restoring the entire cache volume can also restore its local rollback baseline, so production deployments should protect PVC snapshots and restore authority. `audit` continues serving with bounded degraded status; `enforce` rejects activation or new handshakes. The `chrome-v1` and `firefox-v1` embedded-SCT profiles require distinct Logs and operators according to certificate lifetime and account for Log retirement and operator history. They are operator-facing certificate health policies, not a replacement for browser public-WebPKI validation.

OxiBelt does not modify or re-sign downstream X.509 certificates, does not inject embedded SCTs, does not staple SCTs through TLS extension 18, and does not submit final certificates to public Logs. A private or local OxiBelt Log is not automatically trusted by Chrome, Firefox, Safari, or another public CT program.

OxiBelt can run a Certificate Transparency (CT) log directly in the OxiBelt process. The
implementation exposes the RFC 6962 v1 JSON API and Static CT v1.1 objects over one RFC 6962 tree,
and supports a separate RFC 9162 v2 log identity and tree. A process is intentionally limited to
one writable log. Run separate workloads for each protocol, temporal shard, gateway, and monitor.

The feature is disabled by default. It is not production-supported until the release qualification
gate described below has completed.

## Trust and signing boundary

- The log process reads only the configured DER public identity. Private log keys stay in a
  purpose-bound `oxibelt-keysigner` process using exactly one CT key and immutable signing profile.
- RFC 6962 uses P-256/SHA-256. RFC 9162 permits P-256/SHA-256 or Ed25519 and requires an
  operator-owned OID as its LogID.
- Accepted roots come from an exact-byte, canonical JSON bundle pinned by `sha256:` digest. A
  production bundle requires at least two independent Ed25519 signatures.
- Root changes create a new signed snapshot. They never mutate a running snapshot in place.

Use `oxibeltctl ct roots build`, `sign`, `verify`, and `diff` to prepare and review bundles. Trust
key identifiers are the first eight bytes of SHA-256 over each raw 32-byte Ed25519 public key,
rendered as lowercase hexadecimal.

## Storage and migration

The `local` profile uses an absolute POSIX directory and crash-consistent local state. It is for
development and interoperability tests only. The `production` profile requires PostgreSQL for
sequencing and S3-compatible versioned object storage for immutable publication. Startup verifies
the exact PostgreSQL schema and probes create-only writes, conditional replacement, version IDs,
and checksum readback. OxiBelt never migrates the production schema while serving traffic.

Run the explicit migration before a rollout:

```console
oxibeltctl ct postgres migrate --database-url-env OXIBELT_CT_DATABASE_URL
oxibeltctl ct postgres storage-check --database-url-env OXIBELT_CT_DATABASE_URL
```

Production object storage must use HTTPS virtual-hosted requests, retention and object lock, and an
operator-supplied deletion-denial attestation. Bucket policy must deny delete and version-delete to
the OxiBelt workload identity. PostgreSQL sequences indexes and timestamps under a row lock; a
fenced lease prevents two active-active replicas from publishing the same checkpoint generation.

## Routing

A CT route selects `ct_log` instead of `upstream`, `upstream_pool`, or `static_root`. After normal
route matching, TLS policy, request framing, route circuit admission, request-body bounds, timeout,
rate limit, and worker admission, OxiBelt dispatches directly to CT. CT requests bypass upstream
proxying, static serving, cache, WAF, retry, and response rewriting.

The RFC 6962 surface includes `add-chain`, `add-pre-chain`, `get-sth`, `get-entries`,
`get-proof-by-hash`, `get-sth-consistency`, and `get-roots`. Static CT publishes `checkpoint` plus
immutable entry/tile objects. RFC 9162 uses `/ct/v2/submit-entry` and binary TransItems. Anonymous
submission is allowed; apply the existing route rate limits and body limits at the CT route.

## Shards and maximum merge delay

Temporal shards are half-open Unix-millisecond expiry intervals. Provision and publish the next
shard before its first accepted expiry; never change the range of an existing identity. Use
`oxibeltctl ct shard plan` and `validate` in change review. The supported production MMD is 60
seconds. Admission fails closed when storage, signing, sequencing, publication, or frozen-state
integrity prevents meeting it. An integrity failure freezes only the affected log identity.

## Monitoring and qualification

Run an independent monitor outside the operator trust boundary:

```console
oxibeltctl ct monitor \
  --url https://ct.example.test \
  --log-id 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --public-key log-public-key.sec1 \
  --witness /var/lib/oxibelt-ct-monitor/witness.json \
  --initialize-witness \
  --max-sth-age-seconds 120
```

The monitor verifies the P-256 LogID and STH signature, rejects rollback/forks, verifies consistency
proofs, and advances its witness atomically. The public-key input is the raw 65-byte uncompressed
P-256 SEC1 point; use `--initialize-witness` only after independently confirming the log identity.
Alert on MMD age, pending entries, publication errors,
gateway verification errors, freezes, and monitor failures.

Before declaring a CT shard production-supported, require all of the following on the exact release
candidate:

1. RFC 6962, Static CT, and RFC 9162 interoperability vectors pass.
2. Restart, signer outage, PostgreSQL failover, object-store conflict, and replica-fencing tests pass.
3. Resource-based load tests meet the 60-second MMD without unbounded memory or queue growth.
4. The independent monitor observes no rollback, fork, invalid proof, or stale STH for seven
   continuous days.
5. Root-bundle quorum, shard schedule, object retention/lock, deletion denial, and immutable image
   evidence are reviewed and archived.

OxiBelt does not inject SCTs into downstream TLS certificates and does not provide an ACME service.
