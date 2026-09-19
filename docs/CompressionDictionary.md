# Compression Dictionary Transport

Compression Dictionary Transport (RFC 9842) is an explicit per-route feature.
It adds `dcb` (dictionary Brotli) and `dcz` (dictionary Zstandard), with separate
upstream-client and downstream-server dictionary scopes. Existing compression
and routes retain their defaults when the feature is disabled.

## Configuration

Enable `[compression_dictionary]`, declare immutable `dictionaries`, bounded
`stores`, and `profiles`, then set `compression_dictionary_profile` on an HTTP
route. A dictionary declaration contains `name`, `path`, lowercase SHA-256
`sha256`, `public`, and its exact HTTPS resource `url`. Paths are resolved at
configuration load; configured bytes are verified and pinned by the runtime.
Only explicitly public configured dictionaries can decode client request bodies.

A store specifies `name`, `kind`, and `quota_bytes`. Kinds are `memory`, `disk`
(with `disk.root`), `shared` (with `shared.backend` naming an existing Redis or
PostgreSQL backend), and `external` (with `external.handler` naming an existing
external cache handler). External handlers must implement the
`compression-dictionaries-v1` capability, including atomic compare-exchange.
A store uses a bounded manifest and content chunks rather than enumerating
arbitrary backend keys. Purges fence publication before collecting old chunks.
External response-cache handlers separately need `dictionary-representation-v1`
to store dictionary-partitioned cache records and preserve their
`dictionary_identity` metadata. Records lacking that capability or matching
provenance are rejected; this capability is distinct from dictionary storage.

Profiles select `downstream`, `upstream`, `learn`, and `request_decode` explicitly,
name their `store`, and list configured `dictionaries`. Every profile supplies:

- `max_dictionary_bytes`, `max_dictionaries`, `max_total_dictionary_bytes`, and
  `max_pending_dictionary_bytes`;
- `max_codec_concurrency` and `max_codec_memory_bytes`;
- `max_decoded_size_bytes`, `max_expansion_ratio`, and `codec_timeout_ms`.

There are no implicit resource budgets. A profile's optional `advertise` table
contains `match`, `id`, and `match_dest`. URL patterns cannot contain regular
expression groups. A route with `dictionary = "name"` serves that configured
resource through the request and response WAF pipeline. Its profile must
include the dictionary and an advertisement. GET and HEAD are supported.

See the finite-budget Helm examples:
[local storage](../deploy/helm/oxibelt/examples/compression-dictionary-local-values.yaml)
and [shared storage](../deploy/helm/oxibelt/examples/compression-dictionary-shared-values.yaml).

## Trust and representations

Downstream dictionary transport requires direct TLS or accepted, connection-owned
PROXY-v2 TLS evidence matching the effective client. Forwarded HTTP headers do
not establish a secure context. Upstream learning and negotiation require the
configured verified HTTPS upstream. Authentication, cookies, client certificate
identities, `Set-Cookie`, private responses, and `no-store` exclude public
learning and dictionary response compression.

The upstream dictionary selection is independent of the downstream client's
`Available-Dictionary`. Upstream dictionary responses are decoded before response
WAF inspection. Downstream encoding happens after response policy evaluation.
Representation transformations invalidate content length and affected digest
metadata, and encoded responses vary on `Accept-Encoding` and
`Available-Dictionary`. Ordinary response compression policy gates still apply.

Learning requires an explicit valid `Use-As-Dictionary` advertisement and
explicit fresh HTTP caching metadata. Collection reserves a bounded amount of
memory before reading, publishes only complete valid bodies, and releases its
reservation on cancellation. Unsupported dictionary types are not learned.
Upstream and downstream scopes, origins, profiles, and route policy identities
remain separate. An in-flight lookup pins verified bytes for its own lifetime.

Ordinary `dcb`/`dcz` request bodies use only a provisioned public dictionary.
The wire prelude and hash are checked before the decoder is selected. Decoded
bytes traverse the existing WAF path and are forwarded as identity content.
Encoded client limits and decoded expansion/size/time budgets both apply.
Tunnels, upgrades, gRPC, and opaque resumable relay traffic are excluded.

## Managed resumable uploads

An upload profile may pin a dictionary:

```toml
[upload_profiles.compression_dictionary]
profile = "public-assets"
dictionary = "assets-v1"
```

Use this table within the corresponding `[[upload_profiles]]` entry. The pin is
validated before the initial informational upload response. Upload offsets and
lengths count encoded bytes. Acknowledging a staged encoded part does not mean
that final decoded WAF validation has completed.

Completion claims a fenced validation lease, decodes the assembled encoded
stream, applies the final WAF check, and publishes a separate decoded object
before identity dispatch. Invalid coding or WAF rejection becomes terminal
`validation_failed`; it cannot become a ready object or be replayed as an
identity request. Storage quotas account for staged encoded and decoded data.
The local journal upgrades from v1 to v2, and PostgreSQL upload schema from v3
to v4. A recovered validation state without its required dictionary pin fails
closed. Keep backups before upgrading persistent upload stores; older binaries
do not understand the new journal and schema contract.

## Operations

`GET /admin/v1/compression-dictionaries?profile=NAME` returns bounded entry,
byte, pending-byte, and active-job counts. It requires
`compression-dictionary:List` on `compression-dictionary-profile/NAME`.

`POST /admin/v1/compression-dictionaries/purge` accepts
`{"profile":"NAME"}` and an optional HTTPS `origin`. It requires
`compression-dictionary:Purge` on the same resource and passes through the Admin
audit mutation gate. Purge affects learned entries; configured files remain
part of the immutable configuration snapshot. Reload configuration to replace
or withdraw a configured dictionary.

Gateway policies reference a profile using `spec.compressionDictionary.profileRef`.
The controller must admit the exact `namespace/profile` using
`--compression-dictionary-profile`; route policies cannot supply dictionary
paths, URLs, or budgets. Only HTTPRoute accepts this policy.

Helm supports immutable read-only ConfigMap/PVC dictionary assets, explicit
revision/digest annotations, and typed bounded writable volumes for learned
disk data. Functional interoperability checks do not constitute performance
qualification.

References: [RFC 9842](https://www.rfc-editor.org/rfc/rfc9842.html),
[resumable upload draft 12, section 8](https://www.ietf.org/archive/id/draft-ietf-httpbis-resumable-upload-12.html#section-8).

## Prefetch and static sidecars

A profile can opt into `prefetch` by supplying `max_bytes`, `max_concurrent`,
and `timeout_ms`. An eligible public HTTPS response may advertise
`Link: </dictionary>; rel="compression-dictionary"`. Fetches use the selected
configured upstream and its TLS policy, require the same origin, omit
credentials, and do not follow redirects or recursively prefetch links. A
fetched response must independently meet the dictionary and freshness rules.

A static route can name `static_files.dictionary_manifest`. Its bounded JSON
`entries` array explicitly binds each resource:

```json
{
  "entries": [{
    "path": "/assets/app.js",
    "identity_sha256": "<64 lowercase hexadecimal characters>",
    "encoded_path": "/assets/app.js.dcb",
    "encoded_sha256": "<64 lowercase hexadecimal characters>",
    "dictionary": "assets-v1",
    "dictionary_sha256": "<64 lowercase hexadecimal characters>",
    "coding": "dcb"
  }]
}
```

Both `dcb` and `dcz` are accepted. Selection requires verified final identity
bytes after response WAF processing; an unavailable or mismatched sidecar falls
back to native negotiation. Encoded paths are confined to the static root.
Sidecar verification uses the profile codec permit, deadline, and memory budget.
The codec admission envelope reserves 512 MiB per active job, so profiles need
at least that amount; concurrency is reduced to fit the declared total budget.
Streaming upstream decoding and downstream encoding together require two codec
jobs and a 1 GiB total budget. With only one available job, downstream encoding
falls back according to the ordinary compression policy.
Sidecar materialization additionally needs room for its encoded and decoded bytes.
It reserves all profile codec permits before reading, retains that reservation
through response-body delivery, and reserves another 128 MiB for manifest
parsing. A 512 MiB profile therefore uses native encoding rather than sidecars;
use a larger explicit budget to enable materialization.

Prometheus exposes `oxibelt_dictionary_encode_jobs_total`,
`oxibelt_dictionary_decode_jobs_total`, and `oxibelt_dictionary_codec_errors_total`.
These counters do not label dictionary content or hashes.

## Integration validation

Run the Docker-backed HTTP/1, HTTP/2, and HTTP/3 dictionary and managed-upload
matrix from the repository root:

```sh
tests/scripts/run-compression-dictionary-integration.sh
```

The script builds a local standalone proxy image and protocol-probe image when
their overrides are unset. To reuse prebuilt images, set
`OXIBELT_DOCKER_IMAGE` to the OxiBelt image tag and
`OXIBELT_PROTOCOL_PROBE_IMAGE` to the protocol-probe image tag. CI loads the
AMD64 OxiBelt artifact and shared helper-image artifact, then supplies these
overrides to run the same script against the tested image.

External storage chunk publication uses `write_if_manifest_matches`: handlers
must atomically compare `manifest_key` with `expected_base64` and insert the
chunk only when the complete manifest bytes still match. A non-atomic read
followed by a write does not implement this capability.
