# Resumable uploads

HTTP resumable upload relay is enabled by default for negotiated requests.
Managed upload sessions are separately opt-in for HTTP/1.1, HTTP/2, and HTTP/3.
A route selects one named `upload_profiles` entry with `resumable_upload`; clients never select a
store, bucket, endpoint, delivery target, owner binding, or credential.

`upload_stores` are operator-owned. A `local` store is durable only for a
single replica using one writable persistent volume. `postgres_s3` keeps
authoritative session and offset state in PostgreSQL and immutable chunks in
S3-compatible storage, so it is the supported multi-replica form. Credentials
are environment-variable names, never TOML values. Configure egress to both
PostgreSQL and the object store, and mount a dedicated trust bundle when the
object-store TLS chain is private.

Local recovery verifies retained chunk and object integrity before serving
sessions, so budget startup I/O for retained data. An uncertain journal sync
fails the local store closed until it is reopened and recovery succeeds.
Use a dedicated private local root, owned by the runtime user with mode `0700`;
do not point it at a shared directory or the filesystem root.

Each `upload_profile` chooses exactly one terminal delivery: a configured
upstream destination, or private object delivery. Object delivery permits only
authenticated `GET`, `HEAD`, and `DELETE`, forces `Cache-Control: no-store`
and attachment disposition, and cannot become public through profile or route
configuration. A profile also selects one typed, independently verified owner
source: IPM, external authentication, or downstream mTLS. The runtime obtains
fresh owner credentials for every operation and never persists bearer tokens
or cookies.

For identity uploads, the runtime commits an offset only after the whole part
passes configured WAF inspection and durable storage. Opt-in dictionary uploads
acknowledge bounded, durably staged encoded bytes and inspect the complete decoded
representation before publication. An interrupted or rejected part leaves the
previous offset for retransmission. It enforces finite session, byte, storage,
part-count, concurrent-session, concurrent-part, and TTL limits. Completion
rechecks the same owner; an uncertain upstream delivery is terminal
indeterminate and is never replayed automatically. A profile, store, or owner
binding change rejects existing continuations rather than migrating them.

Gateway API tenants reference a profile through `OxiBeltRoutePolicy` only:

```yaml
spec:
  resumableUpload:
    profileRef: media-ingest
```

The Gateway controller accepts this only when its Helm
`routePolicy.resumableUploadProfiles` includes the exact policy namespace and
profile. The controller supplies its exact operator-owned data-plane target as
`--resumable-upload-target namespace/kind/name` (kind `deployment` or
`daemonset`); together they form the admission tuple
`(target, namespace, profile)`. That admission is intentionally separate from
`OxiBeltDataPlaneTarget` assignment: a tenant cannot use a policy to select a
different target or increase its target's namespace authorization.

The actual rollout workload must match that target for legacy and each static
multi-target deployment. Managed routes require exact data-plane compatibility;
rolling compatibility with a previous binary is rejected. Use an unconditional
prefix `HTTPRoute` so creation, append, lookup, and object methods reach the same
policy. In Helm static multi-target mode, `rollout.target` still selects the
one workload authorized for the configured upload-profile allowlist; matching
profile names do not grant access to the other targets. The profile's native
identity requirements still apply. For Gateway
external authentication, include an admitted `ExternalAuth` filter with zero
body capture, then bind the operator profile to the provider name in the
controller's rendered TOML and its verified subject field. A profile reference
alone does not supply authentication.

For a local store, mount an RWO PVC at the absolute `upload_stores.local.root` and
run a single data-plane replica. For `postgres_s3`, inject the PostgreSQL and
S3 credential variables from a narrowly scoped Secret, mount the optional
object-store CA as read-only, and declare explicit NetworkPolicy egress for
the database and object store. Helm mounts and projections are deployment
plumbing; the reviewed base TOML remains the authority for the store/profile
semantics and must use the matching environment names.

This feature is not a client idempotency-header protocol and does not accept a
new client idempotency header.

## Protocol and inspection boundaries

The protocol is pinned to [draft-ietf-httpbis-resumable-upload-12](https://www.ietf.org/archive/id/draft-ietf-httpbis-resumable-upload-12.html),
interop version `9`. This is not tus v1. Clients send
`Upload-Draft-Interop-Version: 9`; an incompatible or missing version never
enables `104` relaying. `104` is informational, not a final response and not an
implicit `Incremental: ?1` request. Existing admission, upload deadlines, and
required buffering remain in force. Relay requests do not use the response
cache, retry replay, or request mirroring. Buffering required by authentication
or WAF can delay upstream discovery. Encoded relay bodies retain their original
octets; an inspection policy that would require changing those octets is
rejected instead. Ordinary, non-resumable compression behavior is unchanged.

Managed uploads accept identity content encoding by default (`415` otherwise).
An explicit public dictionary pin enables `dcb` or `dcz` as described in
[Compression Dictionary Transport](CompressionDictionary.md). Such uploads keep
encoded offsets during staging; final decoding and whole-body WAF inspection
must succeed before a decoded object becomes available for delivery.
Every wire request retains the ordinary route body-size and timeout limits;
`max_upload_bytes` is an additional assembled-representation limit and counts
encoded bytes for dictionary uploads. Their decoded representation also obeys
the dictionary profile's decoded-size limit and the upload staging budget. If WAF
needs the body, `inspection_bytes` must cover the entire part and entire
assembled representation. Exceeding it returns `413`; a prefix inspection
never authorizes publication. Configure it to cover the intended assembled
size when body-dependent rules are enabled. The ordinary route's prefix-WAF
contract is unchanged.

Creation uses an ordinary `POST`, `PUT`, or `PATCH` target with
`Upload-Complete`. Its first `104` identifies a durably created upload resource.
`HEAD`/`GET` of that resource retrieve a durable offset; `PATCH` requires
`Content-Type: application/partial-upload`, `Upload-Offset`, and
`Upload-Complete`; `DELETE` cancels it. `GET` of the resource's `/status` suffix
returns an authenticated status document without storage keys. Incomplete parts
do not advance the acknowledged offset. Identity parts also require inspection
before acknowledgement; dictionary uploads defer decoded inspection until
completion. A lookup fences an
older pending append, so the returned offset can be used by the next request.

The profile fixes the managed destination. A route's ordinary backend is only
a fallback for non-upload traffic; it cannot redirect managed completion.
Completion restores the original method, URI, and content type, uses the
current request's credentials, and reauthorizes the original target before
whole-body WAF inspection. Bearer tokens and cookies from creation are never
stored. An upstream result with uncertain side effects becomes `indeterminate`;
clients must consult status and must not treat it as permission to replay.

## Operator configuration

All limits below are required, finite, and deliberately have no implicit
managed-service defaults. `staging_dir` is a private, writable absolute
directory on every replica, including PostgreSQL/S3 deployments.
`max_staging_bytes` covers the largest assembled representation and bounds
concurrent staging per process. Durable store quotas also cover active
reservations and assembled objects. Allow space for both chunks and a final
object during assembly. `max_sessions` includes retained completed sessions,
deletion tombstones, and S3 cleanup intents, including zero-byte intents;
session and storage capacity is released only after durable cleanup.

```toml
[[upload_stores]]
name = "media-local"
kind = "local"
[upload_stores.local]
root = "/var/lib/oxibelt/uploads"

[[upload_profiles]]
name = "media-ingest"
store = "media-local"
public_base_url = "https://uploads.example.com/"
control_path_prefix = "/media/uploads"
object_path_prefix = "/media/objects"
staging_dir = "/var/lib/oxibelt/upload-staging"
max_staging_bytes = 536870912
max_upload_bytes = 268435456
max_part_bytes = 268435456
inspection_bytes = 268435456
max_storage_bytes = 4294967296
max_sessions = 64
max_parts = 128
max_concurrent_uploads = 4
max_concurrent_parts = 4
ttl_seconds = 3600
object_ttl_seconds = 86400
destination = { kind = "object" }
identity = { kind = "external_auth", source = "upload-auth", subject_field = "remote-user" }

[[routes]]
name = "media"
hosts = ["uploads.example.com"]
path_prefix = "/media"
external_auth = "upload-auth"
resumable_upload = "media-ingest"
```

The example references an independently configured external-auth provider.
It must return a stable, nonempty subject in the selected verified provider
field and must authorize without consuming the request body. A successful
fail-open response has no verified identity and cannot own an upload.
IPM profiles instead use `identity = { kind = "ipm", source = "<IPM namespace>" }`
and require route IPM authorization. mTLS profiles use `kind = "mtls"`, an
operator trust-domain `source`, and a route client-certificate matcher; the
owner is the fingerprint of the verified downstream certificate, never a
client-supplied forwarding header.

To deliver upstream, replace the destination with
`destination = { kind = "upstream", upstream = "media-origin" }`, referring to
an operator-configured upstream. No client URL selects an upstream. Control
and object prefixes must be disjoint and covered by a prefix-only route with
the configured public host. Conditional/method-only matchers, static/CT
targets, redirects, direct responses, cache policies, and retry policies are
not accepted on a managed route. Profile or policy changes conservatively
reject incompatible old continuations; retained data expires under its
original retention policy rather than being implicitly migrated. Keep retired
stores configured until their sessions and objects have drained. A live reload
retains a bounded cleanup task for removed stores, but an unconfigured store
cannot be rediscovered after a process restart; removing its configuration is
not a substitute for verifying cleanup.

For multi-replica storage, replace the local store with the following and set
the profile's `store = "media-shared"`. Provision the bucket beforehand.

```toml
[[upload_stores]]
name = "media-shared"
kind = "postgres_s3"
[upload_stores.postgres_s3]
postgres_url_env = "UPLOAD_POSTGRES_URL"
max_connections = 8
s3_bucket = "private-uploads"
s3_region = "us-east-1"
s3_endpoint = "https://upload-s3.storage.svc/"
s3_prefix = "oxibelt/uploads"
s3_virtual_hosted_style = false
s3_access_key_env = "UPLOAD_S3_ACCESS_KEY"
s3_secret_key_env = "UPLOAD_S3_SECRET_KEY"
s3_root_certificate = "/etc/oxibelt/upload-s3-ca/ca.pem"
```

The optional PEM CA augments trusted roots; it never disables certificate or
hostname verification. Use a PostgreSQL connection URL requiring verified TLS
in production. The database role needs permission to create the store's private
schema and its tables/indexes at initialization, then read/write those tables.
Every replica must use the same store name, bucket, region, endpoint, and prefix.
Those fields determine the private schema and S3 subprefix; credentials are
not part of the identity and may rotate. Grant S3 access only to that store's
prefix, including multipart upload, read, list, and deletion needed for cleanup.
Configure an S3
[`AbortIncompleteMultipartUpload` lifecycle rule](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpu-abort-incomplete-mpu-lifecycle-config.html)
of no more than one day for that prefix. OxiBelt explicitly aborts failed
uploads and schedules a bounded abort when an upload task is cancelled, but a
process or node can fail before cleanup code runs; only the bucket lifecycle
can clean an empty multipart session if the process fails between S3 initiation
and persisting its identifier. Before any part upload, OxiBelt records the
multipart identifier and upper-bound bytes in PostgreSQL. The database-clock
lease refreshes that cleanup intent; stale-intent GC explicitly aborts the
stored multipart identifier and releases `max_storage_bytes` only after
confirmed cleanup. The bucket rule is therefore defense in depth for the one
pre-persistence crash window, not a substitute for durable quota enforcement.
Multipart part sizes adapt to the known object length so the supported 1 TiB
upload limit remains within S3's
[10,000-part ceiling](https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html).
Use a dedicated unversioned bucket without S3 Object Lock for these cleanup and
retention guarantees. Ordinary object deletion does not remove historical
versions or override provider retention controls; if an operator enables those
features, retained historical versions and their billing are outside
`max_storage_bytes` and the supported managed-upload quota contract.
No metadata migration between differently identified stores is implicit.

Deployment-only Helm overlays are provided for
[single-instance local storage](../deploy/helm/oxibelt/examples/resumable-upload-local-values.yaml)
and [shared PostgreSQL/S3 storage](../deploy/helm/oxibelt/examples/resumable-upload-shared-values.yaml).
They require independently provisioned PVCs, Secrets, CA ConfigMaps, and native
configuration. The local overlay disables surge and autoscaling: an RWO volume
alone does not prevent two Pods on the same node from opening one store.
Staging volume capacity must cover the configured per-process staging quota.
The shared overlay's NetworkPolicy requires additional explicit egress for
external authentication and upstream delivery when used.

Run `tests/scripts/run-managed-upload-store.sh` for the isolated PostgreSQL and
TLS MinIO durability/replica qualification. It requires rootless Docker and
cleans its own test resources; it is not a production capacity benchmark.

The protocol fixtures exercise negotiated relay and the managed mTLS lifecycle
over real HTTP/1.1, HTTP/2, and HTTP/3 connections:

```sh
tests/scripts/run-proxy-integration-matrix.sh http-semantics incremental-rfc10036
tests/scripts/run-proxy-integration-matrix.sh http-semantics incremental-rfc10036-unpooled
tests/scripts/run-proxy-integration-matrix.sh http-semantics managed-upload-real-wire
```
