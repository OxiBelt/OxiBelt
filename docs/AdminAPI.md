# Admin API

OxiBelt exposes its authenticated control-plane API on the configured
`[admin]` listener. The canonical machine-readable contract is
`docs/admin-openapi.json`, an OpenAPI 3.1 document for the current
`/admin/v1/*` surface.

The running Admin listener serves the same contract and metadata through:

- `GET /admin/v1/openapi.json`
- `GET /admin/v1/capabilities`
- `GET /admin/v1/version`
- `GET /admin/v1/audit`

The three metadata endpoints require normal Admin bearer authentication and
`admin:ReadMetadata` through IPM. The resource names are
`metadata/openapi`, `metadata/capabilities`, and `metadata/version`, which map
to resources such as `oxibelt:<namespace>:admin:metadata/openapi`.
`GET /admin/v1/audit` requires `admin:ReadAudit` on `audit/admin`.

`/admin/v1/capabilities` reports the API version, package version, compiled
or configured Admin features, and request-size limits used by the Admin API.
`/admin/v1/version` reports the API version, package name, and package version.
When `[admin.audit]` is enabled, `/admin/v1/audit` returns unified Admin
request audit records as `{ "audit": [...] }`; otherwise it returns `409`.
Records include actor, peer, method, path, authorization action/resource,
outcome, status, and a redacted request summary. Request bodies are summarized
with byte count, top-level JSON keys, and selected safe scalar fields, not
stored as raw payloads.

The legacy signed query purge endpoints under `/cache/purge*` are documented
in `docs/Configuration.md`; they are intentionally outside the first
`/admin/v1/*` OpenAPI contract.

## IPM Administration

`GET /admin/v1/ipm/status` returns the active IPM `generation`, `etag`,
static/store object counts, and the last refresh result. Mutating IPM
endpoints require `If-Match` with this ETag; missing ETags return `428`, stale
ETags return `412`.

When `[ipm].backend` resolves to a PostgreSQL shared-state backend, OxiBelt
loads a strict hybrid IPM snapshot from TOML plus `oxibelt_ipm_*` tables. TOML
entries remain visible with `source = "config"` and are read-only. Store
entries use `source = "store"` and can be managed through:

- principals: `GET/POST /admin/v1/ipm/principals`,
  `GET/PATCH/DELETE /admin/v1/ipm/principals/{id}`
- credentials: `GET/POST /admin/v1/ipm/credentials`,
  `GET/PATCH/DELETE /admin/v1/ipm/credentials/{id}`,
  `POST /admin/v1/ipm/credentials/{id}/rotate`,
  `POST /admin/v1/ipm/credentials/{id}/revoke`
- policies: `GET/POST /admin/v1/ipm/policies`,
  `GET/PATCH/DELETE /admin/v1/ipm/policies/{id}`
- bindings: `GET/POST /admin/v1/ipm/bindings`,
  `DELETE /admin/v1/ipm/bindings/{id}`
- audit: `GET /admin/v1/ipm/audit`

If no PostgreSQL IPM store is configured, list/get endpoints keep serving the
static TOML snapshot and mutation endpoints return `409`. Store refresh is
generation-based and keeps the last-good snapshot if the DB rows fail strict
validation, including any ID conflict with TOML principals, credentials,
policies, or bindings.

Credential create and rotate responses return a new `obt_v1_<base64url>` token
exactly once. OxiBelt stores only a `sha256-v1` digest plus token prefix. Rotate
keeps the previous token valid until `previous_token_overlap_until`; revoke and
delete clear regular access subject to lockout prevention.
