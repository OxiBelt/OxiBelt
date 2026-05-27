# Admin API

OxiBelt exposes its authenticated control-plane API on the configured
`[admin]` listener. The canonical machine-readable contract is
`docs/admin-openapi.json`, an OpenAPI 3.1 document for the current
`/admin/v1/*` surface.

The running Admin listener serves the same contract and metadata through:

- `GET /admin/v1/openapi.json`
- `GET /admin/v1/capabilities`
- `GET /admin/v1/version`

All three metadata endpoints require normal Admin bearer authentication and
`admin:ReadMetadata` through IPM. The resource names are
`metadata/openapi`, `metadata/capabilities`, and `metadata/version`, which map
to resources such as `oxibelt:<namespace>:admin:metadata/openapi`.

`/admin/v1/capabilities` reports the API version, package version, compiled
or configured Admin features, and request-size limits used by the Admin API.
`/admin/v1/version` reports the API version, package name, and package version.

The legacy signed query purge endpoints under `/cache/purge*` are documented
in `docs/Configuration.md`; they are intentionally outside the first
`/admin/v1/*` OpenAPI contract.
