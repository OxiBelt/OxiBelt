# OxiBelt Stable Changelog

This file records stable OxiBelt releases only. Beta releases are recorded in
[CHANGELOG-beta.md](CHANGELOG-beta.md). Development build tags such as
`0.7.0-build.46d6ea54` do not receive changelog entries or GitHub Releases.

OxiBelt follows [Semantic Versioning](https://semver.org/). Starting with the
release after `0.6.5`, every stable entry is a person-reviewed, cumulative
description of changes since the immediately preceding stable release. Release
automation rejects missing, cross-channel, misordered, or placeholder-only
entries. See the
[contributor release contract](CONTRIBUTING.md#release-changelog-and-upgrade-contract)
for the governed entry format.

## [0.6.6] - 2026-08-14

> Published maintenance release. The immutable release was cut from a
> maintenance branch before this governed entry existed. This entry records
> the published change without moving the tag, reconstructing release
> evidence, or retroactively qualifying that cut under the current contract.

- Changes since: `0.6.5`
- Supported upgrade sources: `0.6.5`
- Upgrade guide: [Upgrade from 0.6.5 to 0.6.6](docs/Upgrading.md#upgrade-from-065-to-066)

### Configuration

- Restore the legacy `access_log.enable_system` switch as an accepted runtime
  source of system access-log enablement while retaining
  `access_log.system.enabled` as the canonical configuration path. When either
  switch enables system records, configured stdout and OTLP sinks receive the
  same records.

### Schema epochs

- No changes for this release.

### Deprecations and removals

- Keep `access_log.enable_system` as a legacy compatibility input. New
  configurations should use `access_log.system.enabled`; neither field is
  removed by this maintenance release.

### Admin API

- No changes for this release.

### Feature lifecycle

- No changes for this release.

### Rulepack compatibility

- No changes for this release.

### Executables and images

- Rebuild the selected `0.6.6` executable or image from the immutable signed
  `0.6.6` source revision. Do not substitute an artifact from the divergent
  development branch merely because it contains the corresponding fix.

### Storage and state

- No changes for this release.

### Upgrade validation

- Validate the complete configuration and referenced files with the `0.6.6`
  `oxibeltctl` before rollout, then confirm the intended system access-log sink
  receives a probe record:

```sh
oxibeltctl config validate /etc/oxibelt/config/oxibelt.toml --local-only
```

### Rollback and irreversible steps

- The change introduces no schema or durable-state migration. Retain the
  prior image digest and configuration, drain the `0.6.6` instance, and
  restore both together if legacy system records cause an unexpected logging
  volume. Records already exported to stdout or OTLP are not retractable.

### Known issues

- The governed entry and lineage reconciliation were added after the signed
  tag and published release. They preserve attributable history but cannot
  manufacture missing exact-tag contract evidence or alter the immutable
  `0.6.6` release commit.

### Security

- Treat access-log destinations as sensitive telemetry sinks. Keep existing
  redaction, transport authentication, retention, and least-privilege controls
  in place when legacy enablement restores delivery.

## [0.6.5] - 2026-07-16

> Historical baseline. This release predates the versioned changelog and
> upgrade contract. No compatibility or migration claims are reconstructed
> retrospectively.

- Source revision:
  [`46b30e90c40530196aa8024b67b4bfaec82d33d3`](https://github.com/OxiBelt/OxiBelt/commit/46b30e90c40530196aa8024b67b4bfaec82d33d3)
- GitHub release:
  [`0.6.5`](https://github.com/OxiBelt/OxiBelt/releases/tag/0.6.5)
- Earlier releases:
  [GitHub Releases](https://github.com/OxiBelt/OxiBelt/releases)
