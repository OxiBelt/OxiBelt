import * as Fs from 'node:fs'
import * as Path from 'node:path'
import * as Toml from 'smol-toml'

type TomlRecord = Record<string, unknown>

/* oxlint-disable oxibelt/pascal-case -- Policy descriptors and reports use stable lower-camel-case keys. */
type CargoPackagePolicy = {
  name: string
  manifestPath: string
  lockfilePath: string
  releaseRewrite: boolean
  versionSource: 'workspace' | 'sentinel'
}

type NpmPackagePolicy = {
  packagePath: string
  version: 'absent' | 'sentinel'
}

type AssignmentPolicy = {
  field: string
  expected: string
}

type ShellAssignmentPolicy = {
  field: string
  allowedLines: string[]
}

export type VersionPolicyViolation = {
  path: string
  field: string
  expected: string
  actual: string
}

export type VersionPolicyReport = {
  version: string
  violations: VersionPolicyViolation[]
}
/* oxlint-enable oxibelt/pascal-case */

const CommittedVersion = '0.0.0'
const ArchiveVersion = '0.0.0-dev.archive'

const CargoPackages: CargoPackagePolicy[] = [
  {
    name: 'oxibelt',
    manifestPath: 'source/Cargo.toml',
    lockfilePath: 'Cargo.lock',
    releaseRewrite: true,
    versionSource: 'workspace'
  },
  {
    name: 'oxibelt-build-identity',
    manifestPath: 'source/crates/oxibelt-build-identity/Cargo.toml',
    lockfilePath: 'Cargo.lock',
    releaseRewrite: true,
    versionSource: 'workspace'
  },
  {
    name: 'oxibelt-control-http',
    manifestPath: 'source/crates/oxibelt-control-http/Cargo.toml',
    lockfilePath: 'Cargo.lock',
    releaseRewrite: true,
    versionSource: 'workspace'
  },
  {
    name: 'oxibelt-control-protocol',
    manifestPath: 'source/crates/oxibelt-control-protocol/Cargo.toml',
    lockfilePath: 'Cargo.lock',
    releaseRewrite: true,
    versionSource: 'workspace'
  },
  {
    name: 'oxibelt-dataplane-strict',
    manifestPath: 'source/apps/oxibelt-dataplane-strict/Cargo.toml',
    lockfilePath: 'Cargo.lock',
    releaseRewrite: true,
    versionSource: 'workspace'
  },
  {
    name: 'oxibelt-deployment-diagnostics',
    manifestPath: 'source/crates/oxibelt-deployment-diagnostics/Cargo.toml',
    lockfilePath: 'Cargo.lock',
    releaseRewrite: true,
    versionSource: 'workspace'
  },
  {
    name: 'oxibelt-gateway-controller',
    manifestPath: 'source/apps/oxibelt-gateway-controller/Cargo.toml',
    lockfilePath: 'Cargo.lock',
    releaseRewrite: true,
    versionSource: 'workspace'
  },
  {
    name: 'oxibelt-keysigner',
    manifestPath: 'source/apps/oxibelt-keysigner/Cargo.toml',
    lockfilePath: 'Cargo.lock',
    releaseRewrite: true,
    versionSource: 'workspace'
  },
  {
    name: 'oxibelt-netport-switcher',
    manifestPath: 'source/apps/oxibelt-netport-switcher/Cargo.toml',
    lockfilePath: 'Cargo.lock',
    releaseRewrite: true,
    versionSource: 'workspace'
  },
  {
    name: 'oxibeltctl',
    manifestPath: 'source/apps/oxibeltctl/Cargo.toml',
    lockfilePath: 'Cargo.lock',
    releaseRewrite: true,
    versionSource: 'workspace'
  },
  {
    name: 'oxibelt-fuzz',
    manifestPath: 'fuzz/Cargo.toml',
    lockfilePath: 'Cargo.lock',
    releaseRewrite: false,
    versionSource: 'sentinel'
  },
  {
    name: 'oxibelt-unsafe-harness',
    manifestPath: 'tests/unsafe_harness/Cargo.toml',
    lockfilePath: 'Cargo.lock',
    releaseRewrite: false,
    versionSource: 'sentinel'
  },
  {
    name: 'perf-probe',
    manifestPath: 'tests/docker/perf_probe/Cargo.toml',
    lockfilePath: 'tests/docker/perf_probe/Cargo.lock',
    releaseRewrite: false,
    versionSource: 'sentinel'
  },
  {
    name: 'pq-probe',
    manifestPath: 'tests/docker/pq_probe/Cargo.toml',
    lockfilePath: 'tests/docker/pq_probe/Cargo.lock',
    releaseRewrite: false,
    versionSource: 'sentinel'
  },
  {
    name: 'protocol-probe',
    manifestPath: 'tests/docker/protocol_probe/Cargo.toml',
    lockfilePath: 'tests/docker/protocol_probe/Cargo.lock',
    releaseRewrite: false,
    versionSource: 'sentinel'
  }
]

const NpmPackages: NpmPackagePolicy[] = [
  { packagePath: 'package.json', version: 'absent' },
  { packagePath: 'devops/package.json', version: 'sentinel' },
  { packagePath: 'ui/person-proof/package.json', version: 'sentinel' }
]

const NpmWorkspacePatterns = ['devops', 'ui/*']

const HelmCharts = [
  'deploy/helm/oxibelt/Chart.yaml',
  'deploy/helm/oxibelt-gateway-controller/Chart.yaml'
]

const DockerAssignments: AssignmentPolicy[] = [
  { field: 'OXIBELT_BUILD_VERSION', expected: ArchiveVersion },
  { field: 'OXIBELT_BUILD_REVISION', expected: 'unknown' },
  { field: 'OXIBELT_BUILD_REF', expected: 'unknown' },
  { field: 'OXIBELT_BUILD_DIRTY', expected: 'unknown' },
  { field: 'OXIBELT_BUILD_KIND', expected: 'source_archive' },
  { field: 'OXIBELT_REF_NAME', expected: ArchiveVersion }
]

const ReleaseHelperDefaults: AssignmentPolicy[] = [
  { field: 'derived_dirty', expected: 'unknown' },
  { field: 'derived_kind', expected: 'source_archive' },
  { field: 'derived_ref', expected: 'unknown' },
  { field: 'derived_version', expected: ArchiveVersion }
]

const ReleaseHelperFallbacks: AssignmentPolicy[] = [
  {
    field: 'oxibelt_version',
    expected: '${OXIBELT_DOCKER_IMAGE_VERSION:-${derived_version}}'
  },
  {
    field: 'oxibelt_revision',
    expected: '${OXIBELT_DOCKER_IMAGE_REVISION:-${derived_revision:-unknown}}'
  },
  {
    field: 'oxibelt_source_ref',
    expected: '${OXIBELT_DOCKER_IMAGE_SOURCE_REF:-${derived_ref}}'
  },
  {
    field: 'oxibelt_source_dirty',
    expected: '${OXIBELT_DOCKER_IMAGE_SOURCE_DIRTY:-${derived_dirty}}'
  },
  {
    field: 'oxibelt_build_kind',
    expected: '${OXIBELT_DOCKER_IMAGE_BUILD_KIND:-${derived_kind}}'
  },
  {
    field: 'oxibelt_ref_name',
    expected: '${OXIBELT_DOCKER_IMAGE_REF_NAME:-${oxibelt_version}}'
  }
]

const ReleaseHelperAssignments: ShellAssignmentPolicy[] = [
  {
    field: 'derived_dirty',
    allowedLines: [
      'derived_dirty="unknown"',
      'derived_dirty="clean"',
      'derived_dirty="dirty"'
    ]
  },
  {
    field: 'derived_kind',
    allowedLines: [
      'derived_kind="source_archive"',
      'derived_kind="tagged_development"',
      'derived_kind="git_development"'
    ]
  },
  {
    field: 'derived_ref',
    allowedLines: [
      'derived_ref="unknown"',
      'derived_ref="$(git -C "${repo_root}" symbolic-ref -q HEAD 2>/dev/null || true)"',
      'derived_ref="refs/tags/${release_tag}"'
    ]
  },
  {
    field: 'derived_version',
    allowedLines: [
      'derived_version="0.0.0-dev.archive"',
      'derived_version="${release_tag}"',
      'derived_version="0.0.0-dev.g${derived_revision:0:8}"',
      'derived_version="${derived_version}+dirty"'
    ]
  },
  {
    field: 'oxibelt_version',
    allowedLines: ['oxibelt_version="${OXIBELT_DOCKER_IMAGE_VERSION:-${derived_version}}"']
  },
  {
    field: 'oxibelt_revision',
    allowedLines: [
      'oxibelt_revision="${OXIBELT_DOCKER_IMAGE_REVISION:-${derived_revision:-unknown}}"',
      'oxibelt_revision="unknown"'
    ]
  },
  {
    field: 'oxibelt_source_ref',
    allowedLines: ['oxibelt_source_ref="${OXIBELT_DOCKER_IMAGE_SOURCE_REF:-${derived_ref}}"']
  },
  {
    field: 'oxibelt_source_dirty',
    allowedLines: ['oxibelt_source_dirty="${OXIBELT_DOCKER_IMAGE_SOURCE_DIRTY:-${derived_dirty}}"']
  },
  {
    field: 'oxibelt_build_kind',
    allowedLines: ['oxibelt_build_kind="${OXIBELT_DOCKER_IMAGE_BUILD_KIND:-${derived_kind}}"']
  },
  {
    field: 'oxibelt_ref_name',
    allowedLines: ['oxibelt_ref_name="${OXIBELT_DOCKER_IMAGE_REF_NAME:-${oxibelt_version}}"']
  }
]

export const RepositoryVersionPolicy = Object.freeze({
  committedVersion: CommittedVersion,
  archiveIdentity: Object.freeze({
    version: ArchiveVersion,
    revision: 'unknown',
    ref: 'unknown',
    dirty: 'unknown',
    kind: 'source_archive'
  }),
  manifestPath: 'Cargo.toml',
  lockfilePath: 'Cargo.lock',
  cargoPackages: Object.freeze(CargoPackages.map(Package => Object.freeze({ ...Package }))),
  npmPackages: Object.freeze(NpmPackages.map(Package => Object.freeze({ ...Package }))),
  npmWorkspacePatterns: Object.freeze([...NpmWorkspacePatterns]),
  pnpmWorkspacePath: 'pnpm-workspace.yaml',
  helmCharts: Object.freeze([...HelmCharts]),
  dockerfilePath: 'source/ops/Dockerfile.alpine',
  dockerAssignments: Object.freeze(DockerAssignments.map(Assignment => Object.freeze({ ...Assignment }))),
  releaseHelperPath: 'tests/scripts/build-docker-image-artifact.sh',
  releaseHelperDefaults: Object.freeze(
    ReleaseHelperDefaults.map(Assignment => Object.freeze({ ...Assignment }))
  ),
  releaseHelperFallbacks: Object.freeze(
    ReleaseHelperFallbacks.map(Assignment => Object.freeze({ ...Assignment }))
  ),
  releaseHelperAssignments: Object.freeze(
    ReleaseHelperAssignments.map(Assignment =>
      Object.freeze({
        field: Assignment.field,
        allowedLines: Object.freeze([...Assignment.allowedLines])
      })
    )
  ),
  archiveIdentitySourcePath: 'source/crates/oxibelt-build-identity/build.rs',
  archiveVersionLiteralOccurrences: 4
})

export const ProductionPackageNames = Object.freeze(
  RepositoryVersionPolicy.cargoPackages
    .filter(Package => Package.releaseRewrite)
    .map(Package => Package.name)
)

function IsRecord(Value: unknown): Value is TomlRecord {
  return typeof Value === 'object' && Value !== null && !Array.isArray(Value)
}

function FormatError(ErrorValue: unknown): string {
  return ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)
}

function PushViolation(
  Violations: VersionPolicyViolation[],
  PathValue: string,
  Field: string,
  Expected: string,
  Actual: string
): void {
  Violations.push({
    path: PathValue,
    field: Field,
    expected: Expected,
    actual: Actual
  })
}

function DisplayValue(Value: string): string {
  return Value.startsWith('<') && Value.endsWith('>') ? Value : JSON.stringify(Value)
}

function ResolvePolicyPath(WorkspacePath: string, RelativePath: string): string {
  if (Path.isAbsolute(RelativePath)) {
    throw new Error(`repository version policy path must be relative: ${RelativePath}`)
  }

  const Resolved = Path.resolve(WorkspacePath, RelativePath)
  const Relative = Path.relative(WorkspacePath, Resolved)
  if (Relative === '' || Relative.startsWith('..') || Path.isAbsolute(Relative)) {
    throw new Error(`repository version policy path must stay inside the workspace: ${RelativePath}`)
  }

  return Resolved
}

function AssertRealPathInsideWorkspace(WorkspacePath: string, ResolvedPath: string): void {
  const RealWorkspace = Fs.realpathSync(WorkspacePath)
  const RealTarget = Fs.realpathSync(ResolvedPath)
  const Relative = Path.relative(RealWorkspace, RealTarget)
  if (Relative === '' || Relative.startsWith('..') || Path.isAbsolute(Relative)) {
    throw new Error('resolved path escapes the repository through a symbolic link')
  }
}

function ReadPolicyFile(
  WorkspacePath: string,
  RelativePath: string,
  Violations: VersionPolicyViolation[]
): string | undefined {
  let Resolved: string
  try {
    Resolved = ResolvePolicyPath(WorkspacePath, RelativePath)
  } catch (ErrorValue) {
    PushViolation(Violations, RelativePath, '<path>', '<inside repository>', FormatError(ErrorValue))
    return undefined
  }

  try {
    const Metadata = Fs.lstatSync(Resolved)
    if (Metadata.isSymbolicLink() || !Metadata.isFile()) {
      PushViolation(Violations, RelativePath, '<file>', '<regular file>', '<not a file>')
      return undefined
    }
    AssertRealPathInsideWorkspace(WorkspacePath, Resolved)
    return Fs.readFileSync(Resolved, 'utf8')
  } catch (ErrorValue) {
    PushViolation(Violations, RelativePath, '<file>', '<readable file>', FormatError(ErrorValue))
    return undefined
  }
}

function ResolvePolicyDirectory(
  WorkspacePath: string,
  RelativePath: string,
  Field: string,
  Violations: VersionPolicyViolation[]
): string | undefined {
  try {
    const Resolved = ResolvePolicyPath(WorkspacePath, RelativePath)
    const Metadata = Fs.lstatSync(Resolved)
    if (Metadata.isSymbolicLink() || !Metadata.isDirectory()) {
      throw new Error('path is not a regular directory')
    }
    AssertRealPathInsideWorkspace(WorkspacePath, Resolved)
    return Resolved
  } catch (ErrorValue) {
    PushViolation(Violations, RelativePath, Field, '<repository directory>', FormatError(ErrorValue))
    return undefined
  }
}

function ParseTomlPolicyFile(
  WorkspacePath: string,
  RelativePath: string,
  Violations: VersionPolicyViolation[]
): TomlRecord | undefined {
  const Content = ReadPolicyFile(WorkspacePath, RelativePath, Violations)
  if (Content === undefined) {
    return undefined
  }

  try {
    const Parsed = Toml.parse(Content)
    if (!IsRecord(Parsed)) {
      throw new Error('top-level TOML value is not an object')
    }
    return Parsed
  } catch (ErrorValue) {
    PushViolation(Violations, RelativePath, '<toml>', '<valid TOML>', FormatError(ErrorValue))
    return undefined
  }
}

function ParseJsonPolicyFile(
  WorkspacePath: string,
  RelativePath: string,
  Violations: VersionPolicyViolation[]
): TomlRecord | undefined {
  const Content = ReadPolicyFile(WorkspacePath, RelativePath, Violations)
  if (Content === undefined) {
    return undefined
  }

  try {
    const Parsed: unknown = JSON.parse(Content)
    if (!IsRecord(Parsed)) {
      throw new Error('top-level JSON value is not an object')
    }
    return Parsed
  } catch (ErrorValue) {
    PushViolation(Violations, RelativePath, '<json>', '<valid JSON>', FormatError(ErrorValue))
    return undefined
  }
}

function ParsePnpmWorkspacePatterns(
  WorkspacePath: string,
  Violations: VersionPolicyViolation[]
): string[] | undefined {
  const RelativePath = RepositoryVersionPolicy.pnpmWorkspacePath
  const Content = ReadPolicyFile(WorkspacePath, RelativePath, Violations)
  if (Content === undefined) {
    return undefined
  }

  const Lines = Content.split(/\r?\n/)
  const PackageHeaders = Lines
    .map((Line, Index) => ({ line: Line, index: Index }))
    .filter(Entry => /^packages\s*:\s*(?:#.*)?$/.test(Entry.line))
  if (PackageHeaders.length !== 1) {
    PushViolation(
      Violations,
      RelativePath,
      'packages',
      '<one top-level sequence>',
      PackageHeaders.length === 0 ? '<missing>' : `<duplicate:${PackageHeaders.length}>`
    )
    return undefined
  }

  const Patterns: string[] = []
  for (let Index = PackageHeaders[0].index + 1; Index < Lines.length; Index += 1) {
    const Line = Lines[Index]
    if (/^\S/.test(Line)) {
      break
    }
    if (/^\s*(?:#.*)?$/.test(Line)) {
      continue
    }
    const Match = /^\s+-\s*(?:"([^"]*)"|'([^']*)'|([^#\s]+))\s*(?:#.*)?$/.exec(Line)
    if (Match === null) {
      PushViolation(Violations, RelativePath, 'packages', '<string sequence>', Line.trim())
      return undefined
    }
    Patterns.push(Match[1] ?? Match[2] ?? Match[3])
  }

  if (Patterns.length === 0) {
    PushViolation(Violations, RelativePath, 'packages', '<non-empty string sequence>', '<empty>')
    return undefined
  }
  return Patterns
}

function CheckString(
  Violations: VersionPolicyViolation[],
  RelativePath: string,
  Field: string,
  Value: unknown,
  Expected: string
): void {
  if (typeof Value !== 'string') {
    PushViolation(Violations, RelativePath, Field, Expected, Value === undefined ? '<missing>' : '<non-string>')
  } else if (Value !== Expected) {
    PushViolation(Violations, RelativePath, Field, Expected, Value)
  }
}

function CheckRootCargoPolicy(
  WorkspacePath: string,
  Violations: VersionPolicyViolation[]
): string {
  const Manifest = ParseTomlPolicyFile(
    WorkspacePath,
    RepositoryVersionPolicy.manifestPath,
    Violations
  )
  if (Manifest === undefined) {
    return RepositoryVersionPolicy.committedVersion
  }

  const Workspace = Manifest.workspace
  if (!IsRecord(Workspace)) {
    PushViolation(
      Violations,
      RepositoryVersionPolicy.manifestPath,
      '[workspace]',
      '<table>',
      '<missing>'
    )
    return RepositoryVersionPolicy.committedVersion
  }

  const Package = Workspace.package
  if (!IsRecord(Package)) {
    PushViolation(
      Violations,
      RepositoryVersionPolicy.manifestPath,
      '[workspace.package]',
      '<table>',
      '<missing>'
    )
  } else {
    CheckString(
      Violations,
      RepositoryVersionPolicy.manifestPath,
      '[workspace.package].version',
      Package.version,
      RepositoryVersionPolicy.committedVersion
    )
  }

  const RootPackages = RepositoryVersionPolicy.cargoPackages
    .filter(PackagePolicy => PackagePolicy.lockfilePath === RepositoryVersionPolicy.lockfilePath)
    .map(PackagePolicy => Path.posix.dirname(PackagePolicy.manifestPath))
    .sort()
  const Members = Workspace.members
  if (!Array.isArray(Members) || !Members.every(Member => typeof Member === 'string')) {
    PushViolation(
      Violations,
      RepositoryVersionPolicy.manifestPath,
      '[workspace].members',
      RootPackages.join(','),
      '<malformed>'
    )
  } else {
    const ActualMembers = [...Members].sort()
    if (ActualMembers.join('\n') !== RootPackages.join('\n')) {
      PushViolation(
        Violations,
        RepositoryVersionPolicy.manifestPath,
        '[workspace].members',
        RootPackages.join(','),
        ActualMembers.join(',')
      )
    }
  }

  return IsRecord(Package) && typeof Package.version === 'string'
    ? Package.version
    : RepositoryVersionPolicy.committedVersion
}

function CheckCargoManifestPolicy(
  WorkspacePath: string,
  PackagePolicy: Readonly<CargoPackagePolicy>,
  Violations: VersionPolicyViolation[]
): void {
  const Manifest = ParseTomlPolicyFile(WorkspacePath, PackagePolicy.manifestPath, Violations)
  if (Manifest === undefined) {
    return
  }

  const Package = Manifest.package
  if (!IsRecord(Package)) {
    PushViolation(Violations, PackagePolicy.manifestPath, '[package]', '<table>', '<missing>')
    return
  }

  CheckString(Violations, PackagePolicy.manifestPath, '[package].name', Package.name, PackagePolicy.name)

  if (PackagePolicy.versionSource === 'sentinel') {
    CheckString(
      Violations,
      PackagePolicy.manifestPath,
      '[package].version',
      Package.version,
      RepositoryVersionPolicy.committedVersion
    )
    return
  }

  const Version = Package.version
  if (!IsRecord(Version) || Version.workspace !== true) {
    PushViolation(
      Violations,
      PackagePolicy.manifestPath,
      '[package].version.workspace',
      'true',
      IsRecord(Version) ? String(Version.workspace ?? '<missing>') : '<missing>'
    )
  }
}

function CheckCargoLockPolicy(
  WorkspacePath: string,
  LockfilePath: string,
  PackagePolicies: ReadonlyArray<Readonly<CargoPackagePolicy>>,
  Violations: VersionPolicyViolation[]
): void {
  const Lockfile = ParseTomlPolicyFile(WorkspacePath, LockfilePath, Violations)
  if (Lockfile === undefined) {
    return
  }

  if (!Array.isArray(Lockfile.package)) {
    PushViolation(Violations, LockfilePath, '[[package]]', '<array>', '<missing>')
    return
  }

  for (const PackagePolicy of PackagePolicies) {
    const Matches = Lockfile.package.filter(Entry => IsRecord(Entry) && Entry.name === PackagePolicy.name)
    const Field = `[[package]] ${PackagePolicy.name}.version`
    if (Matches.length !== 1) {
      PushViolation(
        Violations,
        LockfilePath,
        Field,
        RepositoryVersionPolicy.committedVersion,
        Matches.length === 0 ? '<missing>' : `<duplicate:${Matches.length}>`
      )
      continue
    }
    CheckString(
      Violations,
      LockfilePath,
      Field,
      Matches[0].version,
      RepositoryVersionPolicy.committedVersion
    )
  }
}

function ExpandNpmWorkspaces(
  WorkspacePath: string,
  SourcePath: string,
  Patterns: string[],
  Violations: VersionPolicyViolation[]
): string[] {
  const Results = new Set<string>()

  for (const Pattern of Patterns) {
    if (!Pattern.includes('*')) {
      Results.add(`${Pattern.replace(/\/+$/, '')}/package.json`)
      continue
    }

    if (!Pattern.endsWith('/*') || Pattern.slice(0, -2).includes('*')) {
      PushViolation(Violations, SourcePath, 'workspaces', '<literal or trailing /* pattern>', Pattern)
      continue
    }

    const Parent = Pattern.slice(0, -2)
    const ParentPath = ResolvePolicyDirectory(WorkspacePath, Parent, 'workspaces', Violations)
    if (ParentPath === undefined) {
      continue
    }

    try {
      for (const Entry of Fs.readdirSync(ParentPath, { withFileTypes: true })) {
        if (Entry.isDirectory()) {
          const PackagePath = `${Parent}/${Entry.name}/package.json`
          if (Fs.existsSync(Path.resolve(WorkspacePath, PackagePath))) {
            Results.add(PackagePath)
          }
        }
      }
    } catch (ErrorValue) {
      PushViolation(Violations, SourcePath, 'workspaces', '<readable workspace directory>', FormatError(ErrorValue))
    }
  }

  return [...Results].sort()
}

function CheckWorkspacePatterns(
  RelativePath: string,
  Patterns: string[],
  Violations: VersionPolicyViolation[]
): void {
  const Expected = [...RepositoryVersionPolicy.npmWorkspacePatterns].sort()
  const Actual = [...Patterns].sort()
  if (Actual.join('\n') !== Expected.join('\n')) {
    PushViolation(
      Violations,
      RelativePath,
      'workspaces',
      Expected.join(','),
      Actual.join(',')
    )
  }
}

function CheckNpmPolicy(
  WorkspacePath: string,
  Violations: VersionPolicyViolation[]
): void {
  const DiscoveredPackages = new Set<string>()
  const RootPackage = ParseJsonPolicyFile(WorkspacePath, 'package.json', Violations)
  if (RootPackage !== undefined) {
    if (RootPackage.private !== true) {
      PushViolation(Violations, 'package.json', 'private', 'true', String(RootPackage.private ?? '<missing>'))
    }
    if ('version' in RootPackage) {
      PushViolation(
        Violations,
        'package.json',
        'version',
        '<absent>',
        typeof RootPackage.version === 'string' ? RootPackage.version : '<present>'
      )
    }

    const Workspaces = RootPackage.workspaces
    if (!Array.isArray(Workspaces) || !Workspaces.every(Value => typeof Value === 'string')) {
      PushViolation(Violations, 'package.json', 'workspaces', '<string array>', '<malformed>')
    } else {
      CheckWorkspacePatterns('package.json', Workspaces, Violations)
      for (const PackagePath of ExpandNpmWorkspaces(
        WorkspacePath,
        'package.json',
        Workspaces,
        Violations
      )) {
        DiscoveredPackages.add(PackagePath)
      }
    }
  }

  const PnpmPatterns = ParsePnpmWorkspacePatterns(WorkspacePath, Violations)
  if (PnpmPatterns !== undefined) {
    CheckWorkspacePatterns(RepositoryVersionPolicy.pnpmWorkspacePath, PnpmPatterns, Violations)
    for (const PackagePath of ExpandNpmWorkspaces(
      WorkspacePath,
      RepositoryVersionPolicy.pnpmWorkspacePath,
      PnpmPatterns,
      Violations
    )) {
      DiscoveredPackages.add(PackagePath)
    }
  }

  const ActualPackages = [...DiscoveredPackages].sort()
  const ExpectedPackages = RepositoryVersionPolicy.npmPackages
    .filter(Package => Package.packagePath !== 'package.json')
    .map(Package => Package.packagePath)
    .sort()
  if (ActualPackages.join('\n') !== ExpectedPackages.join('\n')) {
    PushViolation(
      Violations,
      'npm workspaces',
      'package.json files',
      ExpectedPackages.join(','),
      ActualPackages.join(',')
    )
  }

  for (const PackagePolicy of RepositoryVersionPolicy.npmPackages) {
    if (PackagePolicy.packagePath === 'package.json') {
      continue
    }
    const Package = ParseJsonPolicyFile(WorkspacePath, PackagePolicy.packagePath, Violations)
    if (Package === undefined) {
      continue
    }
    if (Package.private !== true) {
      PushViolation(
        Violations,
        PackagePolicy.packagePath,
        'private',
        'true',
        String(Package.private ?? '<missing>')
      )
    }
    CheckString(
      Violations,
      PackagePolicy.packagePath,
      'version',
      Package.version,
      RepositoryVersionPolicy.committedVersion
    )
  }
}

function EscapeRegExp(Value: string): string {
  return Value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function ReadUniqueScalar(
  Content: string,
  RelativePath: string,
  Field: string,
  Prefix: string,
  Expected: string,
  Violations: VersionPolicyViolation[],
  IgnoreCase = false
): string | undefined {
  const Pattern = new RegExp(
    `^[ \\t]*${Prefix}${EscapeRegExp(Field)}\\s*=\\s*"?([^"\\s]+)"?\\s*$`,
    IgnoreCase ? 'gmi' : 'gm'
  )
  const Matches = [...Content.matchAll(Pattern)]
  if (Matches.length !== 1) {
    PushViolation(
      Violations,
      RelativePath,
      Field,
      Expected,
      Matches.length === 0 ? '<missing>' : `<duplicate:${Matches.length}>`
    )
    return undefined
  }
  return Matches[0][1]
}

function CheckAllowedShellAssignments(
  Content: string,
  RelativePath: string,
  Violations: VersionPolicyViolation[]
): void {
  for (const Assignment of RepositoryVersionPolicy.releaseHelperAssignments) {
    const Pattern = new RegExp(
      `^[ \\t]*(?:(?:export|readonly|local)\\s+)?${EscapeRegExp(Assignment.field)}\\s*=.*$`,
      'gm'
    )
    const Actual = [...Content.matchAll(Pattern)].map(Match => Match[0].trim())
    const Expected = [...Assignment.allowedLines]
    if (Actual.join('\n') !== Expected.join('\n')) {
      PushViolation(
        Violations,
        RelativePath,
        `${Assignment.field} assignments`,
        Expected.join(' | '),
        Actual.length === 0 ? '<missing>' : Actual.join(' | ')
      )
    }
  }
}

function ReadUniqueHelmScalar(
  Content: string,
  RelativePath: string,
  Field: string,
  Expected: string,
  Violations: VersionPolicyViolation[]
): string | undefined {
  const Pattern = new RegExp(
    `^${EscapeRegExp(Field)}:\\s*(?:"([^"]*)"|'([^']*)'|([^\\s#]+))\\s*(?:#.*)?$`,
    'gm'
  )
  const Matches = [...Content.matchAll(Pattern)]
  if (Matches.length !== 1) {
    PushViolation(
      Violations,
      RelativePath,
      Field,
      Expected,
      Matches.length === 0 ? '<missing>' : `<duplicate:${Matches.length}>`
    )
    return undefined
  }
  return Matches[0][1] ?? Matches[0][2] ?? Matches[0][3]
}

function CheckHelmPolicy(
  WorkspacePath: string,
  Violations: VersionPolicyViolation[]
): void {
  const HelmRoot = ResolvePolicyDirectory(
    WorkspacePath,
    'deploy/helm',
    'Chart.yaml files',
    Violations
  )
  if (HelmRoot !== undefined) {
    try {
      const ActualCharts = Fs.readdirSync(HelmRoot, {
        withFileTypes: true
      })
        .filter(Entry => Entry.isDirectory())
        .map(Entry => `deploy/helm/${Entry.name}/Chart.yaml`)
        .filter(ChartPath => Fs.existsSync(Path.resolve(WorkspacePath, ChartPath)))
        .sort()
      const ExpectedCharts = [...RepositoryVersionPolicy.helmCharts].sort()
      if (ActualCharts.join('\n') !== ExpectedCharts.join('\n')) {
        PushViolation(
          Violations,
          'deploy/helm',
          'Chart.yaml files',
          ExpectedCharts.join(','),
          ActualCharts.join(',')
        )
      }
    } catch (ErrorValue) {
      PushViolation(
        Violations,
        'deploy/helm',
        'Chart.yaml files',
        RepositoryVersionPolicy.helmCharts.join(','),
        FormatError(ErrorValue)
      )
    }
  }

  for (const ChartPath of RepositoryVersionPolicy.helmCharts) {
    const Content = ReadPolicyFile(WorkspacePath, ChartPath, Violations)
    if (Content === undefined) {
      continue
    }
    for (const Field of ['version', 'appVersion']) {
      const Value = ReadUniqueHelmScalar(
        Content,
        ChartPath,
        Field,
        RepositoryVersionPolicy.committedVersion,
        Violations
      )
      if (Value !== undefined && Value !== RepositoryVersionPolicy.committedVersion) {
        PushViolation(
          Violations,
          ChartPath,
          Field,
          RepositoryVersionPolicy.committedVersion,
          Value
        )
      }
    }
  }
}

function CheckDockerPolicy(
  WorkspacePath: string,
  Violations: VersionPolicyViolation[]
): void {
  const Dockerfile = ReadPolicyFile(
    WorkspacePath,
    RepositoryVersionPolicy.dockerfilePath,
    Violations
  )
  if (Dockerfile !== undefined) {
    const FirstStage = /^[ \t]*FROM(?:[ \t]|$)/mi.exec(Dockerfile)
    const GlobalArguments = FirstStage === null
      ? Dockerfile
      : Dockerfile.slice(0, FirstStage.index)
    const StageInstructions = FirstStage === null
      ? ''
      : Dockerfile.slice(FirstStage.index)
    if (FirstStage === null) {
      PushViolation(
        Violations,
        RepositoryVersionPolicy.dockerfilePath,
        'FROM',
        '<at least one build stage>',
        '<missing>'
      )
    }
    for (const Assignment of RepositoryVersionPolicy.dockerAssignments) {
      const Value = ReadUniqueScalar(
        GlobalArguments,
        RepositoryVersionPolicy.dockerfilePath,
        Assignment.field,
        'ARG\\s+',
        Assignment.expected,
        Violations,
        true
      )
      if (Value !== undefined && Value !== Assignment.expected) {
        PushViolation(
          Violations,
          RepositoryVersionPolicy.dockerfilePath,
          Assignment.field,
          Assignment.expected,
          Value
        )
      }

      const StageDefaultPattern = new RegExp(
        `^[ \\t]*ARG[ \\t]+${EscapeRegExp(Assignment.field)}` +
        '(?:[ \\t]*=[ \\t]*([^#\\r\\n]*?))[ \\t]*(?:#.*)?$',
        'gmi'
      )
      const StageDefaults = [...StageInstructions.matchAll(StageDefaultPattern)]
        .map(Match => (Match[1] ?? '').trim())
      if (StageDefaults.length > 0) {
        PushViolation(
          Violations,
          RepositoryVersionPolicy.dockerfilePath,
          `${Assignment.field} stage defaults`,
          '<unset ARG redeclarations>',
          StageDefaults.join(',')
        )
      }
    }
  }

  const Helper = ReadPolicyFile(
    WorkspacePath,
    RepositoryVersionPolicy.releaseHelperPath,
    Violations
  )
  if (Helper === undefined) {
    return
  }

  CheckAllowedShellAssignments(
    Helper,
    RepositoryVersionPolicy.releaseHelperPath,
    Violations
  )

  const DefaultBlock = Helper.split(/^[ \t]*if \[\[ "\$\{derived_revision\}"/m, 1)[0]
  for (const Assignment of RepositoryVersionPolicy.releaseHelperDefaults) {
    const Value = ReadUniqueScalar(
      DefaultBlock,
      RepositoryVersionPolicy.releaseHelperPath,
      Assignment.field,
      '',
      Assignment.expected,
      Violations
    )
    if (Value !== undefined && Value !== Assignment.expected) {
      PushViolation(
        Violations,
        RepositoryVersionPolicy.releaseHelperPath,
        Assignment.field,
        Assignment.expected,
        Value
      )
    }
  }

  const FallbackBlock = Helper.split(/^[ \t]*case "\$\{artifact_arch\}"/m, 1)[0]
  for (const Assignment of RepositoryVersionPolicy.releaseHelperFallbacks) {
    const Value = ReadUniqueScalar(
      FallbackBlock,
      RepositoryVersionPolicy.releaseHelperPath,
      Assignment.field,
      '',
      Assignment.expected,
      Violations
    )
    if (Value !== undefined && Value !== Assignment.expected) {
      PushViolation(
        Violations,
        RepositoryVersionPolicy.releaseHelperPath,
        Assignment.field,
        Assignment.expected,
        Value
      )
    }
  }
}

function CheckArchiveIdentitySource(
  WorkspacePath: string,
  Violations: VersionPolicyViolation[]
): void {
  const Content = ReadPolicyFile(
    WorkspacePath,
    RepositoryVersionPolicy.archiveIdentitySourcePath,
    Violations
  )
  if (Content === undefined) {
    return
  }

  const Literal = JSON.stringify(RepositoryVersionPolicy.archiveIdentity.version)
  const Occurrences = Content.split(Literal).length - 1
  if (Occurrences !== RepositoryVersionPolicy.archiveVersionLiteralOccurrences) {
    PushViolation(
      Violations,
      RepositoryVersionPolicy.archiveIdentitySourcePath,
      'archive version literal occurrences',
      `${RepositoryVersionPolicy.archiveVersionLiteralOccurrences} x ${Literal}`,
      `${Occurrences} x ${Literal}`
    )
  }
}

export function CollectRepositoryVersionPolicyViolations(
  WorkspacePath: string
): VersionPolicyReport {
  const ResolvedWorkspace = Path.resolve(WorkspacePath)
  const Violations: VersionPolicyViolation[] = []
  const Version = CheckRootCargoPolicy(ResolvedWorkspace, Violations)

  for (const PackagePolicy of RepositoryVersionPolicy.cargoPackages) {
    CheckCargoManifestPolicy(ResolvedWorkspace, PackagePolicy, Violations)
  }

  const Lockfiles = new Map<string, Array<Readonly<CargoPackagePolicy>>>()
  for (const PackagePolicy of RepositoryVersionPolicy.cargoPackages) {
    const Policies = Lockfiles.get(PackagePolicy.lockfilePath) ?? []
    Policies.push(PackagePolicy)
    Lockfiles.set(PackagePolicy.lockfilePath, Policies)
  }
  for (const [LockfilePath, PackagePolicies] of Lockfiles) {
    CheckCargoLockPolicy(ResolvedWorkspace, LockfilePath, PackagePolicies, Violations)
  }

  CheckNpmPolicy(ResolvedWorkspace, Violations)
  CheckHelmPolicy(ResolvedWorkspace, Violations)
  CheckDockerPolicy(ResolvedWorkspace, Violations)
  CheckArchiveIdentitySource(ResolvedWorkspace, Violations)

  return {
    version: Version,
    violations: Violations
  }
}

export function AssertRepositoryVersionPolicy(WorkspacePath: string): string {
  const Report = CollectRepositoryVersionPolicyViolations(WorkspacePath)
  if (Report.violations.length > 0) {
    const Details = Report.violations
      .map(Violation =>
        `- ${Violation.path} ${Violation.field}: expected ${DisplayValue(Violation.expected)}, ` +
        `found ${DisplayValue(Violation.actual)}`
      )
      .join('\n')
    throw new Error(`committed repository version policy requires development defaults:\n${Details}`)
  }
  return Report.version
}
