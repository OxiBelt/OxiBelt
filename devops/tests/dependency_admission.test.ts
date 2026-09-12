import * as Assert from 'node:assert/strict'
import * as Fs from 'node:fs'
import * as Os from 'node:os'
import * as Path from 'node:path'
import test from 'node:test'
import { ValidateDependencyAdmission } from '../sources/dependency_admission.js'

/* oxlint-disable oxibelt/pascal-case -- Test fixtures intentionally mirror external JSON and YAML keys. */
type Fixture = {
  root: string
  policyPath: string
  licenseReportPath: string
  auditReportPath: string
}

const PackageManager = 'pnpm@11.21.0+sha512.521705bce689924eac72f5a3587122f362689ef6571e55ba80076fd637c11132ecffada26fad4ea79c485bfddbfd3d5a2a5b05805a77e893de71ec8a6cca3bb1'
const Pnpm12PackageManager =
  'pnpm@12.4.1+sha512.2e81e399d73fe8390dab25e06aa788ab7a5908248d2f5a370f82b481147a6a7a367bf8048f9a6fdb6460f21a66f0542dedb8b94ca2c8723596741920b1656d4c'
const Pnpm12Integrity = 'sha512-LoHjmdc/6DkNqyXgaqeIq3pZCCSNL1o3D4K0gRR6ano2e/gEj5pv22Rg8hpm8FQt7bi5TKLIcjWWdBkgsWVtTA=='
const Integrity = `sha512-${Buffer.alloc(64, 7).toString('base64')}`

function WriteJson(FilePath: string, Value: unknown): void {
  Fs.writeFileSync(FilePath, `${JSON.stringify(Value, null, 2)}\n`)
}

function CreateFixture(): Fixture {
  const Root = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-dependency-admission-'))
  Fs.mkdirSync(Path.join(Root, 'packages'))
  WriteJson(Path.join(Root, 'package.json'), {
    name: 'fixture-root',
    private: true,
    packageManager: PackageManager,
    workspaces: ['packages'],
    dependencies: { alpha: '1.2.3' },
    devDependencies: { esbuild: '0.28.2' }
  })
  WriteJson(Path.join(Root, 'packages', 'package.json'), {
    name: '@fixture/packages',
    private: true,
    dependencies: {}
  })
  Fs.writeFileSync(
    Path.join(Root, 'pnpm-workspace.yaml'),
    `packages:
  - "packages"
registry: "https://registry.npmjs.org/"
blockExoticSubdeps: true
trustLockfile: false
strictDepBuilds: true
minimumReleaseAge: 1440
auditConfig:
  ignoreGhsas: []
allowBuilds:
  "esbuild@0.28.2": true
`
  )
  Fs.writeFileSync(
    Path.join(Root, 'pnpm-lock.yaml'),
    `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      alpha:
        specifier: 1.2.3
        version: 1.2.3
    devDependencies:
      esbuild:
        specifier: 0.28.2
        version: 0.28.2

  packages: {}

packages:

  alpha@1.2.3:
    resolution: {integrity: ${Integrity}}

  esbuild@0.28.2:
    resolution: {integrity: ${Integrity}}

snapshots:

  alpha@1.2.3: {}

  esbuild@0.28.2: {}
`
  )
  const PolicyPath = Path.join(Root, 'dependency-policy.json')
  WriteJson(PolicyPath, {
    schemaVersion: 1,
    rust: { preserved: true },
    node: {
      allowedRegistries: ['https://registry.npmjs.org/'],
      allowedLicenses: ['MIT'],
      lifecycleScripts: [
        {
          package: 'esbuild',
          version: '0.28.2',
          rationale: 'tsx requires the platform-specific esbuild compiler binary.'
        }
      ],
      auditExceptions: []
    }
  })
  const LicenseReportPath = Path.join(Root, 'licenses.json')
  WriteJson(LicenseReportPath, {
    MIT: [{ name: 'alpha', versions: ['1.2.3'], paths: ['/virtual/alpha'] }]
  })
  const AuditReportPath = Path.join(Root, 'audit.json')
  WriteJson(AuditReportPath, {
    advisories: {},
    metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 } }
  })

  return { root: Root, policyPath: 'dependency-policy.json', licenseReportPath: LicenseReportPath, auditReportPath: AuditReportPath }
}

function Cleanup(FixtureValue: Fixture): void {
  Fs.rmSync(FixtureValue.root, { force: true, recursive: true })
}

function Validate(FixtureValue: Fixture): ReturnType<typeof ValidateDependencyAdmission> {
  return ValidateDependencyAdmission({
    workspacePath: FixtureValue.root,
    policyPath: FixtureValue.policyPath,
    licenseReportPath: FixtureValue.licenseReportPath,
    auditReportPath: FixtureValue.auditReportPath,
    now: new Date('2026-07-21T12:00:00.000Z')
  })
}

function UsePnpm12Lockfile(FixtureValue: Fixture): void {
  const ManifestPath = Path.join(FixtureValue.root, 'package.json')
  const Manifest = JSON.parse(Fs.readFileSync(ManifestPath, 'utf8')) as { packageManager: string }
  Manifest.packageManager = Pnpm12PackageManager
  WriteJson(ManifestPath, Manifest)
  Fs.writeFileSync(
    Path.join(FixtureValue.root, 'pnpm-lock.yaml'),
    `lockfileVersion: '9.0'

importers:

  .:
    configDependencies: {}
    packageManagerDependencies:
      pnpm:
        specifier: 12.4.1
        version: 12.4.1

packages:

  pnpm@12.4.1:
    resolution: {integrity: ${Pnpm12Integrity}}

  '@pnpm/exe.linux-x64@12.4.1':
    resolution: {integrity: ${Integrity}}
    cpu: [x64]
    os: [linux]

snapshots:

  pnpm@12.4.1:
    optionalDependencies:
      '@pnpm/exe.linux-x64': 12.4.1

  '@pnpm/exe.linux-x64@12.4.1':
    optional: true

---
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      alpha:
        specifier: 1.2.3
        version: 1.2.3
    devDependencies:
      esbuild:
        specifier: 0.28.2
        version: 0.28.2

  packages: {}

packages:

  alpha@1.2.3:
    resolution: {integrity: ${Integrity}}

  esbuild@0.28.2:
    resolution: {integrity: ${Integrity}}

snapshots:

  alpha@1.2.3: {}

  esbuild@0.28.2: {}
`
  )
}

test('accepts exact manifests, integrity-only lock entries, policy-bound scripts, and clean reports', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))

  Assert.deepEqual(Validate(FixtureValue), {
    manifests: 2,
    lockedPackages: 2,
    lifecycleScripts: 1,
    licenses: 1
  })
})

test('validates pnpm 12 managed tool dependencies across both lockfile documents', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  UsePnpm12Lockfile(FixtureValue)

  Assert.equal(Validate(FixtureValue).lockedPackages, 4)
})

test('rejects pnpm 12 lockfile tool integrity and package-manager pin drift', async TestContext => {
  await TestContext.test('package manager integrity', IntegrityContext => {
    const FixtureValue = CreateFixture()
    IntegrityContext.after(() => Cleanup(FixtureValue))
    UsePnpm12Lockfile(FixtureValue)
    const LockPath = Path.join(FixtureValue.root, 'pnpm-lock.yaml')
    const Lock = Fs.readFileSync(LockPath, 'utf8').replace(Pnpm12Integrity, Integrity)
    Fs.writeFileSync(LockPath, Lock)

    Assert.throws(() => Validate(FixtureValue), /does not match package[.]json packageManager SHA-512/)
  })

  await TestContext.test('managed package version', VersionContext => {
    const FixtureValue = CreateFixture()
    VersionContext.after(() => Cleanup(FixtureValue))
    UsePnpm12Lockfile(FixtureValue)
    const LockPath = Path.join(FixtureValue.root, 'pnpm-lock.yaml')
    const Lock = Fs.readFileSync(LockPath, 'utf8').replace(
      'specifier: 12.4.1\n        version: 12.4.1',
      'specifier: 12.4.0\n        version: 12.4.0'
    )
    Fs.writeFileSync(LockPath, Lock)

    Assert.throws(() => Validate(FixtureValue), /packageManagerDependencies must pin pnpm to 12[.]4[.]1/)
  })

  await TestContext.test('platform executable integrity node', ExecutableContext => {
    const FixtureValue = CreateFixture()
    ExecutableContext.after(() => Cleanup(FixtureValue))
    UsePnpm12Lockfile(FixtureValue)
    const LockPath = Path.join(FixtureValue.root, 'pnpm-lock.yaml')
    const Lock = Fs.readFileSync(LockPath, 'utf8').replace(
      `  '@pnpm/exe.linux-x64@12.4.1':\n    resolution: {integrity: ${Integrity}}`,
      "  '@pnpm/exe.linux-x64@12.4.1':\n    resolution: {tarball: https://registry.npmjs.org/@pnpm/exe.linux-x64/-/exe.tgz}"
    )
    Fs.writeFileSync(LockPath, Lock)

    Assert.throws(() => Validate(FixtureValue), /non-registry or non-integrity resolution/)
  })
})

test('rejects duplicate package identities within each pnpm 12 lockfile document', async TestContext => {
  await TestContext.test('managed tools document', ToolContext => {
    const FixtureValue = CreateFixture()
    ToolContext.after(() => Cleanup(FixtureValue))
    UsePnpm12Lockfile(FixtureValue)
    const LockPath = Path.join(FixtureValue.root, 'pnpm-lock.yaml')
    const Lock = Fs.readFileSync(LockPath, 'utf8')
    const Entry = `  pnpm@12.4.1:\n    resolution: {integrity: ${Pnpm12Integrity}}`
    Fs.writeFileSync(LockPath, Lock.replace(Entry, `${Entry}\n\n${Entry}`))

    Assert.throws(() => Validate(FixtureValue), /repeats package pnpm@12[.]4[.]1 in one document/)
  })

  await TestContext.test('workspace dependency document', WorkspaceContext => {
    const FixtureValue = CreateFixture()
    WorkspaceContext.after(() => Cleanup(FixtureValue))
    UsePnpm12Lockfile(FixtureValue)
    const LockPath = Path.join(FixtureValue.root, 'pnpm-lock.yaml')
    const Lock = Fs.readFileSync(LockPath, 'utf8')
    const Entry = `  alpha@1.2.3:\n    resolution: {integrity: ${Integrity}}`
    Fs.writeFileSync(LockPath, Lock.replace(Entry, `${Entry}\n\n${Entry}`))

    Assert.throws(() => Validate(FixtureValue), /repeats package alpha@1[.]2[.]3 in one document/)
  })
})

test('allows a tool package in both pnpm 12 documents only with identical integrity', async TestContext => {
  await TestContext.test('identical integrity', IntegrityContext => {
    const FixtureValue = CreateFixture()
    IntegrityContext.after(() => Cleanup(FixtureValue))
    UsePnpm12Lockfile(FixtureValue)
    const LockPath = Path.join(FixtureValue.root, 'pnpm-lock.yaml')
    const Lock = Fs.readFileSync(LockPath, 'utf8')
    const Entry = `  alpha@1.2.3:\n    resolution: {integrity: ${Integrity}}`
    Fs.writeFileSync(
      LockPath,
      Lock.replace(Entry, `${Entry}\n\n  pnpm@12.4.1:\n    resolution: {integrity: ${Pnpm12Integrity}}`)
    )

    Assert.equal(Validate(FixtureValue).lockedPackages, 4)
  })

  await TestContext.test('conflicting integrity', ConflictContext => {
    const FixtureValue = CreateFixture()
    ConflictContext.after(() => Cleanup(FixtureValue))
    UsePnpm12Lockfile(FixtureValue)
    const LockPath = Path.join(FixtureValue.root, 'pnpm-lock.yaml')
    const Lock = Fs.readFileSync(LockPath, 'utf8')
    const Entry = `  alpha@1.2.3:\n    resolution: {integrity: ${Integrity}}`
    Fs.writeFileSync(
      LockPath,
      Lock.replace(Entry, `${Entry}\n\n  pnpm@12.4.1:\n    resolution: {integrity: ${Integrity}}`)
    )

    Assert.throws(() => Validate(FixtureValue), /has conflicting integrity across documents/)
  })
})

test('rejects ranged external manifest dependencies', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  const ManifestPath = Path.join(FixtureValue.root, 'package.json')
  const Manifest = JSON.parse(Fs.readFileSync(ManifestPath, 'utf8')) as { dependencies: Record<string, string> }
  Manifest.dependencies.alpha = '^1.2.3'
  WriteJson(ManifestPath, Manifest)

  Assert.throws(() => Validate(FixtureValue), /must pin external dependency alpha to an exact semantic version/)
})

test('rejects tarball and other non-integrity lock resolutions', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  const LockPath = Path.join(FixtureValue.root, 'pnpm-lock.yaml')
  const Lock = Fs.readFileSync(LockPath, 'utf8').replace(
    `resolution: {integrity: ${Integrity}}`,
    'resolution: {tarball: https://example.invalid/alpha.tgz}'
  )
  Fs.writeFileSync(LockPath, Lock)

  Assert.throws(() => Validate(FixtureValue), /non-registry or non-integrity resolution/)
})

test('requires lifecycle-script approvals to be exact and policy-bound', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  const WorkspacePath = Path.join(FixtureValue.root, 'pnpm-workspace.yaml')
  const Workspace = Fs.readFileSync(WorkspacePath, 'utf8').replace('"esbuild@0.28.2": true', 'esbuild: true')
  Fs.writeFileSync(WorkspacePath, Workspace)

  Assert.throws(() => Validate(FixtureValue), /allowBuilds must exactly match node.lifecycleScripts/)
})

test('rejects disallowed licenses and unadmitted advisories', async TestContext => {
  await TestContext.test('license', LicenseContext => {
    const FixtureValue = CreateFixture()
    LicenseContext.after(() => Cleanup(FixtureValue))
    WriteJson(FixtureValue.licenseReportPath, {
      GPL: [{ name: 'alpha', versions: ['1.2.3'] }]
    })

    Assert.throws(() => Validate(FixtureValue), /disallowed or unknown license expression: GPL/)
  })
  await TestContext.test('advisory', AdvisoryContext => {
    const FixtureValue = CreateFixture()
    AdvisoryContext.after(() => Cleanup(FixtureValue))
    WriteJson(FixtureValue.auditReportPath, {
      advisories: {
        123: {
          github_advisory_id: 'GHSA-2345-6789-cfgh',
          module_name: 'alpha',
          vulnerable_versions: '<1.2.4'
        }
      },
      metadata: { vulnerabilities: { low: 1 } }
    })

    Assert.throws(() => Validate(FixtureValue), /unadmitted advisories: GHSA-2345-6789-CFGH:alpha:<1[.]2[.]4/)
  })
})

test('rejects pnpm audit error envelopes with bounded diagnostics', async TestContext => {
  await TestContext.test('numeric timeout code', NumericContext => {
    const FixtureValue = CreateFixture()
    NumericContext.after(() => Cleanup(FixtureValue))
    WriteJson(FixtureValue.auditReportPath, {
      error: { code: 23, message: 'The operation was aborted due to timeout', details: 'must-not-be-rendered' }
    })

    Assert.throws(
      () => Validate(FixtureValue),
      ErrorValue =>
        ErrorValue instanceof Error &&
        ErrorValue.message ===
          'pnpm audit command returned an error report (code 23): The operation was aborted due to timeout'
    )
  })
  await TestContext.test('string error code', StringContext => {
    const FixtureValue = CreateFixture()
    StringContext.after(() => Cleanup(FixtureValue))
    WriteJson(FixtureValue.auditReportPath, {
      error: { code: 'ERR_PNPM_AUDIT_BAD_RESPONSE', message: 'Registry response was unavailable' }
    })

    Assert.throws(
      () => Validate(FixtureValue),
      ErrorValue =>
        ErrorValue instanceof Error &&
        ErrorValue.message ===
          'pnpm audit command returned an error report (code ERR_PNPM_AUDIT_BAD_RESPONSE): Registry response was unavailable'
    )
  })
  await TestContext.test('malformed envelope', MalformedContext => {
    const FixtureValue = CreateFixture()
    MalformedContext.after(() => Cleanup(FixtureValue))
    WriteJson(FixtureValue.auditReportPath, {
      error: { code: { secret: 'must-not-be-rendered' }, message: 'also-must-not-be-rendered' }
    })

    Assert.throws(
      () => Validate(FixtureValue),
      ErrorValue =>
        ErrorValue instanceof Error &&
        ErrorValue.message === 'pnpm audit report contains a malformed error envelope' &&
        !ErrorValue.message.includes('must-not-be-rendered')
    )
  })
  await TestContext.test('error envelope takes precedence over success fields', MixedContext => {
    const FixtureValue = CreateFixture()
    MixedContext.after(() => Cleanup(FixtureValue))
    WriteJson(FixtureValue.auditReportPath, {
      error: { code: 23, message: 'timeout', details: 'must-not-be-rendered' },
      advisories: {},
      metadata: { vulnerabilities: {} }
    })

    Assert.throws(
      () => Validate(FixtureValue),
      ErrorValue =>
        ErrorValue instanceof Error && ErrorValue.message === 'pnpm audit command returned an error report (code 23): timeout'
    )
  })
  await TestContext.test('diagnostics are single-line and truncated', BoundedContext => {
    const FixtureValue = CreateFixture()
    BoundedContext.after(() => Cleanup(FixtureValue))
    WriteJson(FixtureValue.auditReportPath, {
      error: {
        code: `CODE\n${'C'.repeat(80)}`,
        message: `first\r\nsecond\tthird\u2028fourth\u2029${'M'.repeat(600)}`
      }
    })

    let ErrorValue: unknown
    Assert.throws(() => Validate(FixtureValue), Candidate => {
      ErrorValue = Candidate
      return true
    })
    Assert.ok(ErrorValue instanceof Error)
    Assert.equal(ErrorValue.message.includes('\n'), false)
    Assert.equal(ErrorValue.message.includes('\r'), false)
    Assert.equal(ErrorValue.message.includes('\t'), false)
    Assert.equal(ErrorValue.message.includes('\u2028'), false)
    Assert.equal(ErrorValue.message.includes('\u2029'), false)
    const Match = ErrorValue.message.match(/^pnpm audit command returned an error report \(code (.*)\): (.*)$/)
    Assert.ok(Match !== null)
    Assert.equal([...Match[1]].length, 64)
    Assert.equal([...Match[2]].length, 512)
    Assert.match(Match[1], /\.\.\.$/)
    Assert.match(Match[2], /\.\.\.$/)
  })
})

test('accepts an active audit exception with an exact report and workspace match', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  const PolicyPath = Path.join(FixtureValue.root, FixtureValue.policyPath)
  const Policy = JSON.parse(Fs.readFileSync(PolicyPath, 'utf8')) as {
    node: { auditExceptions: Array<Record<string, string>> }
  }
  Policy.node.auditExceptions.push({
    id: 'GHSA-2345-6789-cfgh',
    package: 'alpha',
    versions: '<1.2.4',
    rationale: 'No patched version is currently compatible with the fixture.',
    owner: '@security-team',
    issue: 'https://github.com/example/project/issues/1',
    reviewedOn: '2026-07-01',
    expiresOn: '2026-08-01'
  })
  WriteJson(PolicyPath, Policy)
  const WorkspacePath = Path.join(FixtureValue.root, 'pnpm-workspace.yaml')
  Fs.writeFileSync(
    WorkspacePath,
    Fs.readFileSync(WorkspacePath, 'utf8').replace(
      '  ignoreGhsas: []',
      '  ignoreGhsas:\n    - "GHSA-2345-6789-cfgh"'
    )
  )
  WriteJson(FixtureValue.auditReportPath, {
    advisories: {
      123: {
        github_advisory_id: 'GHSA-2345-6789-cfgh',
        module_name: 'alpha',
        vulnerable_versions: '<1.2.4'
      }
    },
    metadata: { vulnerabilities: { low: 1 } }
  })

  Assert.equal(Validate(FixtureValue).lockedPackages, 2)
})

test('rejects an active policy ignore that is absent from the audit report', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  const PolicyPath = Path.join(FixtureValue.root, FixtureValue.policyPath)
  const Policy = JSON.parse(Fs.readFileSync(PolicyPath, 'utf8')) as {
    node: { auditExceptions: Array<Record<string, string>> }
  }
  Policy.node.auditExceptions.push({
    id: 'GHSA-2345-6789-cfgh',
    package: 'alpha',
    versions: '<1.2.4',
    rationale: 'No patched version is currently compatible with the fixture.',
    owner: '@security-team',
    issue: 'https://github.com/example/project/issues/1',
    reviewedOn: '2026-07-01',
    expiresOn: '2026-08-01'
  })
  WriteJson(PolicyPath, Policy)
  const WorkspacePath = Path.join(FixtureValue.root, 'pnpm-workspace.yaml')
  Fs.writeFileSync(
    WorkspacePath,
    Fs.readFileSync(WorkspacePath, 'utf8').replace(
      '  ignoreGhsas: []',
      '  ignoreGhsas:\n    - "GHSA-2345-6789-cfgh"'
    )
  )

  Assert.throws(() => Validate(FixtureValue), /stale or unreported advisories: GHSA-2345-6789-CFGH/)
})

test('rejects expired audit exceptions even when pnpm ignore configuration matches', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  const PolicyPath = Path.join(FixtureValue.root, FixtureValue.policyPath)
  const Policy = JSON.parse(Fs.readFileSync(PolicyPath, 'utf8')) as {
    node: { auditExceptions: Array<Record<string, string>> }
  }
  Policy.node.auditExceptions.push({
    id: 'GHSA-2345-6789-cfgh',
    package: 'alpha',
    versions: '<1.2.4',
    rationale: 'No patched version is currently compatible with the fixture.',
    owner: '@security-team',
    issue: 'https://github.com/example/project/issues/1',
    reviewedOn: '2026-07-01',
    expiresOn: '2026-07-20'
  })
  WriteJson(PolicyPath, Policy)
  const WorkspacePath = Path.join(FixtureValue.root, 'pnpm-workspace.yaml')
  Fs.writeFileSync(
    WorkspacePath,
    Fs.readFileSync(WorkspacePath, 'utf8').replace(
      '  ignoreGhsas: []',
      '  ignoreGhsas:\n    - "GHSA-2345-6789-cfgh"'
    )
  )

  Assert.throws(() => Validate(FixtureValue), /expired on 2026-07-20/)
})
